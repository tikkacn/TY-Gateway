// ty-release-fetch checks and downloads a signed TY Gateway release. It is
// intentionally read-only with respect to installed programs and services.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"tygateway/internal/release"
)

// The public mirror is selected when building a signed device release. It is
// intentionally not a web/API parameter or a runtime URL supplied by users.
var githubRepo = "tikkacn/TY-Gateway"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "fetch" && args[0] != "stage" && args[0] != "stage-local") {
		return errors.New("usage: ty-release-fetch check|fetch|stage|stage-local [-channel pilot|stable] [-public-key FILE] [-output-dir DIR] [-bundle FILE -artifact FILE for stage-local]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	channel := fs.String("channel", "pilot", "pilot or stable")
	keyPath := fs.String("public-key", "/etc/ty-gateway/release-public.pem", "pinned release public key")
	outputDir := fs.String("output-dir", "", "existing directory for a verified archive")
	bundlePath := fs.String("bundle", "", "local signed release bundle for stage-local")
	artifactPath := fs.String("artifact", "", "local release archive for stage-local")
	jsonOutput := fs.Bool("json", false, "print machine-readable result")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (args[0] != "check" && *outputDir == "") ||
		(args[0] == "stage-local") != (*bundlePath != "" && *artifactPath != "") ||
		(args[0] != "stage-local" && (*bundlePath != "" || *artifactPath != "")) {
		return errors.New("unexpected argument or missing -output-dir")
	}
	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	key, err := release.ParsePublicKeyPEM(keyData)
	if err != nil {
		return err
	}
	var m release.Manifest
	var bundle []byte
	var filename string
	if args[0] == "stage-local" {
		bundle, err = readBoundedRegular(*bundlePath, release.MaxBundleBytes)
		if err != nil {
			return err
		}
		m, err = release.VerifyBundle(key, bundle)
		if err != nil {
			return err
		}
		if m.Channel != *channel || m.Platform != "linux-arm64" {
			return errors.New("release channel or platform mismatch")
		}
	} else {
		downloader, createErr := release.NewMirroredDownloader(key, githubRepo)
		if createErr != nil {
			return createErr
		}
		m, bundle, err = downloader.LatestBundle(context.Background(), *channel)
		if err != nil {
			return err
		}
		if args[0] != "check" {
			versionDir, cacheErr := prepareVersionCache(*outputDir, m.Channel, m.Version)
			if cacheErr != nil {
				return cacheErr
			}
			filename, err = downloader.DownloadArtifact(context.Background(), m, versionDir)
			if err != nil {
				return err
			}
		}
	}
	if args[0] == "check" {
		return emit(*jsonOutput, fetchResult{Channel: m.Channel, Version: m.Version, Size: m.Size})
	}
	versionDir, err := prepareVersionCache(*outputDir, m.Channel, m.Version)
	if err != nil {
		return err
	}
	if args[0] == "stage-local" {
		filename, err = cacheLocalArtifact(*artifactPath, versionDir, m)
		if err != nil {
			return err
		}
	}
	if err := cacheSignedBundle(filepath.Join(versionDir, "release.json"), bundle); err != nil {
		return err
	}
	if args[0] == "fetch" {
		return emit(*jsonOutput, fetchResult{Channel: m.Channel, Version: m.Version, Size: m.Size, Bundle: filepath.Join(versionDir, "release.json"), Artifact: filename})
	}
	stageParent, err := os.MkdirTemp(versionDir, "stage-")
	if err != nil {
		return err
	}
	staged, err := release.StageOverlayArchive(filename, stageParent)
	if err != nil {
		_ = os.RemoveAll(stageParent)
		return err
	}
	return emit(*jsonOutput, fetchResult{Channel: m.Channel, Version: m.Version, Size: m.Size, Bundle: filepath.Join(versionDir, "release.json"), Artifact: filename, Staged: staged})
}

type fetchResult struct {
	Channel  string `json:"channel"`
	Version  string `json:"version"`
	Size     int64  `json:"size"`
	Bundle   string `json:"bundle,omitempty"`
	Artifact string `json:"artifact,omitempty"`
	Staged   string `json:"staged,omitempty"`
}

func emit(machine bool, result fetchResult) error {
	if machine {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if result.Staged != "" {
		fmt.Printf("verified overlay staged without installation: %s\n", result.Staged)
	} else if result.Artifact != "" {
		fmt.Printf("verified archive saved: %s\n", result.Artifact)
	} else {
		fmt.Printf("signed release available: %s linux-arm64 (%d bytes)\n", result.Version, result.Size)
	}
	return nil
}

func readBoundedRegular(filename string, limit int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("local release file is not a regular file within the size limit")
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("local release file exceeds the size limit")
	}
	return data, nil
}

func cacheLocalArtifact(source, destDir string, m release.Manifest) (string, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != m.Size {
		return "", errors.New("local artifact size differs from signed manifest")
	}
	f, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := release.VerifyArtifact(m, f); err != nil {
		return "", err
	}
	final := filepath.Join(destDir, filepath.Base(m.Artifact))
	if existing, err := os.Lstat(final); err == nil {
		if !existing.Mode().IsRegular() {
			return "", errors.New("cached artifact is not a regular file")
		}
		cached, err := os.Open(final)
		if err != nil {
			return "", err
		}
		verifyErr := release.VerifyArtifact(m, cached)
		closeErr := cached.Close()
		if verifyErr != nil || closeErr != nil {
			return "", errors.New("cached artifact differs from signed manifest")
		}
		return final, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(destDir, ".local-artifact-")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, io.LimitReader(f, m.Size+1)); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	checked, err := os.Open(tmp.Name())
	if err != nil {
		return "", err
	}
	verifyErr := release.VerifyArtifact(m, checked)
	closeErr := checked.Close()
	if verifyErr != nil || closeErr != nil {
		return "", errors.New("local artifact changed during caching")
	}
	if err := os.Link(tmp.Name(), final); err != nil {
		return "", err
	}
	return final, nil
}

var cacheVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func prepareVersionCache(base, channel, version string) (string, error) {
	if (channel != "pilot" && channel != "stable") || !cacheVersionPattern.MatchString(version) {
		return "", errors.New("invalid release cache channel or version")
	}
	baseInfo, err := os.Lstat(base)
	if err != nil {
		return "", err
	}
	if !baseInfo.IsDir() || baseInfo.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && baseInfo.Mode().Perm()&0022 != 0 {
		return "", errors.New("release cache must be a real, non-writable-by-others directory")
	}
	channelDir := filepath.Join(base, channel)
	if err := os.Mkdir(channelDir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	channelInfo, err := os.Lstat(channelDir)
	if err != nil {
		return "", err
	}
	if !channelInfo.IsDir() || channelInfo.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && channelInfo.Mode().Perm()&0077 != 0 {
		return "", errors.New("release channel cache must be a private real directory")
	}
	versionDir := filepath.Join(channelDir, version)
	if err := os.Mkdir(versionDir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	versionInfo, err := os.Lstat(versionDir)
	if err != nil {
		return "", err
	}
	if !versionInfo.IsDir() || versionInfo.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && versionInfo.Mode().Perm()&0077 != 0 {
		return "", errors.New("release version cache must be a private real directory")
	}
	return versionDir, nil
}

func cacheSignedBundle(filename string, bundle []byte) error {
	if len(bundle) == 0 || len(bundle) > release.MaxBundleBytes {
		return errors.New("signed release bundle size is invalid")
	}
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("cached release bundle is not a regular file")
		}
		previous, err := os.ReadFile(filename)
		if err != nil || string(previous) != string(bundle) {
			return errors.New("cached release bundle differs from downloaded signature")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(filename), ".release-bundle-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	_, writeErr := f.Write(bundle)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("could not save signed release bundle")
	}
	if err := os.Link(f.Name(), filename); err != nil {
		if errors.Is(err, os.ErrExist) {
			return cacheSignedBundle(filename, bundle)
		}
		return err
	}
	return nil
}
