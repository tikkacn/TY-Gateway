package release

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	maxOverlayEntries = 2048
	maxExpandedBytes  = 1 << 30
	maxTarPadding     = 1 << 20
)

// StageOverlayArchive extracts a verified release archive into a new directory.
// It never executes the installer. The staging directory must be private to the
// caller; otherwise another local user could swap files after validation.
func StageOverlayArchive(archivePath, parentDir string) (string, error) {
	archiveInfo, err := os.Lstat(archivePath)
	if err != nil {
		return "", err
	}
	if !archiveInfo.Mode().IsRegular() || archiveInfo.Size() <= 0 || archiveInfo.Size() > MaxArtifactBytes {
		return "", errors.New("release archive must be a regular file within the size limit")
	}
	parentInfo, err := os.Lstat(parentDir)
	if err != nil {
		return "", err
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("release staging parent must be a real directory")
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("open release gzip: %w", err)
	}
	defer gz.Close()
	tmp, err := os.MkdirTemp(parentDir, ".ty-release-extract-")
	if err != nil {
		return "", err
	}
	defer func() {
		// tmp is returned by MkdirTemp directly beneath the checked parent.
		if filepath.Dir(tmp) == filepath.Clean(parentDir) && strings.HasPrefix(filepath.Base(tmp), ".ty-release-extract-") {
			_ = os.RemoveAll(tmp)
		}
	}()

	reader := tar.NewReader(gz)
	seen := make(map[string]bool)
	root := ""
	var expanded int64
	entries := 0
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return "", fmt.Errorf("read release tar: %w", nextErr)
		}
		entries++
		if entries > maxOverlayEntries {
			return "", errors.New("release archive has too many entries")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || name != path.Clean(name) || strings.HasPrefix(name, "/") ||
			strings.Contains(name, "\\") || !filePattern.MatchString(name) ||
			name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") ||
			strings.HasPrefix(name, "./") || strings.Contains(name, "/./") {
			return "", errors.New("unsafe path in release archive")
		}
		parts := strings.Split(name, "/")
		if parts[0] == "." || parts[0] == ".." || strings.HasPrefix(parts[0], ".") {
			return "", errors.New("unsafe archive root directory")
		}
		if root == "" {
			root = parts[0]
		} else if root != parts[0] {
			return "", errors.New("release archive has multiple root directories")
		}
		if seen[name] {
			return "", errors.New("duplicate entry in release archive")
		}
		seen[name] = true
		if header.Linkname != "" {
			return "", errors.New("links are not allowed in release archive")
		}
		target := filepath.Join(tmp, filepath.FromSlash(name))
		rel, err := filepath.Rel(tmp, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", errors.New("release archive path escapes staging directory")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return "", errors.New("release directory has a body")
			}
			if err := os.MkdirAll(target, 0700); err != nil {
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if len(parts) == 1 || header.Size < 0 || header.Size > maxExpandedBytes-expanded {
				return "", errors.New("release file is misplaced or too large")
			}
			expanded += header.Size
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return "", err
			}
			mode := os.FileMode(0600)
			if header.Mode&0111 != 0 {
				mode = 0700
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return "", err
			}
			_, copyErr := io.CopyN(out, reader, header.Size)
			syncErr := out.Sync()
			closeErr := out.Close()
			if copyErr != nil || syncErr != nil || closeErr != nil {
				return "", errors.New("release file could not be extracted")
			}
		default:
			return "", errors.New("release archive contains unsupported file type")
		}
	}
	if root == "" {
		return "", errors.New("release archive is empty")
	}
	// Draining verifies the gzip trailer instead of accepting a truncated stream.
	remaining, err := io.Copy(io.Discard, io.LimitReader(gz, maxTarPadding+1))
	if err != nil || remaining > maxTarPadding {
		return "", errors.New("release gzip trailer or padding is invalid")
	}
	for _, required := range []string{
		"install-oec-overlay.sh", "restore-oec-overlay.sh", "SHA256SUMS", "overlay-manifest.json",
		"payload/usr/local/bin/ty-release-fetch", "payload/usr/local/libexec/ty-gateway-update",
		"payload/usr/local/libexec/ty-gateway-update-service",
		"payload/etc/systemd/system/ty-gateway-update-recover.service",
		"payload/etc/systemd/system/ty-gateway-update-service.service",
		"payload/etc/ty-gateway/release-public.pem",
	} {
		info, err := os.Lstat(filepath.Join(tmp, root, required))
		if err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("release archive is missing %s", required)
		}
	}
	final := filepath.Join(parentDir, root)
	if _, err := os.Lstat(final); err == nil {
		return "", errors.New("refusing to overwrite an existing staged release")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(filepath.Join(tmp, root), final); err != nil {
		return "", err
	}
	return final, nil
}
