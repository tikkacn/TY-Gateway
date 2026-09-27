// ty-release-manifest prepares and verifies detached, Ed25519-signed release
// metadata. It does not publish files or install software on a device.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"tygateway/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ty-release-manifest create|sign|verify [flags]")
	}
	switch args[0] {
	case "create":
		return create(args[1:])
	case "sign":
		return sign(args[1:])
	case "verify":
		return verify(args[1:])
	default:
		return errors.New("usage: ty-release-manifest create|sign|verify [flags]")
	}
}

func create(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	artifact := fs.String("artifact", "", "local overlay archive")
	version := fs.String("version", "", "release version, such as 0.7.0")
	channel := fs.String("channel", "pilot", "pilot or stable")
	output := fs.String("output", "", "new manifest JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *artifact == "" || *version == "" || *output == "" || fs.NArg() != 0 {
		return errors.New("create requires -artifact, -version and -output")
	}
	f, err := os.Open(*artifact)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > release.MaxArtifactBytes {
		return errors.New("artifact must be a regular file within the size limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil || n != info.Size() {
		return errors.New("artifact changed or could not be hashed")
	}
	m := release.Manifest{
		FormatVersion: 1,
		Product:       "ty-gateway",
		Channel:       *channel,
		Version:       *version,
		Platform:      "linux-arm64",
		Artifact:      "releases/" + *version + "/" + filepath.Base(*artifact),
		SHA256:        hex.EncodeToString(h.Sum(nil)),
		Size:          n,
		PublishedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	data, err := release.Marshal(m)
	if err != nil {
		return err
	}
	return writeNew(*output, data, 0644)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "manifest JSON path")
	keyPath := fs.String("private-key", "", "PKCS#8 Ed25519 private PEM path")
	output := fs.String("output", "", "new single-object signed release bundle path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *keyPath == "" || *output == "" || fs.NArg() != 0 {
		return errors.New("sign requires -manifest, -private-key and -output")
	}
	manifest, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	key, err := privateKey(*keyPath)
	if err != nil {
		return err
	}
	bundle, err := release.SignBundle(key, manifest)
	if err != nil {
		return err
	}
	return writeNew(*output, bundle, 0644)
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "", "single-object signed release bundle path")
	keyPath := fs.String("public-key", "", "Ed25519 public PEM path")
	artifactPath := fs.String("artifact", "", "local overlay archive path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || *keyPath == "" || *artifactPath == "" || fs.NArg() != 0 {
		return errors.New("verify requires -bundle, -public-key and -artifact")
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	key, err := publicKey(*keyPath)
	if err != nil {
		return err
	}
	m, err := release.VerifyBundle(key, bundle)
	if err != nil {
		return err
	}
	if filepath.Base(*artifactPath) != filepath.Base(m.Artifact) {
		return errors.New("artifact filename does not match signed manifest")
	}
	f, err := os.Open(*artifactPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := release.VerifyArtifact(m, f); err != nil {
		return err
	}
	fmt.Printf("verified %s %s %s\n", m.Product, m.Version, m.Platform)
	return nil
}

func privateKey(filename string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("signing key must be a regular owner-only file")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid PKCS#8 signing key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return edKey, nil
}

func publicKey(filename string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return release.ParsePublicKeyPEM(data)
}

func writeNew(filename string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
