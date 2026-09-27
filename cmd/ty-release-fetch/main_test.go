package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tygateway/internal/release"
)

func TestPrepareVersionCacheSeparatesVersions(t *testing.T) {
	base := t.TempDir()
	one, err := prepareVersionCache(base, "pilot", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	two, err := prepareVersionCache(base, "pilot", "1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if one == two || one != filepath.Join(base, "pilot", "1.0.0") || two != filepath.Join(base, "pilot", "1.0.1") {
		t.Fatalf("version caches collide: %q, %q", one, two)
	}
	if again, err := prepareVersionCache(base, "pilot", "1.0.0"); err != nil || again != one {
		t.Fatalf("existing private cache was not reused: %q, %v", again, err)
	}
	if stable, err := prepareVersionCache(base, "stable", "1.0.0"); err != nil || stable == one {
		t.Fatalf("pilot and stable signatures collided: %q, %v", stable, err)
	}
	if _, err := prepareVersionCache(base, "pilot", "../escape"); err == nil {
		t.Fatal("unsafe cache version was accepted")
	}
}

func TestPrepareVersionCacheRejectsNonDirectory(t *testing.T) {
	base := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(base, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareVersionCache(base, "pilot", "1.0.0"); err == nil {
		t.Fatal("file accepted as cache directory")
	}
}

func TestCacheSignedBundleRejectsChanges(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "release.json")
	if err := cacheSignedBundle(filename, []byte("signed")); err != nil {
		t.Fatal(err)
	}
	if err := cacheSignedBundle(filename, []byte("signed")); err != nil {
		t.Fatalf("identical bundle not reused: %v", err)
	}
	if err := cacheSignedBundle(filename, []byte("changed")); err == nil {
		t.Fatal("changed bundle replaced a cached signature")
	}
	if data, err := os.ReadFile(filename); err != nil || string(data) != "signed" {
		t.Fatalf("cached signed bundle changed: %q, %v", data, err)
	}
}

func TestStageLocalRequiresSignedMatchingArchive(t *testing.T) {
	dir := t.TempDir()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"install-oec-overlay.sh":                                       "#!/bin/sh\n",
		"restore-oec-overlay.sh":                                       "#!/bin/sh\n",
		"SHA256SUMS":                                                   "signed package checksums\n",
		"overlay-manifest.json":                                        "{}\n",
		"payload/usr/local/bin/ty-release-fetch":                       "fetch",
		"payload/usr/local/libexec/ty-gateway-update":                  "update",
		"payload/usr/local/libexec/ty-gateway-update-service":          "update service",
		"payload/etc/systemd/system/ty-gateway-update-recover.service": "recover unit",
		"payload/etc/systemd/system/ty-gateway-update-service.service": "update unit",
		"payload/etc/ty-gateway/release-public.pem":                    "public",
	} {
		payload := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: "overlay/" + name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(payload))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "local-upload.tar.gz")
	if err := os.WriteFile(artifact, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "release-public.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(archive.Bytes())
	manifest, err := release.Marshal(release.Manifest{
		FormatVersion: 1, Product: "ty-gateway", Channel: "pilot", Version: "0.7.0",
		Platform: "linux-arm64", Artifact: "releases/0.7.0/local-upload.tar.gz",
		SHA256: hex.EncodeToString(hash[:]), Size: int64(archive.Len()), PublishedAt: "2026-09-27T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := release.SignBundle(private, manifest)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "signed-release.json")
	if err := os.WriteFile(bundlePath, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	argv := []string{"stage-local", "-channel", "pilot", "-public-key", keyPath,
		"-output-dir", cache, "-bundle", bundlePath, "-artifact", artifact}
	if err := run(argv); err != nil {
		t.Fatal(err)
	}
	versionDir := filepath.Join(cache, "pilot", "0.7.0")
	if _, err := os.Stat(filepath.Join(versionDir, "release.json")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(versionDir)
	if err != nil {
		t.Fatal(err)
	}
	staged := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "stage-") {
			if _, err := os.Stat(filepath.Join(versionDir, entry.Name(), "overlay", "install-oec-overlay.sh")); err == nil {
				staged = true
			}
		}
	}
	if !staged {
		t.Fatal("signed local release was not staged")
	}
	corrupt := append([]byte(nil), bundle...)
	corrupt[len(corrupt)/2] ^= 1
	if err := os.WriteFile(bundlePath, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(argv); err == nil {
		t.Fatal("altered signature bundle was accepted")
	}
}
