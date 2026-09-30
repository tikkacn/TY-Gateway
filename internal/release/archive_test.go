package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type archiveEntry struct {
	name string
	kind byte
	body string
	link string
}

func makeArchive(t *testing.T, entries []archiveEntry) string {
	t.Helper()
	var content bytes.Buffer
	gz := gzip.NewWriter(&content)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		h := &tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: 0755, Size: int64(len(entry.body)), Linkname: entry.link}
		if entry.kind == tar.TypeDir || entry.kind == tar.TypeSymlink {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "release.tar.gz")
	if err := os.WriteFile(filename, content.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func validOverlayEntries() []archiveEntry {
	return []archiveEntry{
		{name: "oec-overlay/", kind: tar.TypeDir},
		{name: "oec-overlay/install-oec-overlay.sh", kind: tar.TypeReg, body: "#!/bin/sh\nexit 0\n"},
		{name: "oec-overlay/restore-oec-overlay.sh", kind: tar.TypeReg, body: "#!/bin/sh\nexit 0\n"},
		{name: "oec-overlay/SHA256SUMS", kind: tar.TypeReg, body: "checksums\n"},
		{name: "oec-overlay/overlay-manifest.json", kind: tar.TypeReg, body: "{}\n"},
		{name: "oec-overlay/payload/usr/local/bin/ty-release-fetch", kind: tar.TypeReg, body: "binary"},
		{name: "oec-overlay/payload/usr/local/libexec/ty-gateway-update", kind: tar.TypeReg, body: "#!/usr/bin/python3\n"},
		{name: "oec-overlay/payload/usr/local/libexec/ty-gateway-update-service", kind: tar.TypeReg, body: "#!/usr/bin/python3\n"},
		{name: "oec-overlay/payload/etc/systemd/system/ty-gateway-update-recover.service", kind: tar.TypeReg, body: "[Unit]\n"},
		{name: "oec-overlay/payload/etc/systemd/system/ty-gateway-update-service.service", kind: tar.TypeReg, body: "[Unit]\n"},
		{name: "oec-overlay/payload/etc/ty-gateway/release-public.pem", kind: tar.TypeReg, body: "public key"},
	}
}

func TestStageOverlayArchive(t *testing.T) {
	archive := makeArchive(t, validOverlayEntries())
	parent := t.TempDir()
	got, err := StageOverlayArchive(archive, parent)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(parent, "oec-overlay") {
		t.Fatalf("stage path = %q", got)
	}
	if data, err := os.ReadFile(filepath.Join(got, "install-oec-overlay.sh")); err != nil || !strings.Contains(string(data), "exit 0") {
		t.Fatalf("installer = %q, %v", data, err)
	}
	if _, err := StageOverlayArchive(archive, parent); err == nil {
		t.Fatal("existing staged directory was replaced")
	}
}

func TestStageOverlayArchiveRejectsUnsafeEntries(t *testing.T) {
	for name, bad := range map[string]archiveEntry{
		"traversal":   {name: "oec-overlay/../outside", kind: tar.TypeReg, body: "bad"},
		"absolute":    {name: "/oec-overlay/outside", kind: tar.TypeReg, body: "bad"},
		"symlink":     {name: "oec-overlay/link", kind: tar.TypeSymlink, link: "../../outside"},
		"second root": {name: "other-root/file", kind: tar.TypeReg, body: "bad"},
		"duplicate":   {name: "oec-overlay/SHA256SUMS", kind: tar.TypeReg, body: "bad"},
	} {
		t.Run(name, func(t *testing.T) {
			archive := makeArchive(t, append(validOverlayEntries(), bad))
			parent := t.TempDir()
			if _, err := StageOverlayArchive(archive, parent); err == nil {
				t.Fatal("unsafe release archive was accepted")
			}
			if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
				t.Fatalf("rejected archive left files: %v, %v", entries, err)
			}
		})
	}
}

func TestStageOverlayArchiveRejectsTruncatedGzip(t *testing.T) {
	archive := makeArchive(t, validOverlayEntries())
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, data[:len(data)-8], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageOverlayArchive(archive, t.TempDir()); err == nil {
		t.Fatal("truncated gzip was accepted")
	}
}
