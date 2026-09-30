package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloaderVerifiesBeforeSaving(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	archive := []byte("safe test archive")
	digest := sha256.Sum256(archive)
	m := sampleManifest()
	m.Size = int64(len(archive))
	m.SHA256 = hex.EncodeToString(digest[:])
	manifest, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := SignBundle(priv, manifest)
	if err != nil {
		t.Fatal(err)
	}
	archiveBody := archive
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/channels/pilot/linux-arm64/latest.json":
			w.Write(bundle)
		case "/" + m.Artifact:
			w.Write(archiveBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	d, err := newDownloader(server.URL, server.Client(), pub)
	if err != nil {
		t.Fatal(err)
	}
	got, signed, err := d.LatestBundle(context.Background(), "pilot")
	if err != nil || got != m {
		t.Fatalf("latest = %#v, %v", got, err)
	}
	if string(signed) != string(bundle) {
		t.Fatal("exact signed bundle bytes were not retained")
	}
	dir := t.TempDir()
	filename, err := d.DownloadArtifact(context.Background(), got, dir)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filename); err != nil || string(data) != string(archive) {
		t.Fatalf("archive = %q, %v", data, err)
	}
	if cached, err := d.DownloadArtifact(context.Background(), got, dir); err != nil || cached != filename {
		t.Fatalf("verified cached archive was not reused: %q, %v", cached, err)
	}
	if err := os.WriteFile(filename, []byte("tampered cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DownloadArtifact(context.Background(), got, dir); err == nil {
		t.Fatal("tampered cached archive was accepted")
	}
	archiveBody = []byte("tampered archive")
	otherDir := t.TempDir()
	if _, err := d.DownloadArtifact(context.Background(), got, otherDir); err == nil {
		t.Fatal("tampered archive passed")
	}
	if matches, _ := filepath.Glob(filepath.Join(otherDir, "*")); len(matches) != 0 {
		t.Fatalf("tampered archive left files: %q", matches)
	}
}

func TestDownloaderRejectsUntrustedInputs(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://example.com/path", "https://user@example.com", "https://example.com/?x=1"} {
		if _, err := newDownloader(origin, nil, pub); err == nil {
			t.Errorf("bad origin accepted: %s", origin)
		}
	}
	d, err := newDownloader("https://example.com", nil, pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Latest(context.Background(), "../../other"); err == nil || !strings.Contains(err.Error(), "channel") {
		t.Fatalf("bad channel result: %v", err)
	}
}
