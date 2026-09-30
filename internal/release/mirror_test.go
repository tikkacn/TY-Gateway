package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type fakeReleaseSource struct {
	manifest Manifest
	bundle   []byte
	latest   error
	artifact error
	file     string
}

func (s *fakeReleaseSource) LatestBundle(context.Context, string) (Manifest, []byte, error) {
	return s.manifest, s.bundle, s.latest
}

func (s *fakeReleaseSource) DownloadArtifact(context.Context, Manifest, string) (string, error) {
	return s.file, s.artifact
}

func TestMirrorsUseAvailableNewestSignedReleaseAndFailClosed(t *testing.T) {
	primary := &fakeReleaseSource{manifest: sampleManifest(), bundle: []byte("primary"), file: "github-archive"}
	backup := &fakeReleaseSource{manifest: sampleManifest(), bundle: []byte("backup"), file: "r2-archive"}
	mirrors := &MirroredDownloader{primary: primary, backup: backup}
	primary.latest = errors.New("github unavailable")
	primary.artifact = errors.New("github unavailable")
	manifest, bundle, err := mirrors.LatestBundle(context.Background(), "pilot")
	if err != nil || manifest != backup.manifest || string(bundle) != "backup" {
		t.Fatalf("R2 fallback: %#v %q %v", manifest, bundle, err)
	}
	if file, err := mirrors.DownloadArtifact(context.Background(), manifest, t.TempDir()); err != nil || file != "r2-archive" {
		t.Fatalf("R2 artifact fallback: %q %v", file, err)
	}
	primary.latest, primary.artifact = nil, nil
	backup.manifest.PublishedAt = "2026-09-25T00:00:00Z"
	if _, _, err := mirrors.LatestBundle(context.Background(), "pilot"); !errors.Is(err, ErrUntrustedRelease) {
		t.Fatalf("same-version conflict accepted: %v", err)
	}
	backup.manifest = sampleManifest()
	primary.latest = ErrUntrustedRelease
	if _, _, err := mirrors.LatestBundle(context.Background(), "pilot"); !errors.Is(err, ErrUntrustedRelease) {
		t.Fatalf("bad signature fell back silently: %v", err)
	}
	primary.latest, primary.artifact = nil, ErrUntrustedRelease
	if _, err := mirrors.DownloadArtifact(context.Background(), manifest, t.TempDir()); !errors.Is(err, ErrUntrustedRelease) {
		t.Fatalf("bad artifact fell back silently: %v", err)
	}
}

func TestGitHubReleasePathsStillRequirePinnedSignatureAndHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifestBytes, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := SignBundle(priv, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tikkacn/TY-Gateway/release-index/channels/pilot/linux-arm64/latest.json":
			_, _ = w.Write(bundle)
		case "/tikkacn/TY-Gateway/releases/download/v0.7.0/ty-gateway-oec-overlay.tar.gz":
			_, _ = w.Write([]byte("overlay archive"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	index, err := newDownloader(server.URL, server.Client(), pub)
	if err != nil {
		t.Fatal(err)
	}
	assets, err := newDownloader(server.URL, server.Client(), pub)
	if err != nil {
		t.Fatal(err)
	}
	github, err := newGitHubSourceAt("tikkacn/TY-Gateway", index, assets)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := github.LatestBundle(context.Background(), "pilot")
	if err != nil || got != manifest {
		t.Fatalf("GitHub signed index: %#v %v", got, err)
	}
	file, err := github.DownloadArtifact(context.Background(), got, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(file); err != nil || string(content) != "overlay archive" || filepath.Base(file) != "ty-gateway-oec-overlay.tar.gz" {
		t.Fatalf("GitHub artifact: %q %v", content, err)
	}
	for _, repo := range []string{"../other", "owner/repo/extra", "user.name/repo", "owner/repo..evil"} {
		if _, err := newGitHubSourceAt(repo, index, assets); err == nil {
			t.Errorf("unsafe GitHub repository accepted: %q", repo)
		}
	}
}
