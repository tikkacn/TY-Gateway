package release

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
)

type releaseSource interface {
	LatestBundle(context.Context, string) (Manifest, []byte, error)
	DownloadArtifact(context.Context, Manifest, string) (string, error)
}

// MirroredDownloader compares two independently signed channel indexes. An
// unavailable mirror can be skipped, but invalid signatures/content or a
// same-version disagreement are not silently accepted.
type MirroredDownloader struct {
	primary releaseSource
	backup  releaseSource
}

// An empty githubRepo intentionally leaves existing R2-only installations
// unchanged until an operator builds a package for an approved public repo.
func NewMirroredDownloader(key ed25519.PublicKey, githubRepo string) (*MirroredDownloader, error) {
	r2, err := NewDownloader(key)
	if err != nil {
		return nil, err
	}
	if githubRepo == "" {
		return &MirroredDownloader{primary: r2}, nil
	}
	github, err := newGitHubSource(githubRepo, key)
	if err != nil {
		return nil, err
	}
	return &MirroredDownloader{primary: github, backup: r2}, nil
}

type sourceResult struct {
	manifest Manifest
	bundle   []byte
	err      error
}

func (d *MirroredDownloader) LatestBundle(ctx context.Context, channel string) (Manifest, []byte, error) {
	if d == nil || d.primary == nil {
		return Manifest{}, nil, errors.New("release source unavailable")
	}
	if d.backup == nil {
		return d.primary.LatestBundle(ctx, channel)
	}
	var primary, backup sourceResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		primary.manifest, primary.bundle, primary.err = d.primary.LatestBundle(ctx, channel)
	}()
	go func() {
		defer wg.Done()
		backup.manifest, backup.bundle, backup.err = d.backup.LatestBundle(ctx, channel)
	}()
	wg.Wait()
	if errors.Is(primary.err, ErrUntrustedRelease) || errors.Is(backup.err, ErrUntrustedRelease) {
		return Manifest{}, nil, fmt.Errorf("%w: one release index failed verification", ErrUntrustedRelease)
	}
	if primary.err != nil && backup.err != nil {
		return Manifest{}, nil, errors.Join(primary.err, backup.err)
	}
	if primary.err != nil {
		return backup.manifest, backup.bundle, nil
	}
	if backup.err != nil {
		return primary.manifest, primary.bundle, nil
	}
	order, err := CompareVersions(primary.manifest.Version, backup.manifest.Version)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("%w: mirrored release version invalid", ErrUntrustedRelease)
	}
	if order == 0 && primary.manifest != backup.manifest {
		return Manifest{}, nil, fmt.Errorf("%w: mirrors disagree on the same release", ErrUntrustedRelease)
	}
	if order < 0 {
		return backup.manifest, backup.bundle, nil
	}
	return primary.manifest, primary.bundle, nil
}

func (d *MirroredDownloader) DownloadArtifact(ctx context.Context, manifest Manifest, destDir string) (string, error) {
	if d == nil || d.primary == nil {
		return "", errors.New("release source unavailable")
	}
	filename, err := d.primary.DownloadArtifact(ctx, manifest, destDir)
	if err == nil || d.backup == nil || errors.Is(err, ErrUntrustedRelease) {
		return filename, err
	}
	filename, backupErr := d.backup.DownloadArtifact(ctx, manifest, destDir)
	if backupErr != nil {
		return "", errors.Join(err, backupErr)
	}
	return filename, nil
}

var githubRepoPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}$`)

type githubSource struct {
	owner, repo string
	index       *Downloader
	assets      *Downloader
}

func newGitHubSource(repo string, key ed25519.PublicKey) (*githubSource, error) {
	index, err := newDownloader("https://raw.githubusercontent.com", nil, key)
	if err != nil {
		return nil, err
	}
	assets, err := newDownloader("https://github.com", nil, key)
	if err != nil {
		return nil, err
	}
	// A GitHub Release asset normally redirects to GitHub's asset CDN. Never
	// follow a redirect to an arbitrary hostname or to cleartext HTTP.
	assets.client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Scheme != "https" {
			return errors.New("release redirect is not trusted")
		}
		switch request.URL.Hostname() {
		case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
			return nil
		default:
			return errors.New("release redirect leaves GitHub asset hosts")
		}
	}
	return newGitHubSourceAt(repo, index, assets)
}

func newGitHubSourceAt(repo string, index, assets *Downloader) (*githubSource, error) {
	if !githubRepoPattern.MatchString(repo) || strings.Contains(repo, "..") || index == nil || assets == nil {
		return nil, errors.New("invalid public GitHub release repository")
	}
	parts := strings.Split(repo, "/")
	return &githubSource{owner: parts[0], repo: parts[1], index: index, assets: assets}, nil
}

func (s *githubSource) LatestBundle(ctx context.Context, channel string) (Manifest, []byte, error) {
	if channel != "pilot" && channel != "stable" {
		return Manifest{}, nil, errors.New("unsupported release channel")
	}
	location := s.index.origin.JoinPath(s.owner, s.repo, "release-index", "channels", channel, "linux-arm64", "latest.json")
	return s.index.latestBundleAt(ctx, channel, location)
}

func (s *githubSource) DownloadArtifact(ctx context.Context, manifest Manifest, destDir string) (string, error) {
	if err := manifest.Validate(); err != nil {
		return "", err
	}
	location := s.assets.origin.JoinPath(s.owner, s.repo, "releases", "download", "v"+manifest.Version, path.Base(manifest.Artifact))
	return s.assets.downloadArtifactAt(ctx, manifest, destDir, location)
}
