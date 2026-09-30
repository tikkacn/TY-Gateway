package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"
)

const DefaultOrigin = "https://oec.uutec.net"

// ErrUntrustedRelease means a source returned bytes that cannot be trusted.
// A mirror outage may fall back, but a bad signature, mismatched artifact or
// conflicting signed metadata must stop the update and raise an alarm.
var ErrUntrustedRelease = errors.New("untrusted release content")

// Downloader only fetches and verifies a release. It never invokes an
// installer, changes service state or applies network settings.
type Downloader struct {
	origin *url.URL
	client *http.Client
	key    ed25519.PublicKey
}

func NewDownloader(key ed25519.PublicKey) (*Downloader, error) {
	return newDownloader(DefaultOrigin, nil, key)
}

func newDownloader(origin string, client *http.Client, key ed25519.PublicKey) (*Downloader, error) {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid release origin")
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid release public key")
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Minute}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != u.Scheme || req.URL.Host != u.Host {
			return errors.New("release redirect leaves the trusted origin")
		}
		return nil
	}
	return &Downloader{origin: u, client: &copyClient, key: key}, nil
}

func (d *Downloader) Latest(ctx context.Context, channel string) (Manifest, error) {
	m, _, err := d.LatestBundle(ctx, channel)
	return m, err
}

// LatestBundle returns the exact signed bytes alongside the parsed manifest so
// a staged package can be re-verified offline immediately before installation.
func (d *Downloader) LatestBundle(ctx context.Context, channel string) (Manifest, []byte, error) {
	if channel != "pilot" && channel != "stable" {
		return Manifest{}, nil, errors.New("unsupported release channel")
	}
	return d.latestBundleAt(ctx, channel, d.origin.JoinPath("channels", channel, "linux-arm64", "latest.json"))
}

func (d *Downloader) latestBundleAt(ctx context.Context, channel string, location *url.URL) (Manifest, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := d.get(ctx, location)
	if err != nil {
		return Manifest{}, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBundleBytes+1))
	if err != nil {
		return Manifest{}, nil, err
	}
	m, err := VerifyBundle(d.key, data)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("%w: %v", ErrUntrustedRelease, err)
	}
	if m.Channel != channel || m.Platform != "linux-arm64" {
		return Manifest{}, nil, fmt.Errorf("%w: release channel or platform mismatch", ErrUntrustedRelease)
	}
	return m, data, nil
}

// DownloadArtifact writes only a fully hash-checked file to destDir. An
// existing file is never overwritten; the caller must separately authorize
// and implement installation.
func (d *Downloader) DownloadArtifact(ctx context.Context, m Manifest, destDir string) (string, error) {
	return d.downloadArtifactAt(ctx, m, destDir, d.origin.JoinPath(m.Artifact))
}

func (d *Downloader) downloadArtifactAt(ctx context.Context, m Manifest, destDir string, location *url.URL) (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	info, err := os.Lstat(destDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("download destination must be a real directory")
	}
	final := filepath.Join(destDir, path.Base(m.Artifact))
	if existing, err := os.Lstat(final); err == nil {
		if !existing.Mode().IsRegular() {
			return "", errors.New("existing release archive is not a regular file")
		}
		f, err := os.Open(final)
		if err != nil {
			return "", err
		}
		verifyErr := VerifyArtifact(m, f)
		closeErr := f.Close()
		if verifyErr != nil || closeErr != nil {
			return "", fmt.Errorf("%w: cached archive differs from signed manifest", ErrUntrustedRelease)
		}
		return final, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	resp, err := d.get(ctx, location)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(destDir, ".ty-release-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, m.Size+1))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return "", errors.New("release archive could not be saved")
	}
	if n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return "", fmt.Errorf("%w: release archive size or hash mismatch", ErrUntrustedRelease)
	}
	if err := os.Link(tmp.Name(), final); err != nil {
		return "", fmt.Errorf("publish verified download without overwrite: %w", err)
	}
	return final, nil
}

func (d *Downloader) get(ctx context.Context, location *url.URL) (*http.Response, error) {
	if location.Scheme != d.origin.Scheme || location.Host != d.origin.Host {
		return nil, errors.New("release URL leaves the trusted origin")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("release source returned HTTP %d", resp.StatusCode)
	}
	return resp, nil
}
