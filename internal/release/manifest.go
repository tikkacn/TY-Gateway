package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	MaxManifestBytes = 16 << 10
	MaxBundleBytes   = 32 << 10
	MaxArtifactBytes = 512 << 20
)

var (
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	hashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	filePattern    = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// Manifest is signed as its exact JSON bytes. Release objects are immutable;
// only the small, signed channel manifest may be replaced.
type Manifest struct {
	FormatVersion int    `json:"format_version"`
	Product       string `json:"product"`
	Channel       string `json:"channel"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	Artifact      string `json:"artifact"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	PublishedAt   string `json:"published_at"`
}

// Bundle is published as one R2 object so readers never observe a new
// manifest with an old detached signature during a channel update.
type Bundle struct {
	FormatVersion int    `json:"format_version"`
	Manifest      string `json:"manifest"`
	Signature     string `json:"signature"`
}

func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return m, errors.New("release manifest size is invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return m, errors.New("release manifest has trailing data")
	}
	if err := m.Validate(); err != nil {
		return m, err
	}
	return m, nil
}

func (m Manifest) Validate() error {
	if m.FormatVersion != 1 || m.Product != "ty-gateway" {
		return errors.New("unsupported release manifest format or product")
	}
	if m.Channel != "pilot" && m.Channel != "stable" {
		return errors.New("unsupported release channel")
	}
	if _, err := parseVersion(m.Version); err != nil || m.Platform != "linux-arm64" {
		return errors.New("unsupported release version or platform")
	}
	if m.Size <= 0 || m.Size > MaxArtifactBytes || !hashPattern.MatchString(m.SHA256) {
		return errors.New("invalid release artifact size or hash")
	}
	if !filePattern.MatchString(m.Artifact) || path.Clean(m.Artifact) != m.Artifact ||
		strings.HasPrefix(m.Artifact, "/") || strings.Contains(m.Artifact, "//") ||
		strings.Contains(m.Artifact, "..") || !strings.HasPrefix(m.Artifact, "releases/"+m.Version+"/") ||
		!strings.HasSuffix(m.Artifact, ".tar.gz") {
		return errors.New("invalid or unsafe release artifact path")
	}
	if _, err := time.Parse(time.RFC3339, m.PublishedAt); err != nil {
		return errors.New("invalid release publish time")
	}
	return nil
}

func parseVersion(value string) ([3]uint32, error) {
	var parsed [3]uint32
	if len(value) > 32 || !versionPattern.MatchString(value) {
		return parsed, errors.New("invalid release version")
	}
	for i, component := range strings.Split(value, ".") {
		part, err := strconv.ParseUint(component, 10, 32)
		if err != nil {
			return parsed, errors.New("release version component is too large")
		}
		parsed[i] = uint32(part)
	}
	return parsed, nil
}

// CompareVersions applies the same strict numeric version ordering used by
// the update gate. It returns -1, 0 or 1 for left versus right.
func CompareVersions(left, right string) (int, error) {
	a, err := parseVersion(left)
	if err != nil {
		return 0, err
	}
	b, err := parseVersion(right)
	if err != nil {
		return 0, err
	}
	for i := range a {
		if a[i] < b[i] {
			return -1, nil
		}
		if a[i] > b[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func Marshal(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Sign(privateKey ed25519.PrivateKey, manifest []byte) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid signing key")
	}
	if _, err := Parse(manifest); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifest)), nil
}

func Verify(publicKey ed25519.PublicKey, manifest, encodedSignature []byte) (Manifest, error) {
	m, err := Parse(manifest)
	if err != nil {
		return m, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return m, errors.New("invalid release public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedSignature)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(publicKey, manifest, sig) {
		return m, errors.New("release signature verification failed")
	}
	return m, nil
}

func SignBundle(privateKey ed25519.PrivateKey, manifest []byte) ([]byte, error) {
	signature, err := Sign(privateKey, manifest)
	if err != nil {
		return nil, err
	}
	bundle := Bundle{
		FormatVersion: 1,
		Manifest:      base64.StdEncoding.EncodeToString(manifest),
		Signature:     signature,
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func VerifyBundle(publicKey ed25519.PublicKey, data []byte) (Manifest, error) {
	var bundle Bundle
	if len(data) == 0 || len(data) > MaxBundleBytes {
		return Manifest{}, errors.New("release bundle size is invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		return Manifest{}, fmt.Errorf("decode release bundle: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Manifest{}, errors.New("release bundle has trailing data")
	}
	if bundle.FormatVersion != 1 {
		return Manifest{}, errors.New("unsupported release bundle format")
	}
	manifest, err := base64.StdEncoding.DecodeString(bundle.Manifest)
	if err != nil {
		return Manifest{}, errors.New("release bundle manifest is invalid")
	}
	return Verify(publicKey, manifest, []byte(bundle.Signature))
}

func VerifyArtifact(m Manifest, r io.Reader) error {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, MaxArtifactBytes+1))
	if err != nil {
		return err
	}
	if n != m.Size || n > MaxArtifactBytes || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return errors.New("release artifact size or hash mismatch")
	}
	return nil
}
