package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sampleManifest() Manifest {
	payload := []byte("overlay archive")
	digest := sha256.Sum256(payload)
	return Manifest{
		FormatVersion: 1,
		Product:       "ty-gateway",
		Channel:       "pilot",
		Version:       "0.7.0",
		Platform:      "linux-arm64",
		Artifact:      "releases/0.7.0/ty-gateway-oec-overlay.tar.gz",
		SHA256:        hex.EncodeToString(digest[:]),
		Size:          int64(len(payload)),
		PublishedAt:   "2026-09-24T00:00:00Z",
	}
}

func TestSignedManifestAndArtifact(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Verify(pub, data, []byte(sig))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(m, bytes.NewReader([]byte("overlay archive"))); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(m, bytes.NewReader([]byte("changed archive"))); err == nil {
		t.Fatal("tampered artifact passed")
	}
	tampered := bytes.Replace(data, []byte(`"version":"0.7.0"`), []byte(`"version":"0.8.0"`), 1)
	if _, err := Verify(pub, tampered, []byte(sig)); err == nil {
		t.Fatal("tampered manifest passed")
	}
	if _, err := Verify(pub, data, []byte("not a signature")); err == nil {
		t.Fatal("invalid signature passed")
	}
	bundle, err := SignBundle(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(pub, bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(pub, append(bundle, []byte(`{"extra":true}`)...)); err == nil {
		t.Fatal("trailing bundle JSON passed")
	}
	tamperedBundle := bytes.Replace(bundle, []byte(`"signature":"`), []byte(`"signature":"x`), 1)
	if _, err := VerifyBundle(pub, tamperedBundle); err == nil {
		t.Fatal("tampered bundle passed")
	}
}

func TestRejectUnsafeManifest(t *testing.T) {
	for _, artifact := range []string{
		"../releases/0.7.0/a.tar.gz",
		"/releases/0.7.0/a.tar.gz",
		"releases/0.7.0/../../a.tar.gz",
		"releases/0.7.0/a.tar.gz?x=1",
		"https://example.com/a.tar.gz",
		"releases/0.8.0/a.tar.gz",
	} {
		m := sampleManifest()
		m.Artifact = artifact
		if err := m.Validate(); err == nil {
			t.Errorf("unsafe path passed: %q", artifact)
		}
	}
	m := sampleManifest()
	m.Size = MaxArtifactBytes + 1
	if err := m.Validate(); err == nil {
		t.Fatal("oversized artifact passed")
	}
	data, err := Marshal(sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(append(data, []byte(`{"extra":true}`)...)); err == nil {
		t.Fatal("trailing JSON passed")
	}
}

func TestCompareVersionsRejectsAmbiguityAndDowngrade(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		want        int
	}{
		{"0.7.0", "0.7.1", -1},
		{"1.0.0", "0.99.99", 1},
		{"1.2.3", "1.2.3", 0},
	} {
		got, err := CompareVersions(tc.left, tc.right)
		if err != nil || got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, %v", tc.left, tc.right, got, err)
		}
	}
	for _, invalid := range []string{"01.2.3", "1.02.3", "1.2.003", "4294967296.0.0", "1.2", "../1.0.0"} {
		if _, err := CompareVersions(invalid, "1.0.0"); err == nil {
			t.Errorf("invalid version accepted: %q", invalid)
		}
		m := sampleManifest()
		m.Version = invalid
		m.Artifact = "releases/" + invalid + "/ty-gateway-oec-overlay.tar.gz"
		if err := m.Validate(); err == nil {
			t.Errorf("invalid manifest version accepted: %q", invalid)
		}
	}
}
