package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateSignVerify(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "ty-gateway-oec-overlay.tar.gz")
	manifest := filepath.Join(dir, "manifest.json")
	bundle := filepath.Join(dir, "release.json")
	privateFile := filepath.Join(dir, "signing.pem")
	publicFile := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(artifact, []byte("test archive"), 0600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"create", "-artifact", artifact, "-version", "0.7.0", "-output", manifest}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "-manifest", manifest, "-private-key", privateFile, "-output", bundle}); err != nil {
		t.Fatal(err)
	}
	verifyArgs := []string{"verify", "-bundle", bundle, "-public-key", publicFile, "-artifact", artifact}
	if err := run(verifyArgs); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("tampered archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(verifyArgs); err == nil {
		t.Fatal("tampered archive was accepted")
	}
	if err := run([]string{"create", "-artifact", artifact, "-version", "0.7.0", "-output", manifest}); err == nil {
		t.Fatal("existing manifest was overwritten")
	}
}
