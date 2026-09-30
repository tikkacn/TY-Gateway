package release

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid release public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("release public key is not Ed25519")
	}
	return edKey, nil
}
