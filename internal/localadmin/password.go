package localadmin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

const passwordIterations = 600_000

var errWeakPassword = errors.New("password must contain at least 12 characters")

type passwordRecord struct {
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
}

func newPasswordRecord(password string) (passwordRecord, error) {
	if !validPassword(password) {
		return passwordRecord{}, errWeakPassword
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return passwordRecord{}, err
	}
	derived := pbkdf2SHA256([]byte(password), salt, passwordIterations, sha256.Size)
	return passwordRecord{
		Algorithm:  "PBKDF2-HMAC-SHA256",
		Iterations: passwordIterations,
		Salt:       base64.RawStdEncoding.EncodeToString(salt),
		Hash:       base64.RawStdEncoding.EncodeToString(derived),
	}, nil
}

func validPassword(password string) bool {
	if !utf8.ValidString(password) || len(password) > 1024 {
		return false
	}
	count := utf8.RuneCountInString(password)
	return count >= 12 && count <= 256
}

func verifyPassword(password string, record passwordRecord) bool {
	if !validPassword(password) || record.Algorithm != "PBKDF2-HMAC-SHA256" || record.Iterations < 100_000 || record.Iterations > 2_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(record.Salt)
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(record.Hash)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, record.Iterations, len(want))
	return hmac.Equal(got, want)
}

// pbkdf2SHA256 implements the PBKDF2 construction from RFC 8018 using the
// standard-library HMAC primitive. The loop and block composition are kept
// deliberately small and are covered by a published test vector.
func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	if iterations < 1 || keyLength < 1 {
		return nil
	}
	blocks := (keyLength + sha256.Size - 1) / sha256.Size
	derived := make([]byte, 0, blocks*sha256.Size)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac.Reset()
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		derived = append(derived, t...)
	}
	return derived[:keyLength]
}
