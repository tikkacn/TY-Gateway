package localadmin

import (
	"encoding/hex"
	"testing"
)

func TestPBKDF2SHA256PublishedVector(t *testing.T) {
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32))
	if got != want {
		t.Fatalf("PBKDF2 vector mismatch: got %s", got)
	}
}

func TestPasswordRecordRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"
	record, err := newPasswordRecord(password)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(password, record) {
		t.Fatal("correct password did not verify")
	}
	if verifyPassword(password+"x", record) {
		t.Fatal("incorrect password verified")
	}
	if validPassword("short") || validPassword(string([]byte{0xff})) {
		t.Fatal("invalid password passed validation")
	}
}
