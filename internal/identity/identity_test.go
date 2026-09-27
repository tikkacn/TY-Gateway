package identity

import "testing"

func TestNormalizeMAC(t *testing.T) {
	got, serial, err := NormalizeMAC("aa-bb:cc.dd eeff")
	if err != nil {
		t.Fatal(err)
	}
	if got != "AABBCCDDEEFF" || serial != got {
		t.Fatalf("unexpected identity: %q %q", got, serial)
	}
}
