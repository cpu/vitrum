package devicekey

import (
	"encoding/hex"
	"testing"
)

func TestStretchKeyGolden(t *testing.T) {
	dk := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	uid := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	got, err := stretchKey(dk, uid)
	if err != nil {
		t.Fatal(err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != "e59a2a1ece5e220a05ec4519619544d4ccec8f656d5db0edd04cca5d2f18e1bb" {
		t.Fatalf("stretchKey() = %s", gotHex)
	}
}
