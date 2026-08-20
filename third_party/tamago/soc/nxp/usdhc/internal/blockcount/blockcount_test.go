package blockcount

import "testing"

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		encoded uint32
		rpmb    bool
		want    uint32
		wantErr bool
	}{
		{name: "zero", encoded: 0, want: 0},
		{name: "one", encoded: 1, want: 1},
		{name: "maximum", encoded: 0xffff, want: 0xffff},
		{name: "too large", encoded: 0x10000, wantErr: true},
		{name: "reliable RPMB", encoded: 0x80000001, rpmb: true, want: 1},
		{name: "reliable maximum", encoded: 0x8000ffff, rpmb: true, want: 0xffff},
		{name: "reliable zero", encoded: 0x80000000, rpmb: true, wantErr: true},
		{name: "reliable non-RPMB", encoded: 0x80000001, wantErr: true},
		{name: "reliable too large", encoded: 0x80010001, rpmb: true, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Decode(test.encoded, test.rpmb)
			if (err != nil) != test.wantErr {
				t.Fatalf("Decode(%#x, %v) error = %v, wantErr %v", test.encoded, test.rpmb, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("Decode(%#x, %v) = %#x, want %#x", test.encoded, test.rpmb, got, test.want)
			}
		})
	}
}
