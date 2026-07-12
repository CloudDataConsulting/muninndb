package keys

import (
	"bytes"
	"testing"
)

func TestPrefixUpperBound(t *testing.T) {
	tests := []struct {
		name   string
		prefix []byte
		want   []byte
	}{
		{name: "empty has no finite upper bound"},
		{name: "single byte", prefix: []byte{0x19}, want: []byte{0x1a}},
		{
			name:   "carry truncates trailing max bytes",
			prefix: []byte{0x01, 0x10, 0xff},
			want:   []byte{0x01, 0x11},
		},
		{name: "all max has no finite upper bound", prefix: []byte{0xff, 0xff}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]byte(nil), tc.prefix...)
			got := PrefixUpperBound(tc.prefix)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("PrefixUpperBound(%x) = %x, want %x", tc.prefix, got, tc.want)
			}
			if !bytes.Equal(tc.prefix, original) {
				t.Fatalf("PrefixUpperBound mutated input: got %x, want %x", tc.prefix, original)
			}
		})
	}
}
