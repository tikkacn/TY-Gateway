package rules

import "testing"

func TestNormalizeIPMatchValue(t *testing.T) {
	cases := []struct {
		input string
		want  string
		valid bool
	}{
		{"192.0.2.7", "192.0.2.7", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"192.0.2.7/24", "192.0.2.0/24", true},
		{"2001:db8::1/64", "2001:db8::/64", true},
		{"192.0.2.7, 2001:db8::1/64", "192.0.2.7,2001:db8::/64", true},
		{"192.0.2.1/99", "", false},
		{"example.com", "", false},
		{"192.0.2.1,,192.0.2.2", "", false},
		{"fe80::1%eth0", "", false},
	}
	for _, tc := range cases {
		got, err := NormalizeIPMatchValue(tc.input)
		if (err == nil) != tc.valid || got != tc.want {
			t.Errorf("NormalizeIPMatchValue(%q) = %q, %v; want %q, valid=%t", tc.input, got, err, tc.want, tc.valid)
		}
	}
}
