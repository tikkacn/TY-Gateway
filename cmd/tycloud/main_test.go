package main

import "testing"

func TestParseSharedFRPSControlPort(t *testing.T) {
	for _, value := range []string{"", "7001", " 7001 "} {
		got, err := parseSharedFRPSControlPort(value)
		if err != nil || got != 7001 {
			t.Errorf("parseSharedFRPSControlPort(%q) = %d, %v; want 7001, nil", value, got, err)
		}
	}
	for _, value := range []string{"7002", "0", "invalid"} {
		if got, err := parseSharedFRPSControlPort(value); err == nil {
			t.Errorf("parseSharedFRPSControlPort(%q) = %d, nil; want an error", value, got)
		}
	}
}
