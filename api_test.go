package srp

import (
	"net"
	"testing"
)

func TestMaskIP(t *testing.T) {
	ip := "10.128.0.0/24"
	maskedIP, mask, err := maskIP(ip)
	if err != nil {
		t.Fatal(err)
	}

	ip = "10.128.0.10"
	if maskedIP != net.ParseIP(ip).Mask(mask).String() {
		t.Fatal("expected match")
	}

	ip = "1.1.1.1"
	if maskedIP == net.ParseIP(ip).Mask(mask).String() {
		t.Fatal("expected no match")
	}

	ip = ""
	if maskedIP == net.ParseIP(ip).Mask(mask).String() {
		t.Fatal("expected no match")
	}
}
