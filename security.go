// +build !openbsd

package srp

// Pledge is not supported outside of OpenBSD.
func Pledge() error { return nil }

// Unveil is not supported outside of OpenBSD.
func Unveil(filename string) error { return nil }
