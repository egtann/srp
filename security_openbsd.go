package srp

import "golang.org/x/sys/unix"

// Pledge limits srp to specific syscalls. Go's stdlib "net" package calls
// sysctl(kern.somaxconn) which cannot be whitelisted by OpenBSD's pledges as
// of OpenBSD 6.6, though the program runs fine without the call, which is why
// we add the `error` pledge.
func Pledge() error {
	const promises = "stdio rpath inet"
	if err := unix.Pledge(promises, ""); err != nil {
		return err
	}
	return nil
}

// Unveil hides the entire filesystem except for the given config file from
// srp. If there's a vulnerability at the application layer that allows a
// hacker to see the filesystem, the only visible file will be our
// configuration file.
func Unveil(filename string) error {
	if err := unix.Unveil(filename, "r"); err != nil {
		return err
	}
	if err := unix.UnveilBlock(); err != nil {
		return err
	}
	return nil
}
