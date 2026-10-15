// fauxware, in Go — the classic angr demo binary, ported from fauxware.c.
// Same backdoor, same prompts, same "Go away!".
//
// I/O goes straight to the kernel through raw syscalls (no os/fmt), so the
// interesting code never enters the Go runtime. That lets symbolic execution
// start right at main.main instead of having to bootstrap the whole runtime.
package main

import (
	"syscall"
	"unsafe"
)

func read(fd uintptr, buf []byte) {
	syscall.RawSyscall(syscall.SYS_READ, fd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
}

func write(s string) {
	syscall.RawSyscall(syscall.SYS_WRITE, 1, uintptr(unsafe.Pointer(unsafe.StringData(s))), uintptr(len(s)))
}

func open(path []byte) uintptr {
	fd, _, _ := syscall.RawSyscall(syscall.SYS_OPEN, uintptr(unsafe.Pointer(&path[0])), syscall.O_RDONLY, 0)
	return fd
}

//go:noinline
func authenticate(username, password []byte) bool {
	// evil back d00r
	if string(password) == "SOSNEAKY" {
		return true
	}

	var stored [8]byte
	pwfile := open(username)
	read(pwfile, stored[:])

	return string(password) == string(stored[:])
}

//go:noinline
func accepted() {
	write("Welcome to the admin console, trusted user!\n")
}

//go:noinline
func rejected() {
	write("Go away!")
	syscall.Exit(1)
}

func main() {
	var username, password [9]byte
	var newline [1]byte

	write("Username: \n")
	read(0, username[:8])
	read(0, newline[:])
	write("Password: \n")
	read(0, password[:8])
	read(0, newline[:])

	if authenticate(username[:], password[:8]) {
		accepted()
	} else {
		rejected()
	}
}
