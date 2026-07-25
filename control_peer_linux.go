//go:build linux

package main

import (
	"errors"
	"net"
	"syscall"
)

// connPeerCredentials reads the connecting process's identity from the kernel.
// SO_PEERCRED cannot be spoofed by the peer, which is what makes it usable as
// authentication rather than as a hint.
func connPeerCredentials(conn net.Conn) (uid, gid int, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("connection is not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var (
		cred    *syscall.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return int(cred.Uid), int(cred.Gid), nil
}

// narrowUmask makes a socket created inside the window 0600 and returns a
// function restoring the previous value. Setting the mode this way rather than
// chmod-ing after bind closes the window in which the socket carries whatever
// umask the process inherited.
func narrowUmask() func() {
	old := syscall.Umask(0o177)
	return func() { syscall.Umask(old) }
}
