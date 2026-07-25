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

// narrowUmask makes a socket created inside the window 0660 and returns a
// function restoring the previous value. Setting the mode this way rather than
// chmod-ing after bind closes the window in which the socket carries whatever
// umask the process inherited.
//
// Group-readable rather than private because the coordinator runs as a
// different service user and has to be able to open the socket — a peer it
// cannot connect to is a peer the SO_PEERCRED check never gets to authorise.
// The containing directory is the sidecar's own systemd RuntimeDirectory, mode
// 0750, so the group in question is already the only one that can reach it, and
// the peer check on every accept is what actually authorises. This mirrors the
// log socket beside it, which has always been group-readable for the same
// reason.
func narrowUmask() func() {
	old := syscall.Umask(0o117)
	return func() { syscall.Umask(old) }
}
