//go:build !linux

package main

import (
	"errors"
	"net"
)

// connPeerCredentials has no portable implementation outside Linux. Returning
// an error rather than a permissive stub means the caller closes a connection
// whose peer it cannot identify, so a platform without SO_PEERCRED fails
// closed. Linux is the production target; elsewhere the control socket is
// usable only with no peer policy configured, which the operator must choose.
func connPeerCredentials(net.Conn) (uid, gid int, err error) {
	return 0, 0, errors.New("peer credentials are not available on this platform")
}

// narrowUmask is a no-op where umask does not exist. The socket inherits the
// containing directory's permissions, which listenControlSocket creates 0700.
func narrowUmask() func() { return func() {} }
