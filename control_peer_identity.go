package main

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

// Resolving the control socket's permitted peer by name rather than by number.
//
// The peer is a service account whose uid is assigned at install time and
// differs between machines, so a unit file cannot hardcode it. Rendering the
// number into the unit would work, but the unit's integrity is checked by
// pinning its ExecStart line verbatim — a per-machine value there turns that
// check into something that cannot be written down. A name is stable across
// machines and resolves to whatever this box assigned.
//
// A name that does not resolve is a hard startup failure rather than a fallback
// to unrestricted. The whole point of naming a peer is to refuse the others;
// silently accepting everyone because the lookup failed would invert it.

// resolvePeerIdentity turns an optional user name and group name into the
// numeric ids the peer check compares against, keeping any explicit numeric
// values already supplied.
//
// A name and a number for the same field is a contradiction rather than a
// precedence question: an operator who wrote both meant one of them, and
// guessing which would silently enforce something they did not ask for.
func resolvePeerIdentity(userName, groupName string, uid, gid int) (int, int, error) {
	if name := strings.TrimSpace(userName); name != "" {
		if uid >= 0 {
			return 0, 0, fmt.Errorf("control peer given both a user name (%q) and a uid (%d)", name, uid)
		}
		resolved, err := user.Lookup(name)
		if err != nil {
			return 0, 0, fmt.Errorf("control peer user %q: %w", name, err)
		}
		parsed, err := strconv.Atoi(resolved.Uid)
		if err != nil {
			return 0, 0, fmt.Errorf("control peer user %q has a non-numeric uid %q", name, resolved.Uid)
		}
		uid = parsed
	}
	if name := strings.TrimSpace(groupName); name != "" {
		if gid >= 0 {
			return 0, 0, fmt.Errorf("control peer given both a group name (%q) and a gid (%d)", name, gid)
		}
		resolved, err := user.LookupGroup(name)
		if err != nil {
			return 0, 0, fmt.Errorf("control peer group %q: %w", name, err)
		}
		parsed, err := strconv.Atoi(resolved.Gid)
		if err != nil {
			return 0, 0, fmt.Errorf("control peer group %q has a non-numeric gid %q", name, resolved.Gid)
		}
		gid = parsed
	}
	return uid, gid, nil
}
