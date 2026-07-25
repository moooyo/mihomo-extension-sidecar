package main

import (
	"os/user"
	"strconv"
	"testing"
)

// A name that cannot be resolved must stop the process, not fall back to
// accepting everyone. Naming a peer is an instruction to refuse the others; a
// lookup failure that quietly widened the socket would invert it, and would do
// so precisely when something about the deployment is already wrong.
func TestUnresolvableNameIsFatalRatherThanUnrestricted(t *testing.T) {
	if _, _, err := resolvePeerIdentity("no-such-user-5gpn-test", "", -1, -1); err == nil {
		t.Fatal("an unresolvable user name was accepted")
	}
	if _, _, err := resolvePeerIdentity("", "no-such-group-5gpn-test", -1, -1); err == nil {
		t.Fatal("an unresolvable group name was accepted")
	}
}

// A name and a number for the same field is a contradiction. Picking one would
// enforce something the operator did not ask for, and which of the two they
// meant is not recoverable from the input.
func TestNameAndNumberTogetherIsRefused(t *testing.T) {
	if _, _, err := resolvePeerIdentity("root", "", 0, -1); err == nil {
		t.Fatal("a user name alongside an explicit uid was accepted")
	}
	if _, _, err := resolvePeerIdentity("", "root", -1, 0); err == nil {
		t.Fatal("a group name alongside an explicit gid was accepted")
	}
}

func TestNothingConfiguredStaysUnrestricted(t *testing.T) {
	uid, gid, err := resolvePeerIdentity("", "", -1, -1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if uid != -1 || gid != -1 {
		t.Fatalf("uid=%d gid=%d, want -1/-1", uid, gid)
	}
}

func TestAResolvableNameBecomesItsID(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	uid, _, err := resolvePeerIdentity(me.Username, "", -1, -1)
	if err != nil {
		t.Skipf("this platform cannot resolve %q: %v", me.Username, err)
	}
	want, err := strconv.Atoi(me.Uid)
	if err != nil {
		t.Skipf("non-numeric uid %q on this platform", me.Uid)
	}
	if uid != want {
		t.Fatalf("uid = %d, want %d", uid, want)
	}
}
