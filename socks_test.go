package main

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestSOCKSUDPDatagramEncodingReusesBoundedStorage(t *testing.T) {
	target := socksTarget{Host: "quic.example.com", Port: 443}
	payload := bytes.Repeat([]byte{0x5a}, 1350)
	packet, err := encodeSOCKSUDPDatagramInto(nil, target, payload)
	if err != nil {
		t.Fatal(err)
	}
	storage := packet
	firstByte := &storage[0]
	allocations := testing.AllocsPerRun(1000, func() {
		packet, err = encodeSOCKSUDPDatagramInto(storage, target, payload)
		if err != nil {
			panic(err)
		}
		storage = packet
	})
	if allocations != 0 {
		t.Fatalf("reused SOCKS UDP encoding allocations = %f", allocations)
	}
	if &storage[0] != firstByte {
		t.Fatal("SOCKS UDP encoding replaced a sufficiently large reusable buffer")
	}
	decoded, decodedTarget, err := parseSOCKSUDPDatagram(storage)
	if err != nil {
		t.Fatal(err)
	}
	if decodedTarget != target || !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded target=%+v payload length=%d", decodedTarget, len(decoded))
	}
	if cap(storage) > maxSOCKSUDPDatagramBytes {
		t.Fatalf("SOCKS UDP buffer capacity = %d", cap(storage))
	}
}

func TestSOCKSAddressEncodingPreservesAddressKinds(t *testing.T) {
	for _, target := range []socksTarget{
		{Host: "192.0.2.1", Port: 443},
		{Host: "2001:db8::1", Port: 443},
		{Host: "quic.example.com", Port: 443},
	} {
		encoded, err := encodeSOCKSAddress(target)
		if err != nil {
			t.Fatalf("encode %+v: %v", target, err)
		}
		decoded, err := readSOCKSAddress(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("decode %+v: %v", target, err)
		}
		if decoded != target {
			t.Fatalf("decoded target=%+v, want %+v", decoded, target)
		}
	}
}

func TestSOCKSUDPReadBufferReusesStorageAndKeepsOversizeSentinel(t *testing.T) {
	buffer := resizeSOCKSUDPReadBuffer(nil, 1500)
	firstByte := &buffer[0]
	allocations := testing.AllocsPerRun(1000, func() {
		buffer = resizeSOCKSUDPReadBuffer(buffer, 1500)
	})
	if allocations != 0 {
		t.Fatalf("reused SOCKS UDP read buffer allocations = %f", allocations)
	}
	if &buffer[0] != firstByte {
		t.Fatal("SOCKS UDP read buffer was replaced without growing")
	}
	wantLength := 1500 + maxSOCKSUDPEnvelopeBytes + 1
	if len(buffer) != wantLength {
		t.Fatalf("SOCKS UDP read buffer length = %d, want %d", len(buffer), wantLength)
	}
	buffer = resizeSOCKSUDPReadBuffer(buffer, maxSOCKSUDPDatagramBytes)
	if len(buffer) != maxSOCKSUDPDatagramBytes || cap(buffer) > maxSOCKSUDPDatagramBytes {
		t.Fatalf("bounded SOCKS UDP read buffer length=%d capacity=%d", len(buffer), cap(buffer))
	}
}

func TestSOCKSServerPacketAuthorizationUsesAssociationSnapshot(t *testing.T) {
	enabled := Config{
		MITM: MITMSettings{Enabled: true},
		Modules: []Module{{
			ID:           "io.example.quic",
			Enabled:      true,
			CaptureHosts: []string{"quic.example.com"},
		}},
		ExecutionOrder: []string{"io.example.quic"},
	}
	runtime, err := compileScriptConfig(enabled)
	if err != nil {
		t.Fatal(err)
	}
	enabled.runtime = runtime
	activeAssociation := &socksServerPacketConn{authorization: newInboundUDPAuthorization(enabled)}
	disabledAssociation := &socksServerPacketConn{authorization: newInboundUDPAuthorization(Config{})}
	enabled = Config{}

	allowed := socksTarget{Host: "quic.example.com", Port: 443}
	if !activeAssociation.targetAllowed(allowed) {
		t.Fatal("association snapshot rejected its enabled capture host")
	}
	allocations := testing.AllocsPerRun(1000, func() {
		if !activeAssociation.targetAllowed(allowed) {
			panic("association snapshot rejected its enabled capture host")
		}
	})
	if allocations != 0 {
		t.Fatalf("association authorization allocations = %f", allocations)
	}
	if disabledAssociation.targetAllowed(allowed) {
		t.Fatal("a new disabled association inherited an older authorization snapshot")
	}
	if !activeAssociation.targetAllowed(socksTarget{Host: "192.0.2.1", Port: 443}) {
		t.Fatal("association snapshot rejected an IP target before the TLS SNI check")
	}
	for _, target := range []socksTarget{
		{Host: "other.example.com", Port: 443},
		{Host: "quic.example.com", Port: 80},
	} {
		if activeAssociation.targetAllowed(target) {
			t.Fatalf("association snapshot allowed unexpected target %+v", target)
		}
	}
}

func TestSOCKSUDPDatagramEncodingRejectsOversizePayload(t *testing.T) {
	target := socksTarget{Host: "quic.example.com", Port: 443}
	payload := make([]byte, maxSOCKSUDPDatagramBytes)
	if _, err := encodeSOCKSUDPDatagramInto(nil, target, payload); err == nil {
		t.Fatal("oversized SOCKS UDP payload was accepted")
	}
}

func TestSOCKSTargetAddressFastPathIsAllocationFree(t *testing.T) {
	target := socksTarget{Host: "quic.example.com", Port: 443}
	address := net.Addr(&target)
	allocations := testing.AllocsPerRun(1000, func() {
		if !matchesSOCKSTarget(address, target) {
			panic("matching SOCKS target was rejected")
		}
	})
	if allocations != 0 {
		t.Fatalf("SOCKS target comparison allocations = %f", allocations)
	}
	if matchesSOCKSTarget(&socksTarget{Host: target.Host, Port: 80}, target) {
		t.Fatal("SOCKS target comparison accepted a different port")
	}
	if !sameSOCKSTarget(
		socksTarget{Host: "::ffff:192.0.2.1", Port: 443},
		socksTarget{Host: "192.0.2.1", Port: 443},
	) {
		t.Fatal("SOCKS target comparison rejected equivalent IP representations")
	}
	if sameSOCKSTarget(socksTarget{Host: "quic.example.com:443", Port: 443}, target) {
		t.Fatal("SOCKS target comparison accepted an embedded domain port")
	}
}

func TestFixedSOCKSPacketConnAcceptsResolvedSourceAndDropsWrongPort(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	target := socksTarget{Host: "quic.example.com", Port: 443}
	packetConn := &fixedSOCKSPacketConn{
		conn:   client,
		relay:  relay.LocalAddr().(*net.UDPAddr),
		target: target,
	}
	wrongPacket, err := encodeSOCKSUDPDatagram(socksTarget{Host: "other.example.com", Port: 80}, []byte("wrong"))
	if err != nil {
		t.Fatal(err)
	}
	rightPacket, err := encodeSOCKSUDPDatagram(socksTarget{Host: "192.0.2.1", Port: 443}, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	clientAddress := client.LocalAddr().(*net.UDPAddr)
	if _, err := relay.WriteToUDP(wrongPacket, clientAddress); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.WriteToUDP(rightPacket, clientAddress); err != nil {
		t.Fatal(err)
	}
	if err := packetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, source, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "right" {
		t.Fatalf("fixed target payload = %q", buffer[:n])
	}
	if !matchesSOCKSTarget(source, target) {
		t.Fatalf("fixed target source = %v", source)
	}
}

func TestInterceptHealthcheckTimesOutWhenSOCKSPeerDoesNotReply(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	release := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}()
	defer close(release)

	cfg := Config{
		Listen:   listener.Addr().String(),
		Username: "healthcheck-user",
		Password: "healthcheck-password",
		MITM:     MITMSettings{Enabled: true},
		Modules: []Module{{
			Enabled:      true,
			CaptureHosts: []string{"*.example.com"},
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = checkInterceptHealth(ctx, cfg)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("healthcheck unexpectedly succeeded against a silent SOCKS peer")
	}
	// The socket deadline and context timer share the same deadline. The read
	// can observe its timeout just before the scheduler publishes ctx.Done(), so
	// wait for that already-due signal instead of racing ctx.Err().
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("healthcheck returned a timeout before its context became done")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("healthcheck context error = %v", ctx.Err())
	}
	if elapsed > time.Second {
		t.Fatalf("healthcheck exceeded its context deadline: %s", elapsed)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("healthcheck did not reach the silent SOCKS peer")
	}
}
