package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion        = 5
	socksAuthNone       = 0
	socksAuthUserPass   = 2
	socksNoAcceptable   = 0xff
	socksCommandConnect = 1
	socksCommandUDP     = 3
	socksAddressIPv4    = 1
	socksAddressDomain  = 3
	socksAddressIPv6    = 4
)

type socksTarget struct {
	Host string
	Port int
}

func (t socksTarget) Network() string { return "udp" }

func (t socksTarget) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

func bindSOCKSHandshakeContext(ctx context.Context, conn net.Conn) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(fired)
	})
	return func() {
		if !stop() {
			<-fired
		}
		_ = conn.SetDeadline(time.Time{})
	}, nil
}

func readSOCKSRequest(conn net.Conn, username, password string) (byte, socksTarget, error) {
	if err := authenticateSOCKSServer(conn, username, password); err != nil {
		return 0, socksTarget{}, err
	}
	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, socksTarget{}, err
	}
	if header[0] != socksVersion || header[2] != 0 {
		return 0, socksTarget{}, errors.New("invalid SOCKS request header")
	}
	target, err := readSOCKSAddress(conn)
	if err != nil {
		return 0, socksTarget{}, err
	}
	return header[1], target, nil
}

func authenticateSOCKSServer(conn net.Conn, username, password string) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion || header[1] == 0 {
		return errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	supported := false
	for _, method := range methods {
		if method == socksAuthUserPass {
			supported = true
			break
		}
	}
	if !supported {
		_, _ = conn.Write([]byte{socksVersion, socksNoAcceptable})
		return errors.New("SOCKS client did not offer username/password authentication")
	}
	if _, err := conn.Write([]byte{socksVersion, socksAuthUserPass}); err != nil {
		return err
	}
	authHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHeader); err != nil {
		return err
	}
	if authHeader[0] != 1 || authHeader[1] == 0 {
		return errors.New("invalid SOCKS authentication header")
	}
	user := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return err
	}
	if passwordLength[0] == 0 {
		return errors.New("empty SOCKS password")
	}
	pass := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	validUser := subtle.ConstantTimeCompare(user, []byte(username))
	validPass := subtle.ConstantTimeCompare(pass, []byte(password))
	status := byte(0)
	if validUser&validPass != 1 {
		status = 1
	}
	if _, err := conn.Write([]byte{1, status}); err != nil {
		return err
	}
	if status != 0 {
		return errors.New("invalid SOCKS credentials")
	}
	return nil
}

func writeSOCKSReply(conn net.Conn, status byte, address net.Addr) error {
	target := socksTarget{Host: "0.0.0.0", Port: 0}
	if address != nil {
		host, portText, err := net.SplitHostPort(address.String())
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return err
		}
		target = socksTarget{Host: host, Port: port}
	}
	payload, err := encodeSOCKSAddress(target)
	if err != nil {
		return err
	}
	_, err = conn.Write(append([]byte{socksVersion, status, 0}, payload...))
	return err
}

func readSOCKSAddress(reader io.Reader) (socksTarget, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(reader, atyp[:]); err != nil {
		return socksTarget{}, err
	}
	var host string
	switch atyp[0] {
	case socksAddressIPv4:
		value := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, value); err != nil {
			return socksTarget{}, err
		}
		host = net.IP(value).String()
	case socksAddressIPv6:
		value := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, value); err != nil {
			return socksTarget{}, err
		}
		host = net.IP(value).String()
	case socksAddressDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return socksTarget{}, err
		}
		if length[0] == 0 {
			return socksTarget{}, errors.New("empty SOCKS domain")
		}
		value := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, value); err != nil {
			return socksTarget{}, err
		}
		host = string(value)
	default:
		return socksTarget{}, fmt.Errorf("unsupported SOCKS address type %d", atyp[0])
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return socksTarget{}, err
	}
	return socksTarget{Host: host, Port: int(binary.BigEndian.Uint16(portBytes[:]))}, nil
}

func encodeSOCKSAddress(target socksTarget) ([]byte, error) {
	if target.Port < 0 || target.Port > 65535 {
		return nil, errors.New("SOCKS target port is out of range")
	}
	var out []byte
	ip := net.ParseIP(target.Host)
	switch {
	case ip != nil && ip.To4() != nil:
		out = append(out, socksAddressIPv4)
		out = append(out, ip.To4()...)
	case ip != nil:
		out = append(out, socksAddressIPv6)
		out = append(out, ip.To16()...)
	default:
		if len(target.Host) == 0 || len(target.Host) > 255 {
			return nil, errors.New("SOCKS target domain length is invalid")
		}
		out = append(out, socksAddressDomain, byte(len(target.Host)))
		out = append(out, target.Host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(target.Port))
	return append(out, port[:]...), nil
}

func dialSOCKS5TCP(ctx context.Context, proxy ProxyConfig, target socksTarget) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp4", proxy.Address)
	if err != nil {
		return nil, fmt.Errorf("dial upstream SOCKS proxy: %w", err)
	}
	releaseContext, err := bindSOCKSHandshakeContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind upstream SOCKS handshake context: %w", err)
	}
	defer releaseContext()
	if err := authenticateSOCKSClient(conn, proxy.Username, proxy.Password); err != nil {
		conn.Close()
		return nil, err
	}
	address, err := encodeSOCKSAddress(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(append([]byte{socksVersion, socksCommandConnect, 0}, address...)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := readSOCKSClientReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func authenticateSOCKSClient(conn net.Conn, username, password string) error {
	if len(username) == 0 || len(username) > 255 || len(password) == 0 || len(password) > 255 {
		return errors.New("SOCKS credentials have invalid length")
	}
	if _, err := conn.Write([]byte{socksVersion, 1, socksAuthUserPass}); err != nil {
		return err
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response != [2]byte{socksVersion, socksAuthUserPass} {
		return errors.New("upstream SOCKS proxy rejected username/password authentication")
	}
	payload := []byte{1, byte(len(username))}
	payload = append(payload, username...)
	payload = append(payload, byte(len(password)))
	payload = append(payload, password...)
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response[0] != 1 || response[1] != 0 {
		return errors.New("upstream SOCKS authentication failed")
	}
	return nil
}

func readSOCKSClientReply(conn net.Conn) (socksTarget, error) {
	var header [3]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return socksTarget{}, err
	}
	if header[0] != socksVersion || header[2] != 0 {
		return socksTarget{}, errors.New("invalid upstream SOCKS reply")
	}
	address, err := readSOCKSAddress(conn)
	if err != nil {
		return socksTarget{}, err
	}
	if header[1] != 0 {
		return socksTarget{}, fmt.Errorf("upstream SOCKS request failed with status %d", header[1])
	}
	return address, nil
}

func dialSOCKS5UDP(ctx context.Context, proxy ProxyConfig, target socksTarget) (*fixedSOCKSPacketConn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	control, err := dialer.DialContext(ctx, "tcp4", proxy.Address)
	if err != nil {
		return nil, fmt.Errorf("dial upstream SOCKS proxy: %w", err)
	}
	releaseContext, err := bindSOCKSHandshakeContext(ctx, control)
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("bind upstream SOCKS handshake context: %w", err)
	}
	defer releaseContext()
	if err := authenticateSOCKSClient(control, proxy.Username, proxy.Password); err != nil {
		control.Close()
		return nil, err
	}
	request, _ := encodeSOCKSAddress(socksTarget{Host: "0.0.0.0", Port: 0})
	if _, err := control.Write(append([]byte{socksVersion, socksCommandUDP, 0}, request...)); err != nil {
		control.Close()
		return nil, err
	}
	relay, err := readSOCKSClientReply(control)
	if err != nil {
		control.Close()
		return nil, err
	}
	relayAddr, err := resolveSOCKSRelay(ctx, proxy.Address, relay)
	if err != nil {
		control.Close()
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		control.Close()
		return nil, err
	}
	return &fixedSOCKSPacketConn{conn: udpConn, control: control, relay: relayAddr, target: target}, nil
}

func resolveSOCKSRelay(ctx context.Context, proxyAddress string, relay socksTarget) (*net.UDPAddr, error) {
	host := relay.Host
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		proxyHost, _, err := net.SplitHostPort(proxyAddress)
		if err != nil {
			return nil, err
		}
		host = proxyHost
	}
	ip := net.ParseIP(host)
	if ip == nil {
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, errors.New("upstream SOCKS UDP relay has no IPv4 address")
		}
		ip = addresses[0]
	}
	if ip = ip.To4(); ip == nil {
		return nil, errors.New("upstream SOCKS UDP relay is not IPv4")
	}
	return &net.UDPAddr{IP: ip, Port: relay.Port}, nil
}

type fixedSOCKSPacketConn struct {
	conn    *net.UDPConn
	control net.Conn
	relay   *net.UDPAddr
	target  socksTarget
	close   sync.Once
}

func (c *fixedSOCKSPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	packet := make([]byte, len(buffer)+512)
	for {
		n, source, err := c.conn.ReadFromUDP(packet)
		if err != nil {
			return 0, nil, err
		}
		if !source.IP.Equal(c.relay.IP) || source.Port != c.relay.Port {
			continue
		}
		payload, sourceTarget, err := parseSOCKSUDPDatagram(packet[:n])
		if err != nil || sourceTarget.Port != 443 || len(payload) > len(buffer) {
			continue
		}
		copy(buffer, payload)
		return len(payload), c.target, nil
	}
}

func (c *fixedSOCKSPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	if address == nil || address.String() != c.target.String() {
		return 0, errors.New("unexpected QUIC upstream address")
	}
	header, err := encodeSOCKSUDPDatagram(c.target, buffer)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.WriteToUDP(header, c.relay); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func (c *fixedSOCKSPacketConn) Close() error {
	var err error
	c.close.Do(func() {
		err = c.conn.Close()
		_ = c.control.Close()
	})
	return err
}

func (c *fixedSOCKSPacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *fixedSOCKSPacketConn) SetDeadline(deadline time.Time) error {
	return c.conn.SetDeadline(deadline)
}

func (c *fixedSOCKSPacketConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *fixedSOCKSPacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}

func (c *fixedSOCKSPacketConn) SetReadBuffer(bytes int) error { return c.conn.SetReadBuffer(bytes) }

func (c *fixedSOCKSPacketConn) SetWriteBuffer(bytes int) error { return c.conn.SetWriteBuffer(bytes) }

func encodeSOCKSUDPDatagram(target socksTarget, payload []byte) ([]byte, error) {
	address, err := encodeSOCKSAddress(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 3, 3+len(address)+len(payload))
	out = append(out, address...)
	return append(out, payload...), nil
}

func parseSOCKSUDPDatagram(packet []byte) ([]byte, socksTarget, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, socksTarget{}, errors.New("invalid or fragmented SOCKS UDP packet")
	}
	reader := &countingReader{reader: bytes.NewReader(packet[3:])}
	target, err := readSOCKSAddress(reader)
	if err != nil {
		return nil, socksTarget{}, err
	}
	offset := 3 + reader.count
	if offset > len(packet) {
		return nil, socksTarget{}, io.ErrUnexpectedEOF
	}
	return packet[offset:], target, nil
}

type socksPeerAddr struct {
	relay  *net.UDPAddr
	target socksTarget
}

func (a socksPeerAddr) Network() string { return "udp" }

func (a socksPeerAddr) String() string { return a.relay.String() + "|" + a.target.String() }

type socksServerPacketConn struct {
	conn      *net.UDPConn
	allowedIP net.IP
	config    *configStore

	mu    sync.Mutex
	relay *net.UDPAddr
}

func (c *socksServerPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	packet := make([]byte, len(buffer)+512)
	for {
		n, source, err := c.conn.ReadFromUDP(packet)
		if err != nil {
			return 0, nil, err
		}
		if !source.IP.Equal(c.allowedIP) {
			continue
		}
		c.mu.Lock()
		if c.relay == nil {
			c.relay = source
		}
		validRelay := source.IP.Equal(c.relay.IP) && source.Port == c.relay.Port
		c.mu.Unlock()
		if !validRelay {
			continue
		}
		payload, target, err := parseSOCKSUDPDatagram(packet[:n])
		if err != nil || !c.targetAllowed(target) || len(payload) > len(buffer) {
			continue
		}
		copy(buffer, payload)
		return len(payload), socksPeerAddr{relay: source, target: target}, nil
	}
}

func (c *socksServerPacketConn) targetAllowed(target socksTarget) bool {
	if c.config == nil {
		return false
	}
	cfg, err := c.config.Current()
	return err == nil && target.Port == 443 && allowedInboundSOCKSTarget(cfg, target)
}

func (c *socksServerPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	peer, ok := address.(socksPeerAddr)
	if !ok {
		peerPointer, pointerOK := address.(*socksPeerAddr)
		if !pointerOK || peerPointer == nil {
			return 0, errors.New("unexpected SOCKS UDP peer address")
		}
		peer = *peerPointer
	}
	packet, err := encodeSOCKSUDPDatagram(peer.target, buffer)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.WriteToUDP(packet, peer.relay); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func (c *socksServerPacketConn) Close() error { return c.conn.Close() }

func (c *socksServerPacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *socksServerPacketConn) SetDeadline(deadline time.Time) error {
	return c.conn.SetDeadline(deadline)
}

func (c *socksServerPacketConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *socksServerPacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}

func (c *socksServerPacketConn) SetReadBuffer(bytes int) error { return c.conn.SetReadBuffer(bytes) }

func (c *socksServerPacketConn) SetWriteBuffer(bytes int) error { return c.conn.SetWriteBuffer(bytes) }

type countingReader struct {
	reader io.Reader
	count  int
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.count += n
	return n, err
}
