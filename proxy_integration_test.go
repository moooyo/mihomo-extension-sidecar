package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3MITMThroughSOCKSUDP(t *testing.T) {
	certPath, keyPath, roots := writeTestInterceptCertificate(t)
	upstreamBody := syntheticWLOCFrame()
	upstreamUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if canonicalHost(r.Host) != "gs-loc.apple.com" || r.URL.Path != "/clls/wloc" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(upstreamBody)
		}),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{loadTestKeyPair(t, certPath, keyPath)},
		},
		QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version2}},
	}
	upstreamDone := make(chan error, 1)
	go func() { upstreamDone <- upstreamServer.Serve(upstreamUDP) }()
	t.Cleanup(func() {
		_ = upstreamServer.Close()
		_ = upstreamUDP.Close()
	})

	relayUser := "relay-username-123"
	relayPassword := "relay-password-1234567890"
	relayAddress, closeRelay := startTestSOCKSUDPRelay(t, upstreamUDP.LocalAddr().(*net.UDPAddr), relayUser, relayPassword)
	t.Cleanup(closeRelay)

	configPath := filepath.Join(t.TempDir(), "config.json")
	configBody := `{
  "version": 2,
  "listen": "127.0.0.1:18080",
  "username": "inbound-user-123",
  "password": "inbound-password-123456789",
  "tls_cert": ` + strconv.Quote(certPath) + `,
  "tls_key": ` + strconv.Quote(keyPath) + `,
  "upstream_proxy": {
    "address": ` + strconv.Quote(relayAddress) + `,
    "username": ` + strconv.Quote(relayUser) + `,
    "password": ` + strconv.Quote(relayPassword) + `
  },
  "mitm": {"enabled":true,"http2":true,"quic_fallback_protection":false},
  "wloc": {
    "enabled": true,
    "longitude": -122.4194,
    "latitude": 37.7749,
    "accuracy": 25,
    "fail_closed": true,
    "max_body_bytes": 1048576
  }
}`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(configPath)
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := newCertificateStore(store)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxyDone := make(chan error, 1)
	proxy := newInterceptProxy(store, certificates)
	proxy.upstreamRoots = roots
	go func() { proxyDone <- proxy.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-proxyDone:
		case <-time.After(3 * time.Second):
			t.Error("interception proxy did not stop")
		}
	})

	clientProxy := ProxyConfig{
		Address:  listener.Addr().String(),
		Username: "inbound-user-123",
		Password: "inbound-password-123456789",
	}
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			target := socksTarget{Host: "gs-loc.apple.com", Port: 443}
			packetConn, err := dialSOCKS5UDP(context.Background(), clientProxy, target)
			if err != nil {
				t.Fatal(err)
			}
			quicTransport := &quic.Transport{Conn: packetConn}
			clientTransport := &http3.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: target.Host},
				QUICConfig:      &quic.Config{Versions: []quic.Version{version}},
				Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
					return quicTransport.Dial(ctx, target, tlsConfig, quicConfig)
				},
			}
			defer clientTransport.Close()
			defer quicTransport.Close()
			defer packetConn.Close()
			request, err := http.NewRequest(http.MethodPost, "https://gs-loc.apple.com/clls/wloc", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := clientTransport.RoundTrip(request)
			if err != nil {
				t.Fatalf("HTTP/3 round trip: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status=%d body=%q", response.StatusCode, body)
			}
			location := extractPatchedWiFiLocation(t, body[10:])
			fields, err := parseProtoFields(location)
			if err != nil {
				t.Fatal(err)
			}
			assertVarintField(t, fields, 1, uint64(int64(3777490000)))
		})
	}

	t.Run("fallback protection", func(t *testing.T) {
		time.Sleep(20 * time.Millisecond)
		fallbackConfig := strings.Replace(configBody, `"quic_fallback_protection":false`, `"quic_fallback_protection":true`, 1)
		if fallbackConfig == configBody {
			t.Fatal("test config did not contain the QUIC fallback setting")
		}
		if err := os.WriteFile(configPath, []byte(fallbackConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		target := socksTarget{Host: "gs-loc.apple.com", Port: 443}
		packetConn, err := dialSOCKS5UDP(context.Background(), clientProxy, target)
		if err != nil {
			t.Fatal(err)
		}
		defer packetConn.Close()
		quicTransport := &quic.Transport{Conn: packetConn}
		defer quicTransport.Close()
		clientTransport := &http3.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: target.Host},
			QUICConfig:      &quic.Config{Versions: []quic.Version{quic.Version1}},
			Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				return quicTransport.Dial(ctx, target, tlsConfig, quicConfig)
			},
		}
		defer clientTransport.Close()
		requestCtx, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer stop()
		request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "https://gs-loc.apple.com/clls/wloc", nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := clientTransport.RoundTrip(request); err == nil {
			response.Body.Close()
			t.Fatal("QUIC fallback protection unexpectedly completed an HTTP/3 request")
		}
	})
}

func startTestSOCKSUDPRelay(t *testing.T, upstream *net.UDPAddr, username, password string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:17890")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestSOCKSUDPAssociation(ctx, conn, upstream, username, password)
		}
	}()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
	}
}

func serveTestSOCKSUDPAssociation(ctx context.Context, control net.Conn, upstream *net.UDPAddr, username, password string) {
	defer control.Close()
	command, _, err := readSOCKSRequest(control, username, password)
	if err != nil || command != socksCommandUDP {
		return
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer relay.Close()
	if err := writeSOCKSReply(control, 0, relay.LocalAddr()); err != nil {
		return
	}
	upstreamConn, err := net.DialUDP("udp4", nil, upstream)
	if err != nil {
		return
	}
	defer upstreamConn.Close()
	go func() {
		<-ctx.Done()
		_ = relay.Close()
		_ = upstreamConn.Close()
	}()
	var destinationMu sync.RWMutex
	var clientAddress *net.UDPAddr
	var responseTarget socksTarget
	go func() {
		packet := make([]byte, 64<<10)
		for {
			n, err := upstreamConn.Read(packet)
			if err != nil {
				return
			}
			destinationMu.RLock()
			client := clientAddress
			target := responseTarget
			destinationMu.RUnlock()
			if client == nil {
				continue
			}
			response, err := encodeSOCKSUDPDatagram(target, packet[:n])
			if err == nil {
				_, _ = relay.WriteToUDP(response, client)
			}
		}
	}()
	packet := make([]byte, 64<<10)
	for {
		n, client, err := relay.ReadFromUDP(packet)
		if err != nil {
			return
		}
		payload, target, err := parseSOCKSUDPDatagram(packet[:n])
		if err != nil {
			continue
		}
		destinationMu.Lock()
		clientAddress = client
		responseTarget = target
		destinationMu.Unlock()
		if _, err := upstreamConn.Write(payload); err != nil {
			return
		}
	}
}

func writeTestInterceptCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "5gpn test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gs-loc.apple.com"},
		DNSNames:     []string{"gs-loc.apple.com", "gs-loc-cn.apple.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if err := os.WriteFile(certPath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	return certPath, keyPath, roots
}

func loadTestKeyPair(t *testing.T, certPath, keyPath string) tls.Certificate {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func syntheticWLOCFrame() []byte {
	location := append(encodeVarintField(1, 1), encodeVarintField(2, 2)...)
	wifi := append(encodeLengthField(1, []byte("00:11:22:33:44:55")), encodeLengthField(2, location)...)
	root := encodeLengthField(2, wifi)
	frame := append(make([]byte, 8), byte(len(root)>>8), byte(len(root)))
	return append(frame, root...)
}
