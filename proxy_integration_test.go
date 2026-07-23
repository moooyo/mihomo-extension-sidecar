package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3MITMThroughSOCKSUDP(t *testing.T) {
	certPath, keyPath, roots := writeTestInterceptCertificate(t)
	upstreamBody := []byte("upstream")
	requestBody := []byte("client-payload")
	var upstreamV1Calls atomic.Int32
	upstreamUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if canonicalHost(r.Host) != "api.example.com" || r.Header.Get("Te") != "trailers" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			if r.URL.Path == "/bodyless" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			if r.URL.Path == "/oversized-header" {
				w.Header().Set("X-Oversized", strings.Repeat("x", int(maxModuleNetworkHeaderBytes)+1))
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.URL.Path != "/v1" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(body, requestBody) {
				http.Error(w, "unexpected request body", http.StatusBadRequest)
				return
			}
			upstreamV1Calls.Add(1)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Trailer", "Grpc-Status")
			_, _ = w.Write(upstreamBody)
			w.Header().Set("Grpc-Status", "0")
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
	relayAddress, relayAssociations, closeRelay := startTestSOCKSUDPRelay(t, upstreamUDP.LocalAddr().(*net.UDPAddr), relayUser, relayPassword)
	t.Cleanup(closeRelay)

	configPath := filepath.Join(t.TempDir(), "config.json")
	manifest := "apiVersion: 5gpn.io/v1\nkind: Extension\n"
	script := `function transform(context) {
	if (context.response.status === 304) return {response: {body: ""}}
  if (context.response.trailers["Grpc-Status"] !== "0") throw new Error("missing upstream trailer")
  return { response: { body: context.response.body + "-patched", trailers: {"Grpc-Status": "7"} } }
}`
	cfg := Config{
		Version: configVersion, Listen: "127.0.0.1:18080", Username: "inbound-user-123", Password: "inbound-password-123456789",
		TLSCert: certPath, TLSKey: keyPath,
		UpstreamProxy:  ProxyConfig{Address: relayAddress, Username: relayUser, Password: relayPassword},
		MITM:           MITMSettings{Enabled: true, HTTP2: true},
		ExecutionOrder: []string{"io.example.http3"},
		Modules: []Module{{
			ID: "io.example.http3", Version: "1.0.0", Name: "HTTP3 fixture", Enabled: true, ImportedAt: time.Now().UTC().Format(time.RFC3339),
			Source: ModuleSource{Digest: digestText(manifest), Body: manifest}, CaptureHosts: []string{"api.example.com"}, CaptureDNS: "trust",
			Scripts: []ScriptRule{{
				ID: "patch", Phase: "response", Match: ActionMatch{Hosts: []string{"api.example.com"}, Schemes: []string{"https"}, PathRegex: "^/(?:v1|bodyless)$", StatusCodes: []int{200, 304}},
				ScriptDigest: digestText(script), ScriptBody: script, BodyMode: "text", TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
			}},
		}},
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configBody := string(configBytes)
	if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
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
	for index, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			target := socksTarget{Host: "api.example.com", Port: 443}
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
			// The first authority request is bodyless so the v1-to-v2 replay
			// path cannot rely on a prior payload request caching v2.
			bodylessRequest, err := http.NewRequest(http.MethodPost, "https://api.example.com/bodyless", nil)
			if err != nil {
				t.Fatal(err)
			}
			bodylessRequest.Header.Set("Te", "trailers")
			bodylessResponse, err := clientTransport.RoundTrip(bodylessRequest)
			if err != nil {
				t.Fatalf("HTTP/3 bodyless round trip: %v", err)
			}
			defer bodylessResponse.Body.Close()
			if _, err := io.ReadAll(bodylessResponse.Body); err != nil {
				t.Fatal(err)
			}
			if bodylessResponse.StatusCode != http.StatusNotModified {
				t.Fatalf("bodyless status=%d", bodylessResponse.StatusCode)
			}

			request, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1", bytes.NewReader(requestBody))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Te", "trailers")
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
			if string(body) != "upstream-patched" {
				t.Fatalf("body=%q", body)
			}
			if response.Trailer.Get("Grpc-Status") != "7" {
				t.Fatalf("trailers=%v", response.Trailer)
			}
			if got, want := upstreamV1Calls.Load(), int32(index+1); got != want {
				t.Fatalf("upstream /v1 calls=%d, want %d (request body was retried unsafely)", got, want)
			}
			if version == quic.Version1 {
				if got := relayAssociations.Load(); got != 2 {
					t.Fatalf("two requests opened %d upstream UDP associations, want v1 probe plus one reused v2 association", got)
				}
			}

			oversizedRequest, err := http.NewRequest(http.MethodGet, "https://api.example.com/oversized-header", nil)
			if err != nil {
				t.Fatal(err)
			}
			oversizedRequest.Header.Set("Te", "trailers")
			oversizedResponse, err := clientTransport.RoundTrip(oversizedRequest)
			if err != nil {
				t.Fatalf("HTTP/3 oversized-header round trip: %v", err)
			}
			defer oversizedResponse.Body.Close()
			if _, err := io.ReadAll(oversizedResponse.Body); err != nil {
				t.Fatal(err)
			}
			if oversizedResponse.StatusCode != http.StatusBadGateway {
				t.Fatalf("oversized-header status=%d", oversizedResponse.StatusCode)
			}
		})
	}

	t.Run("revocation on existing UDP association", func(t *testing.T) {
		target := socksTarget{Host: "api.example.com", Port: 443}
		packetConn, err := dialSOCKS5UDP(context.Background(), clientProxy, target)
		if err != nil {
			t.Fatal(err)
		}
		defer packetConn.Close()
		quicTransport := &quic.Transport{Conn: packetConn}
		defer quicTransport.Close()
		newClientTransport := func() *http3.Transport {
			return &http3.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: target.Host},
				QUICConfig:      &quic.Config{Versions: []quic.Version{quic.Version2}},
				Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
					return quicTransport.Dial(ctx, target, tlsConfig, quicConfig)
				},
			}
		}
		clientTransport := newClientTransport()
		request, err := http.NewRequest(http.MethodGet, "https://api.example.com/bodyless", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Te", "trailers")
		response, err := clientTransport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(response.Body); err != nil {
			response.Body.Close()
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotModified {
			t.Fatalf("pre-revocation status = %d", response.StatusCode)
		}

		disabledCfg := cfg
		disabledCfg.Modules = append([]Module(nil), cfg.Modules...)
		disabledCfg.Modules[0].Enabled = false
		disabledBody, err := json.Marshal(disabledCfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, disabledBody, 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.Current()
		if err != nil || activeInterceptHost(loaded, target.Host) {
			t.Fatalf("revoked config was not loaded: active=%t err=%v", activeInterceptHost(loaded, target.Host), err)
		}

		request, err = http.NewRequest(http.MethodGet, "https://api.example.com/bodyless", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Te", "trailers")
		response, err = clientTransport.RoundTrip(request)
		if err != nil {
			t.Fatalf("existing QUIC connection did not return a fail-closed HTTP response: %v", err)
		}
		_, _ = io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("post-revocation existing-connection status = %d", response.StatusCode)
		}
		if err := clientTransport.Close(); err != nil {
			t.Fatal(err)
		}

		newConnectionTransport := newClientTransport()
		defer newConnectionTransport.Close()
		requestCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		request, err = http.NewRequestWithContext(requestCtx, http.MethodGet, "https://api.example.com/bodyless", nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := newConnectionTransport.RoundTrip(request); err == nil {
			response.Body.Close()
			t.Fatal("revoked SNI completed a new QUIC handshake on the old UDP association")
		}

		if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		restored, err := store.Current()
		if err != nil || !activeInterceptHost(restored, target.Host) {
			t.Fatalf("test config was not restored: active=%t err=%v", activeInterceptHost(restored, target.Host), err)
		}
	})

	t.Run("fallback protection", func(t *testing.T) {
		time.Sleep(20 * time.Millisecond)
		fallbackConfig := strings.Replace(configBody, `"quic_fallback_protection":false`, `"quic_fallback_protection":true`, 1)
		if fallbackConfig == configBody {
			t.Fatal("test config did not contain the QUIC fallback setting")
		}
		if err := os.WriteFile(configPath, []byte(fallbackConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		target := socksTarget{Host: "api.example.com", Port: 443}
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
		request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "https://api.example.com/v1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := clientTransport.RoundTrip(request); err == nil {
			response.Body.Close()
			t.Fatal("QUIC fallback protection unexpectedly completed an HTTP/3 request")
		}
	})
}

func startTestSOCKSUDPRelay(t *testing.T, upstream *net.UDPAddr, username, password string) (string, *atomic.Int32, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:17890")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	associations := &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			associations.Add(1)
			go serveTestSOCKSUDPAssociation(ctx, conn, upstream, username, password)
		}
	}()
	return listener.Addr().String(), associations, func() {
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
		Subject:      pkix.Name{CommonName: "api.example.com"},
		DNSNames:     []string{"api.example.com"},
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
