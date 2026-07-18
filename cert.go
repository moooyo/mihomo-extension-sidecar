package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type certificateStore struct {
	config *configStore

	mu          sync.Mutex
	certPath    string
	keyPath     string
	certModTime time.Time
	keyModTime  time.Time
	certificate *tls.Certificate
}

func newCertificateStore(config *configStore) (*certificateStore, error) {
	store := &certificateStore{config: config}
	if _, err := store.currentCertificate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *certificateStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("unrecognized interception SNI")
	}
	cfg, err := s.config.Current()
	if err != nil || !activeInterceptHost(cfg, hello.ServerName) {
		return nil, errors.New("unrecognized interception SNI")
	}
	return s.currentCertificate()
}

func (s *certificateStore) currentCertificate() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.config.Current()
	if err != nil {
		return nil, err
	}
	certInfo, err := os.Stat(cfg.TLSCert)
	if err != nil {
		return s.staleOrError(fmt.Errorf("stat TLS certificate: %w", err))
	}
	keyInfo, err := os.Stat(cfg.TLSKey)
	if err != nil {
		return s.staleOrError(fmt.Errorf("stat TLS private key: %w", err))
	}
	if s.certificate != nil && s.certPath == cfg.TLSCert && s.keyPath == cfg.TLSKey &&
		certInfo.ModTime().Equal(s.certModTime) && keyInfo.ModTime().Equal(s.keyModTime) {
		return s.certificate, nil
	}
	certificate, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return s.staleOrError(fmt.Errorf("load TLS keypair: %w", err))
	}
	if len(certificate.Certificate) == 0 {
		return s.staleOrError(errors.New("TLS keypair contains no certificate"))
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return s.staleOrError(fmt.Errorf("parse TLS leaf certificate: %w", err))
	}
	if err := validateInterceptLeaf(leaf, certificateHostPatterns(cfg), time.Now()); err != nil {
		return s.staleOrError(err)
	}
	certificate.Leaf = leaf
	s.certPath = cfg.TLSCert
	s.keyPath = cfg.TLSKey
	s.certModTime = certInfo.ModTime()
	s.keyModTime = keyInfo.ModTime()
	s.certificate = &certificate
	return s.certificate, nil
}

func (s *certificateStore) staleOrError(err error) (*tls.Certificate, error) {
	if s.certificate == nil {
		return nil, err
	}
	log.Printf("intercept: certificate reload failed; retaining the last valid leaf: %v", err)
	return s.certificate, nil
}

func validateInterceptLeaf(leaf *x509.Certificate, requiredHosts []string, now time.Time) error {
	if leaf == nil {
		return errors.New("missing TLS leaf certificate")
	}
	if leaf.IsCA {
		return errors.New("interception runtime must not receive a CA certificate")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("interception TLS leaf certificate is not currently valid")
	}
	for _, host := range requiredHosts {
		probe := host
		if strings.HasPrefix(probe, "*.") {
			probe = "probe." + strings.TrimPrefix(probe, "*.")
		}
		if err := leaf.VerifyHostname(probe); err != nil {
			return fmt.Errorf("interception TLS certificate does not cover %s: %w", host, err)
		}
	}
	return nil
}
