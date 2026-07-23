package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

const interceptHealthcheckTimeout = 5 * time.Second

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	flags := flag.NewFlagSet("5gpn-intercept", flag.ExitOnError)
	configPath := flags.String("config", "/etc/5gpn/intercept/config.json", "path to the interception configuration")
	checkConfig := flags.Bool("check-config", false, "validate the configuration and exit")
	checkEnabled := flags.Bool("check-enabled", false, "exit successfully only when MITM and at least one extension are enabled")
	printMihomoFields := flags.Bool("print-mihomo-fields", false, "print tab-separated mihomo credentials and exit")
	printCertificateHosts := flags.Bool("print-certificate-hosts", false, "print the canonical certificate SAN list and exit")
	printCertificateDigest := flags.Bool("print-certificate-digest", false, "print the canonical certificate SAN digest and exit")
	printCertificateRequest := flags.Bool("print-certificate-request", false, "print the SAN digest followed by the canonical SAN list and exit")
	healthcheck := flags.Bool("healthcheck", false, "verify the local SOCKS5 service and exit")
	_ = flags.Parse(os.Args[1:])
	if *printCertificateHosts || *printCertificateDigest || *printCertificateRequest {
		cfg, err := loadCertificateConfig(*configPath)
		if err != nil {
			log.Fatalf("intercept: certificate request configuration error: %v", err)
		}
		if *printCertificateRequest {
			fmt.Println(certificateDigest(cfg))
			for _, host := range certificateHostPatterns(cfg) {
				fmt.Println(host)
			}
		} else if *printCertificateHosts {
			for _, host := range certificateHostPatterns(cfg) {
				fmt.Println(host)
			}
		} else {
			fmt.Println(certificateDigest(cfg))
		}
		return
	}
	store, err := newConfigStore(*configPath)
	if err != nil {
		if *checkConfig {
			log.Fatalf("intercept: configuration error: %v", err)
		}
		log.Fatal("intercept: configuration unavailable")
	}
	cfg, err := store.Current()
	if err != nil {
		log.Fatal("intercept: configuration unavailable")
	}
	if err := cfg.ValidateDeployment(); err != nil {
		log.Fatalf("intercept: deployment boundary error: %v", err)
	}
	if *checkConfig {
		return
	}
	if *printMihomoFields {
		fmt.Printf("%s\t%s\t%s\t%s\n", cfg.Username, cfg.Password, cfg.UpstreamProxy.Username, cfg.UpstreamProxy.Password)
		return
	}
	if *checkEnabled {
		if !cfg.MITM.Enabled || !hasActiveExtensions(cfg) {
			os.Exit(3)
		}
		return
	}
	if *healthcheck {
		if !cfg.MITM.Enabled || !hasActiveExtensions(cfg) {
			log.Fatal("intercept: healthcheck unavailable without an active extension")
		}
		ctx, cancel := context.WithTimeout(context.Background(), interceptHealthcheckTimeout)
		defer cancel()
		if err := checkInterceptHealth(ctx, cfg); err != nil {
			log.Fatalf("intercept: healthcheck failed: %v", err)
		}
		return
	}
	if !cfg.MITM.Enabled || !hasActiveExtensions(cfg) {
		log.Print("intercept: no active interception extension; service will remain stopped")
		return
	}
	certificates, err := newCertificateStore(store)
	if err != nil {
		log.Fatalf("intercept: certificate error: %v", err)
	}
	listener, err := net.Listen("tcp4", cfg.Listen)
	if err != nil {
		log.Fatalf("intercept: listen %s: %v", cfg.Listen, err)
	}
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, stopRuntime := context.WithCancel(signalCtx)
	defer stopRuntime()
	logs := newEngineLogHub(engineLogRingCapacity)
	store.setEngineLogPublisher(logs)
	logService, err := startEngineLogService(logs, store, version)
	if err != nil {
		log.Print("intercept: engine log service unavailable; continuing without UI log streaming")
		logService = nil
	}
	proxy := newInterceptProxy(store, certificates)
	proxy.setEngineLogPublisher(logs)
	go stopWhenMITMDisabled(ctx, store, stopRuntime)
	log.Printf("intercept: modular TLS and HTTP/3 SOCKS5 TCP/UDP service listening on %s (http2=%t quic_fallback_protection=%t)", cfg.Listen, cfg.MITM.HTTP2, cfg.MITM.QUICFallbackProtection)
	logs.Publish(EngineLog{
		Level: "info", Source: "engine",
		Message: fmt.Sprintf("sidecar started with %d active extensions", activeExtensionCount(cfg)),
	})
	var logDone chan struct{}
	if logService != nil {
		logDone = make(chan struct{})
		go func() {
			defer close(logDone)
			if err := logService.Serve(ctx); err != nil && ctx.Err() == nil {
				log.Print("intercept: engine log service stopped unexpectedly; data plane remains active")
			}
		}()
	}
	proxyErr := proxy.Serve(ctx, listener)
	logs.Publish(EngineLog{Level: "info", Source: "engine", Message: "sidecar stopping"})
	stopRuntime()
	if logService != nil {
		logService.Close()
		<-logDone
	} else {
		logs.Close()
	}
	if proxyErr != nil {
		log.Fatalf("intercept: service failed: %v", proxyErr)
	}
}

func checkInterceptHealth(ctx context.Context, cfg Config) error {
	host := activeHostPatterns(cfg)[0]
	if strings.HasPrefix(host, "*.") {
		host = "probe." + strings.TrimPrefix(host, "*.")
	}
	proxy := ProxyConfig{Address: cfg.Listen, Username: cfg.Username, Password: cfg.Password}
	conn, err := dialSOCKS5UDP(ctx, proxy, socksTarget{Host: host, Port: 443})
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func stopWhenMITMDisabled(ctx context.Context, store *configStore, stop context.CancelFunc) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg, err := store.Current()
			if err != nil {
				log.Print("intercept: could not refresh MITM state")
				continue
			}
			if !cfg.MITM.Enabled || !hasActiveExtensions(cfg) {
				log.Print("intercept: no active interception extension; stopping service")
				stop()
				return
			}
		}
	}
}
