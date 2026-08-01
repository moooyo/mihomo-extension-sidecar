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
	bundleStoreDir := flags.String("bundle-store", "/var/lib/5gpn-intercept",
		"directory this sidecar keeps its own durable state in: bundles and extension storage")
	controlSocket := flags.String("control-socket", "/run/5gpn-intercept/control.sock",
		"machine-only control API socket; empty disables the API")
	controlPeerUID := flags.Int("control-peer-uid", -1, "only accept control connections from this uid (-1 for any)")
	controlPeerGID := flags.Int("control-peer-gid", -1, "only accept control connections from this gid (-1 for any)")
	controlPeerUser := flags.String("control-peer-user", "",
		"only accept control connections from this user; resolved at startup, mutually exclusive with --control-peer-uid")
	controlPeerGroup := flags.String("control-peer-group", "",
		"only accept control connections from this group; resolved at startup, mutually exclusive with --control-peer-gid")
	_ = flags.Parse(os.Args[1:])

	// Resolved before anything else starts. A named peer that does not exist is
	// a configuration error, and continuing with an unrestricted socket because
	// the lookup failed would invert what naming a peer is for.
	peerUID, peerGID, err := resolvePeerIdentity(*controlPeerUser, *controlPeerGroup, *controlPeerUID, *controlPeerGID)
	if err != nil {
		log.Fatalf("intercept: %v", err)
	}
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
	// The sidecar owns its plugin state. The coordinator's file is consulted only
	// until the first bundle is served; from that moment the manager decides,
	// including when a purge leaves it with nothing. A deployment that has never
	// been pushed a bundle keeps using the file, which is what makes this a
	// migration rather than a flag day.
	var control *controlServer
	if *controlSocket != "" {
		bundles, err := openBundleStore(*bundleStoreDir)
		if err != nil {
			log.Fatalf("intercept: bundle store: %v", err)
		}
		manager := newBundleManager(bundles, logs)
		if err := manager.Recover(); err != nil {
			// Serving nothing is the safe state: mihomo's capture rules treat a
			// processor with no bundle as not ready and fail closed, so an
			// unusable artifact must not also take the process down.
			log.Printf("intercept: could not recover a bundle, continuing with none: %v", err)
		}
		// Flips the moment the first bundle is served, whether that is one
		// recovered here or the first one pushed.
		store.setBundleSource(func() (*Config, bool) { return manager.Active(), manager.Migrated() })
		if manager.Active() != nil {
			log.Printf("intercept: serving pushed bundle %s", manager.ActiveID())
		}
		control = newControlServer(manager, version, peerUID, peerGID)
		go func() {
			if err := control.Serve(*controlSocket); err != nil {
				log.Printf("intercept: control API stopped: %v", err)
			}
		}()
		defer control.Close()
	}

	// The extension store is derived from this directory whether or not the
	// control API is enabled, so the emptiness openBundleStore rejects has to be
	// rejected here too: filepath.Join("", ...) is a relative path, and durable
	// state would land in whatever working directory the unit happened to have.
	if *bundleStoreDir == "" {
		log.Fatal("intercept: --bundle-store must not be empty")
	}
	proxy := newInterceptProxy(store, certificates, *bundleStoreDir)
	proxy.setEngineLogPublisher(logs)
	go stopWhenMITMDisabled(ctx, store, stopRuntime, startupPublishGrace)
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

// startupPublishGrace is how long a freshly started process waits for its
// coordinator to publish before it will honour a "nothing is active" verdict.
//
// It must exceed the coordinator's own publish window, which is a socket wait
// plus one control-API round trip.
const startupPublishGrace = 15 * time.Second

func stopWhenMITMDisabled(ctx context.Context, store *configStore, stop context.CancelFunc, grace time.Duration) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	// A withdrawn bundle makes Current fail on every tick, so the summary is
	// reported once per outage rather than four times a second. Serving nothing is
	// not a reason to stop: the control socket is how a new bundle arrives, and
	// mihomo already fails closed on a processor that is not ready.
	reported := false
	// A stale bundle that decodes cleanly is not the same as no bundle, and it
	// used to be treated as authoritative the moment this process started.
	//
	// Turning the MITM master off and back on is exactly that shape. Off stops
	// this service, so the bundle its store points at says disabled. On writes
	// the document, the path unit starts this process, and the coordinator then
	// pushes the enabled bundle -- but a cold start adopts the durable pointer
	// first, saw "no active extension", and stopped within about 460 ms, racing
	// the commit. The commit landed on some runs and was lost to the exit on
	// others, so the master switch was a one-way door: the document said enabled,
	// the console reported expected-but-not-running, and only an explicit
	// `systemctl start` recovered it.
	//
	// systemd's ExecCondition=--check-enabled reads the *file*, so it has already
	// established that the master is on. Until an active configuration has
	// actually been observed, give the coordinator its publish window rather than
	// stopping on a verdict this process is about to be corrected on. Once one has
	// been observed, the master really was turned off while running, which is what
	// this loop is for, and it stops immediately as before.
	observedActive := false
	deadline := time.Now().Add(grace)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg, err := store.Current()
			if err != nil {
				if !reported {
					log.Print("intercept: could not refresh MITM state")
					reported = true
				}
				continue
			}
			reported = false
			if !cfg.MITM.Enabled || !hasActiveExtensions(cfg) {
				if !observedActive && time.Now().Before(deadline) {
					continue
				}
				log.Print("intercept: no active interception extension; stopping service")
				stop()
				return
			}
			observedActive = true
		}
	}
}
