package main

import (
	"reflect"
	"testing"
)

func TestUpstreamTransportProjectionPreservesOnlyTransportAuthorization(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.generation = 41
	cfg.Modules[0].HostMappings = []HostMapping{
		{Pattern: "api.example.com", Target: "203.0.113.8"},
	}
	cfg.Modules[0].Network = true
	compiled, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = compiled

	projection := newUpstreamTransportProjection(cfg)
	if projection.generation != cfg.generation || projection.proxy != cfg.UpstreamProxy || projection.http2 != cfg.MITM.HTTP2 {
		t.Fatalf("transport projection = %+v", projection)
	}
	for _, test := range []struct {
		host string
		port string
		want socksTarget
		ok   bool
	}{
		{host: "api.example.com", port: "443", want: socksTarget{Host: "203.0.113.8", Port: 443}, ok: true},
		// The network grant is unbounded, so every port and host the module did
		// not capture is servable rather than only the ones it listed.
		{host: "worker.example.com", port: "8443", want: socksTarget{Host: "worker.example.com", Port: 8443}, ok: true},
		{host: "worker.example.com", port: "443", want: socksTarget{Host: "worker.example.com", Port: 443}, ok: true},
		{host: "other.example.com", port: "443", want: socksTarget{Host: "other.example.com", Port: 443}, ok: true},
	} {
		got, ok := projection.targets.upstreamTarget(test.host, test.port)
		if ok != test.ok || got != test.want {
			t.Fatalf("target %s:%s = %+v, %t; want %+v, %t", test.host, test.port, got, ok, test.want, test.ok)
		}
	}
	assertProjectionExcludesScriptRuntime(t, reflect.TypeOf(projection))
}

func TestInboundUDPAuthorizationPreservesAssociationHostSnapshotOnly(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	compiled, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = compiled
	authorization := newInboundUDPAuthorization(cfg)

	if !authorization.allows(socksTarget{Host: "api.example.com", Port: 443}) {
		t.Fatal("authorization rejected the captured host")
	}
	if !authorization.allows(socksTarget{Host: "192.0.2.1", Port: 443}) {
		t.Fatal("authorization rejected an IP target before the SNI check")
	}
	for _, target := range []socksTarget{
		{Host: "other.example.com", Port: 443},
		{Host: "api.example.com", Port: 80},
	} {
		if authorization.allows(target) {
			t.Fatalf("authorization accepted unexpected target %+v", target)
		}
	}
	assertProjectionExcludesScriptRuntime(t, reflect.TypeOf(authorization))
}

func TestUpstreamTargetProjectionMatchesValidatedConfigResolution(t *testing.T) {
	t.Parallel()
	cfg := validNativeConfig()
	cfg.Modules[0].CaptureHosts = []string{"*.example.com", "api.example.com"}
	cfg.Modules[0].HostMappings = []HostMapping{
		{Pattern: "*.example.com", Target: "198.51.100.7"},
		{Pattern: "api.example.com", Target: "203.0.113.8"},
	}
	cfg.Modules[0].Network = true
	projection := newUpstreamTransportProjection(cfg)
	for _, target := range []struct {
		host string
		port string
	}{
		{host: "API.EXAMPLE.COM.", port: "443"},
		{host: "sub.example.com", port: "80"},
		{host: "example.com", port: "443"},
		{host: "events.example.net", port: "8080"},
		{host: "worker.example.net", port: "8443"},
		{host: "worker.example.net", port: "443"},
		{host: "worker.example.net", port: "invalid"},
	} {
		want, wantOK := activeModuleUpstreamTarget(cfg, target.host, target.port)
		got, gotOK := projection.targets.upstreamTarget(target.host, target.port)
		if gotOK != wantOK || got != want {
			t.Fatalf("target %s:%s projected=(%+v,%t), config=(%+v,%t)", target.host, target.port, got, gotOK, want, wantOK)
		}
	}
}

func TestLongLivedTransportOwnersRetainOnlyNarrowProjections(t *testing.T) {
	t.Parallel()
	configType := reflect.TypeOf(Config{})
	generationType := reflect.TypeOf(upstreamTransportGeneration{})
	projectionField, exists := generationType.FieldByName("projection")
	if !exists || projectionField.Type != reflect.TypeOf(upstreamTransportProjection{}) {
		t.Fatalf("upstream transport owner projection field = %+v, exists=%t", projectionField, exists)
	}
	authorizationField, exists := reflect.TypeOf(socksServerPacketConn{}).FieldByName("authorization")
	if !exists || authorizationField.Type != reflect.TypeOf(inboundUDPAuthorization{}) {
		t.Fatalf("UDP association authorization field = %+v, exists=%t", authorizationField, exists)
	}
	for _, owner := range []reflect.Type{generationType, reflect.TypeOf(socksServerPacketConn{})} {
		for index := 0; index < owner.NumField(); index++ {
			fieldType := owner.Field(index).Type
			if fieldType == configType || fieldType.Kind() == reflect.Pointer && fieldType.Elem() == configType {
				t.Fatalf("long-lived owner %s retains Config through field %s", owner, owner.Field(index).Name)
			}
		}
	}
	assertProjectionExcludesScriptRuntime(t, projectionField.Type)
	assertProjectionExcludesScriptRuntime(t, authorizationField.Type)
}

func assertProjectionExcludesScriptRuntime(t *testing.T, root reflect.Type) {
	t.Helper()
	prohibited := map[reflect.Type]string{
		reflect.TypeOf(Config{}):               "Config",
		reflect.TypeOf(Module{}):               "Module",
		reflect.TypeOf(ScriptRule{}):           "ScriptRule",
		reflect.TypeOf(compiledScriptConfig{}): "compiledScriptConfig",
		reflect.TypeOf(compiledScriptModule{}): "compiledScriptModule",
		reflect.TypeOf(compiledScriptRule{}):   "compiledScriptRule",
	}
	seen := make(map[reflect.Type]struct{})
	var visit func(reflect.Type)
	visit = func(current reflect.Type) {
		for current.Kind() == reflect.Pointer {
			current = current.Elem()
		}
		if name, blocked := prohibited[current]; blocked {
			t.Fatalf("projection type %s retains prohibited %s", root, name)
		}
		if current.PkgPath() == "github.com/dop251/goja" && current.Name() == "Program" {
			t.Fatalf("projection type %s retains goja.Program", root)
		}
		// The jq artifact is snapshot-owned for the same reason the goja one is,
		// so it is prohibited here for the same reason.
		if current.PkgPath() == "github.com/itchyny/gojq" && current.Name() == "Code" {
			t.Fatalf("projection type %s retains gojq.Code", root)
		}
		if _, exists := seen[current]; exists {
			return
		}
		seen[current] = struct{}{}
		switch current.Kind() {
		case reflect.Array, reflect.Slice:
			visit(current.Elem())
		case reflect.Map:
			visit(current.Key())
			visit(current.Elem())
		case reflect.Struct:
			for index := 0; index < current.NumField(); index++ {
				visit(current.Field(index).Type)
			}
		case reflect.Interface:
			t.Fatalf("projection type %s retains an interface field through %s", root, current)
		}
	}
	visit(root)
}

// The resolver form names nameservers for 5gpn-dns to query. It is not a
// destination, and the sidecar must not dial it.
//
// It used to. Both places that turn a mapping into a SOCKS target took the
// value verbatim, so "server:1.1.1.1" was written out as a SOCKS domain name --
// mayBeIPAddress says true because of the colon, netip.ParseAddr then fails, and
// the default branch encodes the literal string as ATYP=3. No egress binding
// names it, because the control plane already excludes the form when it builds
// selectors, so the connection died at the interception listener's terminator.
//
// The result was a mapping that was 100% broken while capture rules, the
// certificate SAN set, the overlay generation and the readiness lease all
// reported healthy, and the operator saw an egress authorisation refusal rather
// than anything about DNS.
func TestResolverFormMappingsAreNotDialled(t *testing.T) {
	t.Parallel()
	module := Module{
		ID: "io.example.resolver", Enabled: true,
		CaptureHosts: []string{"api.example.com", "alias.example.com"},
		HostMappings: []HostMapping{
			{Pattern: "api.example.com", Target: "server:1.1.1.1"},
			{Pattern: "alias.example.com", Target: "origin.example.net"},
		},
	}
	cfg := Config{Version: configVersion, MITM: MITMSettings{Enabled: true}, Modules: []Module{module}, ExecutionOrder: []string{module.ID}}

	if got := mappedInterceptTarget(cfg, "api.example.com"); got != "api.example.com" {
		t.Fatalf("mappedInterceptTarget = %q; a resolver spec must never become a dial host", got)
	}
	// The alias form is load-bearing and must still substitute.
	if got := mappedInterceptTarget(cfg, "alias.example.com"); got != "origin.example.net" {
		t.Fatalf("mappedInterceptTarget = %q, want the alias target", got)
	}

	projection := newUpstreamTransportProjection(cfg)
	for _, projected := range projection.targets.modules {
		for _, mapping := range projected.mappings {
			if mapping.resolverForm() {
				t.Fatalf("a resolver-form mapping reached the projection: %+v", mapping)
			}
		}
	}
}

// A colon cannot appear in a domain name. Anything arriving here with one is a
// host:port that was never split, a zoned IPv6 literal, or a resolver spec that
// leaked out of a mapping -- all three used to be encoded as a domain and sent.
func TestSOCKSAddressRefusesAColonInADomain(t *testing.T) {
	t.Parallel()
	if _, err := appendSOCKSAddress(nil, socksTarget{Host: "server:1.1.1.1", Port: 443}); err == nil {
		t.Fatal("a resolver spec was encoded as a SOCKS domain name")
	}
	if _, err := appendSOCKSAddress(nil, socksTarget{Host: "fe80::1%eth0", Port: 443}); err == nil {
		t.Fatal("a zoned IPv6 literal was encoded as a SOCKS domain name")
	}
	if _, err := appendSOCKSAddress(nil, socksTarget{Host: "origin.example.net", Port: 443}); err != nil {
		t.Fatalf("an ordinary domain was refused: %v", err)
	}
}
