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
	cfg.Modules[0].NetworkOrigins = []string{"https://worker.example.com:8443"}
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
		{host: "worker.example.com", port: "8443", want: socksTarget{Host: "worker.example.com", Port: 8443}, ok: true},
		{host: "worker.example.com", port: "443"},
		{host: "other.example.com", port: "443"},
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
	cfg.Modules[0].NetworkOrigins = []string{
		"http://events.example.net:8080",
		"https://worker.example.net:8443",
	}
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
