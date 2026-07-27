package main

import (
	"testing"

	"github.com/dop251/goja"
)

func webAPIRuntime(t *testing.T) *goja.Runtime {
	t.Helper()
	vm := goja.New()
	if err := installWebAPI(vm); err != nil {
		t.Fatal(err)
	}
	return vm
}

func evalString(t *testing.T, vm *goja.Runtime, source string) string {
	t.Helper()
	value, err := vm.RunString(source)
	if err != nil {
		t.Fatalf("%s: %v", source, err)
	}
	return value.String()
}

func TestURLExposesThePartsBundlesRead(t *testing.T) {
	t.Parallel()
	vm := webAPIRuntime(t)
	source := `const u = new URL("https://weatherkit.apple.com/api/v1/availability/en-US/31.25/121.5?country=CN");
[u.protocol, u.hostname, u.host, u.pathname, u.search, u.origin, u.searchParams.get("country"), String(u.searchParams.get("absent"))].join("|")`
	got := evalString(t, vm, source)
	want := "https:|weatherkit.apple.com|weatherkit.apple.com|/api/v1/availability/en-US/31.25/121.5|?country=CN|https://weatherkit.apple.com|CN|null"
	if got != want {
		t.Fatalf("url parts = %q, want %q", got, want)
	}
}

func TestURLSearchParamsMutationIsVisibleInHref(t *testing.T) {
	t.Parallel()
	// Upstream's request path sets dataSets and then reads the URL back. Two
	// disagreeing views of one address would silently drop the edit.
	vm := webAPIRuntime(t)
	source := `const u = new URL("https://weatherkit.apple.com/api/v2/weather/en-US/1/2?dataSets=a,b&keep=yes")
u.searchParams.set("dataSets", "a")
u.searchParams.delete("keep")
u.toString()`
	got := evalString(t, vm, source)
	if got != "https://weatherkit.apple.com/api/v2/weather/en-US/1/2?dataSets=a" {
		t.Fatalf("href = %q", got)
	}
}

func TestURLRejectsARelativeAddressWithoutABase(t *testing.T) {
	t.Parallel()
	vm := webAPIRuntime(t)
	if _, err := vm.RunString(`new URL("/api/v1/availability/")`); err == nil {
		t.Fatal("expected a relative URL without a base to be rejected")
	}
	got := evalString(t, vm, `new URL("/api/v2/weather/x", "https://weatherkit.apple.com/ignored").toString()`)
	if got != "https://weatherkit.apple.com/api/v2/weather/x" {
		t.Fatalf("resolved = %q", got)
	}
}

func TestURLPathnameDefaultsToRoot(t *testing.T) {
	t.Parallel()
	vm := webAPIRuntime(t)
	if got := evalString(t, vm, `new URL("https://example.com").pathname`); got != "/" {
		t.Fatalf("pathname = %q, want /", got)
	}
}

func TestTextCodecsRoundTrip(t *testing.T) {
	t.Parallel()
	// The FlatBuffers runtime the bundles carry builds a TextDecoder for every
	// ByteBuffer and a TextEncoder for every Builder, so the binary path depends
	// on these existing.
	vm := webAPIRuntime(t)
	source := `const bytes = new TextEncoder().encode("空气质量 ok")
new TextDecoder("utf-8").decode(bytes)`
	if got := evalString(t, vm, source); got != "空气质量 ok" {
		t.Fatalf("round trip = %q", got)
	}
	if got := evalString(t, vm, `new TextDecoder().decode()`); got != "" {
		t.Fatalf("empty decode = %q, want an empty string", got)
	}
}

func TestTextDecoderRefusesANonUTF8Label(t *testing.T) {
	t.Parallel()
	// Decoding another encoding as UTF-8 would corrupt the payload somewhere far
	// from here, so it fails at construction instead.
	vm := webAPIRuntime(t)
	if _, err := vm.RunString(`new TextDecoder("gbk")`); err == nil {
		t.Fatal("expected a non-UTF-8 label to be rejected")
	}
}

func TestTextDecoderFatalRejectsInvalidBytes(t *testing.T) {
	t.Parallel()
	vm := webAPIRuntime(t)
	if _, err := vm.RunString(`new TextDecoder("utf-8", {fatal: true}).decode(new Uint8Array([0xff, 0xfe]))`); err == nil {
		t.Fatal("expected fatal decoding to reject invalid UTF-8")
	}
	if got := evalString(t, vm, `new TextDecoder().decode(new Uint8Array([104, 105]))`); got != "hi" {
		t.Fatalf("decode = %q", got)
	}
}

func TestNativeScriptsDoNotGetTheWebGlobals(t *testing.T) {
	t.Parallel()
	// Native scripts were reviewed against a smaller surface; widening it for
	// them would change what an already-approved snapshot can do.
	source := `function transform(context) {
  return { response: { body: [typeof URL, typeof TextDecoder].join(",") } }
}`
	result, err := asyncRuntimeCall(t, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "undefined,undefined" {
		t.Fatalf("native globals = %q, want them absent", got)
	}
}
