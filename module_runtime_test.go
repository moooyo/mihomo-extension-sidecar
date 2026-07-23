package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

func nativeRuntimeRule(source string, phase string, bodyMode string) ScriptRule {
	return ScriptRule{
		ID: "action", Phase: phase,
		Match:        ActionMatch{Hosts: []string{"api.example.com"}, Schemes: []string{"https"}, PathRegex: "^/"},
		ScriptDigest: digestText(source), ScriptBody: source, BodyMode: bodyMode,
		TimeoutMS: 1000, MaxBodyBytes: 1 << 20,
	}
}

func nativeRuntimeModule() Module {
	return Module{ID: "io.example.fixture", CaptureHosts: []string{"api.example.com"}}
}

func TestNativeScriptTransformsResponseFromTypedContext(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  return { response: { status: 201, headers: {"X-Mode": context.settings.mode}, body: context.response.body + "!" } }
}`
	module := nativeRuntimeModule()
	module.Settings = []ModuleSetting{{Key: "mode", Type: "text", Required: true, Value: json.RawMessage(`"clean"`)}}
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte("ok")}
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedBody || string(result.Body) != "ok!" || result.StatusCode != 201 || result.Headers.Get("X-Mode") != "clean" {
		t.Fatalf("native result = %+v", result)
	}
}

func TestNativeScriptSupportsBinaryBodies(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  const input = context.response.body
  return { response: { body: new Uint8Array([input[2], input[1], input[0]]) } }
}`
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header), Body: []byte{1, 2, 3}}
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(source, "response", "binary"), request, &response)
	if err != nil || !bytes.Equal(result.Body, []byte{3, 2, 1}) {
		t.Fatalf("binary result=%+v err=%v", result, err)
	}
}

func TestNativeScriptTransformsResponseTrailers(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  if (context.response.trailers["Grpc-Status"] !== "0") throw new Error("missing upstream trailer")
  return { response: { trailers: {"Grpc-Status": "7", "Grpc-Message": "blocked"} } }
}`
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodPost, Headers: make(http.Header)}
	response := scriptMessage{
		URL: request.URL, StatusCode: 200, Headers: make(http.Header),
		Trailers: http.Header{"Grpc-Status": {"0"}},
	}
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(source, "response", "none"), request, &response)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ChangedTrailers || result.Trailers.Get("Grpc-Status") != "7" || result.Trailers.Get("Grpc-Message") != "blocked" {
		t.Fatalf("native trailer result = %+v", result)
	}
}

func TestNativeScriptRejectsRequestAndFramingTrailers(t *testing.T) {
	t.Parallel()
	request := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodPost, Headers: make(http.Header)}
	requestRule := nativeRuntimeRule(`function transform() { return {request: {trailers: {"X-Final": "value"}}} }`, "request", "none")
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), requestRule, request, nil); err == nil {
		t.Fatal("request trailer patch was accepted")
	}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	responseTE := nativeRuntimeRule(`function transform() { return {response: {headers: {"TE": "trailers"}}} }`, "response", "none")
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), responseTE, request, &response); err == nil {
		t.Fatal("response TE header was accepted")
	}
	for _, name := range []string{"Content-Length", "Content-Type", "Authorization", "If-Match"} {
		name := name
		t.Run(name, func(t *testing.T) {
			source := fmt.Sprintf(`function transform() { return {response: {trailers: {%q: "value"}}} }`, name)
			responseRule := nativeRuntimeRule(source, "response", "none")
			if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), responseRule, request, &response); err == nil {
				t.Fatalf("forbidden trailer %q was accepted", name)
			}
		})
	}
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "NUL", value: "value\x00tail"},
		{name: "DEL", value: "value\x7ftail"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf(`function transform() { return {response: {trailers: {"X-Final": %q}}} }`, test.value)
			responseRule := nativeRuntimeRule(source, "response", "none")
			if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), responseRule, request, &response); err == nil {
				t.Fatalf("invalid trailer value %q was accepted", test.value)
			}
		})
	}
}

func TestExportedHeadersEnforceDeterministicHardLimits(t *testing.T) {
	t.Parallel()
	tooManyFields := make(map[string]any, maxScriptHeaderFields+1)
	for index := 0; index <= maxScriptHeaderFields; index++ {
		tooManyFields[fmt.Sprintf("X-Field-%03d", index)] = "value"
	}
	tooManyValues := make([]any, maxScriptHeaderValues+1)
	for index := range tooManyValues {
		tooManyValues[index] = ""
	}
	totalOverflow := make(map[string]any)
	for index := 0; index < 5; index++ {
		totalOverflow[fmt.Sprintf("X-Total-%d", index)] = strings.Repeat("x", maxScriptHeaderValueBytes)
	}
	for name, value := range map[string]any{
		"field count":      tooManyFields,
		"value count":      map[string]any{"X-Many": tooManyValues},
		"single value":     map[string]any{"X-Large": strings.Repeat("x", maxScriptHeaderValueBytes+1)},
		"total bytes":      totalOverflow,
		"duplicate casing": map[string]any{"X-Duplicate": "one", "x-duplicate": "two"},
	} {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			var first string
			for attempt := 0; attempt < 8; attempt++ {
				_, err := exportedHeaders(value)
				if err == nil {
					t.Fatal("oversized or ambiguous headers were accepted")
				}
				if attempt == 0 {
					first = err.Error()
				} else if err.Error() != first {
					t.Fatalf("nondeterministic errors: first=%q current=%q", first, err)
				}
			}
		})
	}
	if _, err := exportedTrailers(map[string]any{"Grpc-Status": "0", "grpc-status": "1"}); err == nil {
		t.Fatal("case-insensitive duplicate trailers were accepted")
	}
	headers, err := exportedHeaders(map[string]any{"X-Multi": []string{"one", "two"}})
	if err != nil || len(headers.Values("X-Multi")) != 2 {
		t.Fatalf("[]string headers=%v err=%v", headers, err)
	}
}

func TestNativeScriptRejectsAmbientNetworkAndTimesOut(t *testing.T) {
	t.Parallel()
	request := scriptMessage{URL: "https://api.example.com/v1", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	networked := `function transform() { return fetch("https://example.com/") }`
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(networked, "response", "none"), request, &response); err == nil {
		t.Fatal("ambient network API was available")
	}
	capabilityProbe := `function transform(context) { return {response: {body: typeof context.network}} }`
	result, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), nativeRuntimeRule(capabilityProbe, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "undefined" {
		t.Fatalf("undeclared network capability result=%q err=%v", result.Body, err)
	}
	timeout := nativeRuntimeRule(`function transform() { while (true) {} }`, "response", "none")
	timeout.TimeoutMS = 50
	started := time.Now()
	if _, err := newScriptRuntime().execute(context.Background(), Config{}, nil, nativeRuntimeModule(), timeout, request, &response); err == nil || time.Since(started) > time.Second {
		t.Fatalf("timeout result err=%v duration=%s", err, time.Since(started))
	}
}

func TestNativePersistentStorageRequiresManifestPermission(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	source := `function transform(context) {
  const previous = context.storage.get("counter")
  context.storage.set("counter", previous == null ? "1" : "2")
  return { response: { body: previous == null ? "empty" : previous } }
}`
	module := nativeRuntimeModule()
	module.PersistentStorage = true
	request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	first := newScriptRuntime(statePath)
	result, err := first.execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "empty" {
		t.Fatalf("first store result=%q err=%v", result.Body, err)
	}
	second := newScriptRuntime(statePath)
	result, err = second.execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response)
	if err != nil || string(result.Body) != "1" {
		t.Fatalf("persisted store result=%q err=%v", result.Body, err)
	}
	module.PersistentStorage = false
	if _, err := second.execute(context.Background(), Config{}, nil, module, nativeRuntimeRule(source, "response", "text"), request, &response); err == nil {
		t.Fatal("storage API was exposed without permission")
	}
}

func TestNativePersistentStorageSurvivesUninstallAndPermissionRevocation(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: http.StatusOK, Headers: make(http.Header)}
	module := nativeRuntimeModule()
	module.PersistentStorage = true
	writeRule := nativeRuntimeRule(`function transform(context) {
  if (!context.storage.set("token", "retained")) throw new Error("store failed")
  return null
}`, "response", "none")
	runtime := newScriptRuntime(statePath)
	if _, err := runtime.execute(context.Background(), Config{}, nil, module, writeRule, request, &response); err != nil {
		t.Fatal(err)
	}

	// Removing the extension leaves its operator-owned storage file untouched.
	revokedRuntime := newScriptRuntime(statePath)
	revokedModule := module
	revokedModule.PersistentStorage = false
	probeRule := nativeRuntimeRule(`function transform(context) {
  return {response: {body: typeof context.storage}}
}`, "response", "text")
	probe, err := revokedRuntime.execute(context.Background(), Config{}, nil, revokedModule, probeRule, request, &response)
	if err != nil || string(probe.Body) != "undefined" {
		t.Fatalf("revoked storage capability result=%q err=%v", probe.Body, err)
	}

	reinstalledRuntime := newScriptRuntime(statePath)
	readAndClearRule := nativeRuntimeRule(`function transform(context) {
  const value = context.storage.get("token")
  const cleared = context.storage.clear()
  return {response: {body: value + ":" + cleared}}
}`, "response", "text")
	retained, err := reinstalledRuntime.execute(
		context.Background(), Config{}, nil, module, readAndClearRule, request, &response,
	)
	if err != nil || string(retained.Body) != "retained:true" {
		t.Fatalf("reinstalled storage result=%q err=%v", retained.Body, err)
	}

	afterClearRuntime := newScriptRuntime(statePath)
	readRule := nativeRuntimeRule(`function transform(context) {
  const value = context.storage.get("token")
  return {response: {body: value == null ? "empty" : value}}
}`, "response", "text")
	cleared, err := afterClearRuntime.execute(context.Background(), Config{}, nil, module, readRule, request, &response)
	if err != nil || string(cleared.Body) != "empty" {
		t.Fatalf("cleared storage result=%q err=%v", cleared.Body, err)
	}
}

func TestNativeStorageNoOpsAndSaveFailuresPreserveMemoryState(t *testing.T) {
	t.Parallel()
	blockedParent := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blockedParent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := newScriptRuntime()
	runtime.statePath = filepath.Join(blockedParent, "store.json")
	moduleID := "io.example.fixture"
	seed := &persistentSnapshot{modules: map[string]map[string]string{
		moduleID: {"key": "value"},
	}}
	runtime.persistent.Store(seed)
	vm := goja.New()
	storage := runtime.storageObject(vm, moduleID)

	if !callStorageBoolean(t, storage, "set", vm.ToValue("key"), vm.ToValue("value")) {
		t.Fatal("setting an unchanged value did not succeed as a no-op")
	}
	if callStorageBoolean(t, storage, "delete", vm.ToValue("missing")) {
		t.Fatal("deleting a missing key did not return false")
	}
	if callStorageBoolean(t, storage, "set", vm.ToValue("key"), vm.ToValue("changed")) {
		t.Fatal("changed value was reported persisted through an unwritable path")
	}
	if runtime.persistent.Load() != seed || runtime.persistent.Load().modules[moduleID]["key"] != "value" {
		t.Fatal("failed set did not restore the previous value")
	}
	if callStorageBoolean(t, storage, "delete", vm.ToValue("key")) {
		t.Fatal("delete was reported persisted through an unwritable path")
	}
	if runtime.persistent.Load() != seed || runtime.persistent.Load().modules[moduleID]["key"] != "value" {
		t.Fatal("failed delete did not restore the previous value")
	}
	if callStorageBoolean(t, storage, "clear") {
		t.Fatal("clear was reported persisted through an unwritable path")
	}
	if runtime.persistent.Load() != seed || runtime.persistent.Load().modules[moduleID]["key"] != "value" {
		t.Fatal("failed clear did not restore the module bucket")
	}

	emptyModuleID := "io.example.empty"
	emptyStorage := runtime.storageObject(vm, emptyModuleID)
	if !callStorageBoolean(t, emptyStorage, "clear") {
		t.Fatal("clearing missing storage did not succeed as a no-op")
	}
	if callStorageBoolean(t, emptyStorage, "set", vm.ToValue("key"), vm.ToValue("value")) {
		t.Fatal("new value was reported persisted through an unwritable path")
	}
	if _, exists := runtime.persistent.Load().modules[emptyModuleID]; exists {
		t.Fatal("failed first set retained an empty module bucket")
	}
}

func TestNativeStorageGetDoesNotBlockDuringPersistence(t *testing.T) {
	t.Parallel()
	moduleID := "io.example.fixture"
	runtime := newScriptRuntime()
	seed := &persistentSnapshot{modules: map[string]map[string]string{
		moduleID: {"key": "old"},
	}}
	runtime.persistent.Store(seed)
	persistEntered := make(chan struct{})
	releasePersist := make(chan struct{})
	runtime.persistPersistent = func(*persistentSnapshot) error {
		close(persistEntered)
		<-releasePersist
		return nil
	}

	writerVM := goja.New()
	writerStorage := runtime.storageObject(writerVM, moduleID)
	writeResult := make(chan struct {
		ok  bool
		err error
	}, 1)
	go func() {
		ok, err := invokeStorageBoolean(writerStorage, "set", writerVM.ToValue("key"), writerVM.ToValue("new"))
		writeResult <- struct {
			ok  bool
			err error
		}{ok: ok, err: err}
	}()
	<-persistEntered

	readerVM := goja.New()
	readerStorage := runtime.storageObject(readerVM, moduleID)
	readResult := make(chan struct {
		value string
		err   error
	}, 1)
	go func() {
		call, ok := goja.AssertFunction(readerStorage.Get("get"))
		if !ok {
			readResult <- struct {
				value string
				err   error
			}{err: errors.New("storage.get is not callable")}
			return
		}
		value, err := call(readerStorage, readerVM.ToValue("key"))
		readResult <- struct {
			value string
			err   error
		}{value: value.String(), err: err}
	}()

	select {
	case result := <-readResult:
		if result.err != nil || result.value != "old" {
			close(releasePersist)
			t.Fatalf("read during persistence value=%q err=%v", result.value, result.err)
		}
	case <-time.After(time.Second):
		close(releasePersist)
		t.Fatal("storage.get blocked behind persistence")
	}
	if runtime.persistent.Load() != seed {
		close(releasePersist)
		t.Fatal("candidate snapshot was published before persistence completed")
	}
	close(releasePersist)
	result := <-writeResult
	if result.err != nil || !result.ok {
		t.Fatalf("storage.set result=%t err=%v", result.ok, result.err)
	}
	if got := runtime.persistent.Load().modules[moduleID]["key"]; got != "new" {
		t.Fatalf("published value = %q", got)
	}
}

func TestNativeStorageConcurrentWritesAreNotLost(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	runtime := newScriptRuntime(statePath)
	const writes = 32
	start := make(chan struct{})
	results := make(chan error, writes)
	var workers sync.WaitGroup
	for index := 0; index < writes; index++ {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			vm := goja.New()
			moduleID := fmt.Sprintf("io.example.concurrent%d", index%2)
			storage := runtime.storageObject(vm, moduleID)
			<-start
			ok, err := invokeStorageBoolean(
				storage, "set", vm.ToValue(fmt.Sprintf("key-%02d", index)), vm.ToValue(fmt.Sprintf("value-%02d", index)),
			)
			if err != nil {
				results <- err
				return
			}
			if !ok {
				results <- fmt.Errorf("write %d returned false", index)
				return
			}
			results <- nil
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}

	reloaded := newScriptRuntime(statePath)
	if reloaded.persistentLoadErr != nil {
		t.Fatalf("reloading persisted state: %v", reloaded.persistentLoadErr)
	}
	for index := 0; index < writes; index++ {
		moduleID := fmt.Sprintf("io.example.concurrent%d", index%2)
		key := fmt.Sprintf("key-%02d", index)
		want := fmt.Sprintf("value-%02d", index)
		if got := runtime.persistent.Load().modules[moduleID][key]; got != want {
			t.Fatalf("live %s/%s = %q, want %q", moduleID, key, got, want)
		}
		if got := reloaded.persistent.Load().modules[moduleID][key]; got != want {
			t.Fatalf("reloaded %s/%s = %q, want %q", moduleID, key, got, want)
		}
	}
}

func TestNativeStorageInvalidExistingStateFailsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "null", body: []byte("null")},
		{name: "corrupt", body: []byte(`{"io.example.fixture":`)},
		{name: "null module bucket", body: []byte(`{"io.example.fixture":null}`)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			statePath := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(statePath, test.body, 0o600); err != nil {
				t.Fatal(err)
			}
			runtime := newScriptRuntime(statePath)
			if runtime.persistentLoadErr == nil {
				t.Fatal("invalid existing store did not disable mutations")
			}
			vm := goja.New()
			storage := runtime.storageObject(vm, "io.example.fixture")
			if callStorageBoolean(t, storage, "set", vm.ToValue("key"), vm.ToValue("value")) {
				t.Fatal("invalid existing store was overwritten by set")
			}
			if callStorageBoolean(t, storage, "clear") {
				t.Fatal("invalid existing store was overwritten by clear")
			}
			got, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.body) {
				t.Fatalf("invalid store changed from %q to %q", test.body, got)
			}
		})
	}
}

func TestNativeStorageOversizedExistingStateFailsClosed(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	file, err := os.Create(statePath)
	if err != nil {
		t.Fatal(err)
	}
	wantSize := int64(maxPersistentStoreBytes) * 4
	if err := file.Truncate(wantSize); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	runtime := newScriptRuntime(statePath)
	if runtime.persistentLoadErr == nil || !strings.Contains(runtime.persistentLoadErr.Error(), "exceeds 4194304 bytes") {
		t.Fatalf("oversized existing store error = %v", runtime.persistentLoadErr)
	}
	vm := goja.New()
	storage := runtime.storageObject(vm, "io.example.fixture")
	if callStorageBoolean(t, storage, "set", vm.ToValue("key"), vm.ToValue("value")) {
		t.Fatal("oversized existing store accepted a mutation")
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != wantSize {
		t.Fatalf("oversized existing store size = %d, want %d", info.Size(), wantSize)
	}
}

func TestNativeStorageInvalidUTF8FailsClosed(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	body := append([]byte(`{"io.example.fixture":{"key":"`), 0xff)
	body = append(body, []byte(`"}}`)...)
	if utf8.Valid(body) {
		t.Fatal("test fixture is valid UTF-8")
	}
	if err := os.WriteFile(statePath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	runtime := newScriptRuntime(statePath)
	if runtime.persistentLoadErr == nil || !strings.Contains(runtime.persistentLoadErr.Error(), "not valid UTF-8") {
		t.Fatalf("invalid UTF-8 store error = %v", runtime.persistentLoadErr)
	}
	vm := goja.New()
	storage := runtime.storageObject(vm, "io.example.fixture")
	if callStorageBoolean(t, storage, "set", vm.ToValue("key"), vm.ToValue("value")) {
		t.Fatal("invalid UTF-8 store accepted a mutation")
	}
	got, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("invalid UTF-8 store changed after rejected mutation")
	}
}

func TestNativeStorageUnreadableExistingPathFailsClosed(t *testing.T) {
	t.Parallel()
	statePath := t.TempDir()
	runtime := newScriptRuntime(statePath)
	if runtime.persistentLoadErr == nil {
		t.Fatal("unreadable existing path did not disable mutations")
	}
	vm := goja.New()
	storage := runtime.storageObject(vm, "io.example.fixture")
	if callStorageBoolean(t, storage, "set", vm.ToValue("key"), vm.ToValue("value")) {
		t.Fatal("unreadable existing path accepted a mutation")
	}
	if info, err := os.Stat(statePath); err != nil || !info.IsDir() {
		t.Fatalf("unreadable path was replaced: info=%v err=%v", info, err)
	}
}

func TestNativeStorageOversizeCandidateDoesNotPublish(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "store.json")
	runtime := newScriptRuntime(statePath)
	seed := persistentFillerSnapshot(63)
	seedBody, err := marshalPersistentSnapshot(seed)
	if err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	if err := runtime.savePersistent(seed); err != nil {
		t.Fatal(err)
	}
	runtime.persistent.Store(seed)

	candidateModules := clonePersistentModules(seed.modules)
	candidateModules["io.example.overflow"] = map[string]string{"payload": strings.Repeat("x", maxPersistentValueBytes)}
	candidateBody, err := json.Marshal(candidateModules)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidateBody) <= maxPersistentStoreBytes {
		t.Fatalf("test candidate is only %d bytes", len(candidateBody))
	}

	vm := goja.New()
	storage := runtime.storageObject(vm, "io.example.overflow")
	if callStorageBoolean(t, storage, "set", vm.ToValue("payload"), vm.ToValue(strings.Repeat("x", maxPersistentValueBytes))) {
		t.Fatal("oversize candidate was accepted")
	}
	if runtime.persistent.Load() != seed {
		t.Fatal("oversize candidate was published")
	}
	got, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, seedBody) {
		t.Fatal("oversize candidate changed the persisted file")
	}
}

func TestNativeStorageKeyLimitAllowsExistingUpdates(t *testing.T) {
	t.Parallel()
	moduleID := "io.example.fixture"
	bucket := make(map[string]string, maxPersistentKeys)
	for index := 0; index < maxPersistentKeys; index++ {
		bucket[fmt.Sprintf("key-%03d", index)] = "old"
	}
	runtime := newScriptRuntime()
	runtime.persistent.Store(&persistentSnapshot{modules: map[string]map[string]string{moduleID: bucket}})
	vm := goja.New()
	storage := runtime.storageObject(vm, moduleID)
	if !callStorageBoolean(t, storage, "set", vm.ToValue("key-000"), vm.ToValue("new")) {
		t.Fatal("updating an existing key at the key limit failed")
	}
	if callStorageBoolean(t, storage, "set", vm.ToValue("overflow"), vm.ToValue("value")) {
		t.Fatal("adding a key beyond the key limit succeeded")
	}
	if got := runtime.persistent.Load().modules[moduleID]["key-000"]; got != "new" {
		t.Fatalf("updated value = %q", got)
	}
}

func persistentFillerSnapshot(count int) *persistentSnapshot {
	modules := make(map[string]map[string]string, count+1)
	payload := strings.Repeat("x", maxPersistentValueBytes)
	for index := 0; index < count; index++ {
		modules[fmt.Sprintf("io.example.filler%03d", index)] = map[string]string{"payload": payload}
	}
	modules["io.example.benchmark"] = map[string]string{"target": "0"}
	return &persistentSnapshot{modules: modules}
}

func invokeStorageBoolean(storage *goja.Object, method string, arguments ...goja.Value) (bool, error) {
	call, ok := goja.AssertFunction(storage.Get(method))
	if !ok {
		return false, fmt.Errorf("storage.%s is not callable", method)
	}
	value, err := call(storage, arguments...)
	if err != nil {
		return false, err
	}
	return value.ToBoolean(), nil
}

func callStorageBoolean(t *testing.T, storage *goja.Object, method string, arguments ...goja.Value) bool {
	t.Helper()
	value, err := invokeStorageBoolean(storage, method, arguments...)
	if err != nil {
		t.Fatalf("storage.%s failed: %v", method, err)
	}
	return value
}

func BenchmarkNativeStorageGet(b *testing.B) {
	moduleID := "io.example.benchmark"
	runtime := newScriptRuntime()
	runtime.persistent.Store(&persistentSnapshot{modules: map[string]map[string]string{
		moduleID: {"key": "value"},
	}})
	b.Run("serial", func(b *testing.B) {
		vm := goja.New()
		storage := runtime.storageObject(vm, moduleID)
		call, ok := goja.AssertFunction(storage.Get("get"))
		if !ok {
			b.Fatal("storage.get is not callable")
		}
		key := vm.ToValue("key")
		b.ReportAllocs()
		b.ResetTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			value, err := call(storage, key)
			if err != nil || value.String() != "value" {
				b.Fatalf("storage.get value=%v err=%v", value, err)
			}
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(worker *testing.PB) {
			vm := goja.New()
			storage := runtime.storageObject(vm, moduleID)
			call, ok := goja.AssertFunction(storage.Get("get"))
			if !ok {
				b.Error("storage.get is not callable")
				return
			}
			key := vm.ToValue("key")
			for worker.Next() {
				value, err := call(storage, key)
				if err != nil || value.String() != "value" {
					b.Errorf("storage.get value=%v err=%v", value, err)
					return
				}
			}
		})
	})
}

func BenchmarkNativeStorageMutationEncoding(b *testing.B) {
	for _, test := range []struct {
		name    string
		fillers int
	}{
		{name: "empty", fillers: 0},
		{name: "one-megabyte", fillers: 16},
		{name: "near-four-megabytes", fillers: 63},
	} {
		test := test
		b.Run(test.name, func(b *testing.B) {
			runtime := newScriptRuntime()
			seed := persistentFillerSnapshot(test.fillers)
			runtime.persistent.Store(seed)
			body, err := marshalPersistentSnapshot(seed)
			if err != nil {
				b.Fatal(err)
			}
			runtime.persistPersistent = func(snapshot *persistentSnapshot) error {
				_, err := marshalPersistentSnapshot(snapshot)
				return err
			}
			vm := goja.New()
			storage := runtime.storageObject(vm, "io.example.benchmark")
			call, ok := goja.AssertFunction(storage.Get("set"))
			if !ok {
				b.Fatal("storage.set is not callable")
			}
			key := vm.ToValue("target")
			values := []goja.Value{vm.ToValue("1"), vm.ToValue("0")}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				value, err := call(storage, key, values[iteration%len(values)])
				if err != nil || !value.ToBoolean() {
					b.Fatalf("storage.set value=%v err=%v", value, err)
				}
			}
		})
	}
}

func TestCompiledScriptSettingsAreClonedPerAction(t *testing.T) {
	t.Parallel()
	source := `function transform(context) {
  const before = context.settings.location.longitude + ":" + context.settings.mode
  context.settings.location.longitude = 0
  context.settings.mode = "mutated"
  return {response: {body: before}}
}`
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Settings = []ModuleSetting{
		{Key: "mode", Type: "text", Value: json.RawMessage(`"clean"`)},
		{Key: "location", Type: "location", Value: json.RawMessage(`{"longitude":113.9,"latitude":22.5,"accuracy":25}`)},
	}
	module.Scripts = []ScriptRule{nativeRuntimeRule(source, "response", "text")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	compiled, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = compiled
	request := scriptMessage{URL: "https://api.example.com/", Headers: make(http.Header)}
	response := scriptMessage{URL: request.URL, StatusCode: 200, Headers: make(http.Header)}
	matched := matchingScriptRules(cfg, "response", response)
	if len(matched) != 1 || matched[0].Rule.program == nil || matched[0].Rule.settings == nil {
		t.Fatalf("compiled action metadata = %+v", matched)
	}
	runtime := newScriptRuntime()
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runtime.execute(context.Background(), cfg, nil, matched[0].Module, matched[0].Rule, request, &response)
		if err != nil || string(result.Body) != "113.9:clean" {
			t.Fatalf("attempt %d result=%q err=%v", attempt, result.Body, err)
		}
	}
}

func TestCompiledScriptRuleUsesRetainedProgram(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return null }`, "response", "none")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	compiled, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = compiled
	message := scriptMessage{URL: "https://api.example.com/", StatusCode: 200, Headers: make(http.Header)}
	matched := matchingScriptRules(cfg, "response", message)
	if len(matched) != 1 || matched[0].Rule.program == nil {
		t.Fatal("compiled action has no retained program")
	}
	matched[0].Rule.ScriptBody = `function (`
	if _, err := newScriptRuntime().execute(context.Background(), cfg, nil, matched[0].Module, matched[0].Rule, message, &message); err != nil {
		t.Fatalf("retained program was not used: %v", err)
	}
}

func TestNativeActionMatchingIsScopedToExtensionCaptureHosts(t *testing.T) {
	t.Parallel()
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return null }`, "response", "none")}
	cfg := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	runtime, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = runtime
	inside := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	outside := scriptMessage{URL: "https://other.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	if len(matchingScriptRules(cfg, "response", inside)) != 1 || len(matchingScriptRules(cfg, "response", outside)) != 0 {
		t.Fatal("native action escaped its extension capture host boundary")
	}
}

func TestNativeActionMatchingUsesTopLevelExecutionOrderForBothPhases(t *testing.T) {
	t.Parallel()
	first := nativeRuntimeModule()
	first.ID = "io.example.first"
	first.Enabled = true
	first.Scripts = []ScriptRule{
		nativeRuntimeRule(`function transform() { return null }`, "request", "none"),
		nativeRuntimeRule(`function transform() { return null }`, "response", "none"),
	}
	first.Scripts[0].ID = "first-request"
	first.Scripts[1].ID = "first-response"
	second := nativeRuntimeModule()
	second.ID = "io.example.second"
	second.Enabled = true
	second.Scripts = []ScriptRule{
		nativeRuntimeRule(`function transform() { return null }`, "request", "none"),
		nativeRuntimeRule(`function transform() { return null }`, "response", "none"),
	}
	second.Scripts[0].ID = "second-request"
	second.Scripts[1].ID = "second-response"
	cfg := Config{
		Modules:        []Module{first, second},
		ExecutionOrder: []string{second.ID, first.ID},
	}
	runtime, err := compileScriptConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.runtime = runtime
	message := scriptMessage{URL: "https://api.example.com/v1", Method: http.MethodGet, StatusCode: 200}
	for _, phase := range []string{"request", "response"} {
		matched := matchingScriptRules(cfg, phase, message)
		if len(matched) != 2 || matched[0].Module.ID != second.ID || matched[1].Module.ID != first.ID {
			t.Fatalf("%s order = %+v", phase, matched)
		}
	}
}

var benchmarkMatchedScriptRules []matchedScriptRule

func BenchmarkMatchingScriptRulesCompiledConfig(b *testing.B) {
	module := nativeRuntimeModule()
	module.Enabled = true
	module.Scripts = make([]ScriptRule, 256)
	for index := range module.Scripts {
		rule := nativeRuntimeRule(`function transform() { return null }`, "response", "none")
		rule.ID = fmt.Sprintf("action-%03d", index)
		rule.Match.PathRegex = fmt.Sprintf("^/path-%03d$", index)
		module.Scripts[index] = rule
	}
	base := Config{Modules: []Module{module}, ExecutionOrder: []string{module.ID}}
	compiled, err := compileScriptConfig(base)
	if err != nil {
		b.Fatal(err)
	}
	message := scriptMessage{URL: "https://api.example.com/miss", Method: http.MethodGet, StatusCode: 200}
	for _, test := range []struct {
		name     string
		compiled bool
	}{
		{name: "compiled", compiled: true},
		{name: "fallback-compile", compiled: false},
	} {
		b.Run(test.name, func(b *testing.B) {
			cfg := base
			if test.compiled {
				cfg.runtime = compiled
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				benchmarkMatchedScriptRules = matchingScriptRules(cfg, "response", message)
			}
		})
	}
}

var benchmarkHostMatched bool

func BenchmarkCompiledCaptureHostMatchers(b *testing.B) {
	activeModule := nativeRuntimeModule()
	activeModule.Enabled = true
	activeModule.CaptureHosts = make([]string, 280)
	for index := range activeModule.CaptureHosts {
		activeModule.CaptureHosts[index] = fmt.Sprintf("*.h%03d.example.com", index)
	}
	activeCfg := Config{
		MITM: MITMSettings{Enabled: true}, Modules: []Module{activeModule}, ExecutionOrder: []string{activeModule.ID},
	}
	activeRuntime, err := compileScriptConfig(activeCfg)
	if err != nil {
		b.Fatal(err)
	}
	activeCfg.runtime = activeRuntime

	ruleModule := nativeRuntimeModule()
	ruleModule.Enabled = true
	ruleModule.CaptureHosts = []string{"*.example.com"}
	ruleModule.Scripts = []ScriptRule{nativeRuntimeRule(`function transform() { return null }`, "response", "none")}
	ruleModule.Scripts[0].Match.Hosts = make([]string, 259)
	for index := range ruleModule.Scripts[0].Match.Hosts {
		ruleModule.Scripts[0].Match.Hosts[index] = fmt.Sprintf("r%03d.example.com", index)
	}
	ruleCfg := Config{Modules: []Module{ruleModule}, ExecutionOrder: []string{ruleModule.ID}}
	ruleRuntime, err := compileScriptConfig(ruleCfg)
	if err != nil {
		b.Fatal(err)
	}
	ruleCfg.runtime = ruleRuntime
	for _, test := range []struct {
		name string
		run  func()
	}{
		{name: "active-wildcard-last", run: func() {
			benchmarkHostMatched = activeInterceptHost(activeCfg, "api.h279.example.com")
		}},
		{name: "rule-exact-last", run: func() {
			benchmarkMatchedScriptRules = matchingScriptRules(ruleCfg, "response", scriptMessage{
				URL: "https://r258.example.com/", Method: http.MethodGet, StatusCode: 200,
			})
		}},
		{name: "rule-exact-miss", run: func() {
			benchmarkMatchedScriptRules = matchingScriptRules(ruleCfg, "response", scriptMessage{
				URL: "https://other.example.com/", Method: http.MethodGet, StatusCode: 200,
			})
		}},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				test.run()
			}
		})
	}
}
