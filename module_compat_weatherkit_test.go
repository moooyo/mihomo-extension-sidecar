package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// The published WeatherKit bundle is not vendored here. Stage it next to this
// package to run this test:
//
//	curl -L -o wk-bundle.js https://github.com/NSRingo/WeatherKit/releases/download/v3.2.0-beta2/response.bundle.js
func wkRun(t *testing.T, argument map[string]any) (map[string]any, error) {
	source, err := os.ReadFile("wk-bundle.js")
	if err != nil {
		t.Skip("stage wk-bundle.js to run this")
	}
	vm := goja.New()
	loop := newAsyncLoop()
	defer loop.close()
	if err := loop.installTimerAPI(vm); err != nil {
		t.Fatal(err)
	}
	if err := installWebAPI(vm); err != nil {
		t.Fatal(err)
	}
	if err := installDOMAPI(vm); err != nil {
		t.Fatal(err)
	}
	installConsoleAPI(vm, nil, EngineLog{})
	options := compatOptions{
		request:   map[string]any{"url": "https://weatherkit.apple.com/api/v1/availability/38/-122?country=US", "method": "GET", "headers": map[string]any{}},
		response:  map[string]any{"status": 200, "headers": map[string]any{}, "body": `["currentWeather"]`},
		argument:  argument,
		startTime: time.Now(),
	}
	entry, err := installProxyCompatAPI(vm, loop, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(source)); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := loop.wait(ctx, entry.settled); err != nil {
		return nil, err
	}
	// Read back what the bundle turned $argument into.
	seen := vm.Get("$argument")
	out := map[string]any{}
	raw, _ := json.Marshal(seen.Export())
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

// Two things this pins, both of which were wrong before it was written.
//
// The bundle reads its settings from $argument only when $argument.Storage says
// so; its switch otherwise defaults to persistent storage and discards
// $argument entirely, which is what the shipped manifest was doing to all eight
// of its settings. And the bundle expands dotted keys into nested objects, so
// "Weather.Provider" has to arrive as a flat key and come out nested.
func TestWeatherKitArgumentSurvivesAsAnObject(t *testing.T) {
	argument := map[string]any{
		"Storage":          "$argument",
		"Weather.Provider": "QWeather",
		"LogLevel":         "INFO",
	}
	got, err := wkRun(t, argument)
	if err != nil {
		t.Fatalf("bundle failed: %v", err)
	}
	t.Logf("$argument after the bundle parsed it: %v", got)
	if got["Storage"] != "$argument" {
		t.Fatalf("Storage = %v; without it the bundle ignores $argument entirely", got["Storage"])
	}
	weather, _ := got["Weather"].(map[string]any)
	if weather["Provider"] != "QWeather" {
		t.Fatalf("Weather.Provider did not survive as %v", got["Weather"])
	}
	if got["LogLevel"] != "INFO" {
		t.Fatalf("LogLevel = %v", got["LogLevel"])
	}
}
