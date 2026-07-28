package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/itchyny/gojq"
)

// A jq action carries an upstream module's own `response-body-json-jq`
// expression instead of a hand-written script that reimplements it. That is the
// point: the published modules express most of their JSON cleanup declaratively,
// and translating each expression into JavaScript was a per-rule review burden
// that produced code this repository then had to own and test.
//
// A jq action never enters the JavaScript runtime at all. No VM, no event loop,
// no proxy-client globals: the body is decoded, transformed, and re-encoded.
const (
	maxJQProgramBytes = 32768
	maxJQOutputBytes  = 64 << 20
)

// jqSettingsVariable exposes the action's decoded settings to the program.
// Without it a jq action cannot depend on operator choices at all, which is
// what kept the TestFlight storefront rewrite in JavaScript: its replacement
// value comes from a setting.
const jqSettingsVariable = "$settings"

func compileJQProgram(program string) (*gojq.Code, error) {
	if len(program) > maxJQProgramBytes {
		return nil, fmt.Errorf("jq program exceeds %d bytes", maxJQProgramBytes)
	}
	parsed, err := gojq.Parse(program)
	if err != nil {
		return nil, fmt.Errorf("parse jq program: %w", err)
	}
	code, err := gojq.Compile(parsed, gojq.WithVariables([]string{jqSettingsVariable}))
	if err != nil {
		return nil, fmt.Errorf("compile jq program: %w", err)
	}
	return code, nil
}

// runJQ transforms one JSON document. A body that is not JSON is an error
// rather than a pass-through: the action matched a path its author declared to
// be JSON, and silently forwarding something else would hide a a mismatch
// between the manifest's pattern and reality.
func runJQ(ctx context.Context, code *gojq.Code, body []byte, settings map[string]any) ([]byte, error) {
	var input any
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, fmt.Errorf("action body is not JSON: %w", err)
	}
	if settings == nil {
		settings = map[string]any{}
	}
	iterator := code.RunWithContext(ctx, input, settings)
	// Only the first output is used. Every published rule this supports is
	// single-output; taking the first keeps a program that unexpectedly streams
	// from concatenating documents into one malformed body.
	value, ok := iterator.Next()
	if !ok {
		return nil, errors.New("jq program produced no output")
	}
	if err, isError := value.(error); isError {
		var halt *gojq.HaltError
		if errors.As(err, &halt) && halt.Value() == nil {
			return nil, errors.New("jq program halted")
		}
		return nil, fmt.Errorf("jq program failed: %w", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("jq output could not be encoded: %w", err)
	}
	if len(encoded) > maxJQOutputBytes {
		return nil, fmt.Errorf("jq output exceeds %d bytes", maxJQOutputBytes)
	}
	return encoded, nil
}

// executeJQ runs a jq action against whichever message the action's phase owns.
func (r *scriptRuntime) executeJQ(
	ctx context.Context,
	module Module,
	rule ScriptRule,
	request scriptMessage,
	response *scriptMessage,
) (scriptResult, error) {
	code, err := r.jqCode(module, rule)
	if err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	body := request.Body
	if rule.Phase == "response" {
		if response == nil {
			return scriptResult{}, fmt.Errorf("extension %s action %s: no response to transform", module.ID, rule.ID)
		}
		body = response.Body
	}
	settings, err := scriptSettingValues(module, rule)
	if err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	transformed, err := runJQ(ctx, code, body, settings)
	if err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	return scriptResult{Body: transformed, ChangedBody: true}, nil
}
