package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"

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

// jqProgram returns the action's compiled expression, mirroring scriptProgram.
//
// The snapshot carries it in production. The on-demand compile is for a rule
// assembled directly in a test, which never goes through compileScriptConfig --
// the same reason scriptProgram keeps its fallback.
func jqProgram(rule ScriptRule) (*gojq.Code, error) {
	if rule.jq != nil {
		return rule.jq, nil
	}
	return compileJQProgram(rule.JQProgram)
}

// errJQBodyNotJSON reports a body a JSON filter has nothing to say about.
//
// This used to be an ordinary failure, on the reasoning that the action matched
// a path its author declared to be JSON and forwarding something else would hide
// a mismatch between the manifest's pattern and reality. Live traffic disproved
// the premise. An origin answers a JSON endpoint with a non-JSON body whenever
// it feels like it -- `404 page not found` in plain text, an HTML error page, a
// CDN block notice -- and none of that is a manifest bug. It is normal HTTP.
//
// Treating it as a failure was actively destructive, because the caller's
// response-phase exit is fail-closed: one unparseable body turned a perfectly
// good 404 from the origin into a 502 the client had no way to interpret. Ads
// cannot hide in a body that is not JSON, so there is nothing for the filter to
// do and nothing leaks by leaving it alone. Failing closed protects capture, not
// this: a transform that cannot run must not destroy what it cannot edit.
var errJQBodyNotJSON = errors.New("action body is not JSON")

// runJQ transforms one JSON document. A body that does not parse as JSON yields
// errJQBodyNotJSON, which the caller turns into a no-op rather than a failure.
//
// The body is decoded with UseNumber rather than into plain `any`, because the
// default decoding makes every JSON number a float64 and silently rounds any
// integer above 2^53 before the program ever runs. That is not a property of a
// filter: the identity program `.` corrupted a bilibili snowflake id from
// ...456068 to ...456000, re-encoded it as a well-formed number, and reported
// nothing. gojq is not the constraint -- it works on int, *big.Int and float64,
// and json.Marshal writes a *big.Int as a bare integer literal -- so the loss
// was entirely in the decode.
//
// The JavaScript path deliberately keeps the float64 behaviour. Loon runs
// JavaScript, JSON.parse is spec-bound to IEEE-754 doubles, and every published
// bundle is written against that; widening numbers there would diverge from the
// client this runtime presents as.
func runJQ(ctx context.Context, code *gojq.Code, body []byte, settings map[string]any) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var input any
	if err := decoder.Decode(&input); err != nil {
		return nil, errJQBodyNotJSON
	}
	// json.Unmarshal accepts a single value and trailing whitespace, nothing
	// else. Decode alone would accept a stream, so a body of two concatenated
	// documents would start being filtered as if it were the first one.
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errJQBodyNotJSON
	}
	input, representable := normaliseJQNumbers(input)
	if !representable {
		return nil, errJQBodyNotJSON
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

// normaliseJQNumbers replaces every json.Number in a decoded document with the
// concrete numeric type gojq operates on: an int where the value fits one, a
// *big.Int where it does not, and a float64 for anything with a fraction or an
// exponent.
//
// The false return is for a literal no numeric type can hold -- 1e400 and the
// like. It is deliberately not an error. json.Unmarshal rejected such a document
// outright, so before this change the body was already classed as unfilterable
// and forwarded untouched; reporting it now would turn a response the origin
// sent perfectly well into the 502 that the response phase produces for a failed
// action. A transform that cannot run must not destroy what it cannot edit.
//
// Converting explicitly rather than handing gojq the json.Number values it also
// accepts keeps the mapping this repository's own, and testable, instead of an
// implementation detail of the dependency.
func normaliseJQNumbers(value any) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, element := range typed {
			normalised, ok := normaliseJQNumbers(element)
			if !ok {
				return nil, false
			}
			typed[key] = normalised
		}
		return typed, true
	case []any:
		for index, element := range typed {
			normalised, ok := normaliseJQNumbers(element)
			if !ok {
				return nil, false
			}
			typed[index] = normalised
		}
		return typed, true
	case json.Number:
		// int64(int(...)) guards a 32-bit platform, where the narrowing would
		// otherwise truncate silently -- the exact failure mode this function
		// exists to remove.
		if integer, err := typed.Int64(); err == nil && int64(int(integer)) == integer {
			return int(integer), true
		}
		if wide, ok := new(big.Int).SetString(typed.String(), 10); ok {
			return wide, true
		}
		number, err := typed.Float64()
		if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
			return nil, false
		}
		return number, true
	default:
		return value, true
	}
}

// executeJQ runs a jq action against whichever message the action's phase owns.
func (r *scriptRuntime) executeJQ(
	ctx context.Context,
	module Module,
	rule ScriptRule,
	request scriptMessage,
	response *scriptMessage,
) (scriptResult, error) {
	code, err := jqProgram(rule)
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
	if errors.Is(err, errJQBodyNotJSON) {
		// Nothing to filter. Leave the message exactly as it arrived.
		return scriptResult{}, nil
	}
	if err != nil {
		return scriptResult{}, fmt.Errorf("extension %s action %s: %w", module.ID, rule.ID, err)
	}
	return scriptResult{Body: transformed, ChangedBody: true}, nil
}
