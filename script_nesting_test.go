package main

import (
	"strings"
	"testing"
)

// goja's parser is recursive descent with no depth limit, and roughly a
// kilobyte of goroutine stack per source byte of `(((...`. Around 500 KB -- half
// what a script snapshot is allowed -- exhausts Go's 1 GB goroutine stack and
// raises `fatal error: stack overflow`, which is a runtime throw no recover()
// can catch. Every publication path compiles third-party script text in the
// running proxy, so this has to be refused before the parser is entered.
//
// The depth here is well past the bound and far below the crash threshold, so
// the test proves the refusal without spending half a gigabyte to do it.
func TestDeeplyNestedScriptIsRefusedBeforeItReachesTheParser(t *testing.T) {
	depth := maxScriptNestingDepth + 1
	source := strings.Repeat("(", depth) + "1" + strings.Repeat(")", depth)
	err := checkScriptNesting(source)
	if err == nil {
		t.Fatal("a script nested past the bound was accepted; goja would take it to a fatal stack overflow")
	}
	if !strings.Contains(err.Error(), "nests") {
		t.Fatalf("refusal did not name the nesting: %v", err)
	}

	// Brackets and braces recurse through the same parser.
	for _, pair := range []struct{ open, close string }{{"[", "]"}, {"{", "}"}} {
		nested := strings.Repeat(pair.open, depth) + strings.Repeat(pair.close, depth)
		if err := checkScriptNesting(nested); err == nil {
			t.Fatalf("%s nested past the bound was accepted", pair.open)
		}
	}

	// A prefix run reserved 512 MiB in measurement without any bracket at all.
	if err := checkScriptNesting(strings.Repeat("!", depth) + "x"); err == nil {
		t.Fatal("an unbounded prefix-operator run was accepted")
	}
}

// The bound must not reject the scripts the catalogue actually ships. Brackets
// inside strings, template literals, comments and regular expressions are not
// nesting, and counting them would refuse ordinary code.
func TestOrdinaryScriptsPassTheNestingBound(t *testing.T) {
	sources := map[string]string{
		"catalogue shape": `function transform(context) {
			const body = JSON.parse(context.response.body)
			if (body && Array.isArray(body.items)) {
				body.items = body.items.filter((item) => !item.ad && item.kind !== "promo")
			}
			return { response: { body: JSON.stringify(body) } }
		}`,
		"unbalanced brackets in strings": `const a = "(((((((" + '[[[[[[[' + "}}}}}}}"; transform = () => null`,
		"template with interpolation":    "const t = `a${ ( 1 + 2 ) }b${ `${inner}` }c`",
		"regex with brackets":            `const re = /^[({[]+/g; const other = a / b / c`,
		"comments with brackets":         "// ((((((((\n/* [[[[[[[[ */ const x = 1",
		"division after call":            `const ratio = f(1) / g(2) / h(3)`,
		"arithmetic is not a prefix run": `const n = 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9`,
	}
	for name, source := range sources {
		if err := checkScriptNesting(source); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}

	// And the depth an ordinary script reaches is nowhere near the bound, so the
	// bound has headroom rather than sitting on top of real usage.
	deep := strings.Repeat("(", maxScriptNestingDepth) + "1" + strings.Repeat(")", maxScriptNestingDepth)
	if err := checkScriptNesting(deep); err != nil {
		t.Errorf("exactly the permitted depth was refused: %v", err)
	}
}

// The whole point is that the refusal happens in the product's validator, not
// only in the helper: a hostile snapshot must be rejected by the same call the
// control API's bundle Stage makes.
func TestValidateRefusesADeeplyNestedScriptSnapshot(t *testing.T) {
	depth := maxScriptNestingDepth + 1
	source := strings.Repeat("(", depth) + "1" + strings.Repeat(")", depth)

	cfg := validNativeConfig()
	cfg.Modules[0].Scripts[0].ScriptBody = source
	cfg.Modules[0].Scripts[0].ScriptDigest = digestText(source)
	cfg.Modules[0].Scripts[0].JQProgram = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("the validator accepted a script that would crash the parser")
	}
	if !strings.Contains(err.Error(), "nests") {
		t.Fatalf("validator refusal did not name the nesting: %v", err)
	}
}
