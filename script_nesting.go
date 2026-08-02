package main

import "fmt"

// maxScriptNestingDepth bounds bracket nesting and unary-prefix runs in a
// snapshotted script.
//
// 256 is far above anything a hand-written or minified extension produces --
// V8 and JavaScriptCore refuse in the same order of magnitude -- and at that
// depth goja's parser reserves roughly half a megabyte of goroutine stack,
// which is a cost rather than a hazard.
const maxScriptNestingDepth = 256

// checkScriptNesting rejects source that would drive goja's parser into a stack
// overflow, before the parser ever sees it.
//
// goja.Compile is recursive descent with no depth limit, and each nesting level
// costs about 2 KiB of goroutine stack -- roughly a kilobyte of stack per source
// byte for `(((...`. Go's default 1 GB goroutine stack is therefore exhausted by
// about 500 KB of nesting, which is under half the 1 MiB a script snapshot is
// already allowed. The result is `fatal error: stack overflow`, a runtime throw
// that no recover() can catch: the process dies.
//
// That matters here rather than in some offline linter because every
// publication path compiles third-party script text inside the running proxy --
// the control API's bundle Stage, and the config reload behind Current() -- and
// because a disabled extension's scripts are compiled too, so declining to
// enable one is not a defence.
//
// The scan only has to bound depth, so it does not need to be a JavaScript
// lexer. It skips comments, string and template literals, and regular
// expressions, because miscounting brackets inside those would reject ordinary
// code. Where the `/` ambiguity cannot be resolved it assumes division, which
// counts the following bytes as code: that can overcount a regex containing
// unbalanced brackets, and overcounting only ever rejects.
func checkScriptNesting(source string) error {
	depth, deepest := 0, 0
	unary, longestUnary := 0, 0
	// Each open template literal remembers the bracket depth it began at, so a
	// closing brace inside `${...}` returns to template text rather than to code.
	var templates []int
	// A `/` starts a regular expression only where a value may begin. After a
	// value -- an identifier, literal, `)` or `]` -- it is division.
	regexAllowed := true

	index := 0
	for index < len(source) {
		char := source[index]

		if len(templates) > 0 && depth == templates[len(templates)-1] {
			// Inside template text: consume until the literal ends or an
			// interpolation opens.
			switch char {
			case '\\':
				index += 2
				continue
			case '`':
				templates = templates[:len(templates)-1]
				index++
				regexAllowed = false
				continue
			case '$':
				if index+1 < len(source) && source[index+1] == '{' {
					depth++
					if depth > deepest {
						deepest = depth
					}
					index += 2
					regexAllowed = true
					continue
				}
			}
			index++
			continue
		}

		switch char {
		case ' ', '\t', '\r', '\n':
			index++
			continue
		case '/':
			if index+1 < len(source) && source[index+1] == '/' {
				for index < len(source) && source[index] != '\n' {
					index++
				}
				continue
			}
			if index+1 < len(source) && source[index+1] == '*' {
				index += 2
				for index+1 < len(source) && !(source[index] == '*' && source[index+1] == '/') {
					index++
				}
				index += 2
				continue
			}
			if regexAllowed {
				index = skipRegexLiteral(source, index)
				regexAllowed = false
				unary = 0
				continue
			}
			index++
			regexAllowed = true
			unary = 0
			continue
		case '\'', '"':
			index = skipQuoted(source, index, char)
			regexAllowed = false
			unary = 0
			continue
		case '`':
			templates = append(templates, depth)
			index++
			continue
		case '(', '[', '{':
			depth++
			if depth > deepest {
				deepest = depth
			}
			index++
			regexAllowed = true
			unary = 0
			continue
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
			index++
			regexAllowed = false
			unary = 0
			continue
		case '!', '~':
			unary++
			if unary > longestUnary {
				longestUnary = unary
			}
			index++
			regexAllowed = true
			continue
		case '+', '-':
			// Only a prefix run counts; `a + b` resets on the operand.
			unary++
			if unary > longestUnary {
				longestUnary = unary
			}
			index++
			regexAllowed = true
			continue
		default:
			if isValueEnd(char) {
				regexAllowed = false
			} else {
				regexAllowed = true
			}
			unary = 0
			index++
			continue
		}
	}

	if deepest > maxScriptNestingDepth {
		return fmt.Errorf("script nests %d levels deep, at most %d are allowed", deepest, maxScriptNestingDepth)
	}
	if longestUnary > maxScriptNestingDepth {
		return fmt.Errorf("script chains %d prefix operators, at most %d are allowed", longestUnary, maxScriptNestingDepth)
	}
	return nil
}

func isValueEnd(char byte) bool {
	switch {
	case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		return true
	case char == '_', char == '$':
		return true
	}
	return false
}

func skipQuoted(source string, index int, quote byte) int {
	index++
	for index < len(source) {
		switch source[index] {
		case '\\':
			index += 2
			continue
		case quote:
			return index + 1
		case '\n':
			// Unterminated: goja will reject it, and continuing as code keeps
			// the scan from swallowing the rest of the source.
			return index + 1
		}
		index++
	}
	return index
}

// skipRegexLiteral consumes /.../flags, honouring escapes and character classes
// so that a `/` inside `[...]` does not end the literal.
func skipRegexLiteral(source string, index int) int {
	index++
	inClass := false
	for index < len(source) {
		switch source[index] {
		case '\\':
			index += 2
			continue
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				index++
				for index < len(source) && isValueEnd(source[index]) {
					index++
				}
				return index
			}
		case '\n':
			return index + 1
		}
		index++
	}
	return index
}
