package main

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Three more directives the published modules declare and this manifest could
// not express, so an extension had to reach for a script -- or, in one case,
// substitute a different mechanism and accept a difference in behaviour.
//
//   - Loon's response-header-add and its siblings modify a real message. The
//     only declarative alternative was mock, which replaces the whole reply.
//   - Loon [Rewrite] and Surge [URL Rewrite] change a request URL in place or
//     answer with a redirect. Upstream WeatherKit's actual delivery is a
//     header-style rewrite to their hosted endpoint, and nothing here could
//     carry it.
//   - request-body-replace-regex edits bytes. jq was standing in for it, which
//     meant parsing and re-serialising the body and normalising key order and
//     whitespace along the way.
const (
	maxHeaderEdits       = 32
	maxRewriteURLBytes   = 4096
	maxReplaceBodyBytes  = 8 << 20
	maxReplacePatternLen = 1024
)

// HeaderEdits sets and removes header fields on the message its action's phase
// owns. Removal runs first, so declaring a name in both is a replacement rather
// than an ordering puzzle.
type HeaderEdits struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

// URLRewrite changes where a request goes. Status 0 rewrites in place, which is
// Loon's `header` form: the client never learns. 302 and 307 answer the client
// with a redirect instead, and 307 is the one that preserves method and body.
type URLRewrite struct {
	Pattern string `json:"pattern"`
	To      string `json:"to"`
	Status  int    `json:"status,omitempty"`

	compiled *regexp.Regexp
}

// BodyReplace edits the body with a regular expression. ValueMap exists because
// a published module hard-codes its replacement while an operator here chooses
// a region: it maps a setting's value to the substitution, and a value missing
// from the map declines the action rather than substituting nothing.
type BodyReplace struct {
	Pattern  string                       `json:"pattern"`
	To       string                       `json:"to"`
	ValueMap map[string]map[string]string `json:"value_map,omitempty"`

	compiled *regexp.Regexp
}

func (h *HeaderEdits) validate() error {
	if h == nil {
		return nil
	}
	if len(h.Set)+len(h.Remove) == 0 {
		return errors.New("header edits declare neither set nor remove")
	}
	if len(h.Set)+len(h.Remove) > maxHeaderEdits {
		return fmt.Errorf("header edits exceed %d fields", maxHeaderEdits)
	}
	for name, value := range h.Set {
		if !httpTokenName(name) {
			return fmt.Errorf("header name %q is invalid", name)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("header %q value contains a newline", name)
		}
	}
	for _, name := range h.Remove {
		if !httpTokenName(name) {
			return fmt.Errorf("header name %q is invalid", name)
		}
	}
	return nil
}

func (r *URLRewrite) validate() error {
	if r == nil {
		return nil
	}
	if r.Status != 0 && r.Status != http.StatusFound && r.Status != http.StatusTemporaryRedirect {
		return fmt.Errorf("rewrite status %d must be omitted, 302, or 307", r.Status)
	}
	if len(r.To) == 0 || len(r.To) > maxRewriteURLBytes {
		return fmt.Errorf("rewrite target must contain 1 to %d bytes", maxRewriteURLBytes)
	}
	if len(r.Pattern) > maxReplacePatternLen {
		return fmt.Errorf("rewrite pattern exceeds %d bytes", maxReplacePatternLen)
	}
	compiled, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("rewrite pattern is invalid: %w", err)
	}
	r.compiled = compiled
	return nil
}

func (b *BodyReplace) validate() error {
	if b == nil {
		return nil
	}
	if len(b.Pattern) == 0 || len(b.Pattern) > maxReplacePatternLen {
		return fmt.Errorf("body replace pattern must contain 1 to %d bytes", maxReplacePatternLen)
	}
	// Bounded like a rewrite target, which it was not: the sibling field has
	// carried this limit all along and the omission here was an oversight, not a
	// distinction. Unbounded, `to` is a whole-document amplifier -- ReplaceAll
	// allocates the result in one piece, and a declarative action is dispatched
	// before any VM exists, so no deadline and no interrupt applies to it.
	if len(b.To) > maxRewriteURLBytes {
		return fmt.Errorf("body replace target exceeds %d bytes", maxRewriteURLBytes)
	}
	compiled, err := regexp.Compile(b.Pattern)
	if err != nil {
		return fmt.Errorf("body replace pattern is invalid: %w", err)
	}
	// A pattern that matches the empty string substitutes at every byte offset,
	// so a 64 MiB body multiplies by the length of `to` with nothing to stop it.
	// No body-replace directive this kind exists to carry ever wants that.
	if compiled.MatchString("") {
		return errors.New("body replace pattern must not match the empty string")
	}
	b.compiled = compiled
	return nil
}

func applyHeaderEdits(edits *HeaderEdits, current http.Header) http.Header {
	updated := current.Clone()
	if updated == nil {
		updated = make(http.Header)
	}
	for _, name := range edits.Remove {
		updated.Del(name)
	}
	for name, value := range edits.Set {
		updated.Set(name, value)
	}
	return updated
}

// executeHeaderEdits touches only the headers. The body is left alone, which is
// the whole difference between this and a mock.
func executeHeaderEdits(rule ScriptRule, request scriptMessage, response *scriptMessage) (scriptResult, error) {
	current := request.Headers
	if rule.Phase == "response" {
		if response == nil {
			return scriptResult{}, errors.New("a response header action has no response")
		}
		current = response.Headers
	}
	return scriptResult{Headers: applyHeaderEdits(rule.Headers, current), ChangedHeaders: true}, nil
}

// executeRewrite either points the request somewhere else or answers with a
// redirect. The in-place form still passes through the same authorisation the
// scripted rewrite uses, so a cross-origin target still needs a declared
// network origin.
func executeRewrite(rule ScriptRule, module Module, request scriptMessage) (scriptResult, error) {
	rewrite := rule.Rewrite
	if rewrite.compiled == nil {
		if err := rewrite.validate(); err != nil {
			return scriptResult{}, err
		}
	}
	match := rewrite.compiled.FindStringSubmatchIndex(request.URL)
	if match == nil {
		// The action's matcher selected this request, but the rewrite's own
		// pattern did not. Declining is the honest outcome: substituting into a
		// template with no captures would build a wrong URL.
		return scriptResult{}, nil
	}
	// {{settings.key}} resolves before the capture groups do, so a setting can
	// choose the host while the pattern still carries the rest of the URL
	// through. An unresolvable key declines the action, which leaves the request
	// going where it was already going.
	settings, err := scriptSettingValuesReadOnly(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	to, ok := expandSettingsTemplate(rewrite.To, nil, settings)
	if !ok {
		return scriptResult{}, nil
	}
	target := string(rewrite.compiled.ExpandString(nil, to, request.URL, match))
	if len(target) == 0 || len(target) > maxRewriteURLBytes {
		return scriptResult{}, fmt.Errorf("rewritten URL must contain 1 to %d bytes", maxRewriteURLBytes)
	}
	if rewrite.Status == 0 {
		return scriptResult{URL: target, ChangedURL: true}, nil
	}
	headers := make(http.Header)
	headers.Set("Location", target)
	return scriptResult{
		StatusCode: rewrite.Status, Headers: headers, Body: nil,
		Synthetic: true, ChangedStatus: true, ChangedHeaders: true, ChangedBody: true,
	}, nil
}

// executeBodyReplace edits the body in place. Unlike the jq form it does not
// parse the document, so everything it does not match survives byte for byte.
func executeBodyReplace(rule ScriptRule, module Module, request scriptMessage, response *scriptMessage) (scriptResult, error) {
	replace := rule.ReplaceBody
	if replace.compiled == nil {
		if err := replace.validate(); err != nil {
			return scriptResult{}, err
		}
	}
	body := request.Body
	if rule.Phase == "response" {
		if response == nil {
			return scriptResult{}, errors.New("a response body action has no response")
		}
		body = response.Body
	}
	if len(body) > maxReplaceBodyBytes {
		return scriptResult{}, fmt.Errorf("body exceeds %d bytes", maxReplaceBodyBytes)
	}
	settings, err := scriptSettingValuesReadOnly(module, rule)
	if err != nil {
		return scriptResult{}, err
	}
	template, ok := expandSettingsTemplate(replace.To, replace.ValueMap, settings)
	if !ok {
		// A setting value with no mapping declines rather than substituting an
		// empty string into the body.
		return scriptResult{}, nil
	}
	if !replace.compiled.Match(body) {
		return scriptResult{}, nil
	}
	return scriptResult{Body: replace.compiled.ReplaceAll(body, []byte(template)), ChangedBody: true}, nil
}

// expandSettingsTemplate substitutes {{settings.key}} in a template. When the
// action declares a valueMap for that key the setting's value is looked up in
// it, which is how a module that hard-codes one value becomes an extension
// whose operator chooses among several.
//
// A missing key or an unmapped value returns false, and every caller declines
// rather than substituting an empty string. For a body replacement that would
// corrupt the document; for a rewrite target it would build a URL pointing at
// nothing, or worse, at something else.
//
// Substituted text is written out and never scanned again. A setting value is
// data, not more template: re-scanning it made `{{settings.k}}` expanding to
// itself a fixed point that spun forever, and an expansion that grew each pass
// allocate the whole string again every pass until the process died. Neither
// was reachable by the deadline -- a declarative action is dispatched before
// the VM exists, so there is no goja.Interrupt to fire and executeRewrite and
// executeBodyReplace take no context -- and the two body slots this pinned are
// the whole process's, so two such requests wedged every extension's captured
// traffic until a restart. An operator could arm it with nothing but a text
// setting whose value happens to contain its own placeholder.
//
// Writing forward also bounds the loop by the template length, so there is no
// iteration cap to choose or to get wrong.
//
// The result is a Go regexp replacement template, not a finished string: both
// callers hand it to ExpandString or ReplaceAll, where `$` introduces a capture
// reference. The author's own template keeps that meaning -- weatherkit's
// `.../v1/$1` relies on it -- but a substituted value must not acquire it, so
// each value is written with its dollars escaped. Unescaped, a setting of
// `p$ssw0rd` expanded to `p` and one of `$100` expanded to nothing, silently,
// because both name capture groups that do not exist.
func expandSettingsTemplate(template string, valueMap map[string]map[string]string, settings map[string]any) (string, bool) {
	var out strings.Builder
	rest := template
	for {
		start := strings.Index(rest, "{{settings.")
		if start < 0 {
			out.WriteString(rest)
			return out.String(), true
		}
		end := strings.Index(rest[start:], "}}")
		if end < 0 {
			out.WriteString(rest)
			return out.String(), true
		}
		key := rest[start+len("{{settings.") : start+end]
		raw, exists := settings[key]
		if !exists {
			return "", false
		}
		value := compatArgumentText(raw)
		if mapping, mapped := valueMap[key]; mapped {
			substitution, found := mapping[value]
			if !found {
				return "", false
			}
			value = substitution
		}
		out.WriteString(rest[:start])
		out.WriteString(strings.ReplaceAll(value, "$", "$$"))
		rest = rest[start+end+2:]
	}
}

// compatArgumentText renders a setting value for substitution. It is the same
// flattening the argument serialiser used before Loon made $argument an object,
// kept here because a replacement template needs text.
func compatArgumentText(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	default:
		return fmt.Sprint(typed)
	}
}
