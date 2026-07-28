package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The jq program shipped by io.5gpn.testflight-region-unlock. It is the reason
// $settings exists: its replacement value comes from an operator choice, which
// is what kept this one action in JavaScript after everything else had moved.
const testflightStorefrontProgram = `def ids: {"US":"143441-19,29","GB":"143444-19,29","CA":"143455-19,29","AU":"143460-19,29","JP":"143462-19,29","HK":"143463-19,29","SG":"143464-19,29","CN":"143465-19,29","KR":"143466-19,29","TW":"143470-19,29"}; if has("storefrontId") and (ids[$settings.storefront] != null) then .storefrontId = ids[$settings.storefront] else . end`

func TestTestFlightShippedJQProgram(t *testing.T) {
	t.Parallel()
	code, err := compileJQProgram(testflightStorefrontProgram)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runJQ(context.Background(), code,
		[]byte(`{"storefrontId":"143441-19,29","other":"keep"}`),
		map[string]any{"storefront": "JP"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["storefrontId"] != "143462-19,29" || decoded["other"] != "keep" {
		t.Fatalf("got %s, want the selected storefront and the untouched field", got)
	}

	// A body with no storefrontId is left alone rather than having one
	// invented, and an unknown region leaves the existing value in place
	// rather than writing null into the request.
	for _, testCase := range []struct{ body, settings, want string }{
		{`{"other":1}`, "JP", `{"other":1}`},
		{`{"storefrontId":"143441-19,29"}`, "ZZ", `{"storefrontId":"143441-19,29"}`},
	} {
		out, err := runJQ(context.Background(), code, []byte(testCase.body), map[string]any{"storefront": testCase.settings})
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(out)) != testCase.want {
			t.Fatalf("got %s, want %s", out, testCase.want)
		}
	}
}
