package main

import (
	"strings"
	"testing"

	"github.com/dop251/goja"
)

func runDOMScript(t *testing.T, source string) goja.Value {
	t.Helper()
	vm := goja.New()
	if err := installDOMAPI(vm); err != nil {
		t.Fatal(err)
	}
	value, err := vm.RunString(source)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDOMParserRoundTripsAndInjectsIntoHead(t *testing.T) {
	t.Parallel()
	// This is the published Bilibili webpage bundle's exact shape: parse the
	// body, create a script element, set its text, append it to head, and
	// serialize documentElement back with a doctype in front.
	value := runDOMScript(t, `
	  const document = new DOMParser().parseFromString(
	    "<html><head><title>t</title></head><body><p>hi</p></body></html>", "text/html")
	  const element = document.createElement("script")
	  element.textContent = "console.log(1)"
	  document.head.appendChild(element)
	  "<!DOCTYPE HTML>" + document.documentElement.outerHTML
	`)
	rendered := value.String()
	if !strings.HasPrefix(rendered, "<!DOCTYPE HTML><html>") {
		t.Fatalf("rendered = %q, want the serialized document element", rendered)
	}
	if !strings.Contains(rendered, "<script>console.log(1)</script></head>") {
		t.Fatalf("rendered = %q, want the script appended inside head", rendered)
	}
	if !strings.Contains(rendered, "<p>hi</p>") {
		t.Fatalf("rendered = %q, want the original body preserved", rendered)
	}
}

func TestDOMQuerySelectorAllRemovesMatchedNodes(t *testing.T) {
	t.Parallel()
	// The bundle's node-filter middleware selects, filters with a predicate, and
	// removes through parentElement. That path is unreachable for the currently
	// pinned bundle, which is exactly why it is pinned by a test: an upstream
	// revision that starts setting nodeFilters must not silently do nothing.
	value := runDOMScript(t, `
	  const document = new DOMParser().parseFromString(
	    "<html><body><div class='ad' id='a'>x</div><div class='ad' id='b'>keep</div><div id='c'>c</div></body></html>",
	    "text/html")
	  const matched = Array.from(document.querySelectorAll("div.ad"))
	  matched.filter(node => node.getAttribute("id") !== "b")
	         .map(node => node.parentElement.removeChild(node))
	  document.body.innerHTML
	`)
	rendered := value.String()
	if strings.Contains(rendered, `id="a"`) {
		t.Fatalf("rendered = %q, want the filtered node removed", rendered)
	}
	if !strings.Contains(rendered, `id="b"`) || !strings.Contains(rendered, `id="c"`) {
		t.Fatalf("rendered = %q, want the predicate-spared and unmatched nodes kept", rendered)
	}
}

func TestDOMNodeIdentityIsStable(t *testing.T) {
	t.Parallel()
	// A script that selects a node twice, or reaches it through parentElement,
	// must get the same object. Handing back a fresh wrapper each time would
	// break the identity comparisons a browser guarantees.
	value := runDOMScript(t, `
	  const document = new DOMParser().parseFromString("<html><body><p id='x'>t</p></body></html>", "text/html")
	  const first = document.querySelector("#x")
	  const second = document.querySelectorAll("p")[0]
	  first === second && first.parentElement === document.body
	`)
	if !value.ToBoolean() {
		t.Fatal("the same node produced different objects")
	}
}

func TestDOMRejectsANonHTMLMimeType(t *testing.T) {
	t.Parallel()
	// XML has different parsing and serialization rules. Returning an HTML tree
	// for it would be a wrong answer rather than a missing one.
	vm := goja.New()
	if err := installDOMAPI(vm); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(`new DOMParser().parseFromString("<a/>", "text/xml")`); err == nil {
		t.Fatal("expected text/xml to be refused")
	}
}

func TestDOMRejectsAForeignNode(t *testing.T) {
	t.Parallel()
	// Grafting an object this document never produced would corrupt the tree.
	vm := goja.New()
	if err := installDOMAPI(vm); err != nil {
		t.Fatal(err)
	}
	_, err := vm.RunString(`
	  const document = new DOMParser().parseFromString("<html><body></body></html>", "text/html")
	  document.body.appendChild({ tagName: "SCRIPT" })
	`)
	if err == nil {
		t.Fatal("expected a foreign object to be refused")
	}
}

func TestDOMIsAbsentFromNativeScripts(t *testing.T) {
	t.Parallel()
	// The document model exists for published bundles. A native script keeps the
	// smaller surface it was reviewed against.
	result, err := asyncRuntimeCall(t, `function transform(context) {
	  return { response: { body: typeof DOMParser } }
	}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Body); got != "undefined" {
		t.Fatalf("DOMParser = %q in a native script, want it undefined", got)
	}
}
