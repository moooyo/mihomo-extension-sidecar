package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/andybalholm/cascadia"
	"github.com/dop251/goja"
	"golang.org/x/net/html"
)

// The published Bilibili webpage bundle parses a response into a document,
// selects nodes, injects a script and a style, and serializes the whole
// document back. Surge runs it inside a webview; this runtime has no browser,
// so the document model below is the bounded stand-in.
//
// It is deliberately a real implementation of a small surface rather than a
// large approximate one. Everything the bundle can reach either works the way a
// browser works or is absent, because a half-present DOM method is the worst
// outcome available: the bundle guards on the property existing, then throws
// inside its own error handling, and the action reports success having changed
// nothing.
const (
	maxDOMDocumentBytes = 8 << 20
	maxDOMNodes         = 200000
	maxDOMSelectorBytes = 1024
)

// domDocument owns one parsed tree. Element wrappers are memoized so that
// identity holds: a script that removes a node it selected earlier, or compares
// parentElement against a node it already has, sees the same object a browser
// would.
type domDocument struct {
	vm      *goja.Runtime
	root    *html.Node
	wrapped map[*html.Node]*goja.Object
}

func installDOMAPI(vm *goja.Runtime) error {
	constructor := func(call goja.ConstructorCall) *goja.Object {
		parser := call.This
		_ = parser.Set("parseFromString", func(inner goja.FunctionCall) goja.Value {
			source := inner.Argument(0).String()
			mime := strings.ToLower(strings.TrimSpace(inner.Argument(1).String()))
			// Only the HTML branch is implemented. An XML document has
			// different parsing and serialization rules, and silently handing
			// back an HTML tree would be a wrong answer rather than a missing
			// one.
			if mime != "text/html" {
				panic(vm.NewTypeError("parseFromString supports text/html only, got %q", mime))
			}
			document, err := newDOMDocument(vm, source)
			if err != nil {
				panic(vm.NewGoError(err))
			}
			return document
		})
		return nil
	}
	return vm.Set("DOMParser", constructor)
}

func newDOMDocument(vm *goja.Runtime, source string) (*goja.Object, error) {
	if len(source) > maxDOMDocumentBytes {
		return nil, fmt.Errorf("document exceeds %d bytes", maxDOMDocumentBytes)
	}
	root, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return nil, fmt.Errorf("parse document: %w", err)
	}
	document := &domDocument{vm: vm, root: root, wrapped: make(map[*html.Node]*goja.Object)}
	if count := countDOMNodes(root); count > maxDOMNodes {
		return nil, fmt.Errorf("document has %d nodes, exceeding %d", count, maxDOMNodes)
	}
	return document.documentObject(), nil
}

func countDOMNodes(node *html.Node) int {
	total := 1
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		total += countDOMNodes(child)
		if total > maxDOMNodes {
			return total
		}
	}
	return total
}

func (d *domDocument) documentObject() *goja.Object {
	object := d.vm.NewObject()
	_ = object.Set("createElement", func(call goja.FunctionCall) goja.Value {
		name := strings.ToLower(strings.TrimSpace(call.Argument(0).String()))
		if name == "" {
			panic(d.vm.NewTypeError("createElement requires a tag name"))
		}
		return d.wrap(&html.Node{Type: html.ElementNode, Data: name})
	})
	_ = object.Set("querySelectorAll", func(call goja.FunctionCall) goja.Value {
		return d.vm.ToValue(d.selectAll(d.root, call.Argument(0)))
	})
	_ = object.Set("querySelector", func(call goja.FunctionCall) goja.Value {
		matches := d.selectAll(d.root, call.Argument(0))
		if len(matches) == 0 {
			return goja.Null()
		}
		return matches[0]
	})
	// documentElement, head, and body are looked up on every read rather than
	// captured once, because the bundle appends to head and then serializes
	// documentElement expecting to see its own change.
	_ = object.DefineAccessorProperty("documentElement",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value { return d.firstElement("html") }),
		nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("head",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value { return d.firstElement("head") }),
		nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("body",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value { return d.firstElement("body") }),
		nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	return object
}

func (d *domDocument) firstElement(tag string) goja.Value {
	var found *html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if found != nil {
			return
		}
		if node.Type == html.ElementNode && node.Data == tag {
			found = node
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(d.root)
	if found == nil {
		return goja.Null()
	}
	return d.wrap(found)
}

func (d *domDocument) selectAll(scope *html.Node, selector goja.Value) []goja.Value {
	text := selector.String()
	if len(text) > maxDOMSelectorBytes {
		panic(d.vm.NewTypeError("selector exceeds %d bytes", maxDOMSelectorBytes))
	}
	compiled, err := cascadia.Compile(text)
	if err != nil {
		panic(d.vm.NewGoError(fmt.Errorf("invalid selector %q: %w", text, err)))
	}
	matched := make([]goja.Value, 0)
	for _, node := range cascadia.QueryAll(scope, compiled) {
		matched = append(matched, d.wrap(node))
	}
	return matched
}

// wrap returns the one object representing this node.
func (d *domDocument) wrap(node *html.Node) *goja.Object {
	if existing, ok := d.wrapped[node]; ok {
		return existing
	}
	object := d.vm.NewObject()
	d.wrapped[node] = object

	_ = object.Set("appendChild", func(call goja.FunctionCall) goja.Value {
		child := d.nodeOf(call.Argument(0))
		if child.Parent != nil {
			child.Parent.RemoveChild(child)
		}
		node.AppendChild(child)
		return d.wrap(child)
	})
	_ = object.Set("removeChild", func(call goja.FunctionCall) goja.Value {
		child := d.nodeOf(call.Argument(0))
		if child.Parent != node {
			panic(d.vm.NewTypeError("removeChild target is not a child of this node"))
		}
		node.RemoveChild(child)
		return d.wrap(child)
	})
	_ = object.Set("querySelectorAll", func(call goja.FunctionCall) goja.Value {
		return d.vm.ToValue(d.selectAll(node, call.Argument(0)))
	})
	_ = object.Set("getAttribute", func(call goja.FunctionCall) goja.Value {
		name := strings.ToLower(call.Argument(0).String())
		for _, attribute := range node.Attr {
			if attribute.Key == name {
				return d.vm.ToValue(attribute.Val)
			}
		}
		return goja.Null()
	})
	_ = object.Set("setAttribute", func(call goja.FunctionCall) goja.Value {
		name := strings.ToLower(call.Argument(0).String())
		value := call.Argument(1).String()
		for index := range node.Attr {
			if node.Attr[index].Key == name {
				node.Attr[index].Val = value
				return goja.Undefined()
			}
		}
		node.Attr = append(node.Attr, html.Attribute{Key: name, Val: value})
		return goja.Undefined()
	})

	_ = object.DefineAccessorProperty("tagName",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			return d.vm.ToValue(strings.ToUpper(node.Data))
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("parentElement",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			if node.Parent == nil || node.Parent.Type != html.ElementNode {
				return goja.Null()
			}
			return d.wrap(node.Parent)
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("textContent",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value { return d.vm.ToValue(domTextContent(node)) }),
		d.vm.ToValue(func(call goja.FunctionCall) goja.Value {
			for node.FirstChild != nil {
				node.RemoveChild(node.FirstChild)
			}
			node.AppendChild(&html.Node{Type: html.TextNode, Data: call.Argument(0).String()})
			return goja.Undefined()
		}), goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("outerHTML",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			rendered, err := domRender(node)
			if err != nil {
				panic(d.vm.NewGoError(err))
			}
			return d.vm.ToValue(rendered)
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("innerHTML",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			var builder strings.Builder
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				rendered, err := domRender(child)
				if err != nil {
					panic(d.vm.NewGoError(err))
				}
				builder.WriteString(rendered)
			}
			return d.vm.ToValue(builder.String())
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	return object
}

// nodeOf recovers the tree node behind a wrapper. A script may only pass back
// an object this document handed it; anything else is rejected rather than
// coerced, because grafting a foreign object into the tree would corrupt it.
func (d *domDocument) nodeOf(value goja.Value) *html.Node {
	object, ok := value.(*goja.Object)
	if !ok {
		panic(d.vm.NewTypeError("expected a node from this document"))
	}
	for node, candidate := range d.wrapped {
		if candidate == object {
			return node
		}
	}
	panic(d.vm.NewTypeError("expected a node from this document"))
}

func domTextContent(node *html.Node) string {
	if node.Type == html.TextNode {
		return node.Data
	}
	var builder strings.Builder
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		builder.WriteString(domTextContent(child))
	}
	return builder.String()
}

func domRender(node *html.Node) (string, error) {
	if node.Parent != nil && node.Type == html.ElementNode {
		// html.Render walks siblings for a detached node, so render through a
		// copy that has none.
		clone := *node
		clone.Parent, clone.PrevSibling, clone.NextSibling = nil, nil, nil
		node = &clone
	}
	var builder strings.Builder
	if err := html.Render(&builder, node); err != nil {
		return "", errors.New("document could not be serialized")
	}
	return builder.String(), nil
}
