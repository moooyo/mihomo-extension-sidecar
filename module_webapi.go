package main

import (
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// installWebAPI defines the small set of web globals a published proxy-client
// bundle expects but goja does not provide.
//
// The bundles reach for URL to read a captured request's path and query, and
// the FlatBuffers runtime they carry constructs a TextDecoder for every
// ByteBuffer and a TextEncoder for every Builder. Without these a bundle throws
// a ReferenceError inside its own catch, completes with the response untouched,
// and looks like it simply chose not to transform anything.
//
// This is deliberately not a complete WHATWG implementation. It is the surface
// the reviewed bundles use, backed by net/url, with no network, no filesystem,
// and no relative-resolution surprises beyond what a base argument implies.
func installWebAPI(vm *goja.Runtime) error {
	if err := vm.Set("URL", newURLConstructor(vm)); err != nil {
		return err
	}
	if err := vm.Set("URLSearchParams", newSearchParamsConstructor(vm)); err != nil {
		return err
	}
	if err := vm.Set("TextEncoder", newTextEncoderConstructor(vm)); err != nil {
		return err
	}
	return vm.Set("TextDecoder", newTextDecoderConstructor(vm))
}

func newURLConstructor(vm *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		raw := call.Argument(0).String()
		parsed, err := url.Parse(raw)
		if err != nil {
			panic(vm.NewTypeError("Invalid URL: %s", raw))
		}
		if base := call.Argument(1); !goja.IsUndefined(base) && !goja.IsNull(base) {
			baseURL, baseErr := url.Parse(base.String())
			if baseErr != nil {
				panic(vm.NewTypeError("Invalid base URL: %s", base.String()))
			}
			parsed = baseURL.ResolveReference(parsed)
		}
		if !parsed.IsAbs() {
			panic(vm.NewTypeError("Invalid URL: %s", raw))
		}
		bindURLObject(vm, call.This, parsed)
		return nil
	}
}

// bindURLObject installs live accessors over one *url.URL, so a mutation
// through searchParams is visible in href and toString rather than leaving two
// disagreeing views of the same address.
func bindURLObject(vm *goja.Runtime, object *goja.Object, parsed *url.URL) {
	params := newSearchParamsObject(vm, parsed)
	accessor := func(name string, get func() string, set func(string)) {
		getter := vm.ToValue(func(goja.FunctionCall) goja.Value { return vm.ToValue(get()) })
		var setter goja.Value = goja.Undefined()
		if set != nil {
			setter = vm.ToValue(func(call goja.FunctionCall) goja.Value {
				set(call.Argument(0).String())
				return goja.Undefined()
			})
		}
		_ = object.DefineAccessorProperty(name, getter, setter, goja.FLAG_FALSE, goja.FLAG_TRUE)
	}

	accessor("href", func() string { return parsed.String() }, func(value string) {
		next, err := url.Parse(value)
		if err != nil || !next.IsAbs() {
			panic(vm.NewTypeError("Invalid URL: %s", value))
		}
		*parsed = *next
	})
	accessor("protocol", func() string { return parsed.Scheme + ":" }, nil)
	accessor("hostname", func() string { return parsed.Hostname() }, func(value string) {
		if port := parsed.Port(); port != "" {
			parsed.Host = value + ":" + port
			return
		}
		parsed.Host = value
	})
	accessor("host", func() string { return parsed.Host }, func(value string) { parsed.Host = value })
	accessor("port", func() string { return parsed.Port() }, nil)
	accessor("origin", func() string {
		if parsed.Scheme == "" || parsed.Host == "" {
			return "null"
		}
		return parsed.Scheme + "://" + parsed.Host
	}, nil)
	accessor("pathname", func() string {
		if parsed.EscapedPath() == "" {
			return "/"
		}
		return parsed.EscapedPath()
	}, func(value string) { parsed.Path = value; parsed.RawPath = "" })
	accessor("search", func() string {
		if parsed.RawQuery == "" {
			return ""
		}
		return "?" + parsed.RawQuery
	}, func(value string) { parsed.RawQuery = strings.TrimPrefix(value, "?") })
	accessor("hash", func() string {
		if parsed.Fragment == "" {
			return ""
		}
		return "#" + parsed.EscapedFragment()
	}, func(value string) { parsed.Fragment = strings.TrimPrefix(value, "#") })

	_ = object.Set("searchParams", params)
	_ = object.Set("toString", func(goja.FunctionCall) goja.Value { return vm.ToValue(parsed.String()) })
	_ = object.Set("toJSON", func(goja.FunctionCall) goja.Value { return vm.ToValue(parsed.String()) })
}

func newSearchParamsConstructor(vm *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		query := ""
		if raw := call.Argument(0); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
			query = strings.TrimPrefix(raw.String(), "?")
		}
		owner := &url.URL{RawQuery: query}
		bindSearchParams(vm, call.This, owner)
		return nil
	}
}

// newSearchParamsObject returns a params view bound to an existing URL, so
// set and delete rewrite that URL's query rather than a detached copy.
func newSearchParamsObject(vm *goja.Runtime, owner *url.URL) *goja.Object {
	object := vm.NewObject()
	bindSearchParams(vm, object, owner)
	return object
}

func bindSearchParams(vm *goja.Runtime, object *goja.Object, owner *url.URL) {
	read := func() url.Values {
		values, err := url.ParseQuery(owner.RawQuery)
		if err != nil {
			// A query this package cannot parse is treated as empty rather than
			// throwing: the caller is reading a captured URL it did not build.
			return url.Values{}
		}
		return values
	}
	write := func(values url.Values) { owner.RawQuery = values.Encode() }

	_ = object.Set("get", func(call goja.FunctionCall) goja.Value {
		values := read()
		name := call.Argument(0).String()
		if list, exists := values[name]; exists && len(list) > 0 {
			return vm.ToValue(list[0])
		}
		return goja.Null()
	})
	_ = object.Set("getAll", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(read()[call.Argument(0).String()])
	})
	_ = object.Set("has", func(call goja.FunctionCall) goja.Value {
		_, exists := read()[call.Argument(0).String()]
		return vm.ToValue(exists)
	})
	_ = object.Set("set", func(call goja.FunctionCall) goja.Value {
		values := read()
		values.Set(call.Argument(0).String(), call.Argument(1).String())
		write(values)
		return goja.Undefined()
	})
	_ = object.Set("append", func(call goja.FunctionCall) goja.Value {
		values := read()
		values.Add(call.Argument(0).String(), call.Argument(1).String())
		write(values)
		return goja.Undefined()
	})
	_ = object.Set("delete", func(call goja.FunctionCall) goja.Value {
		values := read()
		values.Del(call.Argument(0).String())
		write(values)
		return goja.Undefined()
	})
	_ = object.Set("toString", func(goja.FunctionCall) goja.Value {
		return vm.ToValue(owner.RawQuery)
	})
	_ = object.Set("forEach", func(call goja.FunctionCall) goja.Value {
		callback, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			panic(vm.NewTypeError("forEach requires a function"))
		}
		for name, list := range read() {
			for _, value := range list {
				if _, err := callback(goja.Undefined(), vm.ToValue(value), vm.ToValue(name), object); err != nil {
					panic(err)
				}
			}
		}
		return goja.Undefined()
	})
}

func newTextEncoderConstructor(vm *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		_ = call.This.Set("encoding", "utf-8")
		_ = call.This.Set("encode", func(inner goja.FunctionCall) goja.Value {
			text := ""
			if raw := inner.Argument(0); !goja.IsUndefined(raw) {
				text = raw.String()
			}
			value, err := newModuleNetworkByteArray(vm, []byte(text))
			if err != nil {
				panic(vm.NewGoError(err))
			}
			return value
		})
		return nil
	}
}

func newTextDecoderConstructor(vm *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		label := "utf-8"
		if raw := call.Argument(0); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
			label = strings.ToLower(raw.String())
		}
		// Only UTF-8 is supported. Silently decoding another encoding as UTF-8
		// would corrupt the payload somewhere far from here.
		switch label {
		case "utf-8", "utf8", "unicode-1-1-utf-8":
		default:
			panic(vm.NewTypeError("TextDecoder supports utf-8 only, got %q", label))
		}
		fatal := false
		if options := call.Argument(1); !goja.IsUndefined(options) && !goja.IsNull(options) {
			if object, ok := options.(*goja.Object); ok {
				fatal = object.Get("fatal").ToBoolean()
			}
		}
		_ = call.This.Set("encoding", "utf-8")
		_ = call.This.Set("fatal", fatal)
		_ = call.This.Set("decode", func(inner goja.FunctionCall) goja.Value {
			raw := inner.Argument(0)
			if goja.IsUndefined(raw) || goja.IsNull(raw) {
				return vm.ToValue("")
			}
			body, err := exportedBody(raw.Export())
			if err != nil {
				panic(vm.NewTypeError("decode requires a Uint8Array or ArrayBuffer"))
			}
			if fatal && !utf8.Valid(body) {
				panic(vm.NewGoError(errors.New("TextDecoder found invalid UTF-8")))
			}
			return vm.ToValue(string(body))
		})
		return nil
	}
}
