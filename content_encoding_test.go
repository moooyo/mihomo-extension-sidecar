package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecodeContentBody(t *testing.T) {
	t.Parallel()
	want := []byte(`{"ads":[1,2],"ok":true}`)
	encoders := map[string]func(*bytes.Buffer){
		"gzip": func(buffer *bytes.Buffer) {
			writer := gzip.NewWriter(buffer)
			_, _ = writer.Write(want)
			_ = writer.Close()
		},
		"deflate": func(buffer *bytes.Buffer) {
			writer := zlib.NewWriter(buffer)
			_, _ = writer.Write(want)
			_ = writer.Close()
		},
		"deflate-raw": func(buffer *bytes.Buffer) {
			writer, _ := flate.NewWriter(buffer, flate.DefaultCompression)
			_, _ = writer.Write(want)
			_ = writer.Close()
		},
		"br": func(buffer *bytes.Buffer) {
			writer := brotli.NewWriter(buffer)
			_, _ = writer.Write(want)
			_ = writer.Close()
		},
	}
	for name, encode := range encoders {
		t.Run(name, func(t *testing.T) {
			var encoded bytes.Buffer
			encode(&encoded)
			encoding := name
			if name == "deflate-raw" {
				encoding = "deflate"
			}
			got, err := decodeContentBody(encoded.Bytes(), encoding, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("decoded body = %q, want %q", got, want)
			}
		})
	}
}

func TestDecodeContentBodyEnforcesExpandedLimit(t *testing.T) {
	t.Parallel()
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	_, _ = writer.Write(bytes.Repeat([]byte("x"), 4096))
	_ = writer.Close()
	if _, err := decodeContentBody(encoded.Bytes(), "gzip", 128); err == nil {
		t.Fatal("expanded body exceeded the limit without an error")
	}
}
