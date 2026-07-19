package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

func isGzip(body []byte) bool {
	return len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
}

func decodeContentBody(body []byte, encoding string, limit int64) ([]byte, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding == "" || encoding == "identity" {
		return body, nil
	}
	var reader io.ReadCloser
	switch encoding {
	case "gzip":
		value, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("open gzip body: %w", err)
		}
		reader = value
	case "deflate":
		value, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			reader = flate.NewReader(bytes.NewReader(body))
		} else {
			reader = value
		}
	case "br":
		reader = io.NopCloser(brotli.NewReader(bytes.NewReader(body)))
	default:
		return nil, fmt.Errorf("content encoding %q is unsupported", encoding)
	}
	defer reader.Close()
	decoded, err := readBounded(reader, limit)
	if err != nil {
		return nil, fmt.Errorf("decode %s body: %w", encoding, err)
	}
	return decoded, nil
}
