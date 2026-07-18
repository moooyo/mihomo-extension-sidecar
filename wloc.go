package main

// The bounded WLOC wire transformer is derived from the MIT-licensed
// FFF686868/proxypin-wloc-spoofer implementation. See THIRD_PARTY_NOTICES.md.

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
)

type wlocTarget struct {
	Longitude float64
	Latitude  float64
	Accuracy  uint32
}

type wlocPatchStats struct {
	WiFi      int
	Cell      int
	Locations int
	Skipped   int
}

type protoField struct {
	number   uint64
	wireType uint64
	value    []byte
	raw      []byte
}

func patchWLOCBody(body []byte, target wlocTarget, maxBytes int64) ([]byte, wlocPatchStats, error) {
	if int64(len(body)) > maxBytes {
		return nil, wlocPatchStats{}, fmt.Errorf("WLOC response exceeds %d bytes", maxBytes)
	}
	plain := body
	compressed := isGzip(body)
	if compressed {
		var err error
		plain, err = gunzipBounded(body, maxBytes)
		if err != nil {
			return nil, wlocPatchStats{}, err
		}
	}
	patched, stats, err := patchWLOCPayload(plain, target)
	if err != nil {
		return nil, stats, err
	}
	return patched, stats, nil
}

func isGzip(body []byte) bool {
	return len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
}

func gunzipBounded(body []byte, maxBytes int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("open gzip WLOC response: %w", err)
	}
	defer zr.Close()
	limited := io.LimitReader(zr, maxBytes+1)
	plain, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("decompress WLOC response: %w", err)
	}
	if int64(len(plain)) > maxBytes {
		return nil, fmt.Errorf("decompressed WLOC response exceeds %d bytes", maxBytes)
	}
	return plain, nil
}

func patchWLOCPayload(body []byte, target wlocTarget) ([]byte, wlocPatchStats, error) {
	if len(body) < 1 {
		return nil, wlocPatchStats{}, errors.New("empty WLOC response")
	}
	offsets := make([]int, 0, 97)
	for _, offset := range []int{0, 2, 4, 6, 8, 10, 12, 14, 16} {
		if offset+10 <= len(body) {
			offsets = append(offsets, offset)
		}
	}
	limit := min(96, len(body)-10)
	for offset := 0; offset <= limit; offset++ {
		if !containsInt(offsets, offset) {
			offsets = append(offsets, offset)
		}
	}
	var diagnostics []string
	for _, offset := range offsets {
		stats := wlocPatchStats{}
		patched, err := patchFramedWLOC(body, offset, target, &stats)
		if err == nil {
			return patched, stats, nil
		}
		if len(diagnostics) < 6 {
			diagnostics = append(diagnostics, fmt.Sprintf("@%d:%v", offset, err))
		}
	}
	for offset := 0; offset <= min(256, len(body)-1); offset++ {
		stats := wlocPatchStats{}
		patchedPayload, err := patchWLOCRoot(body[offset:], target, &stats)
		if err == nil && stats.Locations > 0 && !bytes.Equal(patchedPayload, body[offset:]) {
			return append(append([]byte(nil), body[:offset]...), patchedPayload...), stats, nil
		}
	}
	return nil, wlocPatchStats{}, fmt.Errorf("no patchable WLOC payload found: %v", diagnostics)
}

func patchFramedWLOC(body []byte, offset int, target wlocTarget, stats *wlocPatchStats) ([]byte, error) {
	if offset < 0 || len(body) < offset+10 {
		return nil, errors.New("body is too short for framed WLOC")
	}
	length := int(body[offset+8])<<8 | int(body[offset+9])
	if length <= 0 || offset+10+length > len(body) {
		return nil, errors.New("invalid framed WLOC length")
	}
	payload := body[offset+10 : offset+10+length]
	patched, err := patchWLOCRoot(payload, target, stats)
	if err != nil {
		return nil, err
	}
	if stats.Locations == 0 || bytes.Equal(payload, patched) {
		return nil, errors.New("framed payload contains no patchable location")
	}
	if len(patched) > 65535 {
		return nil, errors.New("patched framed payload is too large")
	}
	out := make([]byte, 0, len(body)-len(payload)+len(patched))
	out = append(out, body[:offset+8]...)
	out = append(out, byte(len(patched)>>8), byte(len(patched)))
	out = append(out, patched...)
	out = append(out, body[offset+10+length:]...)
	return out, nil
}

func patchWLOCRoot(body []byte, target wlocTarget, stats *wlocPatchStats) ([]byte, error) {
	fields, err := parseProtoFields(body)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body))
	for _, field := range fields {
		if field.wireType == 2 && field.number == 2 {
			patched, patchErr := patchWLOCWiFi(field.value, target, stats)
			if patchErr != nil {
				stats.Skipped++
				out = append(out, field.raw...)
				continue
			}
			out = append(out, encodeLengthField(field.number, patched)...)
			continue
		}
		if field.wireType == 2 && (field.number == 22 || field.number == 24) {
			patched, patchErr := patchWLOCCell(field.value, target, stats)
			if patchErr != nil {
				stats.Skipped++
				out = append(out, field.raw...)
				continue
			}
			out = append(out, encodeLengthField(field.number, patched)...)
			continue
		}
		out = append(out, field.raw...)
	}
	return out, nil
}

func patchWLOCWiFi(body []byte, target wlocTarget, stats *wlocPatchStats) ([]byte, error) {
	fields, err := parseProtoFields(body)
	if err != nil {
		return nil, err
	}
	hasMAC := false
	for _, field := range fields {
		if field.number == 1 && field.wireType == 2 && validMACString(field.value) {
			hasMAC = true
			break
		}
	}
	if !hasMAC {
		return body, nil
	}
	changed := false
	out := make([]byte, 0, len(body))
	for _, field := range fields {
		if field.number == 2 && field.wireType == 2 {
			patched, patchErr := patchWLOCLocation(field.value, target, stats)
			if patchErr != nil {
				stats.Skipped++
				out = append(out, field.raw...)
				continue
			}
			if !bytes.Equal(patched, field.value) {
				changed = true
			}
			out = append(out, encodeLengthField(field.number, patched)...)
			continue
		}
		out = append(out, field.raw...)
	}
	if changed {
		stats.WiFi++
	}
	return out, nil
}

func patchWLOCCell(body []byte, target wlocTarget, stats *wlocPatchStats) ([]byte, error) {
	fields, err := parseProtoFields(body)
	if err != nil {
		return nil, err
	}
	changed := false
	out := make([]byte, 0, len(body))
	for _, field := range fields {
		if field.number == 5 && field.wireType == 2 {
			patched, patchErr := patchWLOCLocation(field.value, target, stats)
			if patchErr != nil {
				stats.Skipped++
				out = append(out, field.raw...)
				continue
			}
			if !bytes.Equal(patched, field.value) {
				changed = true
			}
			out = append(out, encodeLengthField(field.number, patched)...)
			continue
		}
		out = append(out, field.raw...)
	}
	if changed {
		stats.Cell++
	}
	return out, nil
}

func patchWLOCLocation(body []byte, target wlocTarget, stats *wlocPatchStats) ([]byte, error) {
	fields, err := parseProtoFields(body)
	if err != nil {
		return nil, err
	}
	hasLatitude := false
	hasLongitude := false
	for _, field := range fields {
		hasLatitude = hasLatitude || (field.number == 1 && field.wireType == 0)
		hasLongitude = hasLongitude || (field.number == 2 && field.wireType == 0)
	}
	if !hasLatitude || !hasLongitude {
		return body, nil
	}
	latitude := uint64(int64(math.Round(target.Latitude * 1e8)))
	longitude := uint64(int64(math.Round(target.Longitude * 1e8)))
	out := make([]byte, 0, len(body))
	for _, field := range fields {
		switch {
		case field.number == 1 && field.wireType == 0:
			out = append(out, encodeVarintField(1, latitude)...)
		case field.number == 2 && field.wireType == 0:
			out = append(out, encodeVarintField(2, longitude)...)
		case field.number == 3 && field.wireType == 0:
			out = append(out, encodeVarintField(3, uint64(target.Accuracy))...)
		default:
			out = append(out, field.raw...)
		}
	}
	stats.Locations++
	return out, nil
}

func parseProtoFields(body []byte) ([]protoField, error) {
	var fields []protoField
	for offset := 0; offset < len(body); {
		start := offset
		key, n, err := decodeVarint(body[offset:])
		if err != nil {
			return nil, err
		}
		offset += n
		number := key >> 3
		wireType := key & 7
		if number == 0 {
			return nil, errors.New("protobuf field number is zero")
		}
		var value []byte
		switch wireType {
		case 0:
			_, consumed, varintErr := decodeVarint(body[offset:])
			if varintErr != nil {
				return nil, varintErr
			}
			value = body[offset : offset+consumed]
			offset += consumed
		case 1:
			if len(body)-offset < 8 {
				return nil, io.ErrUnexpectedEOF
			}
			value = body[offset : offset+8]
			offset += 8
		case 2:
			length, consumed, lengthErr := decodeVarint(body[offset:])
			if lengthErr != nil {
				return nil, lengthErr
			}
			offset += consumed
			if length > uint64(len(body)-offset) {
				return nil, io.ErrUnexpectedEOF
			}
			value = body[offset : offset+int(length)]
			offset += int(length)
		case 5:
			if len(body)-offset < 4 {
				return nil, io.ErrUnexpectedEOF
			}
			value = body[offset : offset+4]
			offset += 4
		default:
			return nil, fmt.Errorf("unsupported protobuf wire type %d", wireType)
		}
		fields = append(fields, protoField{
			number:   number,
			wireType: wireType,
			value:    value,
			raw:      body[start:offset],
		})
	}
	return fields, nil
}

func decodeVarint(body []byte) (uint64, int, error) {
	var value uint64
	for index := 0; index < 10; index++ {
		if index >= len(body) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		b := body[index]
		if index == 9 && b > 1 {
			return 0, 0, errors.New("protobuf varint overflows uint64")
		}
		value |= uint64(b&0x7f) << (7 * index)
		if b < 0x80 {
			return value, index + 1, nil
		}
	}
	return 0, 0, errors.New("protobuf varint is too long")
}

func encodeVarint(value uint64) []byte {
	var out [10]byte
	index := 0
	for value >= 0x80 {
		out[index] = byte(value) | 0x80
		value >>= 7
		index++
	}
	out[index] = byte(value)
	return append([]byte(nil), out[:index+1]...)
}

func encodeVarintField(number, value uint64) []byte {
	out := encodeVarint(number << 3)
	return append(out, encodeVarint(value)...)
}

func encodeLengthField(number uint64, value []byte) []byte {
	out := encodeVarint(number<<3 | 2)
	out = append(out, encodeVarint(uint64(len(value)))...)
	return append(out, value...)
}

func validMACString(value []byte) bool {
	if len(value) != 17 {
		return false
	}
	for index, b := range value {
		if index%3 == 2 {
			if b != ':' {
				return false
			}
			continue
		}
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
	}
	return true
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
