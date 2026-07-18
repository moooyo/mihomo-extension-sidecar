package main

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestPatchWLOCFramedWiFi(t *testing.T) {
	t.Parallel()
	originalLocation := append(encodeVarintField(1, 1), encodeVarintField(2, 2)...)
	originalLocation = append(originalLocation, encodeVarintField(3, 99)...)
	wifi := encodeLengthField(1, []byte("aa:bb:cc:dd:ee:ff"))
	wifi = append(wifi, encodeLengthField(2, originalLocation)...)
	root := encodeLengthField(2, wifi)
	frame := make([]byte, 10)
	frame[8] = byte(len(root) >> 8)
	frame[9] = byte(len(root))
	frame = append(frame, root...)
	frame = append(frame, 0xde, 0xad)

	target := wlocTarget{Longitude: -122.4194, Latitude: 37.7749, Accuracy: 25}
	patched, stats, err := patchWLOCBody(frame, target, 1<<20)
	if err != nil {
		t.Fatalf("patchWLOCBody: %v", err)
	}
	if stats.WiFi != 1 || stats.Locations != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if !bytes.Equal(patched[len(patched)-2:], []byte{0xde, 0xad}) {
		t.Fatal("frame suffix was not preserved")
	}
	location := extractPatchedWiFiLocation(t, patched[10:len(patched)-2])
	fields, err := parseProtoFields(location)
	if err != nil {
		t.Fatal(err)
	}
	wantLatitude := uint64(int64(3777490000))
	wantLongitudeSigned := int64(-12241940000)
	wantLongitude := uint64(wantLongitudeSigned)
	assertVarintField(t, fields, 1, wantLatitude)
	assertVarintField(t, fields, 2, wantLongitude)
	assertVarintField(t, fields, 3, 25)
}

func TestPatchWLOCGzipReturnsPlainPatchedBody(t *testing.T) {
	t.Parallel()
	location := append(encodeVarintField(1, 1), encodeVarintField(2, 2)...)
	wifi := append(encodeLengthField(1, []byte("00:11:22:33:44:55")), encodeLengthField(2, location)...)
	root := encodeLengthField(2, wifi)
	frame := append(make([]byte, 8), byte(len(root)>>8), byte(len(root)))
	frame = append(frame, root...)

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	patched, stats, err := patchWLOCBody(compressed.Bytes(), wlocTarget{Longitude: 1, Latitude: 2, Accuracy: 3}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if isGzip(patched) || stats.Locations != 1 {
		t.Fatalf("unexpected gzip result: gzip=%v stats=%+v", isGzip(patched), stats)
	}
}

func TestPatchWLOCRejectsUnrelatedBody(t *testing.T) {
	t.Parallel()
	if _, _, err := patchWLOCBody([]byte("not protobuf"), wlocTarget{Longitude: 1, Latitude: 2, Accuracy: 3}, 1<<20); err == nil {
		t.Fatal("unrelated body was accepted")
	}
}

func extractPatchedWiFiLocation(t *testing.T, root []byte) []byte {
	t.Helper()
	rootFields, err := parseProtoFields(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, rootField := range rootFields {
		if rootField.number != 2 || rootField.wireType != 2 {
			continue
		}
		wifiFields, err := parseProtoFields(rootField.value)
		if err != nil {
			t.Fatal(err)
		}
		for _, wifiField := range wifiFields {
			if wifiField.number == 2 && wifiField.wireType == 2 {
				return wifiField.value
			}
		}
	}
	t.Fatal("patched WiFi location not found")
	return nil
}

func assertVarintField(t *testing.T, fields []protoField, number, want uint64) {
	t.Helper()
	for _, field := range fields {
		if field.number != number || field.wireType != 0 {
			continue
		}
		got, _, err := decodeVarint(field.value)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("field %d = %d, want %d", number, got, want)
		}
		return
	}
	t.Fatalf("field %d not found", number)
}
