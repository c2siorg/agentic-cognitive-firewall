package state

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseConfirmation_AcceptsValidValues(t *testing.T) {
	c, err := ParseConfirmation(map[string]any{
		"values": []any{"UK12345678901234567890", "amy@corp.example"},
	})
	if err != nil {
		t.Fatalf("ParseConfirmation: %v", err)
	}
	want := []string{"UK12345678901234567890", "amy@corp.example"}
	if !reflect.DeepEqual(c.Values, want) {
		t.Errorf("values = %v, want %v", c.Values, want)
	}
}

func TestParseConfirmation_RejectsMalformed(t *testing.T) {
	tooMany := make([]any, maxTrustedValues+1)
	for i := range tooMany {
		tooMany[i] = "val"
	}
	cases := map[string]any{
		"not an object":     []any{"x"},
		"missing values":    map[string]any{},
		"empty values":      map[string]any{"values": []any{}},
		"unknown field":     map[string]any{"values": []any{"x"}, "admin": true},
		"wrong values type": map[string]any{"values": "x"},
		"non-string entry":  map[string]any{"values": []any{123}},
		"empty entry":       map[string]any{"values": []any{""}},
		"oversized entry":   map[string]any{"values": []any{strings.Repeat("a", maxValueLen+1)}},
		"too many entries":  map[string]any{"values": tooMany},
	}
	for name, payload := range cases {
		if _, err := ParseConfirmation(payload); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
}
