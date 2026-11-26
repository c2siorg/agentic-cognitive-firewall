package state

import (
	"errors"
	"fmt"
)

// Confirmation holds the values a user explicitly approved mid-session via the
// on_confirm hook so the session's argument-taint tracking trusts them going
// forward.
type Confirmation struct {
	Values []string
}

// ParseConfirmation validates an on_confirm payload. It expects an object with
// a non-empty list of non-empty strings under "values" (bounded by
// maxTrustedValues and maxValueLen) and rejects unknown keys.
func ParseConfirmation(payload any) (*Confirmation, error) {
	m, ok := payload.(map[string]any)
	if !ok {
		return nil, errors.New("confirmation must be an object")
	}
	for k := range m {
		if k != "values" {
			return nil, fmt.Errorf("unknown confirmation field %q", k)
		}
	}
	values, err := stringList(m["values"], "values", maxTrustedValues, true)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errors.New("values must contain at least one entry")
	}
	return &Confirmation{Values: values}, nil
}
