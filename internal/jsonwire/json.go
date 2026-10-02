// Package jsonwire decodes bounded JSON without duplicate or unknown fields.
package jsonwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Decode rejects ambiguous objects, excessive nesting and trailing documents.
func Decode(data []byte, limit int, value any) error {
	if len(data) == 0 || len(data) > limit {
		return errors.New("JSON byte limit exceeded")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := inspect(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON document")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value)
}

func inspect(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("unexpected JSON delimiter")
	}
	keys := make(map[string]bool)
	for d.More() {
		if delim == '{' {
			token, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || keys[key] {
				return errors.New("duplicate JSON field")
			}
			keys[key] = true
		}
		if err := inspect(d, depth+1); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil {
		return err
	}
	if (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return errors.New("invalid JSON closing delimiter")
	}
	return nil
}
