package jsonwire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf16"
)

// Encode retains the ASCII JSON string encoding used by persistent identity hashes.
func Encode(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	text := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	var result bytes.Buffer
	for _, r := range string(text) {
		if r < 128 {
			result.WriteByte(byte(r))
			continue
		}
		if r <= 0xffff {
			if _, err := fmt.Fprintf(&result, "\\u%04x", r); err != nil {
				return nil, err
			}
		} else {
			first, second := utf16.EncodeRune(r)
			if _, err := fmt.Fprintf(&result, "\\u%04x\\u%04x", first, second); err != nil {
				return nil, err
			}
		}
	}
	return result.Bytes(), nil
}
