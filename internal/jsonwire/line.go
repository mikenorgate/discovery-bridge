package jsonwire

import (
	"bufio"
	"errors"
)

// ReadLine reads one bounded newline-delimited frame without accepting partial
// EOF frames. The caller supplies the transport's read deadline.
func ReadLine(reader *bufio.Reader, limit int) ([]byte, error) {
	if limit < 1 {
		return nil, errors.New("invalid frame limit")
	}
	result := []byte{}
	for {
		part, err := reader.ReadSlice('\n')
		if len(result)+len(part) > limit {
			return nil, errors.New("local frame byte limit")
		}
		result = append(result, part...)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}
