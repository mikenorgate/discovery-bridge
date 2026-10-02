package linuxnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// MaxMessage bounds the existing private broker IPC protocol.
const MaxMessage = 8192

// Send passes bounded JSON and at most two owned socket descriptors.
func Send(fd int, value any, descriptors []int) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > MaxMessage || len(descriptors) > 2 {
		return errors.New("broker message exceeds limit")
	}
	var control []byte
	if len(descriptors) > 0 {
		control = unix.UnixRights(descriptors...)
	}
	sent, err := unix.SendmsgN(fd, data, control, nil, unix.MSG_DONTWAIT)
	if err != nil {
		return err
	}
	if sent != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// Receive returns one JSON packet and close-on-exec descriptors owned by caller.
func Receive(fd int) (data json.RawMessage, descriptors []int, err error) {
	buffer := make([]byte, MaxMessage)
	control := make([]byte, unix.CmsgSpace(8))
	n, oobn, flags, _, err := unix.Recvmsg(fd, buffer, control, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			for _, descriptor := range descriptors {
				err = errors.Join(err, unix.Close(descriptor))
			}
			descriptors = nil
		}
	}()
	controls, err := unix.ParseSocketControlMessage(control[:oobn])
	if err != nil {
		return nil, nil, err
	}
	unexpected := false
	for _, item := range controls {
		if item.Header.Level != unix.SOL_SOCKET || item.Header.Type != unix.SCM_RIGHTS {
			unexpected = true
			continue
		}
		fds, parseErr := unix.ParseUnixRights(&item)
		if parseErr != nil {
			return nil, descriptors, parseErr
		}
		descriptors = append(descriptors, fds...)
	}
	if unexpected {
		return nil, descriptors, errors.New("unexpected broker ancillary data")
	}
	if n == 0 {
		return nil, descriptors, io.EOF
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(descriptors) > 2 {
		return nil, descriptors, errors.New("truncated broker message")
	}
	if !json.Valid(buffer[:n]) {
		return nil, descriptors, fmt.Errorf("invalid broker JSON")
	}
	return json.RawMessage(buffer[:n]), descriptors, nil
}
