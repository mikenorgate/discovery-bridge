package router

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

// notify uses systemd's inherited Unix datagram socket, with no extra service.
func notify(ctx context.Context, ready bool) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "@") {
		return errors.New("invalid systemd notification socket")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unixgram", path)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	deadline, _ := bounded.Deadline()
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	message := "WATCHDOG=1"
	if ready {
		message = "READY=1\n" + message
	}
	_, err = connection.Write([]byte(message))
	return err
}
