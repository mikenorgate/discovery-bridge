package translation

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func immutableConfig(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var info unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return nil, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != 0 || info.Mode&0022 != 0 || fs.Flags&unix.ST_RDONLY == 0 {
		return nil, errors.New("translator configuration must be root-owned and immutable")
	}
	return boundedRead(f)
}

func boundedRead(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil || len(data) > 65536 {
		return nil, errors.New("translator observation unavailable or oversized")
	}
	return data, nil
}

func processArgs(pid int) ([]byte, error) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return boundedRead(f)
}
