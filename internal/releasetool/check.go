package releasetool

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

func (t tool) checkSource() error {
	data, err := t.command(nil, "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return err
	}
	allowed := strings.Fields(".github cmd internal registry packaging tests docs .gitignore .dockerignore .go-version .golangci.yml Makefile README.md LICENSE go.mod go.sum Containerfile")
	bad := strings.Fields("vault inventory inventories build-inputs captures")
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`),
		regexp.MustCompile("/home/" + `[^/\s]+/`),
		regexp.MustCompile(`[a-zA-Z0-9.-]+\.xyz\b`),
	}
	var problems []error
	for _, name := range strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00") {
		parts := strings.Split(name, "/")
		if !contains(allowed, parts[0]) {
			problems = append(problems, fmt.Errorf("%s: excluded source path", name))
			continue
		}
		for _, part := range parts {
			if contains(bad, part) {
				problems = append(problems, fmt.Errorf("%s: excluded source path", name))
			}
		}
		if contains(strings.Fields(".pcap .pcapng .db .sqlite .log .stderr .pem .key .py"), filepath.Ext(name)) {
			problems = append(problems, fmt.Errorf("%s: excluded artifact", name))
			continue
		}
		info, err := os.Lstat(t.path(name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			problems = append(problems, fmt.Errorf("%s: source must be a regular file", name))
			continue
		}
		if strings.HasPrefix(name, "registry/") && filepath.Base(name) != "assets.go" {
			continue
		}
		content, err := os.ReadFile(t.path(name))
		if err != nil {
			return err
		}
		for _, pattern := range patterns {
			if pattern.Match(content) {
				problems = append(problems, fmt.Errorf("%s: private file or identifier pattern", name))
				break
			}
		}
	}
	return errors.Join(problems...)
}

func (t tool) checkArtifacts() error {
	if err := t.validateNative(); err != nil {
		return err
	}
	directory := t.path("dist", "releases", t.settings.arch)
	var metadata buildMetadata
	if err := readJSON(filepath.Join(directory, "build.json"), &metadata); err != nil {
		return err
	}
	pinned, err := t.pinnedGo()
	if err != nil {
		return err
	}
	if metadata.Architecture != t.settings.arch || metadata.GoVersion != pinned || metadata.CGo || len(metadata.Artifacts) != 2 {
		return errors.New("artifact compiler or architecture differs")
	}
	checks := map[string]string{}
	for name, expected := range metadata.Artifacts {
		if filepath.Base(name) != name {
			return errors.New("invalid artifact path")
		}
		file := filepath.Join(directory, name)
		sum, err := checksum(file)
		if err != nil {
			return err
		}
		if sum != expected {
			return fmt.Errorf("artifact checksum differs: %s", name)
		}
		checks[name] = sum
		if strings.HasSuffix(name, ".deb") {
			data, err := t.command(nil, "dpkg-deb", "--fsys-tarfile", file)
			if err != nil {
				return err
			}
			if err := t.inspectPayload(tar.NewReader(bytes.NewReader(data)), metadata); err != nil {
				return err
			}
			control, err := t.text("dpkg-deb", "--field", file)
			if err != nil {
				return err
			}
			if !strings.Contains(control+"\n", "Architecture: "+metadata.Architecture+"\n") || !strings.Contains(control+"\n", "Version: "+strings.Replace(metadata.Version, "-", "~", 1)+"\n") {
				return errors.New("debian control provenance differs")
			}
			data, err = t.command(nil, "dpkg-deb", "--ctrl-tarfile", file)
			if err != nil {
				return err
			}
			if err := t.inspectControl(tar.NewReader(bytes.NewReader(data))); err != nil {
				return err
			}
		} else if strings.HasSuffix(name, ".tar.gz") {
			if err := t.inspectArchive(file, metadata); err != nil {
				return err
			}
		} else {
			return errors.New("unexpected package artifact")
		}
	}
	checks["build.json"], err = checksum(filepath.Join(directory, "build.json"))
	if err != nil {
		return err
	}
	return checkChecksums(filepath.Join(directory, "SHA256SUMS"), checks)
}

func (t tool) inspectArchive(file string, metadata buildMetadata) (err error) {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	z, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, z.Close()) }()
	return t.inspectPayload(tar.NewReader(z), metadata)
}

func (t tool) inspectPayload(reader *tar.Reader, metadata buildMetadata) error {
	expected := map[string]string{}
	for name, sum := range metadata.Payload {
		expected[name] = sum
	}
	sum, err := checksum(t.path("dist", "native", metadata.Architecture, "build.json"))
	if err != nil {
		return err
	}
	expected["usr/share/doc/discovery-bridge/build.json"] = sum
	found := map[string]string{}
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if h.Typeflag == tar.TypeDir && (name == "" || name == ".") {
			continue
		}
		if path.IsAbs(name) || contains(strings.Split(name, "/"), "..") || h.Uid != 0 || h.Gid != 0 || !contains([]string{"", "root"}, h.Uname) || !contains([]string{"", "root"}, h.Gname) {
			return errors.New("unsafe package ownership or path")
		}
		if h.Typeflag == tar.TypeDir {
			ancestor := false
			for file := range expected {
				ancestor = ancestor || strings.HasPrefix(file, name+"/")
			}
			if !ancestor {
				return errors.New("unexpected package directory")
			}
			continue
		}
		if h.Typeflag != tar.TypeReg || expected[name] == "" || found[name] != "" || h.ModTime.Unix() != metadata.Epoch || h.Mode != int64(payloadMode(name)) {
			return fmt.Errorf("invalid package member: %s", name)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		found[name] = hex.EncodeToString(digest[:])
		if found[name] != expected[name] {
			return fmt.Errorf("package payload checksum differs: %s", name)
		}
		if name == "usr/bin/discovery-bridge" {
			if len(content) < 20 || !bytes.Equal(content[:6], []byte{0x7f, 'E', 'L', 'F', 2, 1}) || binary.LittleEndian.Uint16(content[18:20]) != map[string]uint16{"amd64": 62, "arm64": 183}[metadata.Architecture] || bytes.Contains(content, []byte("/home/")) || bytes.Contains(content, []byte("/Users/")) {
				return errors.New("binary architecture or trimmed paths differ")
			}
		}
	}
	return require(equalJSON(found, expected), "incomplete release payload")
}

func (t tool) inspectControl(reader *tar.Reader) error {
	found := map[string]bool{}
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir && (name == "." || name == "") {
			continue
		}
		mode := int64(0644)
		if name == "postinst" {
			mode = 0755
		}
		if h.Typeflag != tar.TypeReg || !contains([]string{"control", "postinst"}, name) || found[name] || h.Mode != mode || h.Uid != 0 || h.Gid != 0 {
			return errors.New("invalid Debian control member")
		}
		found[name] = true
		if name == "postinst" {
			actual, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			expected, err := os.ReadFile(t.path("packaging", "debian", "postinst"))
			if err != nil {
				return err
			}
			if !bytes.Equal(actual, expected) {
				return errors.New("debian install script differs")
			}
		}
	}
	return require(len(found) == 2, "incomplete Debian control files")
}
