package releasetool

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type module struct {
	Path, Version, Sum string
}

type buildMetadata struct {
	Schema        int               `json:"schema"`
	Version       string            `json:"version"`
	Architecture  string            `json:"architecture"`
	Source        string            `json:"source_commit"`
	Dirty         bool              `json:"source_dirty"`
	Epoch         int64             `json:"source_date_epoch"`
	GoVersion     string            `json:"go_version"`
	CGo           bool              `json:"cgo_enabled"`
	Binary        string            `json:"binary_sha256"`
	Compatibility map[string]any    `json:"compatibility"`
	Modules       []module          `json:"modules"`
	Payload       map[string]string `json:"payload_sha256"`
	Artifacts     map[string]string `json:"artifacts,omitempty"`
}

var supportFiles = map[string]string{
	"systemd/discovery-bridge-collector.service": "usr/lib/systemd/system/discovery-bridge-collector.service",
	"systemd/discovery-bridge-publisher.service": "usr/lib/systemd/system/discovery-bridge-publisher.service",
	"sysusers/discovery-bridge.conf":             "usr/lib/sysusers.d/discovery-bridge.conf",
	"tmpfiles/discovery-bridge.conf":             "usr/lib/tmpfiles.d/discovery-bridge.conf",
	"dbus/org.discovery-bridge.conf":             "usr/share/dbus-1/system.d/org.discovery-bridge.conf",
	"examples/router.disabled.json":              "usr/share/doc/discovery-bridge/examples/router.disabled.json",
	"README.md":                                  "usr/share/doc/discovery-bridge/INSTALL.md",
}

func (t tool) pinnedGo() (string, error) {
	data, err := os.ReadFile(t.path(".go-version"))
	return "go" + strings.TrimSpace(string(data)), err
}

func (t tool) compile() error {
	if !versionPattern.MatchString(t.settings.version) {
		return errors.New("release version must be MAJOR.MINOR.PATCH with optional prerelease")
	}
	env := []string{"CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOFLAGS="}
	data, err := t.command(env, "go", "env", "-json", "GOVERSION", "GOOS", "GOARCH", "GOROOT")
	if err != nil {
		return err
	}
	var settings map[string]string
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	pinned, err := t.pinnedGo()
	if err != nil {
		return err
	}
	t.settings.arch = settings["GOARCH"]
	if err := t.validateNative(); err != nil {
		return err
	}
	if settings["GOVERSION"] != pinned || settings["GOOS"] != "linux" {
		return errors.New("use the pinned Go compiler on native Linux")
	}
	directory := t.path("dist", "native", t.settings.arch)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	binary := filepath.Join(directory, "discovery-bridge")
	if _, err := t.command(env, "go", "build", "-trimpath", "-buildvcs=true", "-ldflags",
		"-s -w -X main.version="+t.settings.version, "-o", binary, "./cmd/discovery-bridge"); err != nil {
		return err
	}
	version, err := t.text(binary, "version")
	if err != nil {
		return err
	}
	if version != "discovery-bridge "+t.settings.version+" ("+pinned+")" {
		return errors.New("compiled version differs from requested inputs")
	}
	licenses := filepath.Join(directory, "licenses")
	if err := os.RemoveAll(licenses); err != nil {
		return err
	}
	for source, name := range map[string]string{
		t.path("LICENSE"): "discovery-bridge.txt", filepath.Join(settings["GOROOT"], "LICENSE"): "go.txt",
	} {
		if err := copyFile(source, filepath.Join(licenses, name), 0644); err != nil {
			return err
		}
	}
	data, err = t.command(env, "go", "list", "-deps", "-json", "./cmd/discovery-bridge")
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	modules := map[string]module{}
	for {
		var entry struct {
			Module *struct {
				module
				Main    bool
				Dir     string
				Replace any
			}
		}
		if err := decoder.Decode(&entry); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if entry.Module == nil || entry.Module.Main {
			continue
		}
		m := entry.Module
		if m.Replace != nil {
			return errors.New("release modules must not use local replacements")
		}
		if _, exists := modules[m.Path]; exists {
			continue
		}
		modules[m.Path] = m.module
		count := 0
		for _, pattern := range []string{"LICENSE*", "COPYING*", "NOTICE*", "PATENTS*"} {
			paths, err := filepath.Glob(filepath.Join(m.Dir, pattern))
			if err != nil {
				return err
			}
			for _, source := range paths {
				info, err := os.Stat(source)
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					continue
				}
				name := strings.ReplaceAll(m.Path, "/", "_") + "-" + filepath.Base(source)
				if err := copyFile(source, filepath.Join(licenses, name), 0644); err != nil {
					return err
				}
				count++
			}
		}
		if count == 0 {
			return fmt.Errorf("missing linked module license: %s", m.Path)
		}
	}
	source, err := t.text("git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	status, err := t.text("git", "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return err
	}
	epochText, err := t.text("git", "show", "-s", "--format=%ct", "HEAD")
	if err != nil {
		return err
	}
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil {
		return err
	}
	digest, err := checksum(binary)
	if err != nil {
		return err
	}
	metadata := buildMetadata{Schema: 1, Version: t.settings.version, Architecture: t.settings.arch,
		Source: source, Dirty: status != "", Epoch: epoch, GoVersion: pinned, Binary: digest,
		Compatibility: map[string]any{"catalog_schema": 1, "snapshot_schemas": []int{1, 2},
			"sqlite_schema": "identities-reservations-gateway_generation"}, Modules: []module{}}
	for _, m := range modules {
		metadata.Modules = append(metadata.Modules, m)
	}
	slices.SortFunc(metadata.Modules, func(a, b module) int { return strings.Compare(a.Path, b.Path) })
	buildInfo, err := t.text("go", "version", "-m", binary)
	if err != nil {
		return err
	}
	for _, field := range []string{"-trimpath=true", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + t.settings.arch,
		"vcs.revision=" + source, "vcs.modified=" + strconv.FormatBool(metadata.Dirty)} {
		if !strings.Contains(buildInfo+"\n", "\tbuild\t"+field+"\n") {
			return fmt.Errorf("compiled build metadata differs: %s", field)
		}
	}
	metadata.Payload, err = t.payloadChecksums()
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(directory, "build.json"), metadata)
}

func (t tool) payload() (map[string]string, error) {
	native := t.path("dist", "native", t.settings.arch)
	files := map[string]string{
		"usr/bin/discovery-bridge":                   filepath.Join(native, "discovery-bridge"),
		"usr/share/doc/discovery-bridge/build.json":  filepath.Join(native, "build.json"),
		"usr/share/doc/discovery-bridge/CONTRACT.md": t.path("docs", "CONTRACT.md"),
	}
	for source, target := range supportFiles {
		files[target] = t.path("packaging", source)
	}
	for _, name := range []string{"manifest.json", "service-types", "iana.csv", "COPYING.avahi"} {
		files["usr/share/discovery-bridge/registry/"+name] = t.path("registry", name)
	}
	licenses, err := os.ReadDir(filepath.Join(native, "licenses"))
	if err != nil {
		return nil, err
	}
	for _, entry := range licenses {
		if !entry.Type().IsRegular() {
			return nil, errors.New("unexpected license file type")
		}
		files["usr/share/doc/discovery-bridge/licenses/"+entry.Name()] = filepath.Join(native, "licenses", entry.Name())
	}
	return files, nil
}

func (t tool) payloadChecksums() (map[string]string, error) {
	files, err := t.payload()
	if err != nil {
		return nil, err
	}
	sums := map[string]string{}
	for target, source := range files {
		if target == "usr/share/doc/discovery-bridge/build.json" {
			continue
		}
		sums[target], err = checksum(source)
		if err != nil {
			return nil, err
		}
	}
	return sums, nil
}

func (t tool) packageArtifacts() error {
	if err := t.validateNative(); err != nil {
		return err
	}
	var metadata buildMetadata
	if err := readJSON(t.path("dist", "native", t.settings.arch, "build.json"), &metadata); err != nil {
		return err
	}
	actual, err := checksum(t.path("dist", "native", t.settings.arch, "discovery-bridge"))
	if err != nil {
		return err
	}
	sums, err := t.payloadChecksums()
	if err != nil {
		return err
	}
	if metadata.Version != t.settings.version || metadata.Architecture != t.settings.arch || actual != metadata.Binary || !equalJSON(sums, metadata.Payload) {
		return errors.New("package inputs changed after native compilation")
	}
	files, err := t.payload()
	if err != nil {
		return err
	}
	names := sortedKeys(files)
	directory := t.path("dist", "releases", t.settings.arch)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	base := "discovery-bridge_" + metadata.Version
	archive := filepath.Join(directory, base+"_linux_"+t.settings.arch+".tar.gz")
	if err := makeArchive(archive, files, metadata.Epoch); err != nil {
		return err
	}
	staging, err := os.MkdirTemp("", "bridge-package-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0755); err != nil {
		return err
	}
	for _, name := range names {
		if err := copyFile(files[name], filepath.Join(staging, name), payloadMode(name)); err != nil {
			return err
		}
	}
	control := filepath.Join(staging, "DEBIAN")
	if err := os.Mkdir(control, 0755); err != nil {
		return err
	}
	text := "Package: discovery-bridge\nVersion: " + strings.Replace(metadata.Version, "-", "~", 1) + "\nArchitecture: " + t.settings.arch + "\n" +
		"Maintainer: Discovery Bridge contributors <maintainers@discovery-bridge.example>\nSection: net\nPriority: optional\n" +
		"Depends: avahi-daemon, dbus, iproute2, systemd (>= 257)\nHomepage: " + repository + "\n" +
		"Description: Linux mDNS and DNS-SD adapters for Kubernetes\n" +
		" Leased discovery catalogs, pod responses and explicit Service publication.\n"
	if err := os.WriteFile(filepath.Join(control, "control"), []byte(text), 0644); err != nil {
		return err
	}
	if err := copyFile(t.path("packaging", "debian", "postinst"), filepath.Join(control, "postinst"), 0755); err != nil {
		return err
	}
	stamp := time.Unix(metadata.Epoch, 0)
	if err := filepath.WalkDir(staging, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, stamp, stamp)
	}); err != nil {
		return err
	}
	deb := filepath.Join(directory, base+"_"+t.settings.arch+".deb")
	if _, err := t.command([]string{"SOURCE_DATE_EPOCH=" + strconv.FormatInt(metadata.Epoch, 10)}, "dpkg-deb",
		"--root-owner-group", "--build", "--uniform-compression", "-Zxz", staging, deb); err != nil {
		return err
	}
	metadata.Artifacts = map[string]string{}
	for _, path := range []string{archive, deb} {
		metadata.Artifacts[filepath.Base(path)], err = checksum(path)
		if err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(directory, "build.json"), metadata); err != nil {
		return err
	}
	checks := map[string]string{}
	for name, sum := range metadata.Artifacts {
		checks[name] = sum
	}
	checks["build.json"], err = checksum(filepath.Join(directory, "build.json"))
	if err != nil {
		return err
	}
	return writeChecksums(filepath.Join(directory, "SHA256SUMS"), checks)
}

func payloadMode(name string) os.FileMode {
	if name == "usr/bin/discovery-bridge" {
		return 0755
	}
	return 0644
}

func sortedKeys[T any](values map[string]T) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func equalJSON(a, b any) bool {
	first, err := json.Marshal(a)
	second, other := json.Marshal(b)
	return err == nil && other == nil && string(first) == string(second)
}

func makeArchive(path string, files map[string]string, epoch int64) (err error) {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	compressed := gzip.NewWriter(out)
	defer func() { err = errors.Join(err, compressed.Close()) }()
	archive := tar.NewWriter(compressed)
	defer func() { err = errors.Join(err, archive.Close()) }()
	for _, name := range sortedKeys(files) {
		data, err := os.ReadFile(files[name])
		if err != nil {
			return err
		}
		header := &tar.Header{Name: name, Mode: int64(payloadMode(name)), Size: int64(len(data)), ModTime: time.Unix(epoch, 0), Format: tar.FormatUSTAR}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		if _, err := archive.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func writeChecksums(path string, checks map[string]string) error {
	var output strings.Builder
	for _, name := range sortedKeys(checks) {
		fmt.Fprintf(&output, "%s  %s\n", checks[name], name)
	}
	return os.WriteFile(path, []byte(output.String()), 0644)
}
