package releasetool

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

type containerInputs struct {
	Base          string                       `json:"base"`
	Debian        string                       `json:"debian_snapshot"`
	Security      string                       `json:"security_snapshot"`
	Kubectl       string                       `json:"kubectl_version"`
	Crictl        string                       `json:"crictl_version"`
	Architectures map[string]map[string]string `json:"architectures"`
	Licenses      map[string]string            `json:"licenses"`
}

type imageMetadata struct {
	Digest    string `json:"platform_digest"`
	Config    string `json:"config_digest"`
	Reference string `json:"qualified_reference"`
	Archive   string `json:"archive"`
	SHA256    string `json:"sha256"`
}

type containerMetadata struct {
	buildMetadata
	Inputs   containerInputs   `json:"container_inputs"`
	Binaries map[string]string `json:"container_binary_sha256"`
	Image    imageMetadata     `json:"image"`
}

func (t tool) download(url, path, expected string) (err error) {
	if sum, err := checksum(path); err == nil && sum == expected {
		return nil
	}
	client := http.Client{Timeout: 30 * time.Second, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" || len(via) >= 10 {
			return errors.New("invalid release input redirect")
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(t.ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("release input HTTP status %d", response.StatusCode)
	}
	temporary := path + ".partial"
	defer func() { _ = os.Remove(temporary) }()
	f, err := os.Create(temporary)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(response.Body, 128*1024*1024+1))
	if err := errors.Join(copyErr, f.Close()); err != nil {
		return err
	}
	if n > 128*1024*1024 {
		return errors.New("release input exceeds size limit")
	}
	sum, err := checksum(temporary)
	if err != nil {
		return err
	}
	if sum != expected {
		return fmt.Errorf("release input checksum mismatch: %s", filepath.Base(path))
	}
	return os.Rename(temporary, path)
}

func (t tool) prepareContainer() error {
	if err := t.validateNative(); err != nil {
		return err
	}
	var metadata containerMetadata
	native := t.path("dist", "native", t.settings.arch)
	if err := readJSON(filepath.Join(native, "build.json"), &metadata); err != nil {
		return err
	}
	sum, err := checksum(filepath.Join(native, "discovery-bridge"))
	if err != nil {
		return err
	}
	if metadata.Architecture != t.settings.arch || sum != metadata.Binary {
		return errors.New("container input differs from native build")
	}
	if err := readJSON(t.path("packaging", "container-inputs.json"), &metadata.Inputs); err != nil {
		return err
	}
	directory := t.path("dist", "container", t.settings.arch)
	if err := os.RemoveAll(directory); err != nil {
		return err
	}
	binaries := filepath.Join(directory, "bin")
	if err := os.MkdirAll(binaries, 0755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(native, "discovery-bridge"), filepath.Join(binaries, "discovery-bridge"), 0555); err != nil {
		return err
	}
	inputs := metadata.Inputs
	checks := inputs.Architectures[t.settings.arch]
	if err := t.download("https://dl.k8s.io/release/"+inputs.Kubectl+"/bin/linux/"+t.settings.arch+"/kubectl", filepath.Join(binaries, "kubectl"), checks["kubectl"]); err != nil {
		return err
	}
	archive := t.path("dist", "crictl-"+t.settings.arch+".tar.gz")
	if err := t.download("https://github.com/kubernetes-sigs/cri-tools/releases/download/"+inputs.Crictl+"/crictl-"+inputs.Crictl+"-linux-"+t.settings.arch+".tar.gz", archive, checks["crictl_archive"]); err != nil {
		return err
	}
	if err := extractCrictl(archive, filepath.Join(binaries, "crictl")); err != nil {
		return err
	}
	metadata.Binaries = map[string]string{}
	for _, name := range []string{"discovery-bridge", "kubectl", "crictl"} {
		path := filepath.Join(binaries, name)
		if err := os.Chmod(path, 0555); err != nil {
			return err
		}
		sum, err := checksum(path)
		if err != nil {
			return err
		}
		metadata.Binaries[name] = sum
	}
	licenses := filepath.Join(directory, "licenses")
	entries, err := os.ReadDir(filepath.Join(native, "licenses"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return errors.New("unexpected native license entry")
		}
		if err := copyFile(filepath.Join(native, "licenses", entry.Name()), filepath.Join(licenses, entry.Name()), 0644); err != nil {
			return err
		}
	}
	if err := copyFile(t.path("registry", "COPYING.avahi"), filepath.Join(licenses, "Avahi-registry.txt"), 0644); err != nil {
		return err
	}
	for name, url := range map[string]string{
		"kubectl": "https://raw.githubusercontent.com/kubernetes/kubernetes/" + inputs.Kubectl + "/LICENSE",
		"crictl":  "https://raw.githubusercontent.com/kubernetes-sigs/cri-tools/" + inputs.Crictl + "/LICENSE",
	} {
		if err := t.download(url, filepath.Join(licenses, name+".txt"), inputs.Licenses[name]); err != nil {
			return err
		}
	}
	for _, name := range []string{"Containerfile", ".dockerignore"} {
		if err := copyFile(t.path(name), filepath.Join(directory, name), 0644); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(directory, "metadata.json"), metadata); err != nil {
		return err
	}
	return writeChecksums(filepath.Join(directory, "SHA256SUMS"), metadata.Binaries)
}

func extractCrictl(archive, output string) (err error) {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	z, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, z.Close()) }()
	r := tar.NewReader(z)
	found := false
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if h.Name != "crictl" {
			continue
		}
		if found || h.Typeflag != tar.TypeReg || h.Size > 128*1024*1024 {
			return errors.New("invalid crictl archive member")
		}
		found = true
		out, err := os.Create(output)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, r)
		if err := errors.Join(copyErr, out.Close()); err != nil {
			return err
		}
	}
	return require(found, "crictl archive member missing")
}

func (t tool) buildContainer() error {
	if err := t.validateNative(); err != nil {
		return err
	}
	if runtime.GOARCH != t.settings.arch {
		return errors.New("container build requires a native runner")
	}
	directory := t.path("dist", "container", t.settings.arch)
	var metadata containerMetadata
	if err := readJSON(filepath.Join(directory, "metadata.json"), &metadata); err != nil {
		return err
	}
	tag := imageName + ":v" + metadata.Version
	inputs := metadata.Inputs
	if _, err := t.command(nil, "podman", "build", "--format=oci", "--layers", "--timestamp="+strconv.FormatInt(metadata.Epoch, 10),
		"--build-arg", "BASE_IMAGE="+inputs.Base, "--build-arg", "DEBIAN_SNAPSHOT="+inputs.Debian,
		"--build-arg", "SECURITY_SNAPSHOT="+inputs.Security, "--label", "org.opencontainers.image.source="+repository,
		"--label", "org.opencontainers.image.revision="+metadata.Source, "--label", "org.opencontainers.image.version="+metadata.Version, "--tag", tag, directory); err != nil {
		return err
	}
	release := t.path("dist", "releases", t.settings.arch)
	if err := os.MkdirAll(release, 0755); err != nil {
		return err
	}
	archive := "discovery-bridge_" + metadata.Version + "_linux_" + t.settings.arch + ".oci.tar"
	path := filepath.Join(release, archive)
	if _, err := t.command(nil, "podman", "save", "--format=oci-archive", "--output", path, tag); err != nil {
		return err
	}
	graph, err := readOCI(path)
	if err != nil {
		return err
	}
	id, err := t.text("podman", "image", "inspect", tag, "--format", "{{.Id}}")
	if err != nil {
		return err
	}
	if graph.Manifest.Config.Digest != "sha256:"+strings.TrimPrefix(id, "sha256:") {
		return errors.New("exported OCI configuration differs from built image")
	}
	if _, err := t.command(nil, "podman", "load", "--input", path); err != nil {
		return err
	}
	reference := "localhost/discovery-bridge-qualified:" + t.settings.arch
	if _, err := t.command(nil, "podman", "tag", graph.Manifest.Config.Digest, reference); err != nil {
		return err
	}
	sum, err := checksum(path)
	if err != nil {
		return err
	}
	metadata.Image = imageMetadata{Digest: graph.Descriptor.Digest, Config: graph.Manifest.Config.Digest, Reference: reference, Archive: archive, SHA256: sum}
	if _, err := inspectOCI(path, metadata); err != nil {
		return err
	}
	return writeJSON(filepath.Join(release, "container.json"), metadata)
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    map[string]string `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type imageIndex struct {
	Schema    int          `json:"schemaVersion"`
	MediaType string       `json:"mediaType,omitempty"`
	Manifests []descriptor `json:"manifests"`
}

type imageManifest struct {
	Schema int          `json:"schemaVersion"`
	Config descriptor   `json:"config"`
	Layers []descriptor `json:"layers"`
}

type ociGraph struct {
	Descriptor descriptor
	Manifest   imageManifest
	Config     struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		RootFS       struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
		Runtime struct {
			Entrypoint, Cmd, Env []string
			User                 string
			Labels               map[string]string
		} `json:"config"`
	}
}

func readOCI(path string) (graph ociGraph, err error) {
	f, err := os.Open(path)
	if err != nil {
		return graph, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	r := tar.NewReader(f)
	files := map[string]int64{}
	data := map[string][]byte{}
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return graph, err
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if h.Typeflag == tar.TypeDir {
			if !slices.Contains([]string{"", ".", "blobs", "blobs/sha256"}, name) {
				return graph, errors.New("unexpected OCI directory")
			}
			continue
		}
		_, duplicate := files[name]
		if h.Typeflag != tar.TypeReg || duplicate {
			return graph, errors.New("invalid or duplicate OCI member")
		}
		if name != "index.json" && name != "oci-layout" && !strings.HasPrefix(name, "blobs/sha256/") {
			return graph, errors.New("unexpected OCI member")
		}
		files[name] = h.Size
		hash := sha256.New()
		if h.Size <= 4*1024*1024 {
			content, err := io.ReadAll(r)
			if err != nil {
				return graph, err
			}
			data[name] = content
			_, _ = hash.Write(content)
		} else {
			if name == "index.json" || name == "oci-layout" {
				return graph, errors.New("oversized OCI metadata")
			}
			if _, err := io.Copy(hash, r); err != nil {
				return graph, err
			}
		}
		if strings.HasPrefix(name, "blobs/sha256/") && strings.TrimPrefix(name, "blobs/sha256/") != hex.EncodeToString(hash.Sum(nil)) {
			return graph, errors.New("OCI blob checksum mismatch")
		}
	}
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(data["oci-layout"], &layout); err != nil {
		return graph, err
	}
	if layout.Version != "1.0.0" {
		return graph, errors.New("invalid OCI layout version")
	}
	var index imageIndex
	if err := json.Unmarshal(data["index.json"], &index); err != nil {
		return graph, err
	}
	if index.Schema != 2 || len(index.Manifests) != 1 {
		return graph, errors.New("expected one qualified OCI platform manifest")
	}
	graph.Descriptor = index.Manifests[0]
	nameFor := func(value descriptor) (string, error) {
		name := "blobs/sha256/" + strings.TrimPrefix(value.Digest, "sha256:")
		if !strings.HasPrefix(value.Digest, "sha256:") || len(value.Digest) != 71 || files[name] != value.Size || value.Size <= 0 {
			return "", errors.New("OCI descriptor differs from blob")
		}
		return name, nil
	}
	manifestName, err := nameFor(graph.Descriptor)
	if err != nil {
		return graph, err
	}
	if err := json.Unmarshal(data[manifestName], &graph.Manifest); err != nil {
		return graph, err
	}
	if graph.Manifest.Schema != 2 {
		return graph, errors.New("invalid OCI manifest schema")
	}
	configName, err := nameFor(graph.Manifest.Config)
	if err != nil {
		return graph, err
	}
	if err := json.Unmarshal(data[configName], &graph.Config); err != nil {
		return graph, err
	}
	expected := map[string]bool{"index.json": true, "oci-layout": true, manifestName: true, configName: true}
	for _, layer := range graph.Manifest.Layers {
		name, err := nameFor(layer)
		if err != nil {
			return graph, err
		}
		expected[name] = true
	}
	if len(expected) != len(files) || len(graph.Config.RootFS.DiffIDs) != len(graph.Manifest.Layers) {
		return graph, errors.New("incomplete or unexpected OCI graph")
	}
	return graph, nil
}

func inspectOCI(path string, metadata containerMetadata) (descriptor, error) {
	sum, err := checksum(path)
	if err != nil {
		return descriptor{}, err
	}
	if sum != metadata.Image.SHA256 {
		return descriptor{}, errors.New("OCI archive checksum mismatch")
	}
	graph, err := readOCI(path)
	if err != nil {
		return descriptor{}, err
	}
	r := graph.Config.Runtime
	if graph.Descriptor.Digest != metadata.Image.Digest || graph.Manifest.Config.Digest != metadata.Image.Config ||
		graph.Config.Architecture != metadata.Architecture || graph.Config.OS != "linux" ||
		!slices.Equal(r.Entrypoint, []string{"/usr/bin/discovery-bridge"}) || !slices.Equal(r.Cmd, []string{"version"}) ||
		r.User != "65532:65532" || !slices.Contains(r.Env, "GOMAXPROCS=2") ||
		r.Labels["org.opencontainers.image.source"] != repository || r.Labels["org.opencontainers.image.revision"] != metadata.Source || r.Labels["org.opencontainers.image.version"] != metadata.Version {
		return descriptor{}, errors.New("OCI runtime or provenance differs from qualified inputs")
	}
	return graph.Descriptor, nil
}

func (t tool) checkContainer() error {
	if err := t.validateNative(); err != nil {
		return err
	}
	directory := t.path("dist", "releases", t.settings.arch)
	var metadata containerMetadata
	if err := readJSON(filepath.Join(directory, "container.json"), &metadata); err != nil {
		return err
	}
	if _, err := inspectOCI(filepath.Join(directory, metadata.Image.Archive), metadata); err != nil {
		return err
	}
	run := func(program string, args ...string) (string, error) {
		base := []string{"run", "--runtime=runc", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=192m", "--pids-limit=64", "--entrypoint=" + program, metadata.Image.Reference}
		return t.text("podman", append(base, args...)...)
	}
	version, err := run("/usr/bin/discovery-bridge", "version")
	if err != nil {
		return err
	}
	if version != "discovery-bridge "+metadata.Version+" ("+metadata.GoVersion+")" {
		return errors.New("imported binary version differs")
	}
	output, err := run("/usr/bin/kubectl", "version", "--client=true", "--output=json")
	if err != nil {
		return err
	}
	var client struct {
		Version struct {
			Git string `json:"gitVersion"`
		} `json:"clientVersion"`
	}
	if err := json.Unmarshal([]byte(output), &client); err != nil {
		return err
	}
	if client.Version.Git != metadata.Inputs.Kubectl {
		return errors.New("imported kubectl version differs")
	}
	version, err = run("/usr/bin/crictl", "--version")
	if err != nil {
		return err
	}
	if version != "crictl version "+metadata.Inputs.Crictl {
		return errors.New("imported crictl version differs")
	}
	version, err = run("/usr/sbin/ip", "-Version")
	if err != nil {
		return err
	}
	if !strings.Contains(version, "iproute2") {
		return errors.New("iproute2 missing")
	}
	for name, expected := range metadata.Binaries {
		output, err := run("/usr/bin/sha256sum", "/usr/bin/"+name)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(output, expected+" ") {
			return fmt.Errorf("imported binary checksum differs: %s", name)
		}
	}
	_, err = run("/bin/sh", "-ec", "test -s /etc/ssl/certs/ca-certificates.crt; test ! -e /usr/local/go; test ! -e /app; test ! -e /root/.kube; test ! -e /etc/discovery-bridge/router.json")
	return err
}
