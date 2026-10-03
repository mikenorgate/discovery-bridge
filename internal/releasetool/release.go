package releasetool

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const indexMediaType = "application/vnd.oci.image.index.v1+json"

func (t tool) prepareRelease() error {
	if !versionPattern.MatchString(t.settings.version) {
		return errors.New("invalid candidate version")
	}
	if os.Getenv("GITHUB_REF_TYPE") == "tag" && os.Getenv("GITHUB_REF_NAME") != "v"+t.settings.version {
		return errors.New("candidate version differs from checked-out tag")
	}
	status, err := t.text("git", "status", "--porcelain")
	if err != nil {
		return err
	}
	if status != "" {
		return errors.New("candidates require a clean source tree")
	}
	source, err := t.text("git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	tag := exec.CommandContext(t.ctx, "git", "rev-parse", "--verify", "refs/tags/v"+t.settings.version+"^{commit}")
	tag.Dir = t.settings.root
	if data, err := tag.Output(); err == nil && strings.TrimSpace(string(data)) != source {
		return errors.New("candidate tag belongs to another source commit")
	}
	output, err := os.OpenFile(os.Getenv("GITHUB_OUTPUT"), os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(output, "version="+t.settings.version)
	return errors.Join(writeErr, output.Close())
}

func sharedBuild(metadata buildMetadata) map[string]any {
	return map[string]any{"source_date_epoch": metadata.Epoch, "go_version": metadata.GoVersion, "cgo_enabled": metadata.CGo, "compatibility": metadata.Compatibility, "modules": metadata.Modules}
}

func (t tool) assembleRelease() error {
	if !versionPattern.MatchString(t.settings.version) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(t.settings.source) ||
		!regexp.MustCompile(`^`+regexp.QuoteMeta(repository)+`/actions/runs/[0-9]+$`).MatchString(t.settings.qualification) {
		return errors.New("invalid release version, source commit or qualification URL")
	}
	if t.settings.output == "" || t.settings.layout == "" || t.settings.input == "" {
		return errors.New("release input, output and layout required")
	}
	output, layout, input := t.path(t.settings.output), t.path(t.settings.layout), t.path(t.settings.input)
	for _, directory := range []string{output, layout} {
		if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
			return errors.New("use new release output and OCI layout directories")
		}
	}
	pinned, err := t.pinnedGo()
	if err != nil {
		return err
	}
	var sourceInputs containerInputs
	if err := readJSON(t.path("packaging", "container-inputs.json"), &sourceInputs); err != nil {
		return err
	}
	platforms := map[string]any{}
	files := map[string]string{}
	archives := []string{}
	descriptors := []descriptor{}
	var common map[string]any
	for _, arch := range []string{"amd64", "arm64"} {
		directory := filepath.Join(input, "qualified-"+arch)
		var build buildMetadata
		var container containerMetadata
		if err := readJSON(filepath.Join(directory, "build.json"), &build); err != nil {
			return err
		}
		if err := readJSON(filepath.Join(directory, "container.json"), &container); err != nil {
			return err
		}
		archive := "discovery-bridge_" + t.settings.version + "_linux_" + arch + ".oci.tar"
		packageNames := []string{"discovery-bridge_" + t.settings.version + "_linux_" + arch + ".tar.gz", "discovery-bridge_" + t.settings.version + "_" + arch + ".deb"}
		expected := append([]string{"build.json", "container.json", "SHA256SUMS", archive}, packageNames...)
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		if len(entries) != len(expected) {
			return fmt.Errorf("unexpected qualified platform files: %s", arch)
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() || !contains(expected, entry.Name()) {
				return errors.New("unexpected qualified input")
			}
		}
		for _, metadata := range []buildMetadata{build, container.buildMetadata} {
			if metadata.Architecture != arch || metadata.Version != t.settings.version || metadata.Source != t.settings.source || metadata.Dirty || metadata.GoVersion != pinned || metadata.CGo {
				return fmt.Errorf("qualified platform provenance differs: %s", arch)
			}
		}
		shared := sharedBuild(build)
		if !equalJSON(shared, sharedBuild(container.buildMetadata)) || build.Binary != container.Binary || !equalJSON(build.Payload, container.Payload) ||
			!equalJSON(container.Inputs, sourceInputs) || container.Binaries["discovery-bridge"] != build.Binary || container.Image.Archive != archive {
			return errors.New("package and container build inputs differ")
		}
		shared["container_inputs"] = container.Inputs
		if common != nil && !equalJSON(common, shared) {
			return errors.New("platforms differ in shared build inputs")
		}
		common = shared
		if len(build.Artifacts) != 2 {
			return errors.New("unexpected package checksum inputs")
		}
		checks := map[string]string{}
		for _, name := range packageNames {
			sum, err := checksum(filepath.Join(directory, name))
			if err != nil {
				return err
			}
			if build.Artifacts[name] != sum {
				return errors.New("qualified package checksum mismatch")
			}
			checks[name] = sum
			files[name] = filepath.Join(directory, name)
		}
		checks["build.json"], err = checksum(filepath.Join(directory, "build.json"))
		if err != nil {
			return err
		}
		if err := checkChecksums(filepath.Join(directory, "SHA256SUMS"), checks); err != nil {
			return err
		}
		desc, err := inspectOCI(filepath.Join(directory, archive), container)
		if err != nil {
			return err
		}
		desc.Annotations = nil
		desc.Platform = map[string]string{"os": "linux", "architecture": arch}
		descriptors = append(descriptors, desc)
		artifacts := map[string]string{}
		for name, sum := range build.Artifacts {
			artifacts[name] = sum
		}
		artifacts[archive] = container.Image.SHA256
		files[archive] = filepath.Join(directory, archive)
		archives = append(archives, filepath.Join(directory, archive))
		platforms[arch] = map[string]any{"binary_sha256": build.Binary, "artifacts": artifacts, "image_digest": container.Image.Digest, "image_config_digest": container.Image.Config}
	}
	if err := os.MkdirAll(output, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0755); err != nil {
		return err
	}
	for name, source := range files {
		if err := copyFile(source, filepath.Join(output, name), 0644); err != nil {
			return err
		}
	}
	for _, archive := range archives {
		if err := copyOCIBlobs(archive, layout); err != nil {
			return err
		}
	}
	wire, err := json.Marshal(imageIndex{Schema: 2, MediaType: indexMediaType, Manifests: descriptors})
	if err != nil {
		return err
	}
	hash := sha256.Sum256(wire)
	digest := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(layout, "blobs", "sha256", digest), wire, 0644); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(layout, "oci-layout"), map[string]string{"imageLayoutVersion": "1.0.0"}); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(layout, "index.json"), imageIndex{Schema: 2, Manifests: []descriptor{{MediaType: indexMediaType, Digest: "sha256:" + digest, Size: int64(len(wire)), Annotations: map[string]string{"org.opencontainers.image.ref.name": "release"}}}}); err != nil {
		return err
	}
	release := map[string]any{"schema": 1, "version": t.settings.version, "tag": "v" + t.settings.version, "source_repository": repository, "source_commit": t.settings.source, "qualification_run": t.settings.qualification, "qualified_roles": []string{"broker", "kubernetes-publisher"}, "platforms": platforms, "image": map[string]string{"reference": imageName + ":v" + t.settings.version, "digest": "sha256:" + digest}}
	for key, value := range common {
		release[key] = value
	}
	if err := writeJSON(filepath.Join(output, "release.json"), release); err != nil {
		return err
	}
	checks := map[string]string{}
	for name := range files {
		checks[name], err = checksum(filepath.Join(output, name))
		if err != nil {
			return err
		}
	}
	checks["release.json"], err = checksum(filepath.Join(output, "release.json"))
	if err != nil {
		return err
	}
	return writeChecksums(filepath.Join(output, "SHA256SUMS"), checks)
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func copyOCIBlobs(archive, output string) (err error) {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	r := tar.NewReader(f)
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag != tar.TypeReg || !strings.HasPrefix(name, "blobs/sha256/") {
			continue
		}
		if len(strings.TrimPrefix(name, "blobs/sha256/")) != 64 || strings.Contains(strings.TrimPrefix(name, "blobs/sha256/"), "/") {
			return errors.New("invalid OCI blob path")
		}
		path := filepath.Join(output, name)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, r)
		if err := errors.Join(copyErr, out.Close()); err != nil {
			return err
		}
	}
}

func checkChecksums(path string, expected map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	found := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || found[name] != "" || expected[name] != sum {
			return errors.New("qualified checksum file differs")
		}
		found[name] = sum
	}
	if !equalJSON(found, expected) {
		return errors.New("incomplete checksum file")
	}
	return nil
}

func (t tool) verifyRegistry() error {
	var release struct {
		Image     struct{ Reference, Digest string }
		Platforms map[string]struct {
			Digest string `json:"image_digest"`
		}
	}
	if err := readJSON(t.path(t.settings.release, "release.json"), &release); err != nil {
		return err
	}
	targets := map[string]string{release.Image.Reference: release.Image.Digest}
	for _, platform := range release.Platforms {
		targets[imageName+"@"+platform.Digest] = platform.Digest
	}
	for target, expected := range targets {
		raw, err := t.command(nil, "skopeo", "inspect", "--raw", "docker://"+target)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if "sha256:"+hex.EncodeToString(sum[:]) != expected {
			return errors.New("registry changed a qualified manifest")
		}
	}
	return nil
}
