package releasetool

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChecksumFileRejectsDuplicatesMissingAndChangedAssets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SHA256SUMS")
	expected := map[string]string{"package.deb": "first", "image.oci.tar": "second"}
	for _, fixture := range []struct {
		Name, Data string
		Valid      bool
	}{
		{"complete", "first  package.deb\nsecond  image.oci.tar\n", true},
		{"duplicate", "first  package.deb\nfirst  package.deb\nsecond  image.oci.tar\n", false},
		{"missing", "first  package.deb\n", false},
		{"changed", "wrong  package.deb\nsecond  image.oci.tar\n", false},
		{"extra", "first  package.deb\nsecond  image.oci.tar\nother  extra\n", false},
	} {
		t.Run(fixture.Name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(fixture.Data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := checkChecksums(path, expected); (err == nil) != fixture.Valid {
				t.Fatal("checksum verification result", err)
			}
		})
	}
}

func TestOCIRejectsUnreferencedModifiedAndDuplicateBlobs(t *testing.T) {
	directory := t.TempDir()
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"diff_ids":[]},"config":{}}`)
	sum := sha256.Sum256(config)
	configDesc := descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(config))}
	manifest, err := json.Marshal(imageManifest{Schema: 2, Config: configDesc, Layers: []descriptor{}})
	if err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256(manifest)
	manifestDesc := descriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(manifest))}
	index, err := json.Marshal(imageIndex{Schema: 2, Manifests: []descriptor{manifestDesc}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"index.json": index, "oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "blobs/sha256/" + configDesc.Digest[7:]: config, "blobs/sha256/" + manifestDesc.Digest[7:]: manifest}
	for _, kind := range []string{"complete", "extra", "changed", "duplicate", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			var output bytes.Buffer
			writer := tar.NewWriter(&output)
			for _, name := range sortedKeys(files) {
				data := files[name]
				if kind == "changed" && name == "blobs/sha256/"+configDesc.Digest[7:] {
					data = append([]byte{}, data...)
					data[0] = '!'
				}
				if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "extra" {
				data := []byte("unexpected")
				sum := sha256.Sum256(data)
				if err := writer.WriteHeader(&tar.Header{Name: "blobs/sha256/" + hex.EncodeToString(sum[:]), Mode: 0644, Size: int64(len(data))}); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "duplicate" {
				if err := writer.WriteHeader(&tar.Header{Name: "index.json", Mode: 0644}); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				if err := writer.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, kind+".tar")
			if err := os.WriteFile(path, output.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readOCI(path); (err == nil) != (kind == "complete") {
				t.Fatal("OCI graph verification result", err)
			}
		})
	}
}

func TestPayloadRejectsUnsafeOwnershipSymlinksAndExtraFiles(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "dist/native/amd64")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "build.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"complete", "owner", "symlink", "extra", "traversal"} {
		t.Run(kind, func(t *testing.T) {
			var output bytes.Buffer
			writer := tar.NewWriter(&output)
			h := &tar.Header{Name: "usr/share/doc/discovery-bridge/build.json", Mode: 0644, Size: 2, ModTime: time.Unix(1234, 0)}
			if kind == "owner" {
				h.Uid = 1000
			}
			if kind == "symlink" {
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "/etc/shadow"
				h.Size = 0
			}
			if kind == "traversal" {
				h.Name = "../build.json"
			}
			if err := writer.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			if h.Size > 0 {
				if _, err := writer.Write([]byte("{}")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "extra" {
				if err := writer.WriteHeader(&tar.Header{Name: "unexpected", Mode: 0644}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			metadata := buildMetadata{Architecture: "amd64", Epoch: h.ModTime.Unix(), Payload: map[string]string{}}
			operation := tool{ctx: context.Background(), settings: options{root: root}}
			if err := operation.inspectPayload(tar.NewReader(bytes.NewReader(output.Bytes())), metadata); (err == nil) != (kind == "complete") {
				t.Fatal("payload verification result", err)
			}
		})
	}
}
