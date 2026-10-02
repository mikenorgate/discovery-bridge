// Package registry describes observed DNS-SD types without restricting discovery.
package registry

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$`)
var letter = regexp.MustCompile(`[A-Za-z]`)
var descriptionKey = regexp.MustCompile(`^([^\[]+)(?:\[([^\]]+)\])?$`)

// Identifier validates a generated RFC6335 service name without its underscore.
func Identifier(value string) (string, error) {
	if len(value) < 1 || len(value) > 15 || !identifier.MatchString(value) || !letter.MatchString(value) {
		return "", errors.New("service name must contain 1 to 15 ASCII letters, digits or single hyphens, including a letter")
	}
	return strings.ToLower(value), nil
}

// ObservedType canonicalizes an observed type, allowing unregistered names.
func ObservedType(value string) (string, error) {
	if _, ok := dns.IsDomainName(value); !ok {
		return "", errors.New("invalid DNS-SD type")
	}
	labels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(value)))
	if len(labels) == 3 && labels[2] == "local" {
		labels = labels[:2]
	}
	if len(labels) != 2 || len(labels[0]) < 2 || labels[0][0] != '_' || (labels[1] != "_tcp" && labels[1] != "_udp") {
		return "", errors.New("expected _service._tcp or _service._udp")
	}
	return strings.Join(labels, "."), nil
}

// GeneratedType validates a generated service type and its transport.
func GeneratedType(value, transport string) (string, error) {
	name, err := Identifier(value)
	if err != nil {
		return "", err
	}
	if transport != "tcp" && transport != "udp" {
		return "", errors.New("DNS-SD transport must be tcp or udp")
	}
	return "_" + name + "._" + transport, nil
}

// Registry holds verified descriptions and IANA service metadata.
type Registry struct {
	descriptions map[string]map[string]string
	metadata     map[string][]map[string]string
	digest       string
}

// Load verifies the manifest and reads bounded public registry files.
func Load(files fs.FS) (*Registry, error) {
	manifest, err := fs.ReadFile(files, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read registry manifest: %w", err)
	}
	var expected struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifest, &expected); err != nil {
		return nil, fmt.Errorf("decode registry manifest: %w", err)
	}
	content := make(map[string][]byte)
	for _, name := range []string{"service-types", "iana.csv", "COPYING.avahi"} {
		file, err := files.Open(name)
		if err != nil {
			return nil, fmt.Errorf("open registry %s: %w", name, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 4_000_001))
		closeErr := file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read registry %s: %w", name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close registry %s: %w", name, closeErr)
		}
		sum := sha256.Sum256(data)
		wanted, ok := expected.Files[name]
		if !ok || len(data) > 4_000_000 || len(data) != wanted.Bytes || hex.EncodeToString(sum[:]) != wanted.SHA256 {
			return nil, fmt.Errorf("registry integrity check failed: %s", name)
		}
		content[name] = data
	}
	r := &Registry{descriptions: make(map[string]map[string]string), metadata: make(map[string][]map[string]string)}
	hash := sha256.New()
	if _, err := hash.Write(content["service-types"]); err != nil {
		return nil, err
	}
	if _, err := hash.Write([]byte{0}); err != nil {
		return nil, err
	}
	if _, err := hash.Write(content["iana.csv"]); err != nil {
		return nil, err
	}
	r.digest = hex.EncodeToString(hash.Sum(nil))
	for _, line := range strings.Split(string(content["service-types"]), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, text, ok := strings.Cut(line, ":")
		match := descriptionKey.FindStringSubmatch(key)
		if !ok || match == nil {
			return nil, errors.New("malformed Avahi description")
		}
		kind, err := ObservedType(match[1])
		if err != nil {
			return nil, err
		}
		if r.descriptions[kind] == nil {
			r.descriptions[kind] = make(map[string]string)
		}
		r.descriptions[kind][match[2]] = strings.TrimSpace(text)
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(content["iana.csv"]), "\ufeff")))
	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read IANA header: %w", err)
	}
	for _, wanted := range []string{"Service Name", "Port Number", "Transport Protocol", "Description"} {
		found := false
		for _, value := range headers {
			if value == wanted {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("missing IANA column: %s", wanted)
		}
	}
	for {
		values, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read IANA record: %w", err)
		}
		row := make(map[string]string, len(headers))
		for index, key := range headers {
			row[key] = values[index]
		}
		key := strings.ToLower(row["Service Name"] + "/" + row["Transport Protocol"])
		r.metadata[key] = append(r.metadata[key], row)
	}
	return r, nil
}

// Describe returns a localized description or the raw observed type.
func (r *Registry) Describe(kind, locale string) (string, error) {
	key, err := ObservedType(kind)
	if err != nil {
		return "", err
	}
	choices := r.descriptions[key]
	for _, language := range []string{locale, strings.Split(locale, "_")[0], ""} {
		if value, ok := choices[language]; ok {
			return value, nil
		}
	}
	return key, nil
}

// Metadata returns independent copies of matching IANA rows.
func (r *Registry) Metadata(service, transport string) []map[string]string {
	rows := r.metadata[strings.ToLower(service+"/"+transport)]
	result := make([]map[string]string, len(rows))
	for i, row := range rows {
		result[i] = maps.Clone(row)
	}
	return result
}

// Digest identifies the verified description and IANA snapshot.
func (r *Registry) Digest() string { return r.digest }
