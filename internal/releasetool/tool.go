// Package releasetool owns native release assembly and disposable qualification.
// It is a build tool, and is excluded from installed packages and images.
package releasetool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const repository = "https://github.com/mikenorgate/discovery-bridge"
const imageName = "ghcr.io/mikenorgate/discovery-bridge"

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

type options struct {
	root, version, arch, input, output, layout, release, source, qualification, artifact string
}

// Run dispatches release operations without installing an SDK on deployment hosts.
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("release operation required")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var settings options
	flags.StringVar(&settings.root, "root", ".", "source root")
	flags.StringVar(&settings.version, "version", "", "release version")
	flags.StringVar(&settings.arch, "arch", "", "native architecture")
	flags.StringVar(&settings.input, "input", "", "qualified platform directories")
	flags.StringVar(&settings.output, "output", "", "new release directory")
	flags.StringVar(&settings.layout, "layout", "", "new OCI index directory")
	flags.StringVar(&settings.release, "release", "", "assembled release directory")
	flags.StringVar(&settings.source, "source-commit", "", "qualified source commit")
	flags.StringVar(&settings.qualification, "qualification-run", "", "qualification workflow URL")
	flags.StringVar(&settings.artifact, "artifact", "", "package installation input")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	root, err := filepath.Abs(settings.root)
	if err != nil {
		return err
	}
	settings.root = root
	t := tool{ctx: ctx, settings: settings}
	switch args[0] {
	case "compile":
		return t.compile()
	case "package":
		return t.packageArtifacts()
	case "container-prepare":
		return t.prepareContainer()
	case "container-build":
		return t.buildContainer()
	case "release-prepare":
		return t.prepareRelease()
	case "release-assemble":
		return t.assembleRelease()
	case "verify-registry":
		return t.verifyRegistry()
	case "check-source":
		return t.checkSource()
	case "check-artifacts":
		return t.checkArtifacts()
	case "check-container":
		return t.checkContainer()
	case "check-install":
		return t.checkInstall()
	case "check-support":
		return t.checkSupport()
	case "check-systemd":
		return t.checkSystemd()
	default:
		return fmt.Errorf("unknown release operation %q", args[0])
	}
}

type tool struct {
	ctx      context.Context
	settings options
}

func (t tool) path(parts ...string) string {
	if len(parts) > 0 && filepath.IsAbs(parts[0]) {
		return filepath.Join(parts...)
	}
	return filepath.Join(append([]string{t.settings.root}, parts...)...)
}

func (t tool) command(env []string, program string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(t.ctx, program, args...)
	cmd.Dir = t.settings.root
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", program, err)
	}
	return data, nil
}

func (t tool) text(program string, args ...string) (string, error) {
	data, err := t.command(nil, program, args...)
	return strings.TrimSpace(string(data)), err
}

func checksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func copyFile(source, destination string, mode os.FileMode) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	return output.Chmod(mode)
}

func require(ok bool, message string) error {
	if !ok {
		return errors.New(message)
	}
	return nil
}

func (t tool) validateNative() error {
	return require(t.settings.arch == "amd64" || t.settings.arch == "arm64", "explicit native architecture required")
}
