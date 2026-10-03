package releasetool

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite" // Qualification uses the same driver as the installed application.
)

var roles = []string{"discovery-bridge-publisher", "discovery-bridge-collector"}

func disposable() error {
	_, docker := os.Stat("/.dockerenv")
	_, podman := os.Stat("/run/.containerenv")
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	return require(os.Geteuid() == 0 && (docker == nil || podman == nil) && strings.Contains(string(data), `VERSION_ID="13"`), "qualification requires root in a disposable Debian 13 container")
}

func accountFile(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Split(line, ":")
		result[fields[0]] = fields
	}
	return result, nil
}

func fileMode(path string, mode os.FileMode, uid, gid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != mode || (uid >= 0 && int(stat.Uid) != uid) || (gid >= 0 && int(stat.Gid) != gid) {
		return fmt.Errorf("unexpected state permissions: %s", filepath.Base(path))
	}
	return nil
}

func absent(path string) error {
	_, err := os.Lstat(path)
	return require(errors.Is(err, os.ErrNotExist), "unexpected active configuration or executable: "+path)
}

func databaseExec(path, query string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	_, runErr := db.Exec(query)
	return errors.Join(runErr, db.Close())
}

func (t tool) checkInstall() error {
	if err := disposable(); err != nil {
		return err
	}
	if t.settings.artifact == "" {
		return errors.New("package artifact required")
	}
	artifact := t.path(t.settings.artifact)
	arch, err := t.text("dpkg-deb", "--field", artifact, "Architecture")
	if err != nil {
		return err
	}
	var metadata buildMetadata
	if err := readJSON(t.path("dist", "native", arch, "build.json"), &metadata); err != nil {
		return err
	}
	state := "/var/lib/discovery-bridge"
	if err := os.MkdirAll(state, 0755); err != nil {
		return err
	}
	database := filepath.Join(state, "identities.db")
	if err := databaseExec(database, "CREATE TABLE retained (value TEXT); INSERT INTO retained VALUES ('existing identity state');"); err != nil {
		return err
	}
	original, err := checksum(database)
	if err != nil {
		return err
	}
	retained := func() error {
		sum, err := checksum(database)
		if err != nil {
			return err
		}
		return require(sum == original, "package installation changed existing state")
	}
	for range 2 {
		if _, err := t.command(nil, "dpkg", "--install", artifact); err != nil {
			return err
		}
		sum, err := checksum("/usr/bin/discovery-bridge")
		if err != nil {
			return err
		}
		version, err := t.text("/usr/bin/discovery-bridge", "version")
		if err != nil {
			return err
		}
		if sum != metadata.Binary || version != "discovery-bridge "+metadata.Version+" ("+metadata.GoVersion+")" {
			return errors.New("installed binary differs from qualified input")
		}
		description, err := t.text("/usr/bin/discovery-bridge", "registry", "describe", "_http._tcp")
		if err != nil {
			return err
		}
		var service struct{ Description string }
		if err := json.Unmarshal([]byte(description), &service); err != nil {
			return err
		}
		if service.Description == "" {
			return errors.New("installed registry description missing")
		}
		for _, path := range []string{"/etc/discovery-bridge/router.json", "/run/discovery-bridge/publisher.sock"} {
			if err := absent(path); err != nil {
				return err
			}
		}
		if err := filepath.WalkDir("/etc/systemd/system", func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if strings.Contains(path, ".wants/") && strings.HasPrefix(entry.Name(), "discovery-bridge-") {
				return errors.New("installation enabled discovery automatically")
			}
			return nil
		}); err != nil {
			return err
		}
		users, err := accountFile("/etc/passwd")
		if err != nil {
			return err
		}
		if len(users[roles[0]]) != 7 || len(users[roles[1]]) != 7 || users[roles[0]][2] == users[roles[1]][2] {
			return errors.New("distinct service accounts missing")
		}
		for _, role := range roles {
			if users[role][5] != "/nonexistent" || users[role][6] != "/usr/sbin/nologin" {
				return errors.New("unexpected service account login")
			}
		}
		uid, err := strconv.Atoi(users[roles[0]][2])
		if err != nil {
			return err
		}
		if err := fileMode(state, 0770, -1, -1); err != nil {
			return err
		}
		if err := fileMode(database, 0660, uid, -1); err != nil {
			return err
		}
		if err := retained(); err != nil {
			return err
		}
	}
	if _, err := t.command(nil, "dpkg", "--remove", "discovery-bridge"); err != nil {
		return err
	}
	if err := absent("/usr/bin/discovery-bridge"); err != nil {
		return err
	}
	if err := retained(); err != nil {
		return err
	}
	if _, err := t.command(nil, "dpkg", "--install", artifact); err != nil {
		return err
	}
	return retained()
}

func (t tool) checkSupport() error {
	directory, err := os.MkdirTemp("", "bridge-support-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(directory) }()
	for _, component := range []string{"sysusers", "tmpfiles"} {
		if err := copyFile(t.path("packaging", component, "discovery-bridge.conf"), filepath.Join(directory, "usr/lib", component+".d", "discovery-bridge.conf"), 0644); err != nil {
			return err
		}
	}
	state := filepath.Join(directory, "var/lib/discovery-bridge")
	if err := os.MkdirAll(state, 0755); err != nil {
		return err
	}
	original := []byte("Existing identity state must remain unchanged.\n")
	for _, name := range []string{"identities.db", "identities.db-wal", "identities.db-shm"} {
		if err := os.WriteFile(filepath.Join(state, name), original, 0644); err != nil {
			return err
		}
	}
	for range 2 {
		if _, err := t.command(nil, "systemd-sysusers", "--root="+directory); err != nil {
			return err
		}
		if _, err := t.command(nil, "systemd-tmpfiles", "--root="+directory, "--create"); err != nil {
			return err
		}
	}
	users, err := accountFile(filepath.Join(directory, "etc/passwd"))
	if err != nil {
		return err
	}
	groups, err := accountFile(filepath.Join(directory, "etc/group"))
	if err != nil {
		return err
	}
	shadow, err := accountFile(filepath.Join(directory, "etc/shadow"))
	if err != nil {
		return err
	}
	if len(users[roles[0]]) != 7 || len(users[roles[1]]) != 7 || users[roles[0]][2] == users[roles[1]][2] || len(groups["discovery-bridge"]) != 4 {
		return errors.New("service accounts or shared group missing")
	}
	group, err := strconv.Atoi(groups["discovery-bridge"][2])
	if err != nil {
		return err
	}
	for _, role := range roles {
		if users[role][5] != "/nonexistent" || users[role][6] != "/usr/sbin/nologin" || len(shadow[role]) < 2 || !strings.HasPrefix(shadow[role][1], "!") || !contains(strings.Split(groups["discovery-bridge"][3], ","), role) {
			return errors.New("service account credentials differ")
		}
	}
	if err := fileMode(state, 0770, -1, group); err != nil {
		return err
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(state, entry.Name())
		if err := fileMode(path, 0660, -1, group); err != nil {
			return err
		}
		if entry.Name() != "identities.db.feed" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !bytes.Equal(data, original) {
				return errors.New("shared-state setup changed existing contents")
			}
		}
	}
	for name, role := range map[string]string{"identities.db": roles[0], "identities.db.feed": roles[1]} {
		uid, err := strconv.Atoi(users[role][2])
		if err != nil {
			return err
		}
		if err := fileMode(filepath.Join(state, name), 0660, uid, group); err != nil {
			return err
		}
	}
	binary := os.Getenv("DISCOVERY_BRIDGE_TEST_BINARY")
	if binary == "" {
		binary = t.path("dist", "discovery-bridge")
	}
	if err := copyFile(binary, filepath.Join(directory, "usr/bin/discovery-bridge"), 0755); err != nil {
		return err
	}
	units := filepath.Join(directory, "usr/lib/systemd/system")
	for _, role := range roles {
		if err := copyFile(t.path("packaging", "systemd", role+".service"), filepath.Join(units, role+".service"), 0644); err != nil {
			return err
		}
	}
	for _, name := range []string{"basic", "sysinit", "shutdown", "multi-user", "network-online"} {
		if err := os.WriteFile(filepath.Join(units, name+".target"), []byte("[Unit]\nDescription=Fixture target\n"), 0644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(units, "avahi-daemon.service"), []byte("[Unit]\nDescription=Fixture dependency\n[Service]\nExecStart=/usr/bin/discovery-bridge version\n"), 0644); err != nil {
		return err
	}
	if _, err := t.command(nil, "systemd-analyze", "--root="+directory, "verify", roles[0]+".service", roles[1]+".service"); err != nil {
		return err
	}
	var example struct {
		Enabled  bool
		Producer string `json:"producer_user"`
	}
	if err := readJSON(t.path("packaging", "examples", "router.disabled.json"), &example); err != nil {
		return err
	}
	return require(!example.Enabled && example.Producer == roles[1], "example must be disabled with the collector producer account")
}

func (t tool) properties(role string) (map[string]string, error) {
	output, err := t.text("systemctl", "show", role, "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "NRestarts", "-p", "WatchdogTimestampMonotonic", "-p", "MemoryMax", "-p", "TasksMax")
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("invalid systemd property")
		}
		values[key] = value
	}
	return values, nil
}

func (t tool) healthy(role string) (map[string]string, error) {
	values, err := t.properties(role)
	if err != nil {
		return nil, err
	}
	if values["ActiveState"] != "active" || values["SubState"] != "running" || values["MemoryMax"] != "134217728" || values["TasksMax"] != "32" {
		return nil, fmt.Errorf("unhealthy unit %s: %v", role, values)
	}
	data, err := os.ReadFile("/proc/" + values["MainPID"] + "/status")
	if err != nil {
		return nil, err
	}
	status := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			status[key] = strings.Fields(value)
		}
	}
	users, err := accountFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"Uid", "CapEff", "NoNewPrivs", "Seccomp", "Threads", "VmRSS"} {
		if len(status[key]) == 0 {
			return nil, errors.New("missing process restriction property")
		}
	}
	caps, err := strconv.ParseUint(status["CapEff"][0], 16, 64)
	if err != nil {
		return nil, err
	}
	threads, err := strconv.Atoi(status["Threads"][0])
	if err != nil {
		return nil, err
	}
	rss, err := strconv.Atoi(status["VmRSS"][0])
	if err != nil {
		return nil, err
	}
	if len(users[role]) != 7 || status["Uid"][0] != users[role][2] || caps != 1<<13 || status["NoNewPrivs"][0] != "1" || status["Seccomp"][0] != "2" || threads > 32 || rss >= 128*1024 {
		return nil, fmt.Errorf("unit %s credentials or limits differ", role)
	}
	return values, nil
}

func (t tool) catalog() (int64, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	value := hex.EncodeToString(nonce)
	body, err := json.Marshal(map[string]any{"schema": 1, "nonce": value})
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(t.ctx, http.MethodPost, "http://127.0.0.1:19443/v1/catalog", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Close = true
	client := http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return 0, err
	}
	var result struct {
		Schema     int
		Nonce      string
		Generation int64
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return 0, err
	}
	if response.StatusCode != http.StatusOK || result.Schema != 1 || result.Nonce != value {
		return 0, errors.New("installed gateway response differs")
	}
	return result.Generation, nil
}

func (t tool) checkSystemd() (err error) {
	if err := disposable(); err != nil {
		return err
	}
	comm, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(comm)) != "systemd" {
		return errors.New("qualification requires a disposable systemd container")
	}
	defer func() {
		if err != nil {
			data, journalErr := t.command(nil, "journalctl", "--no-pager", "-n", "80", "-u", roles[0], "-u", roles[1])
			_, writeErr := os.Stderr.Write(data)
			err = errors.Join(err, journalErr, writeErr)
		}
	}()
	if err := absent("/etc/discovery-bridge/router.json"); err != nil {
		return err
	}
	if _, err := t.command(nil, "systemctl", "start", roles[0]); err != nil {
		return err
	}
	properties, err := t.properties(roles[0])
	if err != nil {
		return err
	}
	if properties["ActiveState"] != "inactive" {
		return errors.New("missing configuration must skip startup")
	}
	for _, args := range [][]string{{"link", "add", "lan0", "type", "dummy"}, {"link", "set", "lan0", "up", "multicast", "on"}, {"addr", "add", "192.0.2.1/24", "dev", "lan0"}, {"-6", "addr", "add", "2001:db8:1::1/64", "dev", "lan0", "nodad"}} {
		if _, err := t.command(nil, "ip", args...); err != nil {
			return err
		}
	}
	var config map[string]any
	if err := readJSON(t.path("packaging", "examples", "router.disabled.json"), &config); err != nil {
		return err
	}
	config["enabled"] = true
	config["gateway"] = map[string]any{"host": "127.0.0.1", "port": 19443, "clients": []string{"127.0.0.1/32"}}
	if err := os.Mkdir("/etc/discovery-bridge", 0755); err != nil {
		return err
	}
	if err := writeJSON("/etc/discovery-bridge/router.json", config); err != nil {
		return err
	}
	if _, err := t.command(nil, "systemctl", "start", roles[1]); err != nil {
		return err
	}
	initial := map[string]map[string]string{}
	for _, role := range roles {
		initial[role], err = t.healthy(role)
		if err != nil {
			return err
		}
		if initial[role]["NRestarts"] != "0" {
			return errors.New("unexpected initial unit restart")
		}
	}
	first, err := t.catalog()
	if err != nil {
		return err
	}
	if err := t.pause(time.Second); err != nil {
		return err
	}
	for _, role := range roles {
		current, err := t.healthy(role)
		if err != nil {
			return err
		}
		before, err := strconv.ParseUint(initial[role]["WatchdogTimestampMonotonic"], 10, 64)
		if err != nil {
			return err
		}
		after, err := strconv.ParseUint(current["WatchdogTimestampMonotonic"], 10, 64)
		if err != nil {
			return err
		}
		if after <= before {
			return errors.New("unit watchdog did not advance")
		}
	}
	if _, err := t.command(nil, "systemctl", "restart", roles[1]); err != nil {
		return err
	}
	generation, err := t.catalog()
	if err != nil {
		return err
	}
	if generation != first+1 {
		return errors.New("collector restart did not advance generation")
	}
	previous, err := t.healthy(roles[1])
	if err != nil {
		return err
	}
	if _, err := t.command(nil, "systemctl", "kill", "--signal=SIGSTOP", roles[1]); err != nil {
		return err
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		current, err := t.properties(roles[1])
		if err != nil {
			return err
		}
		if current["ActiveState"] == "active" && current["MainPID"] != "0" && current["MainPID"] != previous["MainPID"] {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("watchdog did not recover stopped collector")
		}
		if err := t.pause(100 * time.Millisecond); err != nil {
			return err
		}
	}
	collector, err := t.healthy(roles[1])
	if err != nil {
		return err
	}
	publisher, err := t.healthy(roles[0])
	if err != nil {
		return err
	}
	generation, err = t.catalog()
	if err != nil {
		return err
	}
	if collector["NRestarts"] != "1" || publisher["MainPID"] != initial[roles[0]]["MainPID"] || generation != first+2 {
		return errors.New("unexpected unit restart or persistent generation")
	}
	if _, err := t.command(nil, "systemctl", "stop", roles[1], roles[0]); err != nil {
		return err
	}
	for _, role := range roles {
		current, err := t.properties(role)
		if err != nil {
			return err
		}
		if current["ActiveState"] != "inactive" {
			return errors.New("unit did not stop")
		}
	}
	state := "/var/lib/discovery-bridge/identities.db"
	if err := fileMode(state, 0660, -1, -1); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", state)
	if err != nil {
		return err
	}
	var count int
	queryErr := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('identities','reservations')").Scan(&count)
	if err := errors.Join(queryErr, db.Close()); err != nil {
		return err
	}
	return require(count == 2, "installed SQLite schema differs")
}

func (t tool) pause(duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-t.ctx.Done():
		return t.ctx.Err()
	case <-timer.C:
		return nil
	}
}
