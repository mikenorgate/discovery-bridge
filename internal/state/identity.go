// Package state preserves persistent DNS identities and permanent reservations.
package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/miekg/dns"
	_ "modernc.org/sqlite" // Registers the CGo-free SQLite driver.
)

var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,7}$`)

// Identities owns SQLite identities and reservations without changing their schema.
type Identities struct {
	mu     sync.Mutex
	db     *sql.DB
	prefix string
}

// Open opens an installation-owned database with its configured host alias prefix.
func Open(ctx context.Context, path, prefix string) (*Identities, error) {
	if !filepath.IsAbs(path) || !prefixPattern.MatchString(prefix) {
		return nil, errors.New("absolute state path and bounded alias prefix required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open identity database: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, query := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=2000",
		`CREATE TABLE IF NOT EXISTS identities (
		 identity TEXT PRIMARY KEY, source TEXT NOT NULL, original BLOB NOT NULL,
		 alias TEXT NOT NULL UNIQUE, collision INTEGER NOT NULL DEFAULT 0,
		 UNIQUE(source, original))`,
		`CREATE TABLE IF NOT EXISTS reservations (name BLOB PRIMARY KEY, identity TEXT NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			return nil, errors.Join(err, db.Close())
		}
	}
	return &Identities{db: db, prefix: prefix}, nil
}

func canonicalWire(name string) ([]byte, error) {
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, errors.New("invalid DNS identity name")
	}
	buffer := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), buffer, 0, nil, false)
	if err != nil {
		return nil, err
	}
	buffer = buffer[:n]
	for index := 0; index < len(buffer) && buffer[index] != 0; {
		length := int(buffer[index])
		index++
		for end := index + length; index < end; index++ {
			if buffer[index] >= 'A' && buffer[index] <= 'Z' {
				buffer[index] += 'a' - 'A'
			}
		}
	}
	return buffer, nil
}

// Alias returns the existing identity or reserves a deterministic new alias.
func (s *Identities) Alias(ctx context.Context, source, name string, collision bool) (id, alias string, err error) {
	if source == "" {
		return "", "", errors.New("source identity required")
	}
	original, err := canonicalWire(name)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256(append([]byte(source+"\x00"), original...))
	id = hex.EncodeToString(hash[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err != nil {
			rollbackErr := tx.Rollback()
			if !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.Join(err, rollbackErr)
			}
		}
	}()
	var count int64
	err = tx.QueryRowContext(ctx, "SELECT alias,collision FROM identities WHERE identity=?", id).Scan(&alias, &count)
	if err == nil && !collision {
		if err := tx.Commit(); err != nil {
			return "", "", err
		}
		return id, alias, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	if err == nil {
		count++
	}
	labels := dns.SplitDomainName(dns.Fqdn(name))
	for attempts := 0; attempts < 4096; attempts++ {
		suffix := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", id, count)))
		ending := hex.EncodeToString(suffix[:])[:20]
		if len(labels) == 2 {
			alias = s.prefix + ending + ".local."
		} else {
			length := int(original[0])
			label := strings.ToValidUTF8(string(original[1:1+length]), "\ufffd")
			for len(label) > 41 {
				_, size := utf8.DecodeLastRuneInString(label)
				label = label[:len(label)-size]
			}
			label += "-" + ending
			wire := append([]byte{byte(len(label))}, []byte(label)...)
			wire = append(wire, original[1+length:]...)
			alias, _, err = dns.UnpackDomainName(wire, 0)
			if err != nil {
				return "", "", err
			}
		}
		reserved, err := canonicalWire(alias)
		if err != nil {
			return "", "", err
		}
		var owner string
		err = tx.QueryRowContext(ctx, "SELECT identity FROM reservations WHERE name=?", reserved).Scan(&owner)
		if err == nil {
			count++
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO reservations VALUES (?,?)", reserved, id); err != nil {
			return "", "", err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO identities VALUES (?,?,?,?,?)
		 ON CONFLICT(identity) DO UPDATE SET alias=excluded.alias,collision=excluded.collision`, id, source, original, alias, count); err != nil {
			return "", "", err
		}
		if err := tx.Commit(); err != nil {
			return "", "", err
		}
		return id, alias, nil
	}
	return "", "", errors.New("alias reservation budget exhausted")
}

// Owns reports whether a name is permanently reserved by this installation.
func (s *Identities) Owns(ctx context.Context, name string) (bool, error) {
	wire, err := canonicalWire(name)
	if err != nil {
		return false, err
	}
	var count int
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reservations WHERE name=?", wire).Scan(&count)
	return count > 0, err
}

// Original resolves a current alias to its observed source and canonical name.
func (s *Identities) Original(ctx context.Context, alias string) (source, name string, err error) {
	var wire []byte
	err = s.db.QueryRowContext(ctx, "SELECT source,original FROM identities WHERE alias=?", dns.Fqdn(alias)).Scan(&source, &wire)
	if err != nil {
		return "", "", err
	}
	name, n, err := dns.UnpackDomainName(wire, 0)
	if err != nil {
		return "", "", err
	}
	if n != len(wire) {
		return "", "", errors.New("invalid persisted canonical name")
	}
	return source, name, nil
}

// Close releases the database connection; SQLite retains its compatible state.
func (s *Identities) Close() error { return s.db.Close() }
