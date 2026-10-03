package state

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Generation holds the exclusive gateway owner and its persisted boot generation.
type Generation struct {
	Number int64
	lock   *os.File
	db     *sql.DB
}

// OpenGeneration increments the existing gateway_generation schema once.
func OpenGeneration(ctx context.Context, path string) (_ *Generation, err error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute generation path required")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	g := &Generation{lock: lock}
	defer func() {
		if err != nil {
			err = errors.Join(err, g.Close())
		}
	}()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	g.db, err = sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	g.db.SetMaxOpenConns(1)
	for _, query := range []string{"PRAGMA synchronous=FULL", "PRAGMA busy_timeout=2000", `CREATE TABLE IF NOT EXISTS gateway_generation (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL)`} {
		if _, err = g.db.ExecContext(ctx, query); err != nil {
			return nil, err
		}
	}
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			rollbackErr := tx.Rollback()
			if !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.Join(err, rollbackErr)
			}
		}
	}()
	err = tx.QueryRowContext(ctx, "SELECT generation FROM gateway_generation WHERE id=1").Scan(&g.Number)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if g.Number < 0 || g.Number == math.MaxInt64 {
		return nil, errors.New("gateway generation exhausted or invalid")
	}
	g.Number++
	if _, err = tx.ExecContext(ctx, `INSERT INTO gateway_generation VALUES (1,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation`, g.Number); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return g, nil
}

// Close releases the database and then the exclusive process lock.
func (g *Generation) Close() error {
	var err error
	if g.db != nil {
		err = g.db.Close()
		g.db = nil
	}
	if g.lock != nil {
		err = errors.Join(err, g.lock.Close())
		g.lock = nil
	}
	return err
}
