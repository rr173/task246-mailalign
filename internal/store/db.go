package store

import (
	"context"
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS message_samples (id INTEGER PRIMARY KEY AUTOINCREMENT, message_key TEXT NOT NULL UNIQUE, visible_from TEXT NOT NULL, return_path TEXT NOT NULL, recipient_ip TEXT NOT NULL, body TEXT NOT NULL, body_sha TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS hops (id INTEGER PRIMARY KEY AUTOINCREMENT, sample_id INTEGER NOT NULL, sequence INTEGER NOT NULL, from_domain TEXT NOT NULL, by_domain TEXT NOT NULL, client_ip TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', UNIQUE(sample_id, sequence), FOREIGN KEY(sample_id) REFERENCES message_samples(id))`,
		`CREATE TABLE IF NOT EXISTS spf_records (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, version INTEGER NOT NULL, mechanisms_json TEXT NOT NULL, status TEXT NOT NULL, UNIQUE(domain, version))`,
		`CREATE TABLE IF NOT EXISTS dkim_records (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, selector TEXT NOT NULL, version INTEGER NOT NULL, body_sha TEXT NOT NULL, status TEXT NOT NULL, UNIQUE(domain, selector, version))`,
		`CREATE TABLE IF NOT EXISTS diagnostics (id INTEGER PRIMARY KEY AUTOINCREMENT, sample_id INTEGER NOT NULL UNIQUE, status TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(sample_id) REFERENCES message_samples(id))`,
		`CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, sample_id INTEGER NOT NULL, diagnostic_id INTEGER NOT NULL, status TEXT NOT NULL, content_sha TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, published_at TEXT, FOREIGN KEY(sample_id) REFERENCES message_samples(id), FOREIGN KEY(diagnostic_id) REFERENCES diagnostics(id))`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func now() string                               { return time.Now().UTC().Format(time.RFC3339Nano) }
func parseTime(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }
