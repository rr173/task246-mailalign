package store

import (
	"context"
	"database/sql"
	"errors"

	"task246-mailalign/internal/model"
)

func (s *Store) CreateSnapshot(ctx context.Context, value *model.Snapshot) (*model.Snapshot, error) {
	stamp := now()
	result, err := s.db.ExecContext(ctx, `INSERT INTO snapshots(sample_id,diagnostic_id,status,content_sha,payload_json,created_at,published_at) VALUES(?,?,?,?,?,?,?)`, value.SampleID, value.DiagnosticID, string(value.Status), value.ContentSHA, value.PayloadJSON, stamp, nil)
	if err != nil {
		return nil, err
	}
	value.ID, _ = result.LastInsertId()
	value.CreatedAt, _ = parseTime(stamp)
	return value, nil
}

func (s *Store) PublishSnapshot(ctx context.Context, id int64) (*model.Snapshot, error) {
	stamp := now()
	result, err := s.db.ExecContext(ctx, `UPDATE snapshots SET status=?,published_at=? WHERE id=? AND status=?`, string(model.SnapshotPublished), stamp, id, string(model.SnapshotDraft))
	if err != nil {
		return nil, err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return nil, model.ErrInvalidState
	}
	return s.Snapshot(ctx, id)
}

func (s *Store) Snapshot(ctx context.Context, id int64) (*model.Snapshot, error) {
	var value model.Snapshot
	var created string
	var published sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id,sample_id,diagnostic_id,status,content_sha,payload_json,created_at,published_at FROM snapshots WHERE id=?`, id).Scan(&value.ID, &value.SampleID, &value.DiagnosticID, &value.Status, &value.ContentSHA, &value.PayloadJSON, &created, &published)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	value.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	if published.Valid {
		parsed, parseErr := parseTime(published.String)
		if parseErr != nil {
			return nil, parseErr
		}
		value.PublishedAt = &parsed
	}
	return &value, nil
}
