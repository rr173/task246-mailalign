package store

import (
	"context"
	"task246-mailalign/internal/model"
)

func (s *Store) Samples(ctx context.Context) ([]model.MessageSample, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,message_key,visible_from,return_path,recipient_ip,body,body_sha,status,created_at,updated_at FROM message_samples ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.MessageSample, 0)
	for rows.Next() {
		value, err := scanSample(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, rows.Err()
}

func (s *Store) SnapshotForSample(ctx context.Context, sampleID int64) (*model.Snapshot, error) {
	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM snapshots WHERE sample_id=? ORDER BY id DESC LIMIT 1`, sampleID).Scan(&id); err != nil {
		return nil, model.ErrNotFound
	}
	return s.Snapshot(ctx, id)
}
