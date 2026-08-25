package store

import (
	"context"
	"database/sql"
	"errors"

	"task246-mailalign/internal/model"
)

func (s *Store) CreateSample(ctx context.Context, value *model.MessageSample) (*model.MessageSample, bool, error) {
	stamp := now()
	result, err := s.db.ExecContext(ctx, `INSERT INTO message_samples(message_key,visible_from,return_path,recipient_ip,body,body_sha,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, value.MessageKey, value.VisibleFrom, value.ReturnPath, value.RecipientIP, value.Body, value.BodySHA, string(value.Status), stamp, stamp)
	if err != nil {
		if existing, getErr := s.SampleByKey(ctx, value.MessageKey); getErr == nil {
			return existing, true, nil
		}
		return nil, false, err
	}
	value.ID, _ = result.LastInsertId()
	value.CreatedAt, _ = parseTime(stamp)
	value.UpdatedAt = value.CreatedAt
	return value, false, nil
}

func scanSample(row interface{ Scan(...any) error }) (*model.MessageSample, error) {
	var value model.MessageSample
	var created, updated string
	err := row.Scan(&value.ID, &value.MessageKey, &value.VisibleFrom, &value.ReturnPath, &value.RecipientIP, &value.Body, &value.BodySHA, &value.Status, &created, &updated)
	if err != nil {
		return nil, err
	}
	value.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	value.UpdatedAt, err = parseTime(updated)
	return &value, err
}

func (s *Store) Sample(ctx context.Context, id int64) (*model.MessageSample, error) {
	value, err := scanSample(s.db.QueryRowContext(ctx, `SELECT id,message_key,visible_from,return_path,recipient_ip,body,body_sha,status,created_at,updated_at FROM message_samples WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	return value, err
}

func (s *Store) SampleByKey(ctx context.Context, key string) (*model.MessageSample, error) {
	value, err := scanSample(s.db.QueryRowContext(ctx, `SELECT id,message_key,visible_from,return_path,recipient_ip,body,body_sha,status,created_at,updated_at FROM message_samples WHERE message_key=?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	return value, err
}

func (s *Store) UpdateSampleStatus(ctx context.Context, id int64, status model.SampleStatus) error {
	result, err := s.db.ExecContext(ctx, `UPDATE message_samples SET status=?,updated_at=? WHERE id=?`, string(status), now(), id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return model.ErrNotFound
	}
	return nil
}
