package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"task246-mailalign/internal/model"
)

func (s *Store) SaveSPF(ctx context.Context, value *model.SPFRecord) (*model.SPFRecord, error) {
	data, err := json.Marshal(value.Mechanisms)
	if err != nil {
		return nil, err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO spf_records(domain,version,mechanisms_json,status) VALUES(?,?,?,?)`, value.Domain, value.Version, string(data), string(value.Status))
	if err != nil {
		var existing model.SPFRecord
		err2 := s.db.QueryRowContext(ctx, `SELECT id,domain,version,mechanisms_json,status FROM spf_records WHERE domain=? AND version=?`, value.Domain, value.Version).Scan(&existing.ID, &existing.Domain, &existing.Version, &data, &existing.Status)
		if err2 == nil {
			_ = json.Unmarshal(data, &existing.Mechanisms)
			return &existing, nil
		}
		return nil, model.ErrConflict
	}
	value.ID, _ = result.LastInsertId()
	return value, nil
}

func (s *Store) SPF(ctx context.Context, domain string) (map[string]model.SPFRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,domain,version,mechanisms_json,status FROM spf_records WHERE status=?`, string(model.RecordActive))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]model.SPFRecord{}
	for rows.Next() {
		var value model.SPFRecord
		var data string
		if err := rows.Scan(&value.ID, &value.Domain, &value.Version, &data, &value.Status); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &value.Mechanisms); err != nil {
			return nil, err
		}
		// Keep the highest active version per domain so an older snapshot cannot overwrite a newer one.
		if existing, ok := result[value.Domain]; !ok || value.Version > existing.Version {
			result[value.Domain] = value
		}
	}
	return result, rows.Err()
}

func (s *Store) SaveDKIM(ctx context.Context, value *model.DKIMRecord) (*model.DKIMRecord, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO dkim_records(domain,selector,version,body_sha,status) VALUES(?,?,?,?,?)`, value.Domain, value.Selector, value.Version, value.BodySHA, string(value.Status))
	if err != nil {
		var existing model.DKIMRecord
		err2 := s.db.QueryRowContext(ctx, `SELECT id,domain,selector,version,body_sha,status FROM dkim_records WHERE domain=? AND selector=? AND version=?`, value.Domain, value.Selector, value.Version).Scan(&existing.ID, &existing.Domain, &existing.Selector, &existing.Version, &existing.BodySHA, &existing.Status)
		if err2 == nil {
			return &existing, nil
		}
		return nil, model.ErrConflict
	}
	value.ID, _ = result.LastInsertId()
	return value, nil
}

func (s *Store) DKIM(ctx context.Context) (map[string]model.DKIMRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,domain,selector,version,body_sha,status FROM dkim_records WHERE status=?`, string(model.RecordActive))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]model.DKIMRecord{}
	for rows.Next() {
		var value model.DKIMRecord
		if err := rows.Scan(&value.ID, &value.Domain, &value.Selector, &value.Version, &value.BodySHA, &value.Status); err != nil {
			return nil, err
		}
		// Keep the highest active version per domain+selector so an older snapshot cannot overwrite a newer one.
		key := value.Domain + ":" + value.Selector
		if existing, ok := result[key]; !ok || value.Version > existing.Version {
			result[key] = value
		}
	}
	return result, rows.Err()
}

func (s *Store) EnsureSample(ctx context.Context, id int64) error {
	var found int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM message_samples WHERE id=?`, id).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ErrNotFound
	}
	return err
}
