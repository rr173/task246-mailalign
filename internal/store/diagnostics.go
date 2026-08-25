package store

import (
	"context"
	"database/sql"
	"errors"

	"task246-mailalign/internal/model"
)

func (s *Store) SaveDiagnostic(ctx context.Context, value *model.Diagnostic) (*model.Diagnostic, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO diagnostics(sample_id,status,payload_json,created_at) VALUES(?,?,?,?)`, value.SampleID, string(value.Status), value.PayloadJSON, now())
	if err != nil {
		if existing, getErr := s.DiagnosticBySample(ctx, value.SampleID); getErr == nil {
			return existing, nil
		}
		return nil, err
	}
	value.ID, _ = result.LastInsertId()
	value.CreatedAt, _ = parseTime(now())
	return value, nil
}

func decodeDiagnostic(id int64, sampleID int64, status string, payload string, stamp string) (*model.Diagnostic, error) {
	value := &model.Diagnostic{ID: id, SampleID: sampleID, Status: model.DiagnosticStatus(status), PayloadJSON: payload}
	var err error
	value.CreatedAt, err = parseTime(stamp)
	return value, err
}

func (s *Store) Diagnostic(ctx context.Context, id int64) (*model.Diagnostic, error) {
	var sampleID int64
	var status, payload, stamp string
	err := s.db.QueryRowContext(ctx, `SELECT sample_id,status,payload_json,created_at FROM diagnostics WHERE id=?`, id).Scan(&sampleID, &status, &payload, &stamp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	return decodeDiagnostic(id, sampleID, status, payload, stamp)
}

func (s *Store) DiagnosticBySample(ctx context.Context, sampleID int64) (*model.Diagnostic, error) {
	var id int64
	var status, payload, stamp string
	err := s.db.QueryRowContext(ctx, `SELECT id,status,payload_json,created_at FROM diagnostics WHERE sample_id=?`, sampleID).Scan(&id, &status, &payload, &stamp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	return decodeDiagnostic(id, sampleID, status, payload, stamp)
}
