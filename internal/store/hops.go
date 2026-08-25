package store

import (
	"context"
	"database/sql"
	"errors"

	"task246-mailalign/internal/model"
)

func (s *Store) AddHop(ctx context.Context, hop *model.Hop) (*model.Hop, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO hops(sample_id,sequence,from_domain,by_domain,client_ip,status,note) VALUES(?,?,?,?,?,?,?)`, hop.SampleID, hop.Sequence, hop.FromDomain, hop.ByDomain, hop.ClientIP, string(hop.Status), hop.Note)
	if err != nil {
		return nil, model.ErrConflict
	}
	hop.ID, _ = result.LastInsertId()
	return hop, nil
}

func scanHop(row interface{ Scan(...any) error }) (*model.Hop, error) {
	var value model.Hop
	err := row.Scan(&value.ID, &value.SampleID, &value.Sequence, &value.FromDomain, &value.ByDomain, &value.ClientIP, &value.Status, &value.Note)
	return &value, err
}

func (s *Store) Hops(ctx context.Context, sampleID int64) ([]model.Hop, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,sample_id,sequence,from_domain,by_domain,client_ip,status,note FROM hops WHERE sample_id=? ORDER BY sequence`, sampleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Hop
	for rows.Next() {
		value, err := scanHop(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, *value)
	}
	return values, rows.Err()
}

func (s *Store) TrustHop(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE hops SET status=? WHERE id=?`, string(model.HopTrusted), id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return model.ErrNotFound
	}
	return nil
}

func (s *Store) Hop(ctx context.Context, id int64) (*model.Hop, error) {
	hop, err := scanHop(s.db.QueryRowContext(ctx, `SELECT id,sample_id,sequence,from_domain,by_domain,client_ip,status,note FROM hops WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	return hop, err
}
