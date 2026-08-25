package service

import "context"

// Recover performs the deterministic startup read pass. No external DNS lookup is made.
func (s *Service) Recover(ctx context.Context) error {
	if _, err := s.store.DB().ExecContext(ctx, `SELECT count(*) FROM message_samples`); err != nil {
		return err
	}
	if _, err := s.store.DB().ExecContext(ctx, `SELECT count(*) FROM snapshots WHERE status='published'`); err != nil {
		return err
	}
	return nil
}

func (s *Service) SelfCheck(ctx context.Context) (map[string]any, error) {
	if err := s.Recover(ctx); err != nil {
		return nil, err
	}
	metrics, err := s.store.Metrics(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"database": "ok", "external_dns": false, "deterministic": true, "metrics": metrics}, nil
}
