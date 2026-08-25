package store

import "context"

func (s *Store) Metrics(ctx context.Context) (map[string]int, error) {
	queries := map[string]string{
		"samples":             "SELECT count(*) FROM message_samples",
		"hops":                "SELECT count(*) FROM hops",
		"spf_records":         "SELECT count(*) FROM spf_records",
		"dkim_records":        "SELECT count(*) FROM dkim_records",
		"diagnostics":         "SELECT count(*) FROM diagnostics",
		"published_snapshots": "SELECT count(*) FROM snapshots WHERE status='published'",
	}
	result := make(map[string]int, len(queries))
	for name, query := range queries {
		var count int
		if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return nil, err
		}
		result[name] = count
	}
	return result, nil
}
