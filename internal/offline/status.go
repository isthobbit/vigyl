package offline

import "time"

// SourceStatus describes the offline data for one scanner.
type SourceStatus struct {
	Source   string    `json:"source"`
	Ready    bool      `json:"ready"`
	Problem  string    `json:"problem,omitempty"`
	SyncedAt time.Time `json:"synced_at,omitempty"`
	Stale    bool      `json:"stale"`
	Items    []string  `json:"items,omitempty"`
}

// Status reports, per source, whether data is present and how old it is.
// Readiness and items come from disk; sync times come from the manifest.
func (p Paths) Status(now time.Time) ([]SourceStatus, error) {
	m, err := p.ReadManifest()
	if err != nil {
		return nil, err
	}

	rows := []struct {
		source string
		ready  error
		info   *SourceInfo
		items  []string
	}{
		{SourceTrivy, p.TrivyReady(), m.Trivy, nil},
		{SourceOSV, p.OSVReady(), m.OSV, p.OSVEcosystems()},
		{SourceSemgrep, p.SemgrepReady(), m.Semgrep, p.SemgrepPacks()},
	}

	out := make([]SourceStatus, 0, len(rows))
	for _, r := range rows {
		s := SourceStatus{Source: r.source, Ready: r.ready == nil, Items: r.items}
		if r.ready != nil {
			s.Problem = r.ready.Error()
		}
		if r.info != nil {
			s.SyncedAt = r.info.SyncedAt
			if r.items == nil {
				s.Items = r.info.Items
			}
		}
		// Data with no recorded sync time (e.g. copied in by hand) counts as
		// stale: we cannot vouch for its age.
		s.Stale = s.Ready && (s.SyncedAt.IsZero() || now.Sub(s.SyncedAt) > StaleAfter)
		out = append(out, s)
	}
	return out, nil
}
