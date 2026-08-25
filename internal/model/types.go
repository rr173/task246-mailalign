package model

import "time"

type SampleStatus string

const (
	SampleReceived SampleStatus = "received"
	SampleParsed   SampleStatus = "parsed"
	SampleAnalyzed SampleStatus = "analyzed"
	SampleSealed   SampleStatus = "sealed"
)

type HopStatus string

const (
	HopObserved   HopStatus = "observed"
	HopTrusted    HopStatus = "trusted"
	HopSuspicious HopStatus = "suspicious"
	HopRejected   HopStatus = "rejected"
)

type DiagnosticStatus string

const (
	DiagnosticDraft        DiagnosticStatus = "draft"
	DiagnosticAligned      DiagnosticStatus = "aligned"
	DiagnosticMisaligned   DiagnosticStatus = "misaligned"
	DiagnosticInconclusive DiagnosticStatus = "inconclusive"
	DiagnosticSealed       DiagnosticStatus = "sealed"
)

type RecordStatus string

const (
	RecordActive     RecordStatus = "active"
	RecordSuperseded RecordStatus = "superseded"
)

type SnapshotStatus string

const (
	SnapshotDraft      SnapshotStatus = "draft"
	SnapshotPublished  SnapshotStatus = "published"
	SnapshotSuperseded SnapshotStatus = "superseded"
)

type MessageSample struct {
	ID          int64        `json:"id"`
	MessageKey  string       `json:"message_key"`
	VisibleFrom string       `json:"visible_from"`
	ReturnPath  string       `json:"return_path"`
	RecipientIP string       `json:"recipient_ip"`
	Body        string       `json:"body"`
	BodySHA     string       `json:"body_sha"`
	Status      SampleStatus `json:"status"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type Hop struct {
	ID         int64     `json:"id"`
	SampleID   int64     `json:"sample_id"`
	Sequence   int       `json:"sequence"`
	FromDomain string    `json:"from_domain"`
	ByDomain   string    `json:"by_domain"`
	ClientIP   string    `json:"client_ip"`
	Status     HopStatus `json:"status"`
	Note       string    `json:"note,omitempty"`
}

type SPFRecord struct {
	ID         int64        `json:"id"`
	Domain     string       `json:"domain"`
	Version    int          `json:"version"`
	Mechanisms []string     `json:"mechanisms"`
	Status     RecordStatus `json:"status"`
}

type DKIMRecord struct {
	ID       int64        `json:"id"`
	Domain   string       `json:"domain"`
	Selector string       `json:"selector"`
	Version  int          `json:"version"`
	BodySHA  string       `json:"body_sha"`
	Status   RecordStatus `json:"status"`
}

type SPFResult struct {
	Status      string   `json:"status"`
	Domain      string   `json:"domain"`
	ClientIP    string   `json:"client_ip"`
	Matched     string   `json:"matched,omitempty"`
	Trace       []string `json:"trace"`
	Explanation string   `json:"explanation"`
}

type DKIMResult struct {
	Status      string `json:"status"`
	Domain      string `json:"domain"`
	Selector    string `json:"selector"`
	ExpectedSHA string `json:"expected_sha"`
	ActualSHA   string `json:"actual_sha"`
	Explanation string `json:"explanation"`
}

type Diagnostic struct {
	ID             int64            `json:"id"`
	SampleID       int64            `json:"sample_id"`
	Status         DiagnosticStatus `json:"status"`
	SPF            SPFResult        `json:"spf"`
	DKIM           DKIMResult       `json:"dkim"`
	StrictAligned  bool             `json:"strict_aligned"`
	RelaxedAligned bool             `json:"relaxed_aligned"`
	NeedsReview    bool             `json:"needs_review"`
	TrustedHops    []int64          `json:"trusted_hops"`
	HopPath        []string         `json:"hop_path"`
	Explanation    []string         `json:"explanation"`
	PayloadJSON    string           `json:"payload_json"`
	CreatedAt      time.Time        `json:"created_at"`
}

type DiagnosticReport struct {
	SampleID        int64          `json:"sample_id"`
	MessageKey      string         `json:"message_key"`
	SampleStatus    SampleStatus   `json:"sample_status"`
	Diagnostic      *Diagnostic    `json:"diagnostic"`
	HopCount        int            `json:"hop_count"`
	TrustedHopCount int            `json:"trusted_hop_count"`
	SPFTraceLength  int            `json:"spf_trace_length"`
	SnapshotID      int64          `json:"snapshot_id,omitempty"`
	Evidence        []EvidenceItem `json:"evidence"`
	EvidenceScore   int            `json:"evidence_score"`
	Summary         string         `json:"summary"`
	RiskLevel       string         `json:"risk_level"`
	NextActions     []string       `json:"next_actions"`
	AuthMethods     int            `json:"auth_methods"`
	DomainRelation  string         `json:"domain_relation"`
}

type EvidenceItem struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	Weight  int    `json:"weight"`
}

type Snapshot struct {
	ID           int64          `json:"id"`
	SampleID     int64          `json:"sample_id"`
	DiagnosticID int64          `json:"diagnostic_id"`
	Status       SnapshotStatus `json:"status"`
	ContentSHA   string         `json:"content_sha"`
	PayloadJSON  string         `json:"payload_json"`
	CreatedAt    time.Time      `json:"created_at"`
	PublishedAt  *time.Time     `json:"published_at,omitempty"`
}
