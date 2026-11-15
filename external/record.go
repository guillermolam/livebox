// Package external wraps third-party security tools in a uniform,
// manifest-gated runner that produces normalized audit records.
package external

import "time"

// Stage names the position of a tool in the external workflow.
type Stage string

const (
	StagePDTM      Stage = "pdtm"
	StageNaabu     Stage = "naabu"
	StageHttpx     Stage = "httpx"
	StageKatana    Stage = "katana"
	StageNuclei    Stage = "nuclei"
	StageSubfinder Stage = "subfinder"
	StageUncover   Stage = "uncover"
	StageInteract  Stage = "interactsh"
	StageNotify    Stage = "notify"
	StageNmap      Stage = "nmap"
)

// Confidence reflects how far a finding has been corroborated.
type Confidence string

const (
	Detected      Confidence = "detected"
	Corroborated  Confidence = "corroborated"
	Verified      Confidence = "verified_exploit"
	Inconclusive  Confidence = "inconclusive"
	FalsePositive Confidence = "false_positive"
)

// Record is the normalized envelope every external tool must produce.
type Record struct {
	EngagementID      string         `json:"engagement_id"`
	DeviceID          string         `json:"device_id,omitempty"`
	Stage             Stage          `json:"stage"`
	Tool              string         `json:"tool"`
	ToolVersion       string         `json:"tool_version,omitempty"`
	TemplateHash      string         `json:"template_or_script_hash,omitempty"`
	ScopeApprovalID   string         `json:"scope_approval_id"`
	Target            string         `json:"target"`
	Observation       map[string]any `json:"observation"`
	FindingID         string         `json:"finding_id,omitempty"`
	Confidence        Confidence     `json:"confidence"`
	ControlEvidence   []string       `json:"control_evidence,omitempty"`
	ReviewerGate      string         `json:"reviewer_gate,omitempty"`
	NextAction        string         `json:"next_action,omitempty"`
	TimestampUTC      time.Time      `json:"timestamp_utc"`
}
