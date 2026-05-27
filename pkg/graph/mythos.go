package graph

import (
	"encoding/json"
	"fmt"
	"io"
)

// MythosReport is the JSON document emitted by a Mythos discovery run.
// Mythos finds vulnerabilities in upstream code; VIM ingests the report and
// traces each finding across the inheritance graph.
//
// Example:
//
//	{
//	  "source": "mythos",
//	  "generated": "2026-05-27T12:00:00Z",
//	  "findings": [
//	    {
//	      "id": "MYTHOS-2026-0001",
//	      "severity": "critical",
//	      "summary": "Heap overflow in header length parser",
//	      "target": { "purl": "pkg:github/upstream/libparse@v1.2.0",
//	                  "path": "upstream/parse.go" }
//	    }
//	  ]
//	}
type MythosReport struct {
	Source    string          `json:"source"`
	Generated string          `json:"generated,omitempty"`
	Findings  []MythosFinding `json:"findings"`
}

// MythosFinding is a single vulnerability discovered by Mythos.
type MythosFinding struct {
	ID       string       `json:"id"`
	Severity string       `json:"severity"`
	Summary  string       `json:"summary"`
	Target   MythosTarget `json:"target"`
}

// MythosTarget identifies the code unit a finding was discovered in. Either
// SWHID (already computed) or Path (a file VIM will hash, resolved relative to
// the corpus root) must be set; SWHID wins when both are present. PURL is
// optional extrinsic package context.
type MythosTarget struct {
	PURL  string `json:"purl,omitempty"`
	Path  string `json:"path,omitempty"`
	SWHID string `json:"swhid,omitempty"`
}

// ParseMythosReport decodes a Mythos report and validates that every finding
// is usable (has an ID and a resolvable target).
func ParseMythosReport(r io.Reader) (*MythosReport, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var report MythosReport
	if err := dec.Decode(&report); err != nil {
		return nil, fmt.Errorf("decoding Mythos report: %w", err)
	}
	if len(report.Findings) == 0 {
		return nil, fmt.Errorf("no findings in Mythos report")
	}
	if report.Source == "" {
		report.Source = "mythos"
	}
	for i, f := range report.Findings {
		if f.ID == "" {
			return nil, fmt.Errorf("finding %d has no id", i)
		}
		if f.Target.SWHID == "" && f.Target.Path == "" {
			return nil, fmt.Errorf("finding %s: target needs a swhid or a path", f.ID)
		}
	}
	return &report, nil
}
