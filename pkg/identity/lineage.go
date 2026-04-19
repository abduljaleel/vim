package identity

import (
	"errors"
	"fmt"
)

// LineageID is VIM's trilateral identity for a single code unit.
// It combines the three identity layers:
//
//   - pURL: extrinsic, ecosystem-aware package identity (optional —
//     only present when the code unit is associated with a published package)
//   - SWHID: intrinsic, content-addressable identity — always present
//   - TLSH: fuzzy similarity identity — present when the content is
//     large/varied enough for TLSH to produce a hash
//
// Only SWHID is required. pURL is empty for vendored or unpublished code.
// TLSH is empty for inputs below TLSH's minimum size (very short files,
// highly repetitive content).
//
// A LineageID is the canonical primary key for a CodeUnit node in the
// VIM graph.
type LineageID struct {
	PURL  *PURL    // optional
	SWHID SWHID    // required
	TLSH  TLSHHash // optional; Hex == "" when unavailable
}

// ComputeLineageID derives a LineageID from raw content bytes and an
// optional pURL. Callers pass nil for pkg when the content is not
// associated with a published package (e.g., a vendored source file
// discovered inside a repository).
//
// The function always computes a SWHID. TLSH is attempted; if the content
// is too small or otherwise rejected by TLSH, the TLSH field is left empty
// and no error is returned — the LineageID is still valid with only SWHID.
func ComputeLineageID(content []byte, pkg *PURL) LineageID {
	id := LineageID{
		PURL:  pkg,
		SWHID: ComputeContentSWHID(content),
	}

	if t, err := ComputeTLSH(content); err == nil {
		id.TLSH = t
	} else if !errors.Is(err, ErrInputTooSmall) {
		// TLSH failed for an unexpected reason. We still return a valid
		// LineageID, but a real ingestion pipeline would log this.
		// Silent fallback here keeps the prototype ergonomic.
		_ = err
	}

	return id
}

// String renders a human-readable representation of a LineageID.
// This is not intended for wire serialisation — it's for logs and debugging.
// Use the forthcoming graph serialisation helpers for storage.
func (l LineageID) String() string {
	purl := "-"
	if l.PURL != nil {
		purl = l.PURL.String()
	}
	tlsh := "-"
	if l.TLSH.Hex != "" {
		tlsh = l.TLSH.Hex
	}
	return fmt.Sprintf("LineageID{pURL=%s swhid=%s tlsh=%s}", purl, l.SWHID.String(), tlsh)
}

// HasFuzzy reports whether the LineageID carries a TLSH hash usable
// for similarity queries.
func (l LineageID) HasFuzzy() bool {
	return l.TLSH.Hex != ""
}

// ExactMatch reports whether two LineageIDs refer to byte-identical content
// (as determined by SWHID equality). This is the fastest match and is used
// by the graph's primary index.
func (l LineageID) ExactMatch(other LineageID) bool {
	return l.SWHID == other.SWHID
}

// FuzzyMatch reports whether two LineageIDs are "similar" per TLSH distance.
// Returns (similar, distance, ok): ok is false when either side lacks a
// TLSH hash. The caller supplies the threshold; a common default for
// near-identical code is 30.
func (l LineageID) FuzzyMatch(other LineageID, threshold int) (similar bool, distance int, ok bool) {
	if !l.HasFuzzy() || !other.HasFuzzy() {
		return false, 0, false
	}
	d, err := l.TLSH.Distance(other.TLSH)
	if err != nil {
		return false, 0, false
	}
	return d <= threshold, d, true
}
