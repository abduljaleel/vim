// Package identity implements VIM's trilateral identity resolution across
// pURL (extrinsic package identity), SWHID (intrinsic content identity),
// and TLSH (fuzzy similarity identity).
//
// These three identity layers are unified via a LineageID value that can
// express exact, near-exact, and cross-packaging-boundary relationships
// between code units in the VIM graph.
package identity

import (
	"crypto/sha1" //nolint:gosec // SWHID requires SHA-1 per spec (sha1_git)
	"fmt"
	"strings"
)

// SWHIDObjectType enumerates the object kinds that Software Heritage IDs
// can refer to. VIM's initial scope only produces content-level SWHIDs
// ("cnt"), but we model the full enum so downstream code that ingests
// SWH graph data can reason about other object types.
type SWHIDObjectType string

const (
	SWHIDContent    SWHIDObjectType = "cnt" // blob / file contents
	SWHIDDirectory  SWHIDObjectType = "dir"
	SWHIDRevision   SWHIDObjectType = "rev" // commit
	SWHIDRelease    SWHIDObjectType = "rel"
	SWHIDSnapshot   SWHIDObjectType = "snp"
)

// SWHID is a Software Heritage persistent identifier.
// Specification: https://www.swhid.org/specification/v1.1/
//
// Core form: swh:<schema>:<object_type>:<object_id>
// where object_id is a hex-encoded SHA-1 computed per SWHID rules
// (for content objects, this matches the Git blob hash).
type SWHID struct {
	Schema     int             // SWHID schema version; v1 as of spec
	ObjectType SWHIDObjectType
	ObjectID   string          // lowercase hex SHA-1
}

// ComputeContentSWHID computes a SWHID for a blob of bytes using the
// Git blob hashing rules: sha1("blob " + len + "\0" + content).
// This matches the value Software Heritage stores for content objects
// and the value Git uses for blob SHAs — the two are intentionally identical.
func ComputeContentSWHID(content []byte) SWHID {
	// Git blob hashing: "blob <len>\0<content>"
	h := sha1.New() //nolint:gosec // required by SWHID/Git blob spec
	fmt.Fprintf(h, "blob %d", len(content))
	h.Write([]byte{0})
	h.Write(content)
	return SWHID{
		Schema:     1,
		ObjectType: SWHIDContent,
		ObjectID:   fmt.Sprintf("%x", h.Sum(nil)),
	}
}

// String renders the SWHID in canonical swh: form.
func (s SWHID) String() string {
	return fmt.Sprintf("swh:%d:%s:%s", s.Schema, s.ObjectType, s.ObjectID)
}

// ParseSWHID parses a canonical SWHID string.
// Qualifiers (?origin=..., ?anchor=...) are tolerated but discarded
// for the initial prototype; full qualifier support is deferred.
func ParseSWHID(raw string) (SWHID, error) {
	// Strip qualifiers if present.
	if i := strings.IndexByte(raw, ';'); i >= 0 {
		raw = raw[:i]
	}

	parts := strings.Split(raw, ":")
	if len(parts) != 4 {
		return SWHID{}, fmt.Errorf("invalid SWHID %q: expected 4 colon-separated components, got %d", raw, len(parts))
	}
	if parts[0] != "swh" {
		return SWHID{}, fmt.Errorf("invalid SWHID %q: must start with 'swh:'", raw)
	}

	var schema int
	if _, err := fmt.Sscanf(parts[1], "%d", &schema); err != nil {
		return SWHID{}, fmt.Errorf("invalid SWHID schema %q: %w", parts[1], err)
	}

	objType := SWHIDObjectType(parts[2])
	switch objType {
	case SWHIDContent, SWHIDDirectory, SWHIDRevision, SWHIDRelease, SWHIDSnapshot:
		// valid
	default:
		return SWHID{}, fmt.Errorf("invalid SWHID object type %q", parts[2])
	}

	// Validate object_id: 40 hex chars (SHA-1).
	if len(parts[3]) != 40 {
		return SWHID{}, fmt.Errorf("invalid SWHID object_id %q: expected 40 hex chars, got %d", parts[3], len(parts[3]))
	}
	for _, c := range parts[3] {
		if !isHex(c) {
			return SWHID{}, fmt.Errorf("invalid SWHID object_id %q: non-hex character %q", parts[3], c)
		}
	}

	return SWHID{Schema: schema, ObjectType: objType, ObjectID: parts[3]}, nil
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}
