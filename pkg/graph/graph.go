// Package graph implements VIM's in-memory vulnerability inheritance graph.
//
// It connects two kinds of nodes:
//
//   - CodeUnit: a content-addressed unit of code, keyed by its SWHID.
//     Byte-identical copies observed in different places are the SAME
//     CodeUnit, recorded as multiple Occurrences. Modified variants are
//     distinct CodeUnits joined by similarity edges weighted by TLSH distance.
//   - Vulnerability: a finding (e.g. discovered by Mythos) attached to the
//     CodeUnit it was discovered in.
//
// Given a vulnerability, the graph computes its blast radius: every other
// place the same or closely-related code lives. Exact copies are certainly
// affected; fuzzy neighbours share lineage and require review, because the
// fix may or may not have been applied to them.
//
// This is the prototype, in-memory realisation of the layer the README
// describes as JanusGraph + Cassandra at production scale. The node and edge
// model is intentionally the same so the storage backend can be swapped in
// later without changing callers.
package graph

import (
	"fmt"
	"sort"

	"github.com/abduljaleel/vim/pkg/identity"
)

const (
	// DefaultFuzzyThreshold is the TLSH distance at or below which two code
	// units are treated as the same lineage for propagation. Per the
	// identity.LineageID docs ~30 is near-identical; 100 is a loose bound
	// that still cleanly separates related from unrelated code.
	DefaultFuzzyThreshold = 100

	// lineageHorizon is the maximum TLSH distance for which a similarity edge
	// is stored at all. Pairs beyond this are treated as unrelated and dropped
	// to keep the graph sparse; queries re-threshold within this horizon.
	lineageHorizon = 200
)

// Occurrence records a place a specific CodeUnit's exact bytes were observed.
type Occurrence struct {
	Repo string // e.g. "github.com/acme/forklib"
	Path string // e.g. "src/parse.go"
	Ref  string // optional commit/tag, e.g. "v1.2.3"
}

// String renders an Occurrence as a single locator for logs and CLI output.
func (o Occurrence) String() string {
	s := o.Repo
	switch {
	case s != "" && o.Path != "":
		s += "/" + o.Path
	case s == "":
		s = o.Path
	}
	if o.Ref != "" {
		s += "@" + o.Ref
	}
	if s == "" {
		return "(unknown location)"
	}
	return s
}

// CodeUnit is a content-addressed node, keyed by SWHID. All Occurrences of a
// CodeUnit carry byte-identical content and therefore share its fate exactly.
type CodeUnit struct {
	ID          identity.LineageID
	Occurrences []Occurrence
}

// Key returns the CodeUnit's primary key (its SWHID object id).
func (c *CodeUnit) Key() string { return c.ID.SWHID.ObjectID }

func (c *CodeUnit) addOccurrence(o Occurrence) {
	for _, e := range c.Occurrences {
		if e == o {
			return
		}
	}
	c.Occurrences = append(c.Occurrences, o)
}

// Vulnerability is a finding attached to the CodeUnit it was discovered in.
type Vulnerability struct {
	ID           string // e.g. "MYTHOS-2026-0001"
	Source       string // discovering tool, e.g. "mythos"
	Severity     string // free-form, e.g. "critical", "high"
	Summary      string
	AffectsSWHID string // SWHID object id of the originally-affected CodeUnit
}

// Relation describes how an impacted CodeUnit relates to the vulnerable origin.
type Relation string

const (
	// RelationOrigin marks the CodeUnit the vulnerability was discovered in.
	// Its Occurrences are the byte-identical copies that are certainly affected.
	RelationOrigin Relation = "origin"
	// RelationFuzzy marks a CodeUnit that shares lineage with the origin
	// (TLSH within threshold) but whose bytes differ — review required.
	RelationFuzzy Relation = "fuzzy"
)

// Impact is one node in a vulnerability's blast radius.
type Impact struct {
	Unit       *CodeUnit
	Relation   Relation
	Distance   int  // TLSH distance to the origin (0 for the origin itself)
	Transitive bool // reached only via intermediate lineage hops
}

type simLink struct {
	to       string
	distance int
}

// Graph is the in-memory vulnerability inheritance graph.
type Graph struct {
	units          map[string]*CodeUnit
	vulns          map[string]*Vulnerability
	adj            map[string][]simLink
	order          []string // insertion order of unit keys, for determinism
	fuzzyThreshold int
}

// New returns an empty Graph. A threshold <= 0 selects DefaultFuzzyThreshold.
func New(fuzzyThreshold int) *Graph {
	if fuzzyThreshold <= 0 {
		fuzzyThreshold = DefaultFuzzyThreshold
	}
	return &Graph{
		units:          make(map[string]*CodeUnit),
		vulns:          make(map[string]*Vulnerability),
		adj:            make(map[string][]simLink),
		fuzzyThreshold: fuzzyThreshold,
	}
}

// FuzzyThreshold reports the TLSH distance used for lineage propagation.
func (g *Graph) FuzzyThreshold() int { return g.fuzzyThreshold }

// AddCodeUnit inserts content as a CodeUnit and records an Occurrence.
// Byte-identical content merges into the existing node (adding the
// Occurrence); new content creates a node and similarity edges to existing
// fuzzy-capable units within the lineage horizon. The resident unit is returned.
func (g *Graph) AddCodeUnit(content []byte, pkg *identity.PURL, occ Occurrence) *CodeUnit {
	id := identity.ComputeLineageID(content, pkg)
	key := id.SWHID.ObjectID

	if u, ok := g.units[key]; ok {
		u.addOccurrence(occ)
		if u.ID.PURL == nil && pkg != nil {
			u.ID.PURL = pkg
		}
		return u
	}

	u := &CodeUnit{ID: id}
	u.addOccurrence(occ)
	g.units[key] = u

	if id.HasFuzzy() {
		for _, k := range g.order {
			other := g.units[k]
			if !other.ID.HasFuzzy() {
				continue
			}
			d, err := id.TLSH.Distance(other.ID.TLSH)
			if err != nil || d > lineageHorizon {
				continue
			}
			g.adj[key] = append(g.adj[key], simLink{to: k, distance: d})
			g.adj[k] = append(g.adj[k], simLink{to: key, distance: d})
		}
	}

	g.order = append(g.order, key)
	return u
}

// AddVulnerability records a finding. AffectsSWHID must be set; the referenced
// CodeUnit need not exist yet (BlastRadius reports if it is missing).
func (g *Graph) AddVulnerability(v Vulnerability) error {
	if v.ID == "" {
		return fmt.Errorf("vulnerability has no ID")
	}
	if v.AffectsSWHID == "" {
		return fmt.Errorf("vulnerability %s has no affected SWHID", v.ID)
	}
	if _, dup := g.vulns[v.ID]; dup {
		return fmt.Errorf("duplicate vulnerability ID %q", v.ID)
	}
	g.vulns[v.ID] = &v
	return nil
}

// UnitByKey returns the CodeUnit with the given SWHID object id, if present.
func (g *Graph) UnitByKey(key string) (*CodeUnit, bool) {
	u, ok := g.units[key]
	return u, ok
}

// Units returns all CodeUnits in insertion order.
func (g *Graph) Units() []*CodeUnit {
	out := make([]*CodeUnit, 0, len(g.order))
	for _, k := range g.order {
		out = append(out, g.units[k])
	}
	return out
}

// Vulnerabilities returns all findings sorted by ID.
func (g *Graph) Vulnerabilities() []*Vulnerability {
	out := make([]*Vulnerability, 0, len(g.vulns))
	for _, v := range g.vulns {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// NumUnits returns the number of unique-content CodeUnits.
func (g *Graph) NumUnits() int { return len(g.units) }

// NumOccurrences returns the total observed copies across all CodeUnits.
func (g *Graph) NumOccurrences() int {
	n := 0
	for _, u := range g.units {
		n += len(u.Occurrences)
	}
	return n
}

// NumSimilarityEdges returns the number of undirected lineage edges.
func (g *Graph) NumSimilarityEdges() int {
	n := 0
	for _, links := range g.adj {
		n += len(links)
	}
	return n / 2
}

// BlastRadius returns the vulnerability and every CodeUnit reachable as
// affected: the origin (whose Occurrences are the byte-identical copies)
// followed by fuzzy lineage neighbours within threshold, sorted by distance.
func (g *Graph) BlastRadius(vulnID string) (*Vulnerability, []Impact, error) {
	v, ok := g.vulns[vulnID]
	if !ok {
		return nil, nil, fmt.Errorf("unknown vulnerability %q", vulnID)
	}
	origin, ok := g.units[v.AffectsSWHID]
	if !ok {
		return v, nil, fmt.Errorf("vulnerability %s targets SWHID swh:1:cnt:%s, which is not in the graph", vulnID, v.AffectsSWHID)
	}
	impacts := append([]Impact{{Unit: origin, Relation: RelationOrigin}}, g.neighbors(origin.Key())...)
	return v, impacts, nil
}

// Lineage returns a CodeUnit and its fuzzy lineage neighbourhood, independent
// of any vulnerability. key is a SWHID object id.
func (g *Graph) Lineage(key string) ([]Impact, error) {
	origin, ok := g.units[key]
	if !ok {
		return nil, fmt.Errorf("no code unit with SWHID swh:1:cnt:%s in the graph", key)
	}
	return append([]Impact{{Unit: origin, Relation: RelationOrigin}}, g.neighbors(key)...), nil
}

// neighbors returns fuzzy lineage neighbours of originKey (excluding itself),
// sorted by ascending distance to the origin then by key.
func (g *Graph) neighbors(originKey string) []Impact {
	reached := g.fuzzyReachable(originKey)
	out := make([]Impact, 0, len(reached))
	for k, dist := range reached {
		out = append(out, Impact{
			Unit:       g.units[k],
			Relation:   RelationFuzzy,
			Distance:   dist,
			Transitive: dist > g.fuzzyThreshold,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Distance != out[j].Distance {
			return out[i].Distance < out[j].Distance
		}
		return out[i].Unit.Key() < out[j].Unit.Key()
	})
	return out
}

// fuzzyReachable runs a BFS over similarity edges whose weight is within the
// fuzzy threshold, returning each reached key mapped to its direct TLSH
// distance to the origin (which may exceed the threshold when reached only
// through intermediate hops).
func (g *Graph) fuzzyReachable(originKey string) map[string]int {
	origin := g.units[originKey]
	visited := map[string]bool{originKey: true}
	reached := make(map[string]int)
	queue := []string{originKey}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, l := range g.adj[cur] {
			if l.distance > g.fuzzyThreshold || visited[l.to] {
				continue
			}
			visited[l.to] = true
			queue = append(queue, l.to)

			dist := l.distance
			if cur != originKey && origin.ID.HasFuzzy() && g.units[l.to].ID.HasFuzzy() {
				if d, err := origin.ID.TLSH.Distance(g.units[l.to].ID.TLSH); err == nil {
					dist = d
				}
			}
			reached[l.to] = dist
		}
	}
	return reached
}
