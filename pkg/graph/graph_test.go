package graph

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// synthetic generates deterministic pseudo-code large and varied enough for
// TLSH to produce a hash (mirrors the helper in the identity package tests).
func synthetic(seedLines int) []byte {
	var b bytes.Buffer
	for i := 0; i < seedLines; i++ {
		b.WriteString("func VulnerableParse(input []byte) error {\n")
		b.WriteString("\tif len(input) < minHeader {\n")
		b.WriteString("\t\treturn errTooSmall\n")
		b.WriteString("\t}\n")
		b.WriteString("\tcopy(buf[:], input[:16])\n") // the "vulnerable" line
		b.WriteString("\treturn nil\n")
		b.WriteString("}\n\n")
	}
	return b.Bytes()
}

// patchOnce applies a single-site fix to one copy of the vulnerable line,
// producing a fork that should remain fuzzily close to the original.
func patchOnce(src []byte) []byte {
	return bytes.Replace(src,
		[]byte("\tcopy(buf[:], input[:16])\n"),
		[]byte("\tif err := safeCopy(&buf, input); err != nil { return err }\n"),
		1)
}

func occ(repo string) Occurrence { return Occurrence{Repo: repo, Path: "parse.go"} }

func TestAddCodeUnit_ExactCopiesMerge(t *testing.T) {
	g := New(0)
	content := synthetic(20)

	a := g.AddCodeUnit(content, nil, occ("github.com/upstream/lib"))
	b := g.AddCodeUnit(content, nil, occ("github.com/fork/lib"))

	if a != b {
		t.Fatal("byte-identical content should resolve to the same CodeUnit")
	}
	if g.NumUnits() != 1 {
		t.Fatalf("want 1 unique unit, got %d", g.NumUnits())
	}
	if g.NumOccurrences() != 2 {
		t.Fatalf("want 2 occurrences, got %d", g.NumOccurrences())
	}
}

func TestBlastRadius_ExactAndFuzzy(t *testing.T) {
	g := New(100)
	vuln := synthetic(20)
	patched := patchOnce(vuln)

	// random, unrelated content — must not enter the blast radius.
	unrelated := make([]byte, 4096)
	if _, err := rand.Read(unrelated); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	origin := g.AddCodeUnit(vuln, nil, occ("github.com/upstream/lib"))
	g.AddCodeUnit(vuln, nil, occ("github.com/verbatim/fork"))      // exact copy
	g.AddCodeUnit(patched, nil, occ("github.com/patched/fork"))    // fuzzy variant
	g.AddCodeUnit(unrelated, nil, occ("github.com/unrelated/app")) // unrelated

	if err := g.AddVulnerability(Vulnerability{
		ID: "MYTHOS-1", Source: "mythos", Severity: "high",
		Summary: "test", AffectsSWHID: origin.Key(),
	}); err != nil {
		t.Fatalf("AddVulnerability: %v", err)
	}

	v, impacts, err := g.BlastRadius("MYTHOS-1")
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}
	if v.ID != "MYTHOS-1" {
		t.Fatalf("unexpected vuln %q", v.ID)
	}

	if impacts[0].Relation != RelationOrigin {
		t.Fatalf("first impact must be the origin, got %s", impacts[0].Relation)
	}
	// Origin node carries both byte-identical copies as occurrences.
	if got := len(impacts[0].Unit.Occurrences); got != 2 {
		t.Errorf("origin should have 2 exact copies, got %d", got)
	}

	var fuzzy int
	for _, im := range impacts[1:] {
		if im.Relation != RelationFuzzy {
			t.Errorf("non-origin impact should be fuzzy, got %s", im.Relation)
		}
		fuzzy++
	}
	if fuzzy != 1 {
		t.Fatalf("expected exactly 1 fuzzy neighbour (the patched fork), got %d", fuzzy)
	}
	if d := impacts[1].Distance; d <= 0 || d > 100 {
		t.Errorf("patched fork distance %d outside (0,100]", d)
	}
	t.Logf("patched-fork TLSH distance to origin: %d", impacts[1].Distance)
}

func TestBlastRadius_TransitiveLineage(t *testing.T) {
	g := New(100)
	a := synthetic(20)
	b := patchOnce(a)            // small patch of A
	c := patchOnce(patchOnce(a)) // two-site patch — further from A

	ua := g.AddCodeUnit(a, nil, occ("upstream"))
	g.AddCodeUnit(b, nil, occ("fork-b"))
	g.AddCodeUnit(c, nil, occ("fork-c"))

	if err := g.AddVulnerability(Vulnerability{
		ID: "MYTHOS-2", AffectsSWHID: ua.Key(), Source: "mythos",
	}); err != nil {
		t.Fatalf("AddVulnerability: %v", err)
	}

	_, impacts, err := g.BlastRadius("MYTHOS-2")
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}

	reached := map[string]bool{}
	for _, im := range impacts {
		for _, o := range im.Unit.Occurrences {
			reached[o.Repo] = true
		}
	}
	for _, repo := range []string{"upstream", "fork-b", "fork-c"} {
		if !reached[repo] {
			t.Errorf("expected %q in blast radius (lineage chain), reached=%v", repo, reached)
		}
	}
}

func TestBlastRadius_Errors(t *testing.T) {
	g := New(0)
	if _, _, err := g.BlastRadius("nope"); err == nil {
		t.Error("expected error for unknown vulnerability")
	}

	// Vulnerability that targets a SWHID not present in the graph.
	if err := g.AddVulnerability(Vulnerability{ID: "MYTHOS-3", AffectsSWHID: "deadbeef"}); err != nil {
		t.Fatalf("AddVulnerability: %v", err)
	}
	if _, _, err := g.BlastRadius("MYTHOS-3"); err == nil {
		t.Error("expected error when affected SWHID is absent from the graph")
	}
}

func TestAddVulnerability_Validation(t *testing.T) {
	g := New(0)
	if err := g.AddVulnerability(Vulnerability{AffectsSWHID: "x"}); err == nil {
		t.Error("expected error for missing ID")
	}
	if err := g.AddVulnerability(Vulnerability{ID: "v"}); err == nil {
		t.Error("expected error for missing AffectsSWHID")
	}
	if err := g.AddVulnerability(Vulnerability{ID: "v", AffectsSWHID: "x"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := g.AddVulnerability(Vulnerability{ID: "v", AffectsSWHID: "y"}); err == nil {
		t.Error("expected error for duplicate ID")
	}
}

func TestParseMythosReport(t *testing.T) {
	good := `{
	  "source": "mythos",
	  "findings": [
	    {"id": "MYTHOS-2026-0001", "severity": "critical",
	     "summary": "overflow", "target": {"path": "upstream/parse.go"}}
	  ]
	}`
	r, err := ParseMythosReport(strings.NewReader(good))
	if err != nil {
		t.Fatalf("ParseMythosReport: %v", err)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != "MYTHOS-2026-0001" {
		t.Fatalf("unexpected report: %+v", r)
	}

	bad := []string{
		`{"findings": []}`, // no findings
		`{"findings": [{"severity": "high", "target": {"path": "x"}}]}`,    // missing id
		`{"findings": [{"id": "X", "target": {}}]}`,                        // target has neither path nor swhid
		`{"findings": [{"id": "X", "target": {"path": "x"}}], "bogus": 1}`, // unknown field
	}
	for _, b := range bad {
		if _, err := ParseMythosReport(strings.NewReader(b)); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
}

func TestLineage(t *testing.T) {
	g := New(100)
	a := synthetic(20)
	origin := g.AddCodeUnit(a, nil, occ("upstream"))
	g.AddCodeUnit(patchOnce(a), nil, occ("fork"))

	impacts, err := g.Lineage(origin.Key())
	if err != nil {
		t.Fatalf("Lineage: %v", err)
	}
	if len(impacts) != 2 {
		t.Fatalf("want origin + 1 neighbour, got %d impacts", len(impacts))
	}
	if _, err := g.Lineage("missing"); err == nil {
		t.Error("expected error for unknown unit")
	}
}
