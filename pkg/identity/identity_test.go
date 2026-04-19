package identity

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// synthetic generates a buffer of deterministic pseudo-text that is
// large and varied enough for TLSH to produce a valid hash.
// TLSH's reference minimum is ~50 bytes with adequate entropy; we pad
// well beyond that so the tests are not brittle on library version bumps.
func synthetic(seedLines int) []byte {
	var b bytes.Buffer
	for i := 0; i < seedLines; i++ {
		// Deterministic content — mixes identifiers so the byte
		// distribution is varied enough for TLSH's bucket counts.
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

func TestComputeContentSWHID_KnownVector(t *testing.T) {
	// Known vector: an empty Git blob hashes to a fixed SHA-1.
	// Compute: sha1("blob 0\0") = e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
	id := ComputeContentSWHID(nil)
	want := "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	if id.ObjectID != want {
		t.Fatalf("empty blob SWHID: got %s, want %s", id.ObjectID, want)
	}
	if id.String() != "swh:1:cnt:"+want {
		t.Fatalf("canonical form: got %s", id.String())
	}
}

func TestComputeContentSWHID_HelloWorld(t *testing.T) {
	// Well-known Git blob hash for "hello world\n"
	//   $ printf 'hello world\n' | git hash-object --stdin
	//   3b18e512dba79e4c8300dd08aeb37f8e728b8dad
	id := ComputeContentSWHID([]byte("hello world\n"))
	want := "3b18e512dba79e4c8300dd08aeb37f8e728b8dad"
	if id.ObjectID != want {
		t.Fatalf("hello world blob SWHID: got %s, want %s", id.ObjectID, want)
	}
}

func TestParseSWHID_RoundTrip(t *testing.T) {
	orig := ComputeContentSWHID([]byte("round trip"))
	parsed, err := ParseSWHID(orig.String())
	if err != nil {
		t.Fatalf("ParseSWHID: %v", err)
	}
	if parsed != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", parsed, orig)
	}
}

func TestParseSWHID_Errors(t *testing.T) {
	bad := []string{
		"",
		"swh:1:cnt",                                          // too few parts
		"git:1:cnt:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", // wrong scheme
		"swh:1:xxx:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", // bad object type
		"swh:1:cnt:shortid",                                  // bad id length
		"swh:X:cnt:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", // bad schema
	}
	for _, b := range bad {
		if _, err := ParseSWHID(b); err == nil {
			t.Errorf("expected error for %q, got nil", b)
		}
	}
}

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in        string
		wantType  string
		wantNS    string
		wantName  string
		wantVer   string
	}{
		{"pkg:npm/lodash@4.17.21", "npm", "", "lodash", "4.17.21"},
		{"pkg:golang/github.com/abduljaleel/vim@v0.1.0", "golang", "github.com/abduljaleel", "vim", "v0.1.0"},
		{"pkg:pypi/requests@2.31.0", "pypi", "", "requests", "2.31.0"},
		{"pkg:github/openssf/scorecard@v4", "github", "openssf", "scorecard", "v4"},
		{"pkg:npm/@babel/core@7.24.0", "npm", "@babel", "core", "7.24.0"},
	}
	for _, c := range cases {
		p, err := ParsePURL(c.in)
		if err != nil {
			t.Errorf("ParsePURL(%q) error: %v", c.in, err)
			continue
		}
		if p.Type != c.wantType || p.Namespace != c.wantNS || p.Name != c.wantName || p.Version != c.wantVer {
			t.Errorf("ParsePURL(%q) = %+v, want type=%s ns=%s name=%s ver=%s",
				c.in, p, c.wantType, c.wantNS, c.wantName, c.wantVer)
		}
	}
}

func TestParsePURL_Errors(t *testing.T) {
	bad := []string{
		"",
		"npm/lodash@4.17.21",              // missing "pkg:"
		"pkg:lodash",                      // no type separator
		"pkg:/lodash",                     // empty type
		"pkg:npm/",                        // empty name
	}
	for _, b := range bad {
		if _, err := ParsePURL(b); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
}

func TestComputeLineageID_EndToEnd(t *testing.T) {
	content := synthetic(20)

	pkg, err := ParsePURL("pkg:npm/example@1.0.0")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	id := ComputeLineageID(content, &pkg)

	if id.SWHID.ObjectID == "" {
		t.Error("SWHID not populated")
	}
	if id.PURL == nil {
		t.Error("pURL not populated")
	}
	if !id.HasFuzzy() {
		t.Error("TLSH not populated for sufficiently large content")
	}

	// Identical bytes -> identical LineageID.
	id2 := ComputeLineageID(content, &pkg)
	if !id.ExactMatch(id2) {
		t.Error("identical content should produce matching SWHID")
	}
	if id.TLSH.Hex != id2.TLSH.Hex {
		t.Error("identical content should produce matching TLSH")
	}
}

func TestFuzzyMatch_DetectsNearDuplicate(t *testing.T) {
	// Two variants of the same file — one has a SINGLE occurrence of the
	// "vulnerable line" replaced. This is the realistic scenario VIM must
	// detect: a fork applies a single-site fix, producing a file that
	// should remain fuzzily close to the unpatched upstream.
	//
	// Threshold note: the right TLSH distance cutoff is ecosystem-dependent
	// and is one of the empirical questions the VIM project intends to
	// answer via large-scale measurement (see the Amazon Security Research
	// Award proposal, RA2/RA3). 100 is chosen as a loose upper bound that
	// safely separates "related" from "unrelated" in the adjacent test
	// (unrelated bytes yield distance ~300).
	original := synthetic(20)
	patched := bytes.Replace(original,
		[]byte("\tcopy(buf[:], input[:16])\n"),
		[]byte("\tif err := safeCopy(&buf, input); err != nil { return err }\n"),
		1) // patch only the first occurrence — realistic single-site fix

	a := ComputeLineageID(original, nil)
	b := ComputeLineageID(patched, nil)

	// Exact match should fail: bytes differ.
	if a.ExactMatch(b) {
		t.Fatal("patched variant must not match original by SWHID")
	}

	similar, dist, ok := a.FuzzyMatch(b, 100)
	if !ok {
		t.Fatal("expected TLSH to be computable for both variants")
	}
	if !similar {
		t.Errorf("patched variant should be fuzzy-similar to original (distance=%d, threshold=100)", dist)
	}
	t.Logf("TLSH distance after single-site patch: %d", dist)
}

func TestFuzzyMatch_DetectsUnrelated(t *testing.T) {
	a := ComputeLineageID(synthetic(20), nil)

	// Random bytes — no shared lineage with the synthetic code.
	random := make([]byte, 4096)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	b := ComputeLineageID(random, nil)

	similar, dist, ok := a.FuzzyMatch(b, 60)
	if !ok {
		t.Fatal("expected both TLSH hashes to be computable")
	}
	if similar {
		t.Errorf("unrelated content should not be fuzzy-similar (distance=%d)", dist)
	}
	t.Logf("TLSH distance between code and random bytes: %d", dist)
}

func TestTLSH_TooSmallInputIsSilentlySkipped(t *testing.T) {
	// A one-liner is below TLSH's minimum. LineageID should still be
	// valid with only SWHID populated.
	id := ComputeLineageID([]byte("x\n"), nil)
	if id.SWHID.ObjectID == "" {
		t.Error("SWHID must still be computed for tiny content")
	}
	if id.HasFuzzy() {
		t.Error("tiny content should not produce a TLSH hash")
	}
}

func TestLineageID_StringIsReadable(t *testing.T) {
	id := ComputeLineageID(synthetic(10), nil)
	s := id.String()
	if !strings.Contains(s, "swh:1:cnt:") {
		t.Errorf("LineageID.String() missing SWHID: %s", s)
	}
}
