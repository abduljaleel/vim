// Package main implements the VIM command-line interface.
//
// vim-cli is the primary developer-facing tool for querying the
// Vulnerability Inheritance Map graph. This is a pre-alpha build.
//
// Two layers are functional:
//   - identity / similarity: the trilateral identity layer
//     (pURL + SWHID + TLSH) over local files.
//   - ingest / query / lineage: an in-memory inheritance graph that takes
//     vulnerabilities discovered by Mythos and traces their blast radius
//     across forks, vendored copies, and modified variants in a corpus.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/abduljaleel/vim/pkg/graph"
	"github.com/abduljaleel/vim/pkg/identity"
)

// version is set at build time via -ldflags.
var version = "0.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("vim-cli %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	case "identity":
		runIdentity(os.Args[2:])
	case "similarity":
		runSimilarity(os.Args[2:])
	case "ingest":
		runIngest(os.Args[2:])
	case "query":
		runQuery(os.Args[2:])
	case "lineage":
		runLineage(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// runIdentity prints the LineageID of a file, demonstrating the
// trilateral identity resolution layer.
func runIdentity(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: vim-cli identity <file> [pURL]")
		os.Exit(1)
	}
	content, err := readFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", args[0], err)
		os.Exit(1)
	}

	var pkg *identity.PURL
	if len(args) > 1 {
		p, err := identity.ParsePURL(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "parsing pURL: %v\n", err)
			os.Exit(1)
		}
		pkg = &p
	}

	id := identity.ComputeLineageID(content, pkg)
	fmt.Printf("File:  %s\n", args[0])
	fmt.Printf("Size:  %d bytes\n", len(content))
	fmt.Printf("SWHID: %s\n", id.SWHID.String())
	if id.PURL != nil {
		fmt.Printf("pURL:  %s\n", id.PURL.String())
	}
	if id.HasFuzzy() {
		fmt.Printf("TLSH:  %s\n", id.TLSH.Hex)
	} else {
		fmt.Println("TLSH:  (not computed — input too small or low entropy)")
	}
}

// runSimilarity compares two files and prints their TLSH distance.
func runSimilarity(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vim-cli similarity <file1> <file2>")
		os.Exit(1)
	}
	a, err := readFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", args[0], err)
		os.Exit(1)
	}
	b, err := readFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", args[1], err)
		os.Exit(1)
	}

	idA := identity.ComputeLineageID(a, nil)
	idB := identity.ComputeLineageID(b, nil)

	fmt.Printf("%s -> SWHID %s\n", args[0], idA.SWHID.ObjectID)
	fmt.Printf("%s -> SWHID %s\n", args[1], idB.SWHID.ObjectID)

	if idA.ExactMatch(idB) {
		fmt.Println("Result: EXACT match (byte-identical)")
		return
	}

	if !idA.HasFuzzy() || !idB.HasFuzzy() {
		fmt.Println("Result: files differ; TLSH unavailable for at least one input")
		return
	}

	dist, err := idA.TLSH.Distance(idB.TLSH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLSH distance: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("TLSH distance: %d\n", dist)
	switch {
	case dist <= 30:
		fmt.Println("Result: HIGH similarity (likely same code, minor edits)")
	case dist <= 100:
		fmt.Println("Result: MODERATE similarity (possibly related / patched variant)")
	default:
		fmt.Println("Result: LOW similarity (likely unrelated)")
	}
}

// runIngest builds the inheritance graph from a corpus and a Mythos report,
// then prints what was ingested and a one-line blast radius per finding.
func runIngest(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vim-cli ingest <mythos-report.json> <corpus-dir>")
		os.Exit(1)
	}
	reportPath, corpusDir := args[0], args[1]

	g, report, err := buildGraph(reportPath, corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ingest: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ingested Mythos report: %s  (source: %s)\n", reportPath, report.Source)
	fmt.Printf("Scanned corpus:         %s\n\n", corpusDir)
	fmt.Println("Graph:")
	fmt.Printf("  Code units (unique content):   %d\n", g.NumUnits())
	fmt.Printf("  Occurrences (observed copies): %d\n", g.NumOccurrences())
	fmt.Printf("  Similarity edges (lineage):    %d\n", g.NumSimilarityEdges())
	fmt.Printf("  Vulnerabilities:               %d\n\n", len(report.Findings))

	fmt.Println("Findings:")
	for _, v := range g.Vulnerabilities() {
		_, impacts, err := g.BlastRadius(v.ID)
		if err != nil {
			fmt.Printf("  - %s [%s] -> %v\n", v.ID, strings.ToUpper(v.Severity), err)
			continue
		}
		confirmed, review := tally(impacts)
		fmt.Printf("  - %s [%s] -> %d identical copies, %d related units to review\n",
			v.ID, strings.ToUpper(v.Severity), confirmed, review)
	}
}

// runQuery prints the full blast radius for one finding, or all of them.
func runQuery(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vim-cli query <mythos-report.json> <corpus-dir> [vuln-id]")
		os.Exit(1)
	}
	reportPath, corpusDir := args[0], args[1]

	g, _, err := buildGraph(reportPath, corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query: %v\n", err)
		os.Exit(1)
	}

	var targets []*graph.Vulnerability
	if len(args) > 2 {
		v, impacts, err := g.BlastRadius(args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "query: %v\n", err)
			os.Exit(1)
		}
		printBlastRadius(g, v, impacts)
		return
	}
	targets = g.Vulnerabilities()
	for i, v := range targets {
		if i > 0 {
			fmt.Println(strings.Repeat("─", 64))
		}
		_, impacts, err := g.BlastRadius(v.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "query %s: %v\n", v.ID, err)
			continue
		}
		printBlastRadius(g, v, impacts)
	}
}

// runLineage prints the lineage neighbourhood of a single file, independent
// of any vulnerability.
func runLineage(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vim-cli lineage <corpus-dir> <file>")
		os.Exit(1)
	}
	corpusDir, file := args[0], args[1]

	g := graph.New(0)
	if err := scanCorpus(g, corpusDir); err != nil {
		fmt.Fprintf(os.Stderr, "lineage: %v\n", err)
		os.Exit(1)
	}

	content, err := readFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", file, err)
		os.Exit(1)
	}
	key := identity.ComputeContentSWHID(content).ObjectID
	if _, ok := g.UnitByKey(key); !ok {
		g.AddCodeUnit(content, nil, graph.Occurrence{Path: filepath.Base(file)})
	}

	impacts, err := g.Lineage(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lineage: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Lineage of %s\n", file)
	fmt.Printf("  SWHID: swh:1:cnt:%s\n\n", key)
	if len(impacts) == 1 {
		fmt.Println("No related units found in the corpus (no shared lineage).")
		return
	}
	fmt.Printf("Related units (TLSH <= %d):\n", g.FuzzyThreshold())
	for _, im := range impacts[1:] {
		for _, o := range im.Unit.Occurrences {
			fmt.Printf("  - %-40s TLSH distance %d%s\n", o, im.Distance, transitiveTag(im))
		}
	}
}

// buildGraph scans the corpus into a graph and attaches a Mythos report.
func buildGraph(reportPath, corpusDir string) (*graph.Graph, *graph.MythosReport, error) {
	g := graph.New(0)
	if err := scanCorpus(g, corpusDir); err != nil {
		return nil, nil, err
	}

	f, err := os.Open(reportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening report: %w", err)
	}
	defer func() { _ = f.Close() }()

	report, err := graph.ParseMythosReport(f)
	if err != nil {
		return nil, nil, err
	}
	if err := attachReport(g, report, corpusDir); err != nil {
		return nil, nil, err
	}
	return g, report, nil
}

// scanCorpus walks corpusDir and adds every regular file as a CodeUnit.
func scanCorpus(g *graph.Graph, corpusDir string) error {
	return filepath.WalkDir(corpusDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(corpusDir, path)
		if err != nil {
			rel = path
		}
		repo, p := splitRepoPath(rel)
		g.AddCodeUnit(content, nil, graph.Occurrence{Repo: repo, Path: p})
		return nil
	})
}

// attachReport resolves each finding's target to a SWHID and records the
// vulnerability, adding the targeted unit if it is not already in the corpus.
func attachReport(g *graph.Graph, report *graph.MythosReport, corpusDir string) error {
	for _, f := range report.Findings {
		swhid, err := resolveTarget(g, f.Target, corpusDir)
		if err != nil {
			return fmt.Errorf("finding %s: %w", f.ID, err)
		}
		if err := g.AddVulnerability(graph.Vulnerability{
			ID:           f.ID,
			Source:       report.Source,
			Severity:     f.Severity,
			Summary:      f.Summary,
			AffectsSWHID: swhid,
		}); err != nil {
			return err
		}
	}
	return nil
}

// resolveTarget returns the SWHID object id a finding refers to. A pre-computed
// SWHID is used directly; otherwise the file at Target.Path (relative to the
// corpus) is hashed and ensured present in the graph.
func resolveTarget(g *graph.Graph, t graph.MythosTarget, corpusDir string) (string, error) {
	if t.SWHID != "" {
		if strings.HasPrefix(t.SWHID, "swh:") {
			parsed, err := identity.ParseSWHID(t.SWHID)
			if err != nil {
				return "", err
			}
			return parsed.ObjectID, nil
		}
		return t.SWHID, nil
	}

	full := t.Path
	if !filepath.IsAbs(full) {
		full = filepath.Join(corpusDir, t.Path)
	}
	content, err := os.ReadFile(full)
	if err != nil {
		return "", fmt.Errorf("reading target %s: %w", t.Path, err)
	}

	var pkg *identity.PURL
	if t.PURL != "" {
		p, err := identity.ParsePURL(t.PURL)
		if err != nil {
			return "", err
		}
		pkg = &p
	}

	key := identity.ComputeContentSWHID(content).ObjectID
	if _, ok := g.UnitByKey(key); !ok {
		repo, p := splitRepoPath(t.Path)
		g.AddCodeUnit(content, pkg, graph.Occurrence{Repo: repo, Path: p})
	}
	return key, nil
}

// printBlastRadius renders a finding and every code unit it reaches.
func printBlastRadius(g *graph.Graph, v *graph.Vulnerability, impacts []graph.Impact) {
	fmt.Printf("Vulnerability %s  [%s]  (source: %s)\n", v.ID, strings.ToUpper(v.Severity), v.Source)
	if v.Summary != "" {
		fmt.Printf("  %s\n", v.Summary)
	}
	origin := impacts[0].Unit
	fmt.Printf("  Origin SWHID: swh:1:cnt:%s\n", origin.Key())
	if origin.ID.PURL != nil {
		fmt.Printf("  Origin pURL:  %s\n", origin.ID.PURL.String())
	}
	fmt.Printf("\nBlast radius — lineage threshold TLSH <= %d:\n\n", g.FuzzyThreshold())

	fmt.Printf("  CONFIRMED · byte-identical copies of the vulnerable code (%d):\n", len(origin.Occurrences))
	for _, o := range origin.Occurrences {
		fmt.Printf("    - %s\n", o)
	}

	fuzzy := impacts[1:]
	reviewLocs := 0
	for _, im := range fuzzy {
		reviewLocs += len(im.Unit.Occurrences)
	}
	fmt.Printf("\n  REVIEW · shares lineage, fix may or may not be applied (%d):\n", reviewLocs)
	if len(fuzzy) == 0 {
		fmt.Println("    (none)")
	}
	for _, im := range fuzzy {
		for _, o := range im.Unit.Occurrences {
			fmt.Printf("    - %-40s TLSH distance %d%s\n", o, im.Distance, transitiveTag(im))
		}
	}

	confirmed, review := tally(impacts)
	fmt.Printf("\n  Summary: %d locations carry identical vulnerable code; %d related units need review.\n",
		confirmed, review)
}

// tally counts confirmed identical copies (origin occurrences) and the number
// of distinct fuzzy units to review.
func tally(impacts []graph.Impact) (confirmed, review int) {
	if len(impacts) == 0 {
		return 0, 0
	}
	confirmed = len(impacts[0].Unit.Occurrences)
	review = len(impacts) - 1
	return confirmed, review
}

func transitiveTag(im graph.Impact) string {
	if im.Transitive {
		return "  (transitive)"
	}
	return ""
}

// splitRepoPath splits a corpus-relative path into a leading repo segment and
// the remaining path. A path with no separator has an empty repo.
func splitRepoPath(rel string) (repo, path string) {
	rel = filepath.ToSlash(rel)
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i], rel[i+1:]
	}
	return "", rel
}

func readFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func printUsage() {
	fmt.Print(`vim-cli — Vulnerability Inheritance Map CLI

Usage:
  vim-cli <command> [flags]

Identity layer (local files):
  identity <file> [pURL]   Compute LineageID (SWHID + TLSH + optional pURL)
  similarity <a> <b>       Compare two files via TLSH distance

Inheritance graph (Mythos findings + a corpus):
  ingest <report.json> <corpus-dir>           Build the graph; show what was ingested
  query  <report.json> <corpus-dir> [vuln-id] Trace a finding's blast radius
  lineage <corpus-dir> <file>                 Show a file's lineage neighbourhood

Other:
  version                  Print the CLI version
  help                     Show this help

A Mythos report is JSON (see examples/mythos/findings.json). The corpus is a
directory of source files VIM scans for forks, vendored copies, and variants.

This project is in pre-alpha development.
See https://github.com/abduljaleel/vim
`)
}
