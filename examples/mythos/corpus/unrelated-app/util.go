// Package util provides small string helpers for the demo application.
//
// This file shares no lineage with the parse library; it exists so the
// inheritance graph has an obvious negative — code that must NOT appear in
// the blast radius of the parser vulnerability.
package util

import (
	"strings"
	"unicode"
)

// slugReplacer collapses common separators to a single hyphen.
var slugReplacer = strings.NewReplacer(" ", "-", "_", "-", "/", "-")

// Slugify lower-cases s, collapses separators, and strips non-alphanumerics.
func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugReplacer.Replace(s)
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevDash = false
		case r == '-' && !prevDash:
			b.WriteRune('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// Truncate shortens s to at most n runes, appending an ellipsis when cut.
func Truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return string(runes[:n-1]) + "…"
}

// WordCount returns the number of whitespace-separated tokens in s.
func WordCount(s string) int {
	return len(strings.Fields(s))
}

// TitleCase upper-cases the first letter of each whitespace-separated word.
func TitleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		words[i] = string(r)
	}
	return strings.Join(words, " ")
}
