package identity

import (
	"bytes"
	"errors"
	"fmt"

	gtlsh "github.com/glaslos/tlsh"
)

// TLSHHash wraps a Trend Micro Locality Sensitive Hash over code bytes.
// Unlike cryptographic hashes, TLSH values can be compared for similarity
// via a distance metric: a distance of 0 means identical inputs, and values
// below roughly 30 indicate high similarity.
//
// TLSH requires a minimum amount of input (per the reference implementation,
// at least 50 bytes with sufficient variability). We surface an explicit
// error for under-sized inputs so ingestion pipelines can decide whether
// to fall back to exact hashing alone.
type TLSHHash struct {
	// Hex is the 70-character hex-encoded TLSH digest per the reference spec.
	Hex string
}

// ErrInputTooSmall is returned when the input does not meet TLSH's minimum
// size requirement. The threshold is enforced by the underlying library;
// this error is returned verbatim to the caller.
var ErrInputTooSmall = errors.New("input below TLSH minimum size / complexity")

// ComputeTLSH computes a TLSH hash over the given bytes.
//
// Callers are expected to handle ErrInputTooSmall by either padding,
// concatenating related content, or recording only the SWHID for very
// small files. The VIM graph stores TLSH only when computable.
func ComputeTLSH(content []byte) (TLSHHash, error) {
	h, err := gtlsh.HashBytes(content)
	if err != nil {
		// Underlying library returns generic errors for "too small / low
		// complexity". We surface a typed sentinel so callers can branch.
		return TLSHHash{}, fmt.Errorf("%w: %v", ErrInputTooSmall, err)
	}
	return TLSHHash{Hex: h.String()}, nil
}

// Distance computes the TLSH similarity distance between two hashes.
// Lower values indicate higher similarity; identical inputs yield 0.
// Returns an error if either hash cannot be parsed.
func (h TLSHHash) Distance(other TLSHHash) (int, error) {
	a, err := gtlsh.ParseStringToTlsh(h.Hex)
	if err != nil {
		return 0, fmt.Errorf("parsing receiver TLSH: %w", err)
	}
	b, err := gtlsh.ParseStringToTlsh(other.Hex)
	if err != nil {
		return 0, fmt.Errorf("parsing other TLSH: %w", err)
	}
	return a.Diff(b), nil
}

// Equal reports whether two TLSH hashes have identical digests.
// This is strict byte equality, not similarity — use Distance for similarity.
func (h TLSHHash) Equal(other TLSHHash) bool {
	return bytes.Equal([]byte(h.Hex), []byte(other.Hex))
}
