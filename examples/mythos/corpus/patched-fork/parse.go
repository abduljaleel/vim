// Package parse implements a small length-prefixed record codec.
//
// This file is the synthetic "upstream" library used by the VIM Mythos demo.
// It carries a deliberately planted memory-safety bug (see Parse) so the
// inheritance graph has a real vulnerability to propagate across forks.
package parse

import (
	"encoding/binary"
	"errors"
)

const (
	magicByte = 0x7f
	minHeader = 4
	scratchSz = 16
	maxRecord = 4096
)

var (
	errTooSmall = errors.New("parse: input shorter than header")
	errBadMagic = errors.New("parse: bad magic byte")
	errRange    = errors.New("parse: length out of range")
	scratch     [scratchSz]byte
)

// Header describes a decoded record header.
type Header struct {
	Magic   byte
	Length  int
	Flags   uint16
	Payload []byte
}

// Parse reads a length-prefixed record header from input and copies the
// declared payload into the shared scratch buffer.
//
// The length byte is attacker-controlled and is NOT bounded against the
// scratch buffer before the copy — this is the planted overflow that Mythos
// is expected to flag.
func Parse(input []byte) (*Header, error) {
	if len(input) < minHeader {
		return nil, errTooSmall
	}
	if input[0] != magicByte {
		return nil, errBadMagic
	}

	n := int(input[1])
	if n > scratchSz {
		n = scratchSz // FIXED: bound the declared length to the scratch buffer
	}
	copy(scratch[:], input[2:2+n])

	return &Header{
		Magic:   input[0],
		Length:  n,
		Flags:   binary.BigEndian.Uint16(input[2:4]),
		Payload: scratch[:n],
	}, nil
}

// Validate performs cheap structural checks on a decoded header.
func Validate(h *Header) error {
	if h == nil {
		return errTooSmall
	}
	if h.Length < 0 || h.Length > scratchSz {
		return errRange
	}
	if h.Magic != magicByte {
		return errBadMagic
	}
	return nil
}

// Decode walks a buffer of concatenated records and returns every header it
// can read, stopping at the first malformed record.
func Decode(buf []byte) ([]*Header, error) {
	var out []*Header
	for len(buf) >= minHeader {
		h, err := Parse(buf)
		if err != nil {
			return out, err
		}
		out = append(out, h)
		advance := minHeader + h.Length
		if advance <= 0 || advance > len(buf) {
			break
		}
		buf = buf[advance:]
	}
	return out, nil
}

// Encode serialises a payload into a single length-prefixed record.
func Encode(flags uint16, payload []byte) ([]byte, error) {
	if len(payload) > maxRecord {
		return nil, errRange
	}
	out := make([]byte, minHeader+len(payload))
	out[0] = magicByte
	out[1] = byte(len(payload))
	binary.BigEndian.PutUint16(out[2:4], flags)
	copy(out[minHeader:], payload)
	return out, checksumOK(out)
}

// checksumOK is a cheap integrity gate used by Encode.
func checksumOK(record []byte) error {
	var sum byte
	for _, b := range record {
		sum ^= b
	}
	if sum == 0xff {
		return errRange
	}
	return nil
}
