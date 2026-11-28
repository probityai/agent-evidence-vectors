package jcsvectors

import (
	"fmt"
	"slices"
)

// Differential is one byte string that two JSON readers in common use read
// apart: one refuses it and the other decodes it, or both decode it to
// different values. A duplicate member keeps its first value in one reader
// and its last in another; an escaped lone surrogate decodes in one and is
// refused by the next; 1e400 is infinity to a double reader and a number to
// a decimal one; 2^53 + 1 rounds in one and not in the other. A signature
// over such bytes validates two documents.
//
// Each case states what RFC 8785 does with it (Error, Canonical) and what
// the corpus's bounded profile does (BoundedError): I-JSON strings and
// integers inside +-(2^53 - 1). Run both readers of a pipeline over every
// case and hold each to the profile it claims.
type Differential struct {
	// ID is the case's identifier in jcs-byte-vectors.
	ID string
	// Family groups cases that exercise one difference, such as
	// "duplicate-member", "invalid-unicode", "non-finite" or "noncharacter".
	Family string
	// Input is the bytes to read. Some are not UTF-8, so compare bytes.
	Input []byte
	// Error is the code RFC 8785 refuses Input with, such as
	// "duplicate-member". It is empty when RFC 8785 accepts Input.
	Error string
	// Canonical is the RFC 8785 output for Input. It is nil when RFC 8785
	// refuses Input, and also for an accepted case whose output the corpus
	// does not pin (an unsafe integer, whose output depends on the double it
	// rounds to): check only that such a case is accepted.
	Canonical []byte
	// BoundedError is the code the bounded profile refuses Input with. It is
	// empty when that profile admits Input.
	BoundedError string
	// Features names what the case exercises, as for [Vector].
	Features []Feature
}

// Accepted reports whether RFC 8785 accepts the case.
func (d Differential) Accepted() bool { return d.Error == "" }

// ParserDifferential reads every parser-differential case in
// jcs-byte-vectors and checks each embedded file against its digest before
// returning. The cases are: every refusal case, every reject case, every
// canonical case the bounded profile refuses, and every noncharacter the
// bounded profile refuses. Their neighbours, which both readers accept
// alike, are controls and are left out. A family added to the corpus's
// refusal cases is yielded with no change here.
//
// The iterator has the type of iter.Seq[Differential], written out so the
// module still builds with Go 1.21; on Go 1.23 or later, range over it:
//
//	cases, err := jcsvectors.ParserDifferential()
//	for d := range cases {
//		_, err := strictDecode(d.Input)
//		// err must be non-nil exactly when d.BoundedError != ""
//	}
func ParserDifferential() (func(yield func(Differential) bool), error) {
	cases, err := differentials()
	if err != nil {
		return nil, err
	}
	return func(yield func(Differential) bool) {
		for _, d := range cases {
			// Each pass yields its own copies, so a reader that edits its
			// input in place cannot change what the next pass reads.
			d.Input = slices.Clone(d.Input)
			d.Canonical = slices.Clone(d.Canonical)
			d.Features = slices.Clone(d.Features)
			if !yield(d) {
				return
			}
		}
	}, nil
}

func differentials() ([]Differential, error) {
	var cases byteCases
	if err := readJSON(byteCorpus+"/cases.json", &cases); err != nil {
		return nil, err
	}
	var out []Differential
	add := func(d Differential) {
		d.Features = features(d.Input, d.Canonical)
		out = append(out, d)
	}
	for _, c := range append(append([]acceptCase{}, cases.CanonicalCases...), cases.NoncharacterCases...) {
		if c.BoundedError == "" {
			if c.Bounded == "reject" {
				return nil, fmt.Errorf("%s case %s: the bounded profile refuses it with no code", byteCorpus, c.ID)
			}
			continue
		}
		canonical, err := c.canonical()
		if err != nil {
			return nil, err
		}
		family := c.Family
		if family == "" {
			family = c.BoundedError
		}
		add(Differential{ID: c.ID, Family: family, Input: []byte(c.Input), Canonical: canonical, BoundedError: c.BoundedError})
	}
	for _, c := range cases.RejectCases {
		// The bounded profile refuses everything RFC 8785 refuses.
		bounded := c.BoundedError
		if bounded == "" {
			bounded = c.JCSError
		}
		if bounded == "" {
			return nil, fmt.Errorf("%s case %s: a reject case with no code", byteCorpus, c.ID)
		}
		family := c.JCSError
		if family == "" {
			family = bounded
		}
		add(Differential{ID: c.ID, Family: family, Input: []byte(c.Input), Error: c.JCSError, BoundedError: bounded})
	}
	for _, c := range cases.refusals() {
		if c.Error == "" || c.Family == "" {
			return nil, fmt.Errorf("%s case %s: a refusal case needs a family and an error", byteCorpus, c.ID)
		}
		input, err := refusalInput(c.ID, c.Input, c.InputHex)
		if err != nil {
			return nil, err
		}
		add(Differential{ID: c.ID, Family: c.Family, Input: input, Error: c.Error, BoundedError: c.Error})
	}
	return out, nil
}
