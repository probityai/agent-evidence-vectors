package aee

import (
	"encoding/json"
	"errors"
	"fmt"
)

// StatementType is the only accepted in-toto statement _type (spec:req-statement-schema@4f99b2e706804a40).
const StatementType = "https://in-toto.io/Statement/v1"

// PredicateType is the only predicateType this implementation accepts
// (spec:req-type-uri@49df4c4db713a87b). A different version URI is rejected fail-closed; the verifier
// never attempts more than one construction (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530).
const PredicateType = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"

// Closed vocabularies (spec:req-verification-design-invariant-follows-recompute-per@defbae512ee38603,req-fields-row-per-executed-attack-attackid@73a2f29b13fa08fa).
const (
	ResultPass         = "pass"
	ResultPassIndirect = "pass_indirect"
	ResultDegraded     = "degraded"
	ResultFail         = "fail"

	BasisSubstrate = "substrate"
	BasisArtifact  = "artifact"

	MethodIntercepted   = "intercepted"
	MethodReconstructed = "reconstructed"

	// The attribution vocabulary is closed and two-valued (spec:req-fields-substrate-input-row-s-claim@5d07a2e68d1623d7).
	// pinned says the row rests on an interception whose committed value the
	// corpus declared in advance; paired says the correspondence was
	// established some other way and is a producer assertion. paired is a
	// floor a producer may always truthfully declare, never a confession.
	AttributionPinned = "pinned"
	AttributionPaired = "paired"

	KindInterception = "interception"
	KindArming       = "arming"
	KindSealed       = "sealed"
	KindExamination  = "examination"

	// The two kinds registered as non-covering (spec:req-fields-dsse-envelope-per-observation-payload-2@6ad791ea2fe1f425). Neither
	// carries constraints, because there is no state in which either covers
	// anything and therefore none in which a constraint could change an
	// outcome. They are named here rather than left to the unknown-kind arm so
	// the refusal a row earns by resolving one says which of the two producer
	// errors it is: a kind that covers nothing by registration, or a kind this
	// verifier has never heard of.
	KindMoatDrop               = "moat-drop"
	KindUncommittedObservation = "uncommitted-observation"

	ActualLayerNone = "none"
)

// Subject is one in-toto statement subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is a parsed in-toto statement carrying an AEE predicate.
type Statement struct {
	Type          string
	Subject       []Subject
	PredicateType string
	PredicateRaw  json.RawMessage
	Predicate     *Predicate

	// ParseCodes collects shape faults found while decoding members; GATE 0
	// folds them into its own code list.
	ParseCodes []Code
}

// Predicate is the decoded predicate body. Member presence is tracked
// explicitly wherever "absent" and "empty" differ normatively.
type Predicate struct {
	Raw map[string]json.RawMessage

	Result        string
	ResultPresent bool

	Env *Environment

	Coverage        *Coverage
	CoveragePresent bool

	Rows        []Row
	RowsPresent bool

	Records        []Record
	RecordsPresent bool

	BatchRoot        string
	BatchRootPresent bool

	IssuedAt        string
	IssuedAtPresent bool
}

// Environment is observationEnvironment (spec:req-fields-limit-common-all-four-stronger@5e7dea1f752df369).
type Environment struct {
	Raw map[string]json.RawMessage

	Substrate      *DigestRef
	Corpus         *Corpus
	CatchPolicy    *DigestRef
	NetworkPosture *NetworkPosture
	Vocabulary     *Vocabulary
	RunEntropy     *DigestRef
}

// DigestRef is a named digest reference ({name?, digest:{sha256: ...}}).
type DigestRef struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Sha256 returns the sha256 member of the digest set ("" when absent).
func (d *DigestRef) Sha256() string {
	if d == nil || d.Digest == nil {
		return ""
	}
	return d.Digest["sha256"]
}

// Corpus carries the digest-committed corpus manifest (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7).
type Corpus struct {
	Name        string            `json:"name"`
	URI         string            `json:"uri"`
	Digest      map[string]string `json:"digest"`
	ManifestRaw json.RawMessage   `json:"manifest"`

	Classes map[string][]string `json:"-"`

	// ExpectedPayloads is the optional per-attack map of the commitment values
	// a substrate is expected to carry when it observes that attack
	// (spec:req-fields-caught-row-whose-containmentobserved-label-2@853cd39a636c0f55). Present distinguishes an absent map from an empty one:
	// a row whose attackId has no entry MUST declare paired, and "the manifest
	// carries no map at all" and "the map carries no entry for this attack"
	// are the same answer to that question, so the two are not separated in
	// the rule -- but a map present and unparseable is a malformed manifest,
	// which is a different answer, and Present is what keeps them apart.
	ExpectedPayloads        map[string][]string `json:"-"`
	ExpectedPayloadsPresent bool                `json:"-"`
	ExpectedPayloadsShapeOK bool                `json:"-"`
}

// Sha256 returns the corpus digest sha256 ("" when absent).
func (c *Corpus) Sha256() string {
	if c == nil || c.Digest == nil {
		return ""
	}
	return c.Digest["sha256"]
}

// NetworkPosture is the substrate-authoritative egress posture pin
// (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7). The set of posture values is a closed registry, and a value
// outside it is a malformed statement rather than a fail-closed row
// (spec:req-fields-digest-pinned-context-evidence-was@64df74fb15323223). That reading was this repository's for two revisions while
// the document introduced the values illustratively and named no consequence
// for one outside the list; the document now registers the set and states the
// consequence, so the reading is cited rather than argued.
//
// Posture holds the decoded string and is empty both when the member is absent
// and when it holds a value of another JSON type. The two are not
// distinguished here on purpose: neither is a registered posture, and the
// closed-registry check reports the same code for both, so keeping them apart
// would add a distinction nothing reads. What matters is that a non-string
// value does NOT fail the surrounding decode -- it did, and a statement
// carrying one then reported the parse catch-all here while the other rails
// named the posture registry, which is a cross-rail split over the same bytes.
type NetworkPosture struct {
	Posture string            `json:"-"`
	Digest  map[string]string `json:"digest"`
}

// UnmarshalJSON decodes the member, mapping a posture that is not a JSON
// string to the empty posture instead of to a decode failure.
func (n *NetworkPosture) UnmarshalJSON(b []byte) error {
	var shadow struct {
		Posture json.RawMessage   `json:"posture"`
		Digest  map[string]string `json:"digest"`
	}
	if err := json.Unmarshal(b, &shadow); err != nil {
		return err
	}
	n.Digest = shadow.Digest
	n.Posture = ""
	if len(shadow.Posture) > 0 {
		var s string
		if json.Unmarshal(shadow.Posture, &s) == nil {
			n.Posture = s
		}
	}
	return nil
}

// EgressPostures is the registry of substrate-authoritative egress postures
// (spec:req-fields-digest-pinned-context-evidence-was@64df74fb15323223). All four values, the append-only rule across minor versions,
// and the fail-closed consequence are the document's own; they were stated
// here as this repository's reading until the document registered them.
var EgressPostures = map[string]bool{
	"no_network":           true,
	"allowlist":            true,
	"sinkhole":             true,
	"unsafe_bypass_egress": true,
}

// isJSONObject reports whether raw is a JSON object. The check is on the first
// non-whitespace byte, which is enough: the bytes have already parsed as JSON
// by the time any caller here holds them.
func isJSONObject(raw []byte) bool {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return c == '{'
		}
	}
	return false
}

// Sha256 returns the posture digest sha256 ("" when absent).
func (n *NetworkPosture) Sha256() string {
	if n == nil || n.Digest == nil {
		return ""
	}
	return n.Digest["sha256"]
}

// Vocabulary is observationVocabulary (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7).
type Vocabulary struct {
	Digest map[string]string `json:"digest"`
	Labels []string          `json:"labels"`
	Caught []string          `json:"caught"`

	LabelsPresent bool `json:"-"`
	CaughtPresent bool `json:"-"`
}

// Sha256 returns the vocabulary digest sha256 ("" when absent). Version 2 of
// the run binding folds this value in, so narrowing the caught set after the
// run derives a binding the producer's own records do not carry.
func (v *Vocabulary) Sha256() string {
	if v == nil || v.Digest == nil {
		return ""
	}
	return v.Digest["sha256"]
}

// Coverage is the coverage bound (spec:req-fields-networkposture-posture-vocabulary-closed-four-2@591aef9c088d9164).
type Coverage struct {
	AssessedClasses []string          `json:"assessedClasses"`
	OutOfScope      map[string]string `json:"outOfScope"`
	RoutedElsewhere map[string]string `json:"routedElsewhere"`
}

// Row is one attackResults row. Pointer members distinguish an absent member
// from an empty value: absent basis/method/attribution is fail-closed
// (spec:req-fields-method-states-how-row-s@d35548444900b334), absent actualLayer is a malformed statement (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5).
type Row struct {
	Raw map[string]json.RawMessage

	AttackID            string
	ContainmentObserved string
	Basis               *string
	Method              *string
	Attribution         *string
	ActualLayer         *string

	// RefsPresent and RefsRaw keep the member's raw shape so non-integer and
	// negative indexes are reportable (ref-malformed) rather than a decode
	// panic. Refs holds the resolved indexes when every entry is a valid
	// non-negative integer.
	RefsPresent bool
	RefsRaw     []json.RawMessage
	Refs        []int
	RefsErr     error
}

// IsSubstrate reports whether the row declares basis: substrate.
func (r *Row) IsSubstrate() bool {
	return r.Basis != nil && *r.Basis == BasisSubstrate
}

// Record is one observation record: a DSSE-shaped envelope (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5).
type Record struct {
	PayloadB64  string           `json:"payload"`
	PayloadType string           `json:"payloadType"`
	Signatures  RecordSignatures `json:"signatures"`
}

// RecordSignatures is a record's signatures member. The requirement it has to
// meet is a count -- the member MUST carry at least one entry (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5) --
// so the decoder's job here is to produce a count for every JSON value the
// member can hold, including the ones that hold no entries at all.
type RecordSignatures []RecordSignature

// UnmarshalJSON decodes the member, mapping a value that is not a JSON array to
// zero entries instead of to a decode failure.
//
// Without this, a member such as "signatures": "sig" failed to decode into a
// slice, the whole statement reported the parse catch-all, and this rail named
// a different condition than the other rails for the same wire bytes. The
// catch-all is the wrong answer twice over: it names neither the record nor the
// member, and the registry has already decided that a signatures member holding
// no entries reports record-signatures-empty rather than the catch-all, since
// an absent member takes that code and an absent member is equally a missing
// required member. A value of the wrong JSON type carries no entry either, so
// it is the same requirement failing and belongs under the same condition.
//
// A member that IS an array keeps its existing strictness: the error surfaces
// unchanged, because an array carries entries and a fault inside one of them is
// a fault in the entry rather than in the count.
func (s *RecordSignatures) UnmarshalJSON(b []byte) error {
	var entries []RecordSignature
	err := json.Unmarshal(b, &entries)
	if err == nil {
		*s = entries
		return nil
	}
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) == nil {
		return err
	}
	*s = nil
	return nil
}

// RecordSignature matches the DSSE signature member shape. The keyid is an
// unauthenticated lookup hint and never the check itself (spec:req-verification-consumer-pin-out-band-set@263aa86dc614e465).
type RecordSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// maxStatementBytes bounds the whole untrusted statement before it is
// unmarshaled. The JCS layer already caps per-record-payload size and nesting
// depth, but nothing bounded the outer statement, so a statement with very many
// records (or huge non-payload fields) could exhaust memory. The bound is
// generous relative to any legitimate AEE statement; it is a resource guard, not
// a conformance rule, and both reference rails apply the same limit.
const maxStatementBytes = 64 << 20 // 64 MiB

// ParseStatement decodes one complete in-toto statement. A nil error means
// the JSON decoded; shape faults that have their own registry code are
// collected into Statement.ParseCodes for GATE 0 rather than failing the
// parse, so one malformed member reports its named code instead of a generic
// failure.
func ParseStatement(b []byte) (*Statement, error) {
	if len(b) > maxStatementBytes {
		return nil, fmt.Errorf("%w: statement is %d bytes", ErrInputTooLarge, len(b))
	}
	var shadow struct {
		Type          *string         `json:"_type"`
		Subject       []Subject       `json:"subject"`
		PredicateType *string         `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(b, &shadow); err != nil {
		return nil, fmt.Errorf("statement does not parse: %w", err)
	}
	// Statement-wide strict I-JSON (RFC 7493), enforced on the RAW bytes before
	// any member is read. stdlib json.Unmarshal is lossy in exactly the two ways
	// this profile forbids -- it silently keeps the last of a repeated member,
	// and it silently substitutes U+FFFD for an unpaired surrogate escape or
	// invalid UTF-8 -- so both faults are unrecoverable one layer later, when
	// every downstream check reads decoded Go strings. This is the seam that
	// makes those checks sound: GATE 0's observationVocabulary rules (sortedness,
	// duplicate-freedom, BMP-only, digest) compare decoded strings and cannot
	// themselves tell a U+FFFD that the producer wrote from one the decoder
	// invented, so a statement whose bytes do not decode faithfully must not
	// reach them at all.
	//
	// Promoted fail-closed:
	//   - ErrDuplicateMember, ErrStringNotScalar: the two lossy-decode faults;
	//   - ErrInputTooLarge, ErrInputTooDeep: the strict pass could not run to
	//     completion, so neither fault above was ruled out. Without these a
	//     producer pads the statement past the parse bounds with an oversized or
	//     deeply nested extra member and the checks above are skipped silently.
	//
	// The number-profile divergences are not promoted: the safe-integer profile
	// is scoped to canonicalized content, and basic parseability is already
	// established above.
	if _, perr := parseJSONValue(b); errors.Is(perr, ErrDuplicateMember) ||
		errors.Is(perr, ErrStringNotScalar) ||
		errors.Is(perr, ErrInputTooLarge) ||
		errors.Is(perr, ErrInputTooDeep) {
		return nil, fmt.Errorf("statement does not parse: %w", perr)
	}
	s := &Statement{Subject: shadow.Subject, PredicateRaw: shadow.Predicate}
	if shadow.Type != nil {
		s.Type = *shadow.Type
	}
	if shadow.PredicateType != nil {
		s.PredicateType = *shadow.PredicateType
	}
	// The three empty predicate states are ONE input (spec/v1/statement.md):
	// an absent member, "predicate": null and "predicate": {} decode to the
	// empty predicate object, and everything downstream is therefore identical
	// for all three. An absent member used to return an error here, which
	// Verify maps to statement-malformed, so the spelling the producer chose
	// decided which reason a relying party was handed for identical bytes.
	// PredicateRaw keeps the carried bytes rather than the normalized form:
	// it is what the attestor re-emits, and normalizing it would rewrite a
	// producer's own JSON.
	raw := shadow.Predicate
	if len(raw) == 0 {
		raw = emptyPredicate
	}
	p, codes := parsePredicate(raw)
	s.Predicate = p
	s.ParseCodes = codes
	return s, nil
}

// emptyPredicate is the decoded form the three empty predicate states share.
// It is spelled once so no caller can normalize one state and miss another.
var emptyPredicate = json.RawMessage(`{}`)

func parsePredicate(raw json.RawMessage) (*Predicate, []Code) {
	var codes []Code
	p := &Predicate{}
	if err := json.Unmarshal(raw, &p.Raw); err != nil {
		return p, appendCode(codes, CodeStatementMalformed)
	}
	// "predicate": null unmarshals into a nil map, which is the same VALUE as
	// the absent member and a different REPRESENTATION from "{}". The states
	// are equivalent normatively, so they are made indistinguishable here by
	// construction rather than left to coincide: every member lookup below
	// already reads a nil map as empty, and a later reader that keyed on
	// Raw == nil would silently reintroduce the distinction the rule forbids.
	if p.Raw == nil {
		p.Raw = map[string]json.RawMessage{}
	}

	if r, ok := p.Raw["result"]; ok {
		p.ResultPresent = true
		if err := json.Unmarshal(r, &p.Result); err != nil {
			codes = appendCode(codes, CodeResultVocabulary)
		}
	}

	if envRaw, ok := p.Raw["observationEnvironment"]; ok {
		env, envCodes := parseEnvironment(envRaw)
		p.Env = env
		for _, c := range envCodes {
			codes = appendCode(codes, c)
		}
	}

	if covRaw, ok := p.Raw["coverage"]; ok {
		p.CoveragePresent = true
		cov := &Coverage{}
		if err := json.Unmarshal(covRaw, cov); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		} else {
			p.Coverage = cov
		}
	}

	if rowsRaw, ok := p.Raw["attackResults"]; ok {
		p.RowsPresent = true
		var rawRows []json.RawMessage
		if err := json.Unmarshal(rowsRaw, &rawRows); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		} else {
			for _, rr := range rawRows {
				row, rowCodes := parseRow(rr)
				p.Rows = append(p.Rows, row)
				for _, c := range rowCodes {
					codes = appendCode(codes, c)
				}
			}
		}
	}

	if recRaw, ok := p.Raw["observationRecords"]; ok {
		p.RecordsPresent = true
		if err := json.Unmarshal(recRaw, &p.Records); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		}
	}

	if brRaw, ok := p.Raw["batchRoot"]; ok {
		p.BatchRootPresent = true
		if err := json.Unmarshal(brRaw, &p.BatchRoot); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		}
	}

	if iaRaw, ok := p.Raw["issuedAt"]; ok {
		p.IssuedAtPresent = true
		if err := json.Unmarshal(iaRaw, &p.IssuedAt); err != nil {
			codes = appendCode(codes, CodeIssuedAtMalformed)
		}
	}

	return p, codes
}

func parseEnvironment(raw json.RawMessage) (*Environment, []Code) {
	var codes []Code
	env := &Environment{}
	if err := json.Unmarshal(raw, &env.Raw); err != nil {
		return env, appendCode(codes, CodeStatementMalformed)
	}

	if r, ok := env.Raw["substrate"]; ok {
		env.Substrate = &DigestRef{}
		if err := json.Unmarshal(r, env.Substrate); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.Substrate = nil
		}
	}
	if r, ok := env.Raw["corpus"]; ok {
		env.Corpus = &Corpus{}
		if err := json.Unmarshal(r, env.Corpus); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.Corpus = nil
		} else if !decodeManifest(env.Corpus) {
			codes = appendCode(codes, CodeStatementMalformed)
		}
	}
	if r, ok := env.Raw["catchPolicy"]; ok {
		env.CatchPolicy = &DigestRef{}
		if err := json.Unmarshal(r, env.CatchPolicy); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.CatchPolicy = nil
		}
	}
	if r, ok := env.Raw["networkPosture"]; ok {
		env.NetworkPosture = &NetworkPosture{}
		if err := json.Unmarshal(r, env.NetworkPosture); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.NetworkPosture = nil
		}
	}
	if r, ok := env.Raw["observationVocabulary"]; ok {
		voc := &Vocabulary{}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(r, &members); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
		} else {
			if err := json.Unmarshal(r, voc); err != nil {
				codes = appendCode(codes, CodeStatementMalformed)
			} else {
				_, voc.LabelsPresent = members["labels"]
				_, voc.CaughtPresent = members["caught"]
				env.Vocabulary = voc
			}
		}
	}
	if r, ok := env.Raw["runEntropy"]; ok {
		env.RunEntropy = &DigestRef{}
		if err := json.Unmarshal(r, env.RunEntropy); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			env.RunEntropy = nil
		}
	}
	return env, codes
}

// decodeManifest reads the two members the embedded corpus manifest carries,
// and reports whether the manifest parsed at all. A manifest that is absent
// entirely is not this function's business -- GATE 0 reports that as an
// incomplete environment from the raw member's own absence.
//
// A present expectedPayloads that is not a map of string arrays is recorded as
// present-but-malformed rather than as absent, so GATE 0 reports the member's
// own code instead of the parse catch-all. That is the same separation
// networkPosture already makes, and for the same reason: a producer told its
// statement is malformed learns nothing about which member to look at.
// The presence guard is written in the POSITIVE polarity, as `len(...) > 0`
// around the decode, rather than as an early return on the empty case. The two
// are equivalent to a reader and are not equivalent to the forcing campaign: an
// early return on the empty case, switched off, falls into a decode of empty
// bytes that fails anyway, so the corpus stops noticing the guard at all. The
// extraction was written the other way once and the ratchet caught it.
func decodeManifest(c *Corpus) bool {
	ok := true
	if len(c.ManifestRaw) > 0 {
		var manifest struct {
			Classes          map[string][]string `json:"classes"`
			ExpectedPayloads json.RawMessage     `json:"expectedPayloads"`
		}
		if err := json.Unmarshal(c.ManifestRaw, &manifest); err != nil {
			ok = false
		} else {
			c.Classes = manifest.Classes
			if len(manifest.ExpectedPayloads) > 0 {
				c.ExpectedPayloadsPresent = true
				var ep map[string][]string
				if json.Unmarshal(manifest.ExpectedPayloads, &ep) == nil {
					c.ExpectedPayloads = ep
					c.ExpectedPayloadsShapeOK = true
				}
			}
		}
	}
	return ok
}

func parseRow(raw json.RawMessage) (Row, []Code) {
	var codes []Code
	row := Row{}
	if err := json.Unmarshal(raw, &row.Raw); err != nil {
		return row, appendCode(codes, CodeStatementMalformed)
	}

	decodeString := func(key string) *string {
		r, ok := row.Raw[key]
		if !ok {
			return nil
		}
		var v string
		if err := json.Unmarshal(r, &v); err != nil {
			codes = appendCode(codes, CodeStatementMalformed)
			return nil
		}
		return &v
	}

	if v := decodeString("attackId"); v != nil {
		row.AttackID = *v
	}
	if v := decodeString("containmentObserved"); v != nil {
		row.ContainmentObserved = *v
	}
	row.Basis = decodeString("basis")
	row.Method = decodeString("method")
	row.Attribution = decodeString("attribution")
	row.ActualLayer = decodeString("actualLayer")

	if refsRaw, ok := row.Raw["observationRefs"]; ok {
		row.RefsPresent = true
		if err := json.Unmarshal(refsRaw, &row.RefsRaw); err != nil {
			row.RefsErr = errors.New("observationRefs is not an array")
		} else {
			for _, el := range row.RefsRaw {
				idx, err := decodeRefIndex(el)
				if err != nil {
					row.RefsErr = err
					break
				}
				row.Refs = append(row.Refs, idx)
			}
		}
	}
	return row, codes
}

// decodeRefIndex enforces that an observationRefs entry is a non-negative
// JSON integer. Non-integer and negative entries are ref-malformed.
func decodeRefIndex(raw json.RawMessage) (int, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("ref is not a number: %s", string(raw))
	}
	i, err := n.Int64()
	if err != nil || string(n) != fmt.Sprintf("%d", i) {
		return 0, fmt.Errorf("ref is not an integer: %s", string(n))
	}
	if i < 0 {
		return 0, fmt.Errorf("ref is negative: %d", i)
	}
	return int(i), nil
}
