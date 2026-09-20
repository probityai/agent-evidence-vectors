package aee

// Unit tests for the result recompute, and specifically for the third
// condition. The conformance replay in vectors_test.go already drives the rule
// over the published corpus; what it cannot show is the two properties the
// corpus has no shape for, namely that the answer is a MINIMUM rather than a
// cascade and that a fail-closed row is never counted as an indirect one.
//
// Every case below is written so that deleting the indirect arm of Recompute
// changes its expected value. A case that reads the same with and without the
// rule would be measuring something else.

import "testing"

func s(v string) *string { return &v }

func pred(rows []Row, outOfScope map[string]string) *Predicate {
	return &Predicate{
		Env: &Environment{Vocabulary: &Vocabulary{
			Labels: []string{"egress_captured", "no_egress"},
			Caught: []string{"egress_captured"},
		}},
		Coverage: &Coverage{OutOfScope: outOfScope},
		Rows:     rows,
	}
}

// row builds a row carrying the WEAKEST truthful attribution. The member is
// required from 0.7 and fail-closes exactly as basis and method do, so a helper
// that omitted it would make every case below read `fail` for a reason none of
// them is about. Attribution has its own cases in TestRecomputeAttributionArm.
func row(label, basis, method string) Row {
	return Row{
		ContainmentObserved: label,
		Basis:               s(basis),
		Method:              s(method),
		Attribution:         s(AttributionPaired),
	}
}

// TestRecomputeAttributionArm pins where attribution enters the recompute, and
// where it does not. It enters through the fail-closed arm every required row
// member with a closed vocabulary shares, and NOWHERE else: a row declaring
// `paired` is not a weaker result, it is a weaker binding between the row and
// the records that cover it, and pricing that in the token would charge an
// honest producer for a layer whose committed value no corpus can predict.
func TestRecomputeAttributionArm(t *testing.T) {
	clean := func(attribution *string) []Row {
		return []Row{{
			ContainmentObserved: "no_egress",
			Basis:               s(BasisSubstrate),
			Method:              s(MethodIntercepted),
			Attribution:         attribution,
		}}
	}
	cases := []struct {
		name        string
		attribution *string
		want        string
	}{
		{"paired reaches the top", s(AttributionPaired), ResultPass},
		{"pinned reaches the same top", s(AttributionPinned), ResultPass},
		{"absent fail-closes", nil, ResultFail},
		{"out of vocabulary fail-closes", s("example_strong"), ResultFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Recompute(pred(clean(tc.attribution), nil)); got != tc.want {
				t.Fatalf("Recompute = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRecomputeIndirectCondition(t *testing.T) {
	cases := []struct {
		name       string
		rows       []Row
		outOfScope map[string]string
		want       string
	}{
		{
			name: "direct clean row reaches the top",
			rows: []Row{row("no_egress", BasisSubstrate, MethodIntercepted)},
			want: ResultPass,
		},
		{
			name: "clean row indirect in vantage",
			rows: []Row{row("no_egress", BasisArtifact, MethodIntercepted)},
			want: ResultPassIndirect,
		},
		{
			name: "clean row indirect in time",
			rows: []Row{row("no_egress", BasisSubstrate, MethodReconstructed)},
			want: ResultPassIndirect,
		},
		{
			name: "clean row indirect on both axes",
			rows: []Row{row("no_egress", BasisArtifact, MethodReconstructed)},
			want: ResultPassIndirect,
		},
		{
			name: "some clean row, not every one",
			rows: []Row{
				row("no_egress", BasisSubstrate, MethodIntercepted),
				row("no_egress", BasisArtifact, MethodReconstructed),
			},
			want: ResultPassIndirect,
		},
		{
			// The minimum, not a cascade: an indirect clean row and a disclosed
			// coverage gap together read as the LOWER of the two contributions.
			name:       "coverage gap outranks indirectness",
			rows:       []Row{row("no_egress", BasisArtifact, MethodReconstructed)},
			outOfScope: map[string]string{"XB": "example scope reason"},
			want:       ResultDegraded,
		},
		{
			// A caught row forces fail whatever the other conditions say.
			name: "a caught row still dominates",
			rows: []Row{
				row("egress_captured", BasisSubstrate, MethodIntercepted),
				row("no_egress", BasisArtifact, MethodReconstructed),
			},
			want: ResultFail,
		},
		{
			// A row fail-closed on method is NOT a clean row, so it contributes
			// fail and never rescues itself into the indirect arm.
			name: "fail-closed method is not an indirect clean row",
			rows: []Row{row("no_egress", BasisArtifact, "example_unknown_method")},
			want: ResultFail,
		},
		{
			// A statement with no rows has no clean row, so the condition cannot
			// hold. Coverage integrity is what keeps this shape off the wire; the
			// recompute's own answer on it is recorded here so a later reader does
			// not have to infer it.
			name: "no rows leaves the condition vacuously false",
			rows: nil,
			want: ResultPass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Recompute(pred(tc.rows, tc.outOfScope)); got != tc.want {
				t.Fatalf("Recompute = %q, want %q", got, tc.want)
			}
		})
	}
}

// The recompute must not read anything the evidence tier reads. There is no
// signature, key or record in any predicate above, and this asserts the
// stronger form: adding records changes nothing, because Recompute never looks
// at them.
func TestRecomputeIgnoresRecords(t *testing.T) {
	p := pred([]Row{row("no_egress", BasisArtifact, MethodReconstructed)}, nil)
	before := Recompute(p)
	p.Records = []Record{{}, {}}
	p.RecordsPresent = true
	p.BatchRoot = "0000000000000000000000000000000000000000000000000000000000000000"
	p.BatchRootPresent = true
	if after := Recompute(p); after != before {
		t.Fatalf("Recompute moved with the record set: %q -> %q", before, after)
	}
	if before != ResultPassIndirect {
		t.Fatalf("expected %q, got %q", ResultPassIndirect, before)
	}
}

// TestRecomputeIsTotal pins the property the specification states first about
// this function and the one the Python rail did not have: "Defined as a total,
// deterministic, severity-independent function of the predicate"
// (spec:req-fields-fail-degraded-pass-indirect-pass@1496facaec24f2da). Total means the function answers on every predicate in its
// domain rather than declining on the ones it cannot fully read, so a member
// the predicate does not carry contributes the fail-closed reading of its own
// axis and nothing raises, returns empty, or asks whether a well-formedness
// gate ran first.
//
// The Python rail guarded on `labels is not None and caught is not None and
// rows` and emitted nothing when the guard failed. Over a predicate carrying no
// rows that made it ACCEPT a statement this rail refuses, and publish a result
// token the definition never derives. These cases are the Go side of that fix:
// they fail if anyone ever adds the same guard here.
func TestRecomputeIsTotal(t *testing.T) {
	clean := []Row{row("no_egress", BasisSubstrate, MethodIntercepted)}
	cases := []struct {
		name string
		pred *Predicate
		want string
	}{
		{
			// No environment at all: empty carried sets, so the row's label is
			// outside the carried labels and the row fail-closes.
			name: "absent environment",
			pred: &Predicate{Rows: clean},
			want: ResultFail,
		},
		{
			name: "environment carrying no vocabulary",
			pred: &Predicate{Env: &Environment{}, Rows: clean},
			want: ResultFail,
		},
		{
			// An empty carried vocabulary is not the same absence as no
			// vocabulary, and the answer is the same: nothing is in an empty
			// set.
			name: "empty carried vocabulary",
			pred: &Predicate{
				Env:  &Environment{Vocabulary: &Vocabulary{}},
				Rows: clean,
			},
			want: ResultFail,
		},
		{
			// Zero rows: no condition holds over them, so the derivation is the
			// top of the ordering. This is the case whose verdict the two rails
			// disagreed on.
			name: "no rows, coverage complete",
			pred: pred(nil, nil),
			want: ResultPass,
		},
		{
			// Zero rows and a disclosed coverage gap: the second condition
			// still holds, because it reads coverage and never the rows.
			name: "no rows, disclosed coverage gap",
			pred: pred(nil, map[string]string{"XA": "not assessed"}),
			want: ResultDegraded,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Recompute(tc.pred); got != tc.want {
				t.Fatalf("Recompute = %q, want %q", got, tc.want)
			}
		})
	}
}
