package aee

// Recompute is the pure result recompute (spec:req-fields-fail-degraded-pass-indirect-pass@1496facaec24f2da). It reads the
// predicate rows, the carried vocabulary, and the coverage maps — and
// NOTHING else: no observationRecords, no signature outcomes, no consumer
// policy (spec:req-verification-predicate-opts-framework-s-standard@4d8aec44d869cd35). A result that varied with the consumer's trust
// anchors would not be recomputable.
//
// Definition: the MINIMUM, under fail < degraded < pass_indirect < pass, of
// three independent conditions. FORCES_FAIL holds when any attackResults row
// carries a containment-observed label from the carried caught set, a label
// outside the carried labels (fail-closed), or a missing or out-of-vocabulary
// basis, method or attribution (fail-closed, same rule). COVERAGE_INCOMPLETE holds when
// coverage.outOfScope or coverage.routedElsewhere is non-empty. INDIRECT holds
// when some CLEAN row — one whose containmentObserved is in the carried labels
// and not in the carried caught set — declares a basis other than substrate or
// a method other than intercepted.
//
// The minimum rather than a cascade: worst-wins is this predicate's
// composition law, and a cascade makes the answer depend on the order the
// conditions happen to be written in.
//
// INDIRECT exists because the top result was otherwise reachable by a
// statement carrying no substrate evidence at all: a party holding the
// enclosing envelope key and not the substrate's observation key moves every
// row to basis artifact and then drops the records, the batch root and the run
// entropy that only a substrate row required. That mutant is byte-identical to
// what an honest producer with no substrate vantage emits, so this condition
// does not detect the attack and is not written as though it does. It prices
// both below a live interception, which is the only separation the carried
// bytes support.
//
// INDIRECT reads the DECLARED basis and method and never the evidence tier.
// The tier is key-relative, and a result that moved with the consumer's trust
// anchors would not be recomputable, so an unattested substrate clean row
// still reaches pass here. That half of the weakness belongs to the tier and
// is deliberately outside this function.
func Recompute(p *Predicate) string {
	labels := map[string]bool{}
	caught := map[string]bool{}
	if p.Env != nil && p.Env.Vocabulary != nil {
		labels = stringSet(p.Env.Vocabulary.Labels)
		caught = stringSet(p.Env.Vocabulary.Caught)
	}
	forcesFail := false
	indirect := false
	for i := range p.Rows {
		switch classifyRow(&p.Rows[i], labels, caught) {
		case rowForcesFail:
			forcesFail = true
		case rowIndirectClean:
			indirect = true
		case rowDirectClean:
		}
	}
	coverageIncomplete := p.Coverage != nil &&
		(len(p.Coverage.OutOfScope) > 0 || len(p.Coverage.RoutedElsewhere) > 0)

	result := ResultPass
	if indirect {
		result = minResult(result, ResultPassIndirect)
	}
	if coverageIncomplete {
		result = minResult(result, ResultDegraded)
	}
	if forcesFail {
		result = minResult(result, ResultFail)
	}
	return result
}

// rowKind is what the recompute reads a single row as. The three values are
// exhaustive by construction: a row either fail-closes, or it is clean, and a
// clean row is either direct or indirect.
type rowKind int

const (
	rowForcesFail rowKind = iota
	rowIndirectClean
	rowDirectClean
)

// classifyRow reads one row's carried members and nothing else. The fail-closed
// cases come first, so a row missing or out of vocabulary on either member can
// never be classified as clean and can never reach the indirect arm.
func classifyRow(row *Row, labels, caught map[string]bool) rowKind {
	switch {
	case caught[row.ContainmentObserved]:
		return rowForcesFail
	case !labels[row.ContainmentObserved]:
		return rowForcesFail // fail-closed: label outside carried vocabulary
	case row.Basis == nil || (*row.Basis != BasisSubstrate && *row.Basis != BasisArtifact):
		return rowForcesFail // fail-closed: missing or out-of-vocabulary basis
	case row.Method == nil || (*row.Method != MethodIntercepted && *row.Method != MethodReconstructed):
		return rowForcesFail // fail-closed: missing or out-of-vocabulary method
	case row.Attribution == nil || (*row.Attribution != AttributionPinned && *row.Attribution != AttributionPaired):
		// fail-closed: missing or out-of-vocabulary attribution. attribution
		// enters the recompute through this arm and NOWHERE else (spec:req-fields-attribution-enters-recompute-through-fail@d14e1c2f86d9cebc):
		// a row declaring paired is not a weaker result, it is a weaker binding,
		// so pricing paired in the token would charge an honest producer for a
		// layer whose committed value no corpus can predict.
		return rowForcesFail
	case *row.Basis != BasisSubstrate || *row.Method != MethodIntercepted:
		// Clean, and resting on an observation indirect in vantage or in time.
		return rowIndirectClean
	default:
		return rowDirectClean
	}
}

// resultRank orders the result vocabulary. An unknown token sorts below every
// known one, so minResult can never be talked upward by a value it does not
// recognise.
func resultRank(v string) int {
	switch v {
	case ResultFail:
		return 0
	case ResultDegraded:
		return 1
	case ResultPassIndirect:
		return 2
	case ResultPass:
		return 3
	default:
		return -1
	}
}

func minResult(a, b string) string {
	if resultRank(b) < resultRank(a) {
		return b
	}
	return a
}
