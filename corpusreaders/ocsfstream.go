package corpusreaders

// A stream of OCSF decision records, read over its whole length: the record
// dimensions rolled up, then the checks only a stream can show (one uid one
// record, the chain's links and gaps and opening, the stream stamps, the tail),
// then the strict profile's own dimensions and each profile's verdict.
//
// No record can show that later records were not deleted, so the tail is
// verified only against a head the relying party holds from a source the
// emitter does not control. Without one it is not_checked, never a pass.

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// ocsfStreamDims are the dimensions read over the whole stream, after the
// record dimensions. A baseline profile refuses on a failed one of either kind.
var ocsfStreamDims = []string{"trust_policy", "record_uniqueness", "chain_links", "chain_gaps", "chain_head",
	"stream_sequence", "stream_head", "tail"}

// ocsfStrictDims are the dimensions the strict profile adds, each its own.
var ocsfStrictDims = []string{"signature_required", "key_named_by_signed_bytes", "tail_anchored",
	"opening_supplied", "numbers_interoperable"}

// ocsfReportDims is every top-level dimension a member may declare a status for.
func ocsfReportDims() []string {
	out := append(append([]string{}, ocsfRecordDims...), ocsfStreamDims...)
	return append(out, "evidence_scope", "content_digests")
}

// ocsfReport is one stream's report: every dimension, separately.
type ocsfReport struct {
	dims   map[string]ocsfDim
	strict map[string]ocsfDim
}

// ocsfRollup reads one record dimension over every record.
func ocsfRollup(records []*ocsfRecord, name string) ocsfDim {
	if len(records) == 0 {
		return ocsfD(ocsfUnavailable, "no record is supplied")
	}
	t := &ocsfTally{}
	for _, rec := range records {
		d := rec.dims[name]
		text := strings.Join(d.findings, "; ")
		if text == "" {
			text = d.status
		}
		switch d.status {
		case ocsfFailed:
			t.fail("record %d: %s", rec.index, text)
		case ocsfNotChecked:
			t.skip("record %d: %s", rec.index, text)
		case ocsfUnavailable:
			t.gone("record %d: %s", rec.index, text)
		}
	}
	return t.result()
}

// ocsfSplitLines is the records one per line (LF, with a CR before it dropped),
// blank lines skipped, each with its 1-based line number.
func ocsfSplitLines(text string) (lines []string, numbers []int, err error) {
	if strings.HasPrefix(text, "\ufeff") {
		return nil, nil, fmt.Errorf("not-utf8: a byte-order mark precedes the text")
	}
	for i, piece := range strings.Split(text, "\n") {
		line := strings.TrimSuffix(piece, "\r")
		if strings.Trim(line, " \t\n\r") != "" {
			lines = append(lines, line)
			numbers = append(numbers, i+1)
		}
	}
	return lines, numbers, nil
}

// ocsfUnreadReport is the report of bytes that are not text the reader accepts:
// nothing is read and every dimension says so.
func ocsfUnreadReport(why string) *ocsfReport {
	rep := &ocsfReport{dims: map[string]ocsfDim{}, strict: map[string]ocsfDim{}}
	rep.dims["structural_validity"] = ocsfD(ocsfFailed, "not read: "+why)
	for _, name := range ocsfReportDims() {
		if _, set := rep.dims[name]; !set {
			rep.dims[name] = ocsfD(ocsfNotChecked, "the records are not read")
		}
	}
	for _, name := range ocsfStrictDims {
		rep.strict[name] = ocsfD(ocsfNotChecked, "the records are not read")
	}
	return rep
}

// ocsfRead reads the records' exact text, one per line, and reports every
// dimension separately. policyDoc is the relying party's own JWKS (nil: none)
// and relying holds the heads it keeps independently.
func ocsfRead(text string, policyDoc, relying any) *ocsfReport {
	lines, numbers, err := ocsfSplitLines(text)
	if err != nil {
		return ocsfUnreadReport(err.Error())
	}
	var policy, usable *ocsfTrustPolicy
	if policyDoc != nil {
		policy = ocsfReadPolicy(policyDoc)
		if len(policy.findings) == 0 {
			usable = policy
		}
	}
	records := make([]*ocsfRecord, len(lines))
	for i, line := range lines {
		records[i] = ocsfReadOne(i, numbers[i], line, usable)
	}
	rep := &ocsfReport{dims: map[string]ocsfDim{}}
	for _, name := range ocsfRecordDims {
		rep.dims[name] = ocsfRollup(records, name)
	}
	switch {
	case policy == nil:
		rep.dims["trust_policy"] = ocsfD(ocsfNotChecked, "no trust policy is configured")
	default:
		rep.dims["trust_policy"] = policy.report()
	}
	var readOK []*ocsfRecord
	for _, rec := range records {
		if rec.doc != nil {
			readOK = append(readOK, rec)
		}
	}
	var kept []*ocsfRecord
	rep.dims["record_uniqueness"], kept = ocsfUniqueness(readOK)
	links, gaps, heads, chains := ocsfChains(kept)
	rep.dims["chain_links"], rep.dims["chain_gaps"], rep.dims["chain_head"] = links, gaps, heads
	seq, head, groups := ocsfStreams(kept)
	rep.dims["stream_sequence"], rep.dims["stream_head"] = seq, head
	rep.dims["tail"] = ocsfTail(chains, groups, ocsfGet(relying, "heads"))
	rep.dims["evidence_scope"] = ocsfEvidenceScope(readOK)
	rep.dims["content_digests"] = ocsfContentDigests(readOK)
	rep.strict = ocsfStrictReport(rep, records)
	return rep
}

func ocsfEvidenceScope(records []*ocsfRecord) ocsfDim {
	seen := map[string]bool{}
	for _, rec := range records {
		for _, b := range rec.absent {
			seen[b] = true
		}
	}
	if len(seen) == 0 {
		return ocsfD(ocsfNotChecked)
	}
	absent := sortedKeys(seen)
	return ocsfD(ocsfNotChecked, fmt.Sprintf("absent from at least one record: %s; the format does not say whether the sink lacked the read capability or there was nothing to record",
		strings.Join(absent, ", ")))
}

func ocsfContentDigests(records []*ocsfRecord) ocsfDim {
	for _, rec := range records {
		if ocsfGet(rec.doc, "unmapped", "aid.content") != nil {
			return ocsfD(ocsfNotSupported, "aid.content digests are not recomputed by this reader")
		}
	}
	return ocsfD(ocsfUnavailable, "no record carries aid.content")
}

// ocsfUniqueness: two records with one uid are one record delivered twice when
// their bytes agree, and a refusal when they do not.
func ocsfUniqueness(records []*ocsfRecord) (ocsfDim, []*ocsfRecord) {
	t := &ocsfTally{}
	byUID := map[string]*ocsfRecord{}
	var kept []*ocsfRecord
	for _, rec := range records {
		uid, ok := rec.uid()
		if !ok {
			kept = append(kept, rec)
			continue
		}
		first := byUID[uid]
		switch {
		case first == nil:
			byUID[uid] = rec
			kept = append(kept, rec)
		case ocsfCanon(first.doc) == ocsfCanon(rec.doc):
			t.skip("records %d and %d are one record (%s) delivered twice", first.index, rec.index, uid)
		default:
			t.fail("records %d and %d both claim uid %s with different content: a replica or a restart sharing a chain_uid, or a substitution",
				first.index, rec.index, uid)
		}
	}
	status := t.status()
	if status == ocsfNotChecked { // a duplicate delivery is a finding, not a check left undone
		status = ocsfVerified
	}
	return ocsfDim{status: status, findings: append(append([]string{}, t.failed...), t.unchecked...)}, kept
}

// ocsfSeq is the sequence number a uid ends in: chain_uid, a dash, then six or
// more digits (and "att-" between them for an attestation uid).
func ocsfSeq(uid, chain string, att bool) *big.Int {
	prefix := chain + "-"
	if att {
		prefix = chain + "-att-"
	}
	if !strings.HasPrefix(uid, prefix) {
		return nil
	}
	tail := uid[len(prefix):]
	if len(tail) < 6 || strings.Trim(tail, "0123456789") != "" {
		return nil
	}
	n, _ := new(big.Int).SetString(tail, 10)
	return n
}

func ocsfSeqOr(n *big.Int, fallback int64) *big.Int {
	if n == nil || n.Sign() == 0 {
		return big.NewInt(fallback)
	}
	return n
}

// ocsfChain is one chain's segments: runs of records linked to each other.
type ocsfChain struct {
	uid  string
	segs [][]*ocsfRecord
}

func ocsfPrev(rec *ocsfRecord) map[string]any {
	m, _ := rec.att()["prev_event"].(map[string]any)
	return m
}

func ocsfChainUID(rec *ocsfRecord) string {
	s, _ := rec.att()["chain_uid"].(string)
	return s
}

func ocsfUIDOf(rec *ocsfRecord) string {
	s, _ := rec.uid()
	return s
}

// ocsfChains reads chain_links, chain_gaps and chain_head, and the segments of
// each chain for the tail.
func ocsfChains(records []*ocsfRecord) (links, gaps, heads ocsfDim, out []ocsfChain) {
	var chained []*ocsfRecord
	for _, rec := range records {
		if rec.att() != nil {
			chained = append(chained, rec)
		}
	}
	if len(chained) == 0 {
		none := ocsfDim{status: ocsfUnavailable, findings: []string{"no chained record is supplied"}, notApplicable: true}
		return none, none, none, nil
	}
	lt, gt, ht := &ocsfTally{}, &ocsfTally{}, &ocsfTally{}
	var order []string
	groups := map[string][]*ocsfRecord{}
	for _, rec := range chained {
		uid := ocsfChainUID(rec)
		if _, seen := groups[uid]; !seen {
			order = append(order, uid)
		}
		groups[uid] = append(groups[uid], rec)
	}
	for _, chainUID := range order {
		out = append(out, ocsfOneChain(chainUID, groups[chainUID], lt, gt, ht))
	}
	return lt.result(), gt.result(), ht.result(), out
}

func ocsfOneChain(chainUID string, members []*ocsfRecord, links, gaps, heads *ocsfTally) ocsfChain {
	byUID := map[string]*ocsfRecord{}
	for _, rec := range members {
		byUID[ocsfUIDOf(rec)] = rec
	}
	successor := map[string]*ocsfRecord{}
	var starts []*ocsfRecord
	for _, rec := range members {
		ocsfUIDPattern(rec, chainUID, links)
		prev := ocsfPrev(rec)
		if prev == nil {
			starts = append(starts, rec)
			continue
		}
		prevUID, _ := prev["uid"].(string)
		if first, forked := successor[prevUID]; forked {
			links.fail("records %d and %d both name %s as their predecessor: the chain forks", first.index, rec.index, prevUID)
			continue
		}
		successor[prevUID] = rec
		before := byUID[prevUID]
		if before == nil {
			starts = append(starts, rec)
			continue
		}
		ocsfLink(before, rec, chainUID, links)
	}
	segs := make([][]*ocsfRecord, len(starts))
	covered := 0
	for i, start := range starts {
		segs[i] = ocsfWalk(start, successor, links)
		covered += len(segs[i])
	}
	if covered != len(members) {
		links.fail("chain %s: %d records sit on a cycle or a fork and are reached from no start", chainUID, len(members)-covered)
	}
	sort.SliceStable(segs, func(a, b int) bool {
		ra, rb := segs[a][0], segs[b][0]
		pa, pb := ocsfPrev(ra) != nil, ocsfPrev(rb) != nil
		if pa != pb {
			return !pa
		}
		if c := ocsfSeqOr(ocsfSeq(ocsfUIDOf(ra), chainUID, false), 0).Cmp(ocsfSeqOr(ocsfSeq(ocsfUIDOf(rb), chainUID, false), 0)); c != 0 {
			return c < 0
		}
		return ra.index < rb.index
	})
	var geneses []string
	for _, seg := range segs {
		if ocsfPrev(seg[0]) == nil {
			geneses = append(geneses, fmt.Sprint(seg[0].index))
		}
	}
	if len(geneses) > 1 {
		links.fail("chain %s: records %s each open the chain", chainUID, strings.Join(geneses, ", "))
	}
	for i := 1; i < len(segs); i++ {
		seg := segs[i]
		prev := ocsfPrev(seg[0])
		if prev == nil {
			continue
		}
		gaps.fail("chain %s: record %d names %v as its predecessor, which is not supplied%s",
			chainUID, seg[0].index, prev["uid"], ocsfMissing(segs, i, chainUID))
	}
	if len(geneses) == 0 && len(segs) > 0 {
		first := segs[0][0]
		heads.gone("chain %s: the earliest supplied record names %v as its predecessor; the chain's opening is not supplied",
			chainUID, ocsfPrev(first)["uid"])
	}
	return ocsfChain{uid: chainUID, segs: segs}
}

// ocsfMissing says how many records lie between the segment before seg and seg.
func ocsfMissing(segs [][]*ocsfRecord, at int, chainUID string) string {
	seg := segs[at]
	here := ocsfSeq(ocsfUIDOf(seg[0]), chainUID, false)
	if here == nil {
		return ""
	}
	var last *big.Int
	for i, s := range segs {
		end := ocsfSeq(ocsfUIDOf(s[len(s)-1]), chainUID, false)
		if i == at || (end != nil && end.Cmp(here) >= 0) {
			continue
		}
		if end == nil {
			end = big.NewInt(0)
		}
		if last == nil || end.Cmp(last) > 0 {
			last = end
		}
	}
	if last == nil {
		return ""
	}
	lost := new(big.Int).Sub(new(big.Int).Sub(here, last), big.NewInt(1))
	if lost.Sign() <= 0 {
		return ""
	}
	plural := "s"
	if lost.Cmp(big.NewInt(1)) == 0 {
		plural = ""
	}
	return fmt.Sprintf(" (%s record%s missing between seq %s and %s)", lost, plural, last, here)
}

func ocsfUIDPattern(rec *ocsfRecord, chainUID string, t *ocsfTally) {
	seq := ocsfSeq(ocsfUIDOf(rec), chainUID, false)
	attUID, _ := rec.att()["uid"].(string)
	attSeq := ocsfSeq(attUID, chainUID, true)
	if seq != nil && attSeq != nil && seq.Cmp(attSeq) != 0 {
		t.fail("record %d: metadata.uid is seq %s and the attestation uid is seq %s", rec.index, seq, attSeq)
	}
}

func ocsfLink(before, rec *ocsfRecord, chainUID string, t *ocsfTally) {
	prev := ocsfPrev(rec)
	prevUID, _ := prev["uid"].(string)
	prevFP, _ := ocsfGet(prev, "fingerprint", "value").(string)
	if stated, _ := before.fingerprint(); prevFP != stated {
		t.fail("record %d: prev_event.fingerprint is not the fingerprint of %s (record %d)", rec.index, prevUID, before.index)
	}
	if !pyEqual(prev["type_uid"], before.doc["type_uid"]) {
		t.fail("record %d: prev_event.type_uid is %v, and %s is type %v", rec.index, prev["type_uid"], prevUID, before.doc["type_uid"])
	}
	if got := ocsfChainUID(before); got != chainUID {
		t.fail("record %d: its predecessor sits on chain %s", rec.index, got)
	}
	a, b := ocsfSeq(ocsfUIDOf(before), chainUID, false), ocsfSeq(ocsfUIDOf(rec), chainUID, false)
	if a != nil && b != nil && b.Cmp(new(big.Int).Add(a, big.NewInt(1))) != 0 {
		t.fail("record %d: seq %s links to seq %s", rec.index, b, a)
	}
}

func ocsfWalk(start *ocsfRecord, successor map[string]*ocsfRecord, t *ocsfTally) []*ocsfRecord {
	out, node := []*ocsfRecord{start}, start
	seen := map[string]bool{ocsfUIDOf(start): true}
	for {
		next, more := successor[ocsfUIDOf(node)]
		if !more {
			return out
		}
		node = next
		if seen[ocsfUIDOf(node)] {
			t.fail("record %d closes a cycle", node.index)
			return out
		}
		seen[ocsfUIDOf(node)] = true
		out = append(out, node)
	}
}

// ocsfStreamGroup is the records of one (epoch, stream_id), by stream_seq.
type ocsfStreamGroup struct {
	epoch  *big.Int
	id     string
	bySeq  map[string]*ocsfRecord
	seqs   []*big.Int
	topSeq *big.Int
}

func (g *ocsfStreamGroup) name() string { return fmt.Sprintf("stream %s epoch %s", g.id, g.epoch) }

func ocsfStreamStamp(rec *ocsfRecord, name string) *big.Int {
	return ocsfInt(ocsfGet(rec.doc, "unmapped", "aid.stream", name))
}

// ocsfStreams reads stream_sequence and stream_head over unmapped."aid.stream".
func ocsfStreams(records []*ocsfRecord) (seq, head ocsfDim, groups []*ocsfStreamGroup) {
	byKey := map[string][]*ocsfRecord{}
	var keys []*ocsfStreamGroup
	for _, rec := range records {
		stream, ok := ocsfGet(rec.doc, "unmapped", "aid.stream").(map[string]any)
		if !ok {
			continue
		}
		id, _ := stream["stream_id"].(string)
		epoch := ocsfStreamStamp(rec, "epoch")
		key := epoch.String() + "\x00" + id
		if _, seen := byKey[key]; !seen {
			keys = append(keys, &ocsfStreamGroup{epoch: epoch, id: id})
		}
		byKey[key] = append(byKey[key], rec)
	}
	if len(keys) == 0 {
		none := ocsfDim{status: ocsfUnavailable, findings: []string{"no record carries aid.stream"}, notApplicable: true}
		return none, none, nil
	}
	sort.Slice(keys, func(a, b int) bool {
		if c := keys[a].epoch.Cmp(keys[b].epoch); c != 0 {
			return c < 0
		}
		return keys[a].id < keys[b].id
	})
	st, ht := &ocsfTally{}, &ocsfTally{}
	for _, g := range keys {
		ocsfReadStream(g, byKey[g.epoch.String()+"\x00"+g.id], st, ht)
	}
	return st.result(), ht.result(), keys
}

func ocsfReadStream(g *ocsfStreamGroup, members []*ocsfRecord, seq, head *ocsfTally) {
	g.bySeq = map[string]*ocsfRecord{}
	for _, rec := range members {
		n := ocsfStreamStamp(rec, "stream_seq")
		if first, dup := g.bySeq[n.String()]; dup {
			seq.fail("%s: records %d and %d both carry stream_seq %s", g.name(), first.index, rec.index, n)
			continue
		}
		g.bySeq[n.String()] = rec
		g.seqs = append(g.seqs, n)
	}
	sort.Slice(g.seqs, func(a, b int) bool { return g.seqs[a].Cmp(g.seqs[b]) < 0 })
	one := big.NewInt(1)
	for i := 1; i < len(g.seqs); i++ {
		a, b := g.seqs[i-1], g.seqs[i]
		if next := new(big.Int).Add(a, one); b.Cmp(next) != 0 {
			seq.fail("%s: stream_seq %s to %s not supplied, between records that are: lost records",
				g.name(), next, new(big.Int).Sub(b, one))
		}
		ea, eb := ocsfStreamStamp(g.bySeq[a.String()], "emission_seq"), ocsfStreamStamp(g.bySeq[b.String()], "emission_seq")
		if eb.Cmp(ea) <= 0 {
			seq.fail("%s: emission_seq %s at stream_seq %s does not follow %s at stream_seq %s", g.name(), eb, b, ea, a)
		}
	}
	if len(g.seqs) > 0 {
		g.topSeq = g.seqs[len(g.seqs)-1]
		if g.seqs[0].Sign() != 0 {
			head.gone("%s: the stream opens at stream_seq 0; stream_seq 0 to %s are not supplied", g.name(),
				new(big.Int).Sub(g.seqs[0], one))
		}
	}
}

// ocsfTail reads the end of each chain and stream against the heads the
// relying party holds independently.
func ocsfTail(chains []ocsfChain, groups []*ocsfStreamGroup, heads any) ocsfDim {
	if len(chains) == 0 && len(groups) == 0 {
		return ocsfD(ocsfUnavailable, "no chained record and no stream stamp is supplied")
	}
	t := &ocsfTally{}
	list, _ := heads.([]any)
	chainHeads := map[string]map[string]any{}
	var chainOrder []string
	streamHeads := map[string]map[string]any{}
	var streamOrder []string
	for _, h := range list {
		m, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if uid, ok := m["chain_uid"].(string); ok {
			if _, seen := chainHeads[uid]; !seen {
				chainOrder = append(chainOrder, uid)
			}
			chainHeads[uid] = m
		}
		if id, ok := m["stream_id"].(string); ok && ocsfIsInt(m["epoch"]) {
			key := ocsfInt(m["epoch"]).String() + "\x00" + id
			if _, seen := streamHeads[key]; !seen {
				streamOrder = append(streamOrder, key)
			}
			streamHeads[key] = m
		}
	}
	for _, chain := range chains {
		ocsfTailChain(chain, chainHeads, t)
	}
	for _, g := range groups {
		ocsfTailStream(g, streamHeads, len(chains) > 0, t)
	}
	for _, uid := range chainOrder {
		if _, left := chainHeads[uid]; left {
			t.fail("chain %s: the relying party holds a head and no record of the chain is supplied", uid)
		}
	}
	for _, key := range streamOrder {
		if m, left := streamHeads[key]; left {
			t.fail("stream %v epoch %v: the relying party holds a head and no record of the stream is supplied",
				m["stream_id"], m["epoch"])
		}
	}
	return t.result()
}

func ocsfTailChain(chain ocsfChain, heads map[string]map[string]any, t *ocsfTally) {
	lastSeg := chain.segs[len(chain.segs)-1]
	last := lastSeg[len(lastSeg)-1]
	held, ok := heads[chain.uid]
	if !ok {
		t.skip("chain %s: no independent head is supplied; deleting the last records leaves a chain that still verifies, ending at %s",
			chain.uid, ocsfUIDOf(last))
		return
	}
	delete(heads, chain.uid)
	var matches []*ocsfRecord
	for _, seg := range chain.segs {
		for _, rec := range seg {
			if pyEqual(ocsfUIDOf(rec), held["uid"]) {
				matches = append(matches, rec)
			}
		}
	}
	switch {
	case len(matches) == 0:
		lost := ""
		a := ocsfSeq(ocsfUIDOf(last), chain.uid, false)
		heldUID, _ := held["uid"].(string)
		if b := ocsfSeq(heldUID, chain.uid, false); a != nil && b != nil && b.Cmp(a) > 0 {
			plural := "s"
			if new(big.Int).Sub(b, a).Cmp(big.NewInt(1)) == 0 {
				plural = ""
			}
			lost = fmt.Sprintf(": %s record%s after seq %s are missing", new(big.Int).Sub(b, a), plural, a)
		}
		t.fail("chain %s: the head the relying party holds, %v, is not supplied%s", chain.uid, held["uid"], lost)
	case !pyEqual(ocsfFingerprintOf(matches[0]), held["fingerprint"]):
		t.fail("chain %s: record %d has the head's uid and another fingerprint", chain.uid, matches[0].index)
	case matches[0] != last:
		t.skip("chain %s: records after the head %v are not anchored by it", chain.uid, held["uid"])
	}
}

func ocsfFingerprintOf(rec *ocsfRecord) any {
	if s, ok := rec.fingerprint(); ok {
		return s
	}
	return nil
}

func ocsfTailStream(g *ocsfStreamGroup, heads map[string]map[string]any, chained bool, t *ocsfTally) {
	key := g.epoch.String() + "\x00" + g.id
	held, ok := heads[key]
	if !ok {
		if !chained {
			t.skip("%s: no independent head is supplied; deleting the last records leaves a stream that still reads as dense, ending at stream_seq %s",
				g.name(), g.topSeq)
		}
		return
	}
	delete(heads, key)
	switch want := held["stream_seq"]; {
	case !ocsfIsInt(want):
		t.fail("%s: the head the relying party holds has no stream_seq", g.name())
	case ocsfInt(want).Cmp(g.topSeq) > 0:
		t.fail("%s: the relying party's head is stream_seq %s; stream_seq %s to %s are not supplied", g.name(),
			ocsfInt(want), new(big.Int).Add(g.topSeq, big.NewInt(1)), ocsfInt(want))
	case ocsfInt(want).Cmp(g.topSeq) < 0:
		t.skip("%s: records after stream_seq %s are not anchored by the head", g.name(), ocsfInt(want))
	}
}

// ocsfStrictReport reads the strict profile's dimensions, each its own.
func ocsfStrictReport(rep *ocsfReport, records []*ocsfRecord) map[string]ocsfDim {
	var wide []string
	for _, rec := range records {
		if rec.doc == nil {
			continue
		}
		for _, path := range rec.wide {
			wide = append(wide, fmt.Sprintf("record %d: %s is an integer a double-based reader reads as another number, so it canonicalizes to other bytes there", rec.index, path))
		}
	}
	opening := &ocsfTally{}
	for _, name := range []string{"chain_head", "stream_head"} {
		d := rep.dims[name]
		if d.status == ocsfVerified || d.notApplicable {
			continue
		}
		for _, text := range d.findings {
			switch d.status {
			case ocsfFailed:
				opening.fail("%s: %s", name, text)
			case ocsfNotChecked:
				opening.skip("%s: %s", name, text)
			default:
				opening.gone("%s: %s", name, text)
			}
		}
	}
	numbers := ocsfD(ocsfVerified)
	if len(wide) > 0 {
		numbers = ocsfD(ocsfFailed, wide...)
	}
	tail := rep.dims["tail"]
	return map[string]ocsfDim{
		"signature_required":        ocsfRollup(records, "signature"),
		"key_named_by_signed_bytes": ocsfRollup(records, "key_binding"),
		"tail_anchored":             {status: tail.status, findings: tail.findings},
		"opening_supplied":          opening.result(),
		"numbers_interoperable":     numbers,
	}
}

// ocsfVerdict is what one profile accepts: ("accept", "") or ("reject",
// "<dimension>:<status>"). A baseline refuses a report in which any record or
// stream dimension failed; strict also requires every strict dimension to be
// verified. Neither changes what the report says.
func ocsfVerdict(rep *ocsfReport, profile string) (verdict, code string) {
	for _, name := range append(append([]string{}, ocsfRecordDims...), ocsfStreamDims...) {
		if rep.dims[name].status == ocsfFailed {
			return "reject", name + ":" + ocsfFailed
		}
	}
	if profile == "baseline" {
		return "accept", ""
	}
	for _, name := range ocsfStrictDims {
		if status := rep.strict[name].status; status != ocsfVerified {
			return "reject", name + ":" + status
		}
	}
	return "accept", ""
}
