package main

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"sort"
	"strings"
)

// site is one weakening mutation: a single syntactic place in the rail that can
// be switched off, plus the identity under which the forcing baseline records
// what happened when it was.
type site struct {
	Key     string `json:"key"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Func    string `json:"func"`
	Op      string `json:"op"`
	Snippet string `json:"snippet"`

	// Set during enumeration, used by apply. Never serialized.
	target  ast.Expr
	replace string
	kind    string
	call    *ast.CallExpr
	assign  *ast.AssignStmt
	ret     *ast.ReturnStmt
	clause  *ast.CaseClause
	swBody  *ast.BlockStmt
	// typeSwitch is the enclosing type switch of a CASE_DEL arm, nil for a
	// tagged value switch. Deleting the last arm that reads the switch's bound
	// symbol leaves it declared and unused, which Go refuses to compile.
	typeSwitch *ast.TypeSwitchStmt
	rng        *ast.RangeStmt
}

// maxSnippet bounds the recorded source excerpt. It is part of the site key, so
// two sites whose first maxSnippet characters agree collide and are separated by
// the occurrence ordinal instead.
const maxSnippet = 150

// keyDigestBytes is how much of the snippet digest goes into a key. Twelve hex
// characters is enough to separate the sites within one function without making
// the baseline unreadable; a collision is not a correctness problem because the
// ordinal disambiguates every group that shares a key.
const keyDigestBytes = 6

// siteKey names a mutation site by WHAT IT IS rather than by where it sits.
//
// The obvious identity -- an ordinal per file, `statement#013` -- renumbers every
// site below any inserted rule, so a one-line addition to the rail would read as
// several hundred simultaneous forcing regressions and the baseline would have to
// be regenerated wholesale on every edit, which is the same as having no ratchet.
// Keying on (file, function, operator, digest of the mutated source) instead moves
// with the code: a site keeps its identity when lines shift around it, and loses
// it exactly when the rule it guards is rewritten, which is the case a reviewer
// should be made to look at.
//
// ordinal separates sites that are otherwise identical -- the same operator on the
// same expression twice inside one function, which `if err != nil { return err }`
// produces constantly. It is assigned in source order, so adding a third copy
// leaves the first two alone.
func siteKey(file, fn, op, snippet string, ordinal int) string {
	sum := sha256.Sum256([]byte(snippet))
	key := fmt.Sprintf("%s::%s::%s::%x", file, fn, op, sum[:keyDigestBytes])
	if ordinal > 1 {
		key = fmt.Sprintf("%s#%d", key, ordinal)
	}
	return key
}

// fileOfKey recovers the source file a key names, so -apply needs only the key.
func fileOfKey(key string) string {
	return strings.SplitN(key, "::", 2)[0]
}

// shortCircuit builds `false && (e)` or `true || (e)`.
//
// The literal `false` alone would be the obvious rewrite and it is wrong: it
// deletes the last use of whatever the guard read, Go then refuses to compile a
// declared-and-unused variable, and the mutant scores as inconclusive instead of
// as the measurement it was supposed to be. Keeping the original expression
// behind a short-circuit forces the branch while leaving every identifier used.
func shortCircuit(e ast.Expr, lit string) ast.Expr {
	op := token.LAND
	if lit == "true" {
		op = token.LOR
	}
	return &ast.BinaryExpr{
		X:  ast.NewIdent(lit),
		Op: op,
		Y:  &ast.ParenExpr{X: e},
	}
}

// suppressCode rewrites appendCode(cs, C) to an immediately-invoked function
// returning cs and discarding C, so one emission disappears while both arguments
// stay referenced.
func suppressCode(call *ast.CallExpr) ast.Expr {
	return &ast.CallExpr{
		Fun: &ast.FuncLit{
			Type: &ast.FuncType{
				Params: &ast.FieldList{List: []*ast.Field{
					{Names: []*ast.Ident{ast.NewIdent("cs")}, Type: &ast.ArrayType{Elt: ast.NewIdent("Code")}},
					{Names: []*ast.Ident{ast.NewIdent("_")}, Type: ast.NewIdent("Code")},
				}},
				Results: &ast.FieldList{List: []*ast.Field{
					{Type: &ast.ArrayType{Elt: ast.NewIdent("Code")}},
				}},
			},
			Body: &ast.BlockStmt{List: []ast.Stmt{
				&ast.ReturnStmt{Results: []ast.Expr{ast.NewIdent("cs")}},
			}},
		},
		Args: []ast.Expr{call.Args[0], call.Args[1]},
	}
}

// flatten returns the leaf operands of a left-associated binary chain of op.
func flatten(e ast.Expr, op token.Token) []ast.Expr {
	be, ok := e.(*ast.BinaryExpr)
	if !ok || be.Op != op {
		return []ast.Expr{e}
	}
	return append(flatten(be.X, op), flatten(be.Y, op)...)
}

// srcOf renders a node as one whitespace-collapsed line, bounded by maxSnippet.
func srcOf(fset *token.FileSet, n ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, n); err != nil {
		return "<unprintable>"
	}
	s := strings.Join(strings.Fields(sb.String()), " ")
	if len(s) > maxSnippet {
		s = s[:maxSnippet] + "..."
	}
	return s
}

type funcRange struct {
	name       string
	start, end token.Pos
}

// funcIndex maps a position to the name of the function declaration holding it,
// and reports whether that declaration returns exactly one bool (whose return
// statements are sub-check arms worth mutating).
type funcIndex struct {
	ranges []funcRange
	bools  []funcRange
}

func newFuncIndex(f *ast.File) *funcIndex {
	idx := &funcIndex{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			name = "(recv)." + name
		}
		fr := funcRange{name, fd.Pos(), fd.End()}
		idx.ranges = append(idx.ranges, fr)
		if returnsOneBool(fd) {
			idx.bools = append(idx.bools, fr)
		}
	}
	return idx
}

func returnsOneBool(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil || len(fd.Type.Results.List) != 1 {
		return false
	}
	if len(fd.Type.Results.List[0].Names) > 1 {
		return false
	}
	id, ok := fd.Type.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "bool"
}

func (i *funcIndex) nameAt(p token.Pos) string {
	for _, fr := range i.ranges {
		if p >= fr.start && p < fr.end {
			return fr.name
		}
	}
	return "-"
}

func (i *funcIndex) inBoolFunc(p token.Pos) bool {
	for _, fr := range i.bools {
		if p >= fr.start && p < fr.end {
			return true
		}
	}
	return false
}

// taggedClauses records the case clauses of TAGGED and TYPE switches. Their case
// lists carry values and types rather than booleans, so `case false && (v):` does
// not typecheck and `case json.Delim:` does not even parse as an expression; the
// equivalent weakening there is to delete the arm and let its value fall through.
func taggedClauses(f *ast.File) map[*ast.CaseClause]switchArm {
	out := map[*ast.CaseClause]switchArm{}
	ast.Inspect(f, func(nd ast.Node) bool {
		var arm switchArm
		switch sw := nd.(type) {
		case *ast.SwitchStmt:
			if sw.Tag == nil {
				return true
			}
			arm.body = sw.Body
		case *ast.TypeSwitchStmt:
			arm.body, arm.typeSwitch = sw.Body, sw
		default:
			return true
		}
		for _, st := range arm.body.List {
			if cc, ok := st.(*ast.CaseClause); ok && len(cc.List) > 0 {
				out[cc] = arm
			}
		}
		return true
	})
	return out
}

// switchArm is where one deletable arm lives: the switch body, and the type
// switch itself when it is one.
type switchArm struct {
	body       *ast.BlockStmt
	typeSwitch *ast.TypeSwitchStmt
}

// unbindIfUnused turns `switch v := x.(type)` into `switch x.(type)` when no
// remaining arm reads v. Go refuses a type switch whose bound symbol no clause
// uses, so without this a deleted arm that was the only reader yields a mutant
// that does not build: a site the campaign can never measure.
func unbindIfUnused(ts *ast.TypeSwitchStmt) {
	assign, ok := ts.Assign.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return
	}
	bound, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return
	}
	used := false
	for _, st := range ts.Body.List {
		ast.Inspect(st, func(n ast.Node) bool {
			if id, isIdent := n.(*ast.Ident); isIdent && id.Name == bound.Name {
				used = true
			}
			return !used
		})
	}
	if !used {
		ts.Assign = &ast.ExprStmt{X: assign.Rhs[0]}
	}
}

func isLit(e ast.Expr, want string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == want
}

// leavesBody reports whether control reaching this statement can never fall
// through to whatever follows it, so a `break` appended at the end of a loop
// body could not run.
//
// This is Go's own definition of a terminating statement, with one addition and
// one parameter. `continue` is added: Go does not count it, because it does not
// end a FUNCTION, but the question here is whether control reaches the end of
// one LOOP BODY, and a continue means it does not. `inClause` says the
// statement sits directly inside a switch or select clause, where an unlabelled
// `break` leaves that clause and falls through rather than leaving the body.
//
// Every uncertain case answers FALSE, which excludes the site. That direction
// is the safe one and the asymmetry is the whole reason this is written out
// rather than approximated by looking at the last statement alone. Excluding a
// site costs one measurement nobody was promised. Including one whose appended
// break is unreachable mints an equivalent mutant, which the campaign scores
// DEAD, and a DEAD LOOP_FIRST row is published as "the corpus does not force
// this universal" -- a claim about the corpus, manufactured by the operator.
func leavesBody(st ast.Stmt, inClause bool) bool {
	switch x := st.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return branchLeaves(x, inClause)
	case *ast.LabeledStmt:
		return leavesBody(x.Stmt, inClause)
	case *ast.BlockStmt:
		return blockLeaves(x.List, inClause)
	case *ast.IfStmt:
		return x.Else != nil && blockLeaves(x.Body.List, inClause) &&
			leavesBody(x.Else, inClause)
	case *ast.ExprStmt:
		call, ok := x.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := call.Fun.(*ast.Ident)
		return ok && id.Name == "panic"
	case *ast.SwitchStmt:
		return clausesLeave(x.Body)
	case *ast.TypeSwitchStmt:
		return clausesLeave(x.Body)
	case *ast.SelectStmt:
		return clausesLeave(x.Body)
	case *ast.ForStmt:
		// `for {}` with no condition. A break inside it would make this wrong
		// in the excluding direction, which is the direction that costs nothing.
		return x.Cond == nil
	}
	return false
}

// branchLeaves reports whether a branch statement leaves the loop body.
//
// `fallthrough` does not: it continues into the next clause. An unlabelled
// `break` inside a switch or select clause leaves THAT clause and falls through
// to whatever follows it, which is why the answer depends on where the
// statement sits and not only on what it says.
func branchLeaves(x *ast.BranchStmt, inClause bool) bool {
	switch x.Tok {
	case token.GOTO, token.CONTINUE:
		return true
	case token.BREAK:
		return !inClause || x.Label != nil
	}
	return false
}

func blockLeaves(list []ast.Stmt, inClause bool) bool {
	if len(list) == 0 {
		return false
	}
	return leavesBody(list[len(list)-1], inClause)
}

// clausesLeave reports whether every arm of a switch or select leaves, and a
// default arm exists so there is an arm for every value. Without the default,
// an unmatched value falls straight through.
func clausesLeave(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	hasDefault := false
	for _, st := range body.List {
		var arm []ast.Stmt
		switch cc := st.(type) {
		case *ast.CaseClause:
			hasDefault = hasDefault || cc.List == nil
			arm = cc.Body
		case *ast.CommClause:
			hasDefault = hasDefault || cc.Comm == nil
			arm = cc.Body
		default:
			return false
		}
		if !blockLeaves(arm, true) {
			return false
		}
	}
	return hasDefault
}

// rangeVars names the identifiers this range statement binds, ignoring blanks.
func rangeVars(x *ast.RangeStmt) map[string]bool {
	bound := map[string]bool{}
	for _, e := range []ast.Expr{x.Key, x.Value} {
		if id, ok := e.(*ast.Ident); ok && id.Name != "_" {
			bound[id.Name] = true
		}
	}
	return bound
}

// reportsViolation reports whether a loop body can say that one MEMBER of the
// collection failed the rule -- a return, or an appendCode naming a code the
// loop chose rather than one it was handed.
//
// This is what separates a QUANTIFIER from an ACCUMULATOR, and both halves of
// it were needed. `for i := range p.Records { leaves[i] = LeafHash(...) }`
// builds a value out of every element and asserts nothing about any of them;
// restricting it to one element measures how the rail computes rather than what
// the corpus obliges a verifier to check.
//
// The second half is subtler and the first pass got it wrong. The rail splices
// one code list into another with `for _, c := range src { dst = appendCode(dst,
// c) }`, and an emission is an emission to a syntactic matcher, so ten such
// loops enumerated as universals. They are not: the loop makes no judgement,
// it copies, and the code it emits is its own range variable. So an appendCode
// whose code argument is a variable this range statement binds does not count.
// A violation report names the code it is reporting.
//
// A func literal's body is not searched: it runs where it is called, which need
// not be inside this loop at all. Nested loops ARE searched, because a
// universal whose violation is reported from an inner loop is still a universal
// of the outer one -- which is exactly why the range-variable test is scoped to
// THIS loop's variables and not to every variable in scope.
func reportsViolation(x *ast.RangeStmt) bool {
	bound := rangeVars(x)
	found := false
	ast.Inspect(x.Body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			found = true
		case *ast.CallExpr:
			id, ok := node.Fun.(*ast.Ident)
			if !ok || id.Name != "appendCode" || len(node.Args) != 2 {
				return true
			}
			arg, isIdent := node.Args[1].(*ast.Ident)
			found = !isIdent || !bound[arg.Name]
		}
		return !found
	})
	return found
}

// quantifies reports whether a range loop is a universal this operator can
// weaken: it ranges over a collection, it can report a violating member, and a
// `break` appended to its body would actually change what it does.
func quantifies(x *ast.RangeStmt) bool {
	if x.Body == nil || len(x.Body.List) == 0 {
		return false
	}
	if leavesBody(x.Body.List[len(x.Body.List)-1], false) {
		return false
	}
	return reportsViolation(x)
}

// collector accumulates the sites of one file.
type collector struct {
	fset  *token.FileSet
	rel   string
	funcs *funcIndex
	out   []*site
}

func (c *collector) add(op string, node ast.Node, s *site) {
	s.File = c.rel
	s.Line = c.fset.Position(node.Pos()).Line
	s.Func = c.funcs.nameAt(node.Pos())
	s.Op = op
	s.Snippet = srcOf(c.fset, node)
	c.out = append(c.out, s)
}

// condSites enumerates the three weakenings of one boolean guard: the whole
// guard off, each disjunct off, each conjunct off.
func (c *collector) condSites(prefix string, cond ast.Expr, owner ast.Node) {
	if !isLit(cond, "false") {
		c.add(prefix+"_OFF", owner, &site{kind: "expr", target: cond, replace: "false"})
	}
	if or := flatten(cond, token.LOR); len(or) > 1 {
		for _, leaf := range or {
			if isLit(leaf, "false") {
				continue
			}
			c.add(prefix+"_DISJ", leaf, &site{kind: "expr", target: leaf, replace: "false"})
		}
	}
	if and := flatten(cond, token.LAND); len(and) > 1 {
		for _, leaf := range and {
			if isLit(leaf, "true") {
				continue
			}
			c.add(prefix+"_CONJ", leaf, &site{kind: "expr", target: leaf, replace: "true"})
		}
	}
}

// collect enumerates every weakening mutation site in one parsed file, in source
// order, with keys already assigned.
func collect(fset *token.FileSet, f *ast.File, rel string) []*site {
	c := &collector{fset: fset, rel: rel, funcs: newFuncIndex(f)}
	tagged := taggedClauses(f)

	ast.Inspect(f, func(nd ast.Node) bool {
		switch x := nd.(type) {
		case *ast.IfStmt:
			if x.Cond != nil {
				c.condSites("IF", x.Cond, x)
			}
		case *ast.CaseClause:
			if arm, isTagged := tagged[x]; isTagged {
				c.add("CASE_DEL", x, &site{kind: "casedel", clause: x, swBody: arm.body, typeSwitch: arm.typeSwitch})
				break
			}
			for _, e := range x.List {
				c.condSites("CASE", e, e)
			}
		case *ast.ReturnStmt:
			if c.funcs.inBoolFunc(x.Pos()) && len(x.Results) == 1 {
				if !isLit(x.Results[0], "true") {
					c.add("RET_TRUE", x, &site{kind: "ret", ret: x, replace: "true"})
				}
				if !isLit(x.Results[0], "false") {
					c.add("RET_FALSE", x, &site{kind: "ret", ret: x, replace: "false"})
				}
			}
		case *ast.RangeStmt:
			if quantifies(x) {
				c.add("LOOP_FIRST", x, &site{kind: "loopfirst", rng: x})
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "appendCode" && len(x.Args) == 2 {
				c.add("CODE_OFF", x, &site{kind: "call", call: x})
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
				if se, ok := x.Lhs[0].(*ast.SelectorExpr); ok && se.Sel.Name == "valid" {
					if !isLit(x.Rhs[0], "true") {
						c.add("VALID_TRUE", x, &site{kind: "assign", assign: x, replace: "true"})
					}
				}
			}
		}
		return true
	})

	sort.SliceStable(c.out, func(i, j int) bool { return c.out[i].Line < c.out[j].Line })
	assignKeys(c.out)
	return c.out
}

// assignKeys gives every site its stable key, numbering repeated keys in source
// order.
func assignKeys(sites []*site) {
	seen := map[string]int{}
	for _, s := range sites {
		base := siteKey(s.File, s.Func, s.Op, s.Snippet, 1)
		seen[base]++
		s.Key = siteKey(s.File, s.Func, s.Op, s.Snippet, seen[base])
	}
}

// apply performs one mutation by rewriting the AST in place.
func apply(f *ast.File, s *site) error {
	done := false
	switch s.kind {
	case "expr":
		replaceExpr(f, s.target, shortCircuit(s.target, s.replace), &done)
	case "ret":
		s.ret.Results[0] = shortCircuit(s.ret.Results[0], s.replace)
		done = true
	case "call":
		replaceExpr(f, s.call, suppressCode(s.call), &done)
	case "assign":
		s.assign.Rhs[0] = shortCircuit(s.assign.Rhs[0], s.replace)
		done = true
	case "loopfirst":
		// The quantifier weakening: "for every member, P" becomes "for the
		// first member that reaches the end of the body, P". A `continue`
		// already in the body is the loop's own filter, so the witness the
		// weakened rail keeps is the first member of the SET THE RULE RANGES
		// OVER, not merely element zero -- which is the reading the operator
		// wants and the reason the break is appended rather than the range
		// expression being sliced.
		//
		// The position is the body's closing brace so go/printer places the
		// statement on its own line; a synthesized node with no position at all
		// is printed adjacent to the one before it.
		s.rng.Body.List = append(s.rng.Body.List,
			&ast.BranchStmt{TokPos: s.rng.Body.Rbrace, Tok: token.BREAK})
		done = true
	case "casedel":
		var kept []ast.Stmt
		for _, st := range s.swBody.List {
			if st == ast.Stmt(s.clause) {
				done = true
				continue
			}
			kept = append(kept, st)
		}
		s.swBody.List = kept
		if done && s.typeSwitch != nil {
			unbindIfUnused(s.typeSwitch)
		}
	}
	if !done {
		return fmt.Errorf("mutation site %s not reachable in AST", s.Key)
	}
	return nil
}

// replaceExpr walks the file replacing the exact node pointer old with nw.
//
// One arm per expression-bearing parent node. The branch count is the node
// count: a table keyed on reflect.Type would be shorter and would hide which
// parents are covered, and a parent that is silently absent is a mutation that
// reports success and changes nothing, which scores as a measurement that was
// never taken. The accepted-complexity table records this.
func replaceExpr(root ast.Node, old, nw ast.Expr, done *bool) {
	ast.Inspect(root, func(n ast.Node) bool {
		if *done || n == nil {
			return !*done
		}
		switch x := n.(type) {
		case *ast.IfStmt:
			if x.Cond == old {
				x.Cond = nw
				*done = true
			}
		case *ast.BinaryExpr:
			if x.X == old {
				x.X = nw
				*done = true
			} else if x.Y == old {
				x.Y = nw
				*done = true
			}
		case *ast.UnaryExpr:
			if x.X == old {
				x.X = nw
				*done = true
			}
		case *ast.ParenExpr:
			if x.X == old {
				x.X = nw
				*done = true
			}
		case *ast.CaseClause:
			for i := range x.List {
				if x.List[i] == old {
					x.List[i] = nw
					*done = true
				}
			}
		case *ast.AssignStmt:
			for i := range x.Rhs {
				if x.Rhs[i] == old {
					x.Rhs[i] = nw
					*done = true
				}
			}
		case *ast.ReturnStmt:
			for i := range x.Results {
				if x.Results[i] == old {
					x.Results[i] = nw
					*done = true
				}
			}
		case *ast.CallExpr:
			if x.Fun == old {
				x.Fun = nw
				*done = true
			}
			for i := range x.Args {
				if x.Args[i] == old {
					x.Args[i] = nw
					*done = true
				}
			}
		case *ast.ExprStmt:
			if x.X == old {
				x.X = nw
				*done = true
			}
		case *ast.KeyValueExpr:
			if x.Value == old {
				x.Value = nw
				*done = true
			}
		case *ast.ForStmt:
			if x.Cond == old {
				x.Cond = nw
				*done = true
			}
		case *ast.SwitchStmt:
			if x.Tag == old {
				x.Tag = nw
				*done = true
			}
		case *ast.IndexExpr:
			if x.Index == old {
				x.Index = nw
				*done = true
			}
		}
		return !*done
	})
}
