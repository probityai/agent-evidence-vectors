// The RFC 8785 vectors as an importable Go package. Its own module so that a
// consumer's go.mod gains one requirement with no transitive ones, and so the
// module proxy serves only these files and not the repository's corpora.
module github.com/probityai/agent-evidence-vectors/jcsvectors

go 1.24
