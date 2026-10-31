// Sentinel module. A directory with its own go.mod is left out of the root module's zip,
// so the Go module proxy does not carry these files. Nothing here is Go source.
module github.com/probityai/agent-evidence-vectors/crates

go 1.24
