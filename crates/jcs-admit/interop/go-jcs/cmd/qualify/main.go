// Copyright 2026 Probity AI. Apache-2.0 license.

// The installed command reads one raw document, then emits the exact outcome.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	gojcs "github.com/probityai/jcs-admit/interop/go-jcs"
)

func run() error {
	admission := flag.String("admission", "", "absolute path to the installed raw admission command")
	profile := flag.String("profile", "rfc8785", "rfc8785, ijson or ijson-integers")
	depth := flag.Int("max-depth", 128, "maximum admitted nesting depth")
	size := flag.Int("max-bytes", 20<<20, "maximum admitted input bytes")
	bare := flag.Bool("bare", false, "record the pinned Go writer without raw admission")
	flag.Parse()
	if *size < 0 || *size > 20<<20 || *depth < 0 || *depth > 128 {
		return fmt.Errorf("invalid finite input caps")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, int64(*size)+1))
	if err != nil {
		return err
	}
	var outcome gojcs.Outcome
	if *bare {
		// Bare observations use the same bounded inputs as the consumer.
		outcome = gojcs.BareTransform(raw)
	} else {
		if *admission == "" {
			return fmt.Errorf("select an installed raw admission command")
		}
		outcome, err = gojcs.Transform(raw, *admission, gojcs.Policy{Profile: *profile, MaxDepth: *depth, MaxBytes: *size})
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(outcome)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
