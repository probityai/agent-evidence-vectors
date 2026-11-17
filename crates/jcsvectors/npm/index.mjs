// RFC 8785 (JSON Canonicalization Scheme) test vectors as files inside this
// package, each checked against its SHA-256 before any case is returned. The
// same files, read by the same rules, as the Go module
// github.com/probityai/agent-evidence-vectors/jcsvectors and the Rust crate
// jcsvectors.

import { readFileSync } from "node:fs";

import { readers } from "./lib.mjs";

export { A2A_CORPUS, BYTE_CORPUS, DEPTH_CAP, FEATURES, PROFILES, SOURCE_GO, admits, features, filter } from "./lib.mjs";

const vectors = readers((name) => new Uint8Array(readFileSync(new URL(`./data/${name}`, import.meta.url))));

/** Every case a canonicalizer must accept, with the exact bytes RFC 8785 requires. */
export const canonical = vectors.canonical;
/** Every case a canonicalizer must refuse. Some inputs are not UTF-8: compare bytes. */
export const reject = vectors.reject;
/** Bytes a printer presents as canonical that RFC 8785 does not print that way. */
export const drifts = vectors.drifts;
/** Input nested past DEPTH_CAP, which an admission gate with that cap must refuse. */
export const tooDeep = vectors.tooDeep;
/** Input nested exactly DEPTH_CAP deep, which such a gate must accept and print. */
export const depthAdmitted = vectors.depthAdmitted;
/** The byte strings two JSON readers read apart, with what RFC 8785 and the bounded profile do. */
export const parserDifferential = vectors.parserDifferential;
/** Every embedded file at its corpus path, checked against its digest. */
export const files = vectors.files;
