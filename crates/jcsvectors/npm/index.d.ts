/** A feature a case exercises, read from its bytes. */
export type Feature =
  | "integer"
  | "unsafe-integer"
  | "fraction"
  | "exponent"
  | "negative-zero"
  | "escape"
  | "non-ascii"
  | "not-utf8";

/** A subset of RFC 8785 an implementation declares it supports. */
export type Profile = "rfc8785" | "integer-only";

export interface Vector {
  id: string;
  corpus: "vectors-a2a-jcs-v01" | "jcs-byte-vectors";
  /** The RFC 8785 clause the case tests; empty for jcs-byte-vectors cases. */
  clause: string;
  input: Uint8Array;
  /** The RFC 8785 output; null for a case that must be refused. */
  canonical: Uint8Array | null;
  features: Feature[];
}

export interface Drift {
  id: string;
  family: string;
  source: string;
  input: Uint8Array;
  presented: Uint8Array;
  canonical: Uint8Array;
}

export interface Differential {
  id: string;
  family: string;
  input: Uint8Array;
  /** The code RFC 8785 refuses the input with; empty when it accepts it. */
  error: string;
  /** The RFC 8785 output; null when refused, or when the corpus pins no bytes. */
  canonical: Uint8Array | null;
  /** The code the bounded profile refuses the input with; empty when it admits it. */
  boundedError: string;
  accepted: boolean;
  features: Feature[];
}

export interface ProfileOption {
  /** Return only the cases inside this profile. */
  profile?: Profile;
}

export const A2A_CORPUS: "vectors-a2a-jcs-v01";
export const BYTE_CORPUS: "jcs-byte-vectors";
export const DEPTH_CAP: 128;
export const SOURCE_GO: "go-encoding-json";
export const FEATURES: Readonly<Record<string, Feature>>;
export const PROFILES: readonly Profile[];

export function canonical(options?: ProfileOption): Vector[];
export function reject(options?: ProfileOption): Vector[];
export function drifts(): Drift[];
export function tooDeep(): Vector[];
export function depthAdmitted(): Vector[];
export function parserDifferential(): Generator<Differential, void, undefined>;
export function files(): [string, Uint8Array][];
export function features(input: Uint8Array, canonical?: Uint8Array | null): Feature[];
/** Throws on a profile this package does not know. */
export function admits(profile: Profile, features: readonly Feature[]): boolean;
export function filter<T extends { features: Feature[] }>(profile: Profile, cases: T[]): { inProfile: T[]; outOfProfile: T[] };
