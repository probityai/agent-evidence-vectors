/** Native Rust Error metadata. Field names and values are not renamed. */
export class JcsError extends Error {
  readonly variant: string;
  readonly fields: Readonly<Record<string, unknown>>;
  constructor(variant: string, fields: Record<string, unknown>, message: string);
}

/** RFC 8785 defaults. Throws JcsError for a refusal, TypeError for non-bytes. */
export function admit(input: Uint8Array): Uint8Array;

/** Explicit I-JSON safe-integer/noncharacter tightening of the native core. */
export function admit_ijson(input: Uint8Array): Uint8Array;
