#!/usr/bin/env python3
"""Break every refusal on purpose and check that a test notices.

A test that passes against unimplemented code measures nothing. This applies each
edit in CASES to the pristine sources, runs the suite that should catch it,
records what the crate ACCEPTED with the refusal gone, then restores. A row that
comes back STILL-GREEN is a test that does not discriminate, not a passing test.

Every cargo call is -j1 on purpose: the sweep is a serial series of builds, and a
second layer of parallelism over an already-parallel compiler has nothing
bounding the product.

Run it from anywhere:  python3 crates/jcs-admit/tools/mutation_sweep.py [LOG_DIR]
It edits the crate it ships in, restores every file it touched, writes one log
per row and results.json to LOG_DIR (a fresh temporary directory by default),
and exits 1 when any row is STILL-GREEN or its anchor did not apply. The
written-up run, including the three test gaps it found, is in
docs/MUTATION-SWEEP.md.
"""
import subprocess, pathlib, json, sys, os, shutil, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOGS = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(
    tempfile.mkdtemp(prefix="jcs-admit-mutate-"))
LOGS.mkdir(parents=True, exist_ok=True)
BACKUP = LOGS / "pristine"
if BACKUP.exists(): shutil.rmtree(BACKUP)
BACKUP.mkdir(parents=True)
FILES = ("parse.rs", "number.rs", "lib.rs", "error.rs")
for f in FILES:
    shutil.copy(ROOT / "src" / f, BACKUP / f)

def restore():
    for f in FILES:
        shutil.copy(BACKUP / f, ROOT / "src" / f)

DUP_GUARD = '''            if !seen.insert(name.clone()) {'''
ENTER = '''        if depth >= self.opts.depth_limit() {'''
HI_SURR = '''                    return Err(self.refuse_string(start, "unpaired high surrogate escape"));'''
LO_SURR = '''            0xDC00..=0xDFFF => return Err(self.refuse_string(start, "unpaired low surrogate escape")),'''
UTF8 = '''                let chunk = core::str::from_utf8(&self.bytes[run_start..self.at])
                    .map_err(|_| self.refuse_string(run_start, "invalid UTF-8"))?;'''
NONCHAR_RUN = '''                if self.opts.wants_noncharacter_check() {
                    if let Some((at, _)) = chunk
                        .char_indices()
                        .find(|&(_, c)| is_noncharacter(c as u32))
                    {
                        return Err(self.refuse_string(run_start + at, NONCHARACTER));
                    }
                }
'''
NONCHAR_AT = '''                        return Err(self.refuse_string(run_start + at, NONCHARACTER));'''
STRING_MSG = '''                write!(f, "JSON string literal refused at byte {offset}: {reason}")'''
NONCHAR_GET = '''    pub(crate) const fn wants_noncharacter_check(&self) -> bool {
        self.reject_noncharacters
    }'''
UNSAFE_FRACTION_BR = '''        if opts.wants_safe_integers() && !d.is_integer() && rounds_past_safe_range(token) {
            return Err(Error::UnsafeInteger {
                token: token.to_owned(),
            });
        }'''
UNSAFE_BR = '''        if opts.wants_safe_integers() && d.is_integer() && d.is_unsafe_magnitude() {
            return Err(Error::UnsafeInteger {
                token: token.to_owned(),
            });
        }'''
NONINT_BR = '''        if opts.wants_integers_only() && !d.is_integer() {
            return Err(Error::NonIntegerNumber {
                token: token.to_owned(),
            });
        }'''
IS_INT = '''    fn is_integer(&self) -> bool {
        self.digits.is_empty() || self.exp10 >= 0
    }'''
FINITE = '''    if !token.parse::<f64>().is_ok_and(f64::is_finite) {'''
SIZE = '''        if let Some(limit) = self.max_bytes {
            if len > limit {'''

CASES = [
  # (id, kind, refusal, file, old, new, cargo args)
  ("R1","red","DuplicateMember","parse.rs", DUP_GUARD,
     '''            let _ = name_at;
            if false {''',
     ["--test","duplicate_members"]),
  ("M1","mutate","DuplicateMember","parse.rs", DUP_GUARD,
     '''            if !seen.insert(String::from_utf8_lossy(&self.bytes[name_at..self.at]).into_owned()) {''',
     ["--test","duplicate_members"]),
  ("R2","red","TooDeep","parse.rs", ENTER, '''        if depth >= usize::MAX {''',
     ["--test","refusal_boundaries","the_depth_cap"]),
  ("M2","mutate","TooDeep","parse.rs", ENTER, '''        if depth > self.opts.depth_limit() {''',
     ["--test","refusal_boundaries","the_depth_cap"]),
  ("R3","red","StringNotScalar/surrogate","parse.rs", HI_SURR,
     '''                    out.push('\\u{FFFD}');
                    return Ok(());''',
     ["--test","attack_strings_keys_members"]),
  ("M3","mutate","StringNotScalar/surrogate","parse.rs", LO_SURR,
     '''            0xDC00..=0xDFFF => { out.push('\\u{FFFD}'); return Ok(()); }''',
     ["--test","attack_strings_keys_members"]),
  ("R4","red","StringNotScalar/utf8","parse.rs", UTF8,
     '''                let lossy = String::from_utf8_lossy(&self.bytes[run_start..self.at]);
                let chunk: &str = &lossy;''',
     ["--test","attack_strings_keys_members"]),
  ("R5","red","StringNotScalar/noncharacter","lib.rs", NONCHAR_GET,
     '''    pub(crate) const fn wants_noncharacter_check(&self) -> bool {
        let _ = self.reject_noncharacters;
        false
    }''',
     ["--test","attack_strings_keys_members"]),
  ("M4","mutate","StringNotScalar/noncharacter","parse.rs", NONCHAR_RUN, "",
     ["--test","attack_strings_keys_members"]),
  ("M4b","mutate","StringNotScalar/noncharacter-offset","parse.rs", NONCHAR_AT,
     '''                        let _ = at;
                        return Err(self.refuse_string(run_start, NONCHARACTER));''',
     ["--test","refusal_messages"]),
  ("M4c","mutate","StringNotScalar/message","error.rs", STRING_MSG,
     '''                write!(f, "JSON string is not a sequence of Unicode scalar values at byte {offset}: {reason}")''',
     ["--test","refusal_messages"]),
  ("R6","red","UnsafeInteger","number.rs", UNSAFE_BR, "", ["--test","ijson_profile"]),
  ("M5","mutate","UnsafeInteger","number.rs", UNSAFE_BR,
     '''        if opts.wants_safe_integers()
            && !token.contains(['e', 'E', '.'])
            && d.is_integer()
            && d.is_unsafe_magnitude()
        {
            return Err(Error::UnsafeInteger {
                token: token.to_owned(),
            });
        }''',
     ["--test","ijson_profile"]),
  ("R6b","red","UnsafeInteger/fraction","number.rs", UNSAFE_FRACTION_BR, "", ["--test","ijson_profile"]),
  ("R7","red","NonIntegerNumber","number.rs", NONINT_BR, "", ["--test","ijson_profile"]),
  ("M6","mutate","NonIntegerNumber","number.rs", IS_INT,
     '''    fn is_integer(&self) -> bool {
        self.exp10 >= 0
    }''',
     ["--test","ijson_profile"]),
  ("R8","red","NonFiniteNumber","number.rs", FINITE, '''    if false {''',
     ["--test","refusal_boundaries","a_non_finite"]),
  ("M7","mutate","NonFiniteNumber","number.rs", FINITE,
     '''    if !token.parse::<f64>().is_ok_and(|v| v != f64::INFINITY) {''',
     ["--test","refusal_boundaries","a_non_finite"]),
  ("R9","red","TooLarge","lib.rs", SIZE,
     '''        if let Some(limit) = self.max_bytes {
            if false && len > limit {''',
     ["--test","refusal_boundaries","the_size_cap"]),
  ("M8","mutate","TooLarge","lib.rs", SIZE,
     '''        if let Some(limit) = self.max_bytes {
            if len >= limit {''',
     ["--test","refusal_boundaries","the_size_cap"]),
]

env = dict(os.environ, CARGO_BUILD_JOBS="1", RUST_TEST_THREADS="1")
results = []
for cid, kind, refusal, fname, old, new, args in CASES:
    restore()
    p = ROOT / "src" / fname
    t = p.read_text()
    n = t.count(old)
    if n != 1:
        results.append(dict(id=cid, kind=kind, refusal=refusal, status="PATCH-DID-NOT-APPLY",
                            occurrences=n, detail="anchor not unique; no conclusion drawn"))
        print(f"{cid}: ANCHOR MATCHED {n} TIMES -- not run", flush=True)
        continue
    p.write_text(t.replace(old, new))
    log = LOGS / f"{cid}.log"
    r = subprocess.run(["cargo","test","-j1"] + args, cwd=ROOT, env=env,
                       stdout=open(log,"w"), stderr=subprocess.STDOUT, timeout=2400)
    out = log.read_text()
    compiled = "could not compile" not in out
    failed = [l.split()[1] for l in out.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
    panic = next((l.strip() for l in out.splitlines() if ": want " in l or "got " in l or "must be" in l), "")
    results.append(dict(id=cid, kind=kind, refusal=refusal, file=fname, exit=r.returncode,
                        compiled=compiled,
                        status=("RED" if r.returncode != 0 else "STILL-GREEN"),
                        failed_tests=failed, first_message=panic[:300], log=str(log)))
    print(f"{cid} {kind:6} {refusal:32} exit={r.returncode} compiled={compiled} "
          f"{'RED' if r.returncode else 'STILL GREEN -- TEST DOES NOT DISCRIMINATE'} "
          f"failed={failed}", flush=True)

restore()
(LOGS / "results.json").write_text(json.dumps(results, indent=2))
print(f"\nrestored pristine sources; logs and results.json in {LOGS}")
undiscriminating = [r["id"] for r in results if r["status"] != "RED"]
if undiscriminating:
    print(f"rows that did not turn red: {undiscriminating}")
    sys.exit(1)
