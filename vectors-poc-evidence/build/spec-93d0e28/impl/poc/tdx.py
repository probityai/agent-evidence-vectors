"""Intel TDX attestation: a real hardware measurement, and a real binding
between that measurement and the evidence signing key.

WHY THIS FILE EXISTS. Everywhere else in this implementation the "enclave" is
an in-process object and the "measurement" is a digest of the policy code. That
reproduces the protocol but not the hardware, and the paper says so. It also
leaves the most important claim in the standard resting on a stand-in: that a
verifier can establish *which code produced this evidence* without trusting the
operator.

This module does it for real, inside a TDX trust domain.

THE BINDING. A quote by itself proves a measured environment exists. It does
not connect that environment to any particular signing key, and an operator who
could pair an honest quote with a key held outside the TD would defeat the
entire scheme. TDX gives us 64 bytes of REPORTDATA that the hardware copies
into the quote it signs. So we put the digest of the evidence public key there:

    REPORTDATA = SHA-512(evidence public key)[:64]

Now the hardware's signature covers both the measurement and the key, and the
statement a verifier gets is the one that actually matters -- *this key lives
inside this measured environment* -- rather than two facts that merely arrived
together.

INTERFACE. Linux configfs-tsm (kernel 6.7+), which is vendor-neutral:
    mkdir  /sys/kernel/config/tsm/report/<name>
    write  inblob   <- 64 bytes of REPORTDATA
    read   outblob  -> the signed quote
    read   provider -> which TSM answered
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

TSM_REPORT = Path("/sys/kernel/config/tsm/report")

# Offsets into a TDX DCAP v4 quote. The header is 48 bytes; the TD report body
# follows and is laid out as in the Intel TDX Module spec.
_HDR = 48
_BODY = {
    "tee_tcb_svn": (0, 16),
    "mrseam": (16, 48),
    "mrsignerseam": (64, 48),
    "seamattributes": (112, 8),
    "tdattributes": (120, 8),
    "xfam": (128, 8),
    "mrtd": (136, 48),  # measurement of the initial TD contents
    "mrconfigid": (184, 48),
    "mrowner": (232, 48),
    "mrownerconfig": (280, 48),
    "rtmr0": (328, 48),
    "rtmr1": (376, 48),
    "rtmr2": (424, 48),
    "rtmr3": (472, 48),
    "reportdata": (520, 64),
}


class TDXUnavailable(RuntimeError):
    pass


def available() -> bool:
    return Path("/dev/tdx_guest").exists() and TSM_REPORT.exists()


def report_data_for_key(public_key_bytes: bytes) -> bytes:
    """The 64 bytes bound into the quote. SHA-512 fills REPORTDATA exactly."""
    return hashlib.sha512(b"poc-evidence-key\x00" + public_key_bytes).digest()


def get_quote(report_data: bytes, privsafe: bool = True) -> tuple[bytes, str]:
    """Ask the hardware for a quote over `report_data`. Returns (quote, provider)."""
    if len(report_data) != 64:
        raise ValueError(f"REPORTDATA must be 64 bytes, got {len(report_data)}")
    if not available():
        raise TDXUnavailable("no TDX guest device or configfs-tsm interface")

    d = TSM_REPORT / f"poc-{uuid.uuid4().hex[:12]}"
    d.mkdir()
    try:
        (d / "inblob").write_bytes(report_data)
        quote = (d / "outblob").read_bytes()
        try:
            provider = (d / "provider").read_text().strip()
        except OSError:
            provider = "unknown"
        return quote, provider
    finally:
        try:
            d.rmdir()
        except OSError:
            pass


@dataclass
class TDXQuote:
    raw: bytes
    provider: str

    def field(self, name: str) -> bytes:
        off, ln = _BODY[name]
        return self.raw[_HDR + off : _HDR + off + ln]

    @property
    def mrtd(self) -> str:
        """The measurement a verifier compares against a reference value."""
        return self.field("mrtd").hex()

    @property
    def reportdata(self) -> str:
        return self.field("reportdata").hex()

    @property
    def rtmrs(self) -> list[str]:
        return [self.field(f"rtmr{i}").hex() for i in range(4)]

    def binds_key(self, public_key_bytes: bytes) -> bool:
        """Does this quote actually commit to this key?

        This is the check that makes the quote mean something. Without it a
        verifier has an honest measurement and a signing key that could have
        come from anywhere.
        """
        return self.field("reportdata") == report_data_for_key(public_key_bytes)

    def summary(self) -> dict:
        return {
            "provider": self.provider,
            "quote_bytes": len(self.raw),
            "mrtd": self.mrtd,
            "rtmr": self.rtmrs,
            "tdattributes": self.field("tdattributes").hex(),
            "xfam": self.field("xfam").hex(),
            "reportdata": self.reportdata,
        }


def attest_key(public_key_bytes: bytes) -> TDXQuote:
    """Produce a hardware quote bound to this evidence key."""
    quote, provider = get_quote(report_data_for_key(public_key_bytes))
    q = TDXQuote(quote, provider)
    if not q.binds_key(public_key_bytes):
        raise RuntimeError("quote REPORTDATA does not match the key it should bind")
    return q


def measure_quote_cost(public_key_bytes: bytes, n: int = 20) -> dict:
    """What the attestation actually costs, which is the number every latency
    table in this paper has so far excluded."""
    rd = report_data_for_key(public_key_bytes)
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        get_quote(rd)
        samples.append((time.perf_counter_ns() - t0) / 1000)
    samples.sort()
    return {
        "n": n,
        "mean_us": round(sum(samples) / len(samples), 1),
        "median_us": round(samples[len(samples) // 2], 1),
        "min_us": round(samples[0], 1),
        "p95_us": round(samples[int(len(samples) * 0.95) - 1], 1),
        "max_us": round(samples[-1], 1),
    }
