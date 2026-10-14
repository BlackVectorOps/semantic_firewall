"""Derive the v5.2.0 risk score of a function from a newer sfw's output.

The signals added after v5.2.0 each add exactly RiskScoreHigh (10) and
escalations are uncapped, so removing their contribution recovers the old
score: Unguarded(...) and WeakenedSecurity(...) always, RemovedCheck(...)
when none of its targets is a v5.2.0 verification primitive.
"""
import re

PRIMITIVE = [
    re.compile(r"^crypto/subtle\.ConstantTime"),
    re.compile(r"^crypto/hmac\.Equal$"),
    re.compile(r"^crypto/(ed25519|ecdsa|rsa)\.Verify"),
    re.compile(r"^\(crypto/x509\.(Certificate|CertificateRequest)\)\.(Verify|CheckSignature)"),
    re.compile(r"^\(crypto/tls\.Conn\)\.VerifyHostname$"),
    re.compile(r"^golang\.org/x/crypto/bcrypt\.CompareHashAndPassword$"),
    re.compile(r"^path/filepath\.IsLocal$"),
]


def labels(delta):
    """Split a topology_delta into its top-level labels."""
    out, depth, cur = [], 0, ""
    for ch in delta:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def new_signal_points(delta):
    pts, which = 0, []
    for l in labels(delta or ""):
        if l.startswith("Unguarded(") or l.startswith("WeakenedSecurity("):
            pts += 10
            which.append(l)
        elif l.startswith("RemovedCheck("):
            targets = l[len("RemovedCheck("):-1].split(",")
            if not any(p.search(t) for t in targets for p in PRIMITIVE):
                pts += 10
                which.append(l)
    return pts, which


def base_risk(fn):
    pts, _ = new_signal_points(fn.get("delta", ""))
    return fn["risk"] - pts
