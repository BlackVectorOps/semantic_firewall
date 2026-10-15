"""Compare high-risk alerts across builds in eval_compare.py output.

usage: python3 -I analyze.py <derive_v520.py dir> <out/*.jsonl ...>
"""
import collections
import json
import re
import sys

sys.path.insert(0, sys.argv[1])
from derive_v520 import base_risk, labels  # noqa: E402

HIGH = 10
rows = []  # (repo, commit, file, function, status, old, now, v520, old_delta, now_delta)
files = errors = 0
for path in sys.argv[2:]:
    for line in open(path):
        r = json.loads(line)
        files += 1
        res = r["results"]
        if any("error" in v for v in res.values()):
            errors += 1
            continue
        old = {f["function"]: f for f in res["old"]["functions"]}
        now = {f["function"]: f for f in res["now"]["functions"]}
        for name in sorted(set(old) | set(now)):
            o, n = old.get(name), now.get(name)
            rows.append((r["repo"], r["commit"], r["file"], name, (n or o)["status"],
                         o["risk"] if o else 0, n["risk"] if n else 0, base_risk(o) if o else 0,
                         o["delta"] if o else "", n["delta"] if n else ""))

print(f"files {files}, files with an error in some build {errors}, changed functions {len(rows)}")
for col, label in ((7, "v5.2.0"), (5, "before session"), (6, "now")):
    print(f"  alerts ({label}): {sum(1 for r in rows if r[col] >= HIGH)}")


def signals(delta):
    out = []
    for l in labels(delta):
        m = re.match(r"([A-Za-z]+[+-]?[a-z]*)", l)
        out.append(m.group(1) if m else l)
    return out


per_signal = collections.Counter()
for r in rows:
    if r[6] >= HIGH:
        for s in set(signals(r[9])):
            if s.startswith(("Capability", "Unguarded", "RemovedCheck", "WeakenedSecurity", "Obfuscation", "AddedGoroutine", "NewFunction")):
                per_signal[s] += 1
print("signals on alerts now:", dict(per_signal.most_common()))


def show(title, sel):
    picked = [r for r in rows if sel(r)]
    print(f"\n== {title}: {len(picked)}")
    for r in picked:
        print(f"{r[0]} {r[1]} {r[2]} :: {r[3]} [{r[4]}] v520={r[7]} old={r[5]} now={r[6]}")
        if r[8] != r[9]:
            print(f"    old: {r[8][:220]}")
        print(f"    now: {r[9][:220]}")


show("alerts this session added (now high, before not)", lambda r: r[6] >= HIGH > r[5])
show("alerts this session removed (before high, now not)", lambda r: r[5] >= HIGH > r[6])
show("alerts the branch adds over v5.2.0 (now high, v5.2.0 not)", lambda r: r[6] >= HIGH > r[7])
