"""Replay a repository's recent commits through one sfw build in batch mode.

For each of the last N non-merge commits (from START) that change non-test
Go files, check the parent and the commit out into two worktrees, download
modules when go.sum changes, and diff every changed file in one
`sfw diff --batch` run, selecting files exactly as the GitHub Action does
(modified, added, renamed; not deleted, _test.go, _generated.go, vendor/,
testdata/). Writes one JSON line per diffed file.

usage: python3 -I eval_history.py <repo-dir> <start-ref> <n-commits> <sfw> <out.jsonl>
"""
import hashlib
import json
import os
import subprocess
import sys

repo, start, n, sfw, out_path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
repo = os.path.abspath(repo)
name = os.path.basename(repo)
wt_old, wt_new = repo + ".wt-old", repo + ".wt-new"


def git(*args, cwd=repo):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


for wt in (wt_old, wt_new):
    if not os.path.isdir(wt):
        git("worktree", "add", "-q", "--detach", wt, start)

downloaded = set()


def download(wt):
    sumfile = os.path.join(wt, "go.sum")
    key = hashlib.sha256(open(sumfile, "rb").read()).hexdigest() if os.path.exists(sumfile) else wt
    if key not in downloaded:
        subprocess.run(["go", "mod", "download"], cwd=wt, capture_output=True, timeout=900)
        downloaded.add(key)


def eligible(path):
    return (path.endswith(".go") and not path.endswith("_test.go") and not path.endswith("_generated.go")
            and not path.startswith("vendor/") and "/testdata/" not in path and not path.startswith("testdata/"))


done = 0
stats = {"commits": 0, "files": 0, "errors": 0}
with open(out_path, "a") as out:
    for c in git("log", "--no-merges", "--format=%H", "-n", str(n * 4), start, "--", "*.go").split():
        if done >= n:
            break
        parents = git("rev-list", "--parents", "-n", "1", c).split()
        if len(parents) != 2:
            continue
        p = parents[1]
        pairs = []
        raw = git("diff", "-z", "--name-status", "-M", p, c, "--", "*.go").split("\0")
        i = 0
        while i < len(raw) and raw[i]:
            status = raw[i]
            if status[0] in "RC":
                old, new = raw[i + 1], raw[i + 2]
                i += 3
            else:
                old = new = raw[i + 1]
                i += 2
            if status[0] == "D" or not eligible(new):
                continue
            pairs.append((old, new))
        if not pairs:
            continue
        done += 1
        git("checkout", "-q", "--detach", "-f", p, cwd=wt_old)
        git("checkout", "-q", "--detach", "-f", c, cwd=wt_new)
        download(wt_old)
        download(wt_new)
        pairs_file = os.path.join(os.path.dirname(repo), name + ".pairs")
        with open(pairs_file, "wb") as pf:
            for old, new in pairs:
                o = os.path.join(wt_old, old)
                nw = os.path.join(wt_new, new)
                pf.write((o if os.path.exists(o) else os.devnull).encode() + b"\0")
                pf.write((nw if os.path.exists(nw) else os.devnull).encode() + b"\0")
        try:
            res = subprocess.run([sfw, "diff", "--no-sandbox", "--batch", pairs_file], capture_output=True, text=True, timeout=1800)
            entries = json.loads(res.stdout)
        except Exception as e:  # noqa: BLE001
            out.write(json.dumps({"repo": name, "commit": c[:12], "batch_error": str(e)[-300:]}) + "\n")
            stats["errors"] += 1
            continue
        stats["commits"] += 1
        for (old, new), e in zip(pairs, entries):
            stats["files"] += 1
            rec = {"repo": name, "commit": c[:12], "file": new}
            if e.get("error"):
                rec["error"] = e["error"][-300:]
                stats["errors"] += 1
            rec["functions"] = [
                {"function": f["function"], "status": f["status"], "risk": f.get("risk_score", 0), "delta": f.get("topology_delta", "")}
                for f in (e.get("functions") or []) if f["status"] != "preserved"
            ]
            out.write(json.dumps(rec) + "\n")
        out.flush()
print(name, stats, file=sys.stderr)
