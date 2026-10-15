"""Replay a repository's recent commits through several sfw builds in batch mode.

Like .claude/handoff/eval_history.py, but every build diffs the same pairs of
each commit, so their outputs line up. Writes one JSON line per diffed file:
{"repo", "commit", "file", "results": {build: {"error"} or {"functions": [...]}}}.

usage: python3 -I eval_compare.py <repo-dir> <start-ref> <n-commits> <out.jsonl> name=sfw [name=sfw ...]
"""
import hashlib
import json
import os
import subprocess
import sys
import time

repo, start, n, out_path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
builds = [a.split("=", 1) for a in sys.argv[5:]]
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
        subprocess.run(["go", "mod", "download"], cwd=wt, capture_output=True, timeout=900,
                       env={**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"})
        downloaded.add(key)


def eligible(path):
    return (path.endswith(".go") and not path.endswith("_test.go") and not path.endswith("_generated.go")
            and not path.startswith("vendor/") and "/testdata/" not in path and not path.startswith("testdata/"))


def functions(entry):
    return [{"function": f["function"], "status": f["status"], "risk": f.get("risk_score", 0),
             "delta": f.get("topology_delta", "")}
            for f in (entry.get("functions") or []) if f["status"] != "preserved"]


done = 0
stats = {"commits": 0, "files": 0, "errors": 0, "seconds": {b: 0.0 for b, _ in builds}}
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
        pairs_file = repo + ".pairs"
        with open(pairs_file, "wb") as pf:
            for old, new in pairs:
                o = os.path.join(wt_old, old)
                nw = os.path.join(wt_new, new)
                pf.write((o if os.path.exists(o) else os.devnull).encode() + b"\0")
                pf.write((nw if os.path.exists(nw) else os.devnull).encode() + b"\0")
        per_build = {}
        for b, sfw in builds:
            t0 = time.time()
            try:
                res = subprocess.run([sfw, "diff", "--no-sandbox", "--batch", pairs_file],
                                     capture_output=True, text=True, timeout=1800)
                per_build[b] = json.loads(res.stdout)
            except Exception as e:  # noqa: BLE001
                per_build[b] = {"batch_error": str(e)[-300:]}
                stats["errors"] += 1
            stats["seconds"][b] += time.time() - t0
        stats["commits"] += 1
        for k, (old, new) in enumerate(pairs):
            stats["files"] += 1
            rec = {"repo": name, "commit": c[:12], "file": new, "results": {}}
            for b, _ in builds:
                entries = per_build[b]
                if isinstance(entries, dict):
                    rec["results"][b] = {"error": entries["batch_error"]}
                    continue
                e = entries[k]
                if e.get("error"):
                    rec["results"][b] = {"error": e["error"][-300:]}
                    stats["errors"] += 1
                else:
                    rec["results"][b] = {"functions": functions(e)}
            out.write(json.dumps(rec) + "\n")
        out.flush()
print(name, json.dumps(stats), file=sys.stderr)
