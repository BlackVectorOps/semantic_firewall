# Handoff: semantic_firewall, branch `ccr-33d08e80-zi15zu` (PR #39)

Written at the end of a long session for the next agent. Read all of it
before touching anything. **Delete `.claude/handoff/` before PR #39 merges.**

## Where things stand (session 2, head `bc91411`)

- Repo `BlackVectorOps/semantic_firewall`, Go module `.../v5`, Go 1.26.3.
- Work branch `ccr-33d08e80-zi15zu`, draft **PR #39** (title still says WIP).
  Session 2 worked on `ccr-2e562674-eku5cl` first, opened PR #40, then the
  user said to move to #39: #39's branch was fast-forwarded and #40 closed.
  If your session is assigned another branch, ask before pushing to #39's.
- CI green on every commit through `bc91411`. Working tree clean.
- `.Jules/` deleted at the user's request (main deleted it too).

### Session 2: hardening pass, two files at a time

The user's process: one hunter sub-agent per pair of files (worktree
isolation, reproducers required, no verifier agents); you judge every
claim by running its reproducer, fix, add tests that fail on the old code
(prove it by stashing the production files), run `tools/mutate` on the
pair, answer every survivor, commit, push.

Done (see commit messages for full lists):
- Pair 1 `guards.go`+`checks.go` (`4332ce1`, `ba8cf93`, `d413a3c`): crash on
  WriteHeader(nil); Unguarded evasions (constant branches, call in both
  arms, `for {}` header, never-returning functions); defer result slots;
  helper/getter/os.IsPermission noise; extracted hmac.Equal; die() helpers.
- Pair 2 `settings.go`+`capability.go` (`4a83b21`, `bc91411`): primitives
  must decide; capabilities via interface conversion / type args /
  RoundTripper; cookie and ClientAuth clearing and decoys; defined types;
  helper-built settings; TLS version raise; LookPath, syscall helpers;
  new filesystem and reflection entries; table tests for every class row.
- Pair 3 `api/deps.go`+`models/deps.go` (`033d245`): vendoring
  (-mod=vendor), newly built packages of unchanged modules, symlinks, asm
  #include, cgo files under any name (magic-byte object detection),
  linknames from parsed comments of all package files keyed by package,
  method-set entry points, init boundary in reach, SCC-memoized reach.

Mutation status: pairs 1 and 2 closed (remaining survivors are the
equivalent classes below). **`deps.go` mutation ran to completion on
`033d245`**; its result is in `mut-deps.txt` here (deps.go is unchanged
since, so `-retest mut-deps.txt` matches by line). Survivors are not yet
triaged. To recheck after adding tests:
`mut -pkgs ./pkg/api -files 'deps\.go$' -run TestDepsDiff -timeout 5m -retest .claude/handoff/mut-deps.txt`.

Next, in order:
1. Triage the `deps.go` survivors in `mut-deps.txt`.
2. Pair 4 `api/risk.go`+`api/batch.go`: a hunter was running when the
   session ended; its results are lost. Relaunch it (prompt: scoring vs
   README, withoutModuleTargets key parsing incl. "(.error).Error" and
   module-prefix paths, batch == separate diffs, races with -race,
   panics; CalculateTopologyDelta has no caller and 0% coverage). Also
   mutate `raisesTLSVersion` (added in pair 2).
3. Pair 5 `diff/loader.go`+`purge.go`, pair 6 `api/diff.go`+
   `cli/diff_logic.go` (readDiffInput error paths), pair 7 the rest
   (fingerprinter, package_functions, cli/deps, cmd/sfw/main).
4. Open question for the user: a tree with `go.work` is analyzed with
   GOWORK=off (documented as a limit). Fail instead, or honor it?
5. Deferred, reported to the user: share the check-helper search across
   functions (needs a per-package cache, outside one pair); settings set
   through a field's address (`flag.BoolVar(&cfg.InsecureSkipVerify..)`);
   func-typed fields (`Transport.DialContext`); a generic function alone.

## The user and how they work

- Quality bar, verbatim: *"I want to build it right, every new addition
  gets vetted tightly with non decoration tests, fully robust every
  statement."* In practice: every new code path gets a test that fails
  when the path is broken; prove it with the mutation tool (below).
- They decide scope, merges and releases. This session cannot push tags;
  the user publishes releases (lowercase `v` tags). Ask before marking the
  PR ready, merging, or releasing.
- Commit messages end with the attribution trailers the harness gives you
  (Co-Authored-By + Claude-Session). No model identifiers anywhere in
  commits, PRs or code.
- Never execute programs under `testdata/`.
- "Crawls" (bug hunts with sub-agents) are paused; when resumed: lean,
  hunters only, you verify every finding, the user chooses scope.
- The user often works from **Termux / proot on android/arm64**. There:
  `-race` is unsupported, the gVisor sandbox can't run (use
  `--no-sandbox`), and everything is slow (`pkg/api` tests ~8 min).
  Cloning the repo needs GitHub auth (`gh auth login`).
- If the user rejects a tool call, check `git status` afterwards: one
  rejected edit this session was written to disk anyway.

## What this branch adds (vs v5.2.0)

Deletion-attack signals (scored in `pkg/api/risk.go`, collected in
`pkg/analysis/topology`):
- `Unguarded(...)` +10: a capability call whose old call sites all had ≥1
  direct control-dependence guard now has one with 0
  (`guards.go: collectCapabilityGuards`; post-dominance by reverse BFS
  avoiding the block; loop headers excluded via `LoopInfo.LoopMap`;
  no-return calls end the function; >2000 blocks → no guards recorded).
- `RemovedCheck(...)` +10, now including **check helpers** (`checks.go`):
  same-package callees reaching a verification primitive within 3 static
  calls (memo keyed by function *and* depth — a bug fixed this session),
  and calls whose camelCase words start with auth/verif/valid/permi/allow/
  admin/acl/csrf/xsrf/signature/privilege/owner/role/access when the
  result decides a branch or is returned (`resultDecides`, ≤4 hops through
  unary/binary ops, conversions, extracts, phis).
- `WeakenedSecurity(...)` +10 (`settings.go`): tls.Config
  InsecureSkipVerify/Min-/MaxVersion<1.2/ClientAuth, http.Cookie
  Secure/HttpOnly/SameSite=None, `ssh.InsecureIgnoreHostKey`.
- `ErrorExits-N` label only, 0 points (`guards.go: countErrorExits`).
  Whether it should score is an open question (eval below).

`sfw deps diff <old> <new>` (`pkg/api/deps.go`, models in
`pkg/models/deps.go`): per changed module, function diffs (own-module
targets aren't capabilities; goroutines labelled only), `reach` (exported
API/inits newly reaching a capability class; inits +10), and an
`unanalyzed` inventory (syso/object 20, linkname 10, others 5). The
inventory scans package directories, and whole modules that use cgo,
because `go list` with cgo off hides a cgo package's C files (bug found
and fixed this session). Fails hard on any package load error.

`sfw diff --batch <pairs>` (`pkg/api/batch.go`, CLI in
`internal/cli/diff_logic.go`): NUL-separated old/new pairs, one load per
module root per side, both sides concurrent; files outside a module, out
of the default build, in ill-typed packages, or in a failing group fall
back to the single-file path. Results equal separate diffs (tested).

Fast source loader (`pkg/diff/loader.go`): go/packages for metadata, own
type-checking; deps parsed with `PurgeFuncBodies`
(`pkg/diff/internal/purge`, copied from x/tools); std and module-cache
deps cached per process. `SFW_LOADER=packages` selects go/packages.
Parity tests in `pkg/diff/loader_parity_test.go`
(`SFW_PARITY_CORPUS=<roots>` runs the corpus check).

Action (`action.yml`): `mode: deps`, and diff mode uses one
`sfw diff --batch`. Tested by `internal/actiontest`.

README documents all of the above (sections: Batch mode, Deletion
signals, sfw deps diff, Loading, Development); examples were run.

## Verification state

Mutation tool: `tools/mutate` (see README → Development). **Fixed in
`b675a1f`:** it used to count any `go test` failure as a kill, so the
user's phone run with `-race` reported 0 survivors everywhere. Those
results are void. It now runs a baseline first and requires a real test
failure for KILLED (otherwise ERROR).

Results on the current code, from this container (no `-race`):
- `pkg/analysis/topology`: the last pass stopped at 420 of 564 mutants;
  every survivor it reported was closed with a test or classed
  equivalent. Rerun the whole group (code changed since).
- `pkg/diff/internal/purge`: 2 survivors, both equivalent.
- **Not yet run with the fixed tool:** `pkg/analysis/topology` (full),
  `pkg/api` (`deps.go` ≈ 459
  mutants; risk/batch/diff), `pkg/diff` (loader, fingerprinter,
  package_functions), `internal/cli` + `cmd/sfw`.

Known equivalent survivors (accepted; don't chase): memo/cache reads and
writes (`checks.go` reached/bodies memo, `guards.go` counts and noReturns,
`settings.go` scans/secure memo); de-duplication guards (`slices.Contains`
before appends, `sites` last-block check, settings `helpers`); scratch
buffer reuse (`g.stack`); early `break`s that only save work; the
`owner != ""` guard on allocations; defensive checks in `structField` and
`declaringType` (SSA FieldAddr invariants, nil field package) and its
same-package fast path; the 4-hop bound in `isErrorExit`; purge
`ellipsis = false` on `;` and `top < 0`.

Coverage (user's phone, `-coverpkg=./...`): 68.9% total; branch files
mostly 90–100%. Real gaps to test:
- `topology.IsVerificationCall` 55.6% (ed25519, x509, tls, bcrypt,
  filepath.IsLocal branches) — table test it.
- `api.readDiffInput` 77.8% (stat error, read error, size limit).
- `diff/loader.go`: `appendLoadError` 62.5%, `hasImportCycle` 82.4%.
- `api.CalculateTopologyDelta` / `assessTopologyDelta` 0%: exported API
  on main with no in-repo caller — keep, add a test.
- Expected 0%: `RunDiff`, `RunDiffBatch`, `RunDepsDiff` (sandbox branch).

## Next steps, in order

1. **Mutation runs** on the untested groups (commands below). Answer
   every survivor with a test or a reason it is equivalent.
2. **Coverage gaps** listed above.
3. **Noise evaluation (task #32):** replay real history and review every
   new high-risk alert by hand; decide whether `ErrorExits` earns points.
   Scripts here: `eval_history.py` (batch replay of a repo's last N
   commits through one sfw build) and `derive_v520.py` (recovers the
   v5.2.0 score from new output; validated with 0 mismatches). Repos
   used: go-chi/chi, gin-gonic/gin, labstack/echo, golang-jwt/jwt,
   casbin/casbin, coreos/go-oidc, gorilla/csrf, gorilla/sessions,
   spf13/cobra, pocketbase/pocketbase (pin pocketbase to `97dd7754`;
   its HEAD needs Go 1.27). The clones were in an ephemeral scratchpad;
   re-clone. Run scripts with `python3 -I`.
4. **Before the PR leaves draft** (ask the user first): refresh the PR
   title/body; at release, bump `SFW_VERSION` in `action.yml` and the
   `@v5.2.0` pins in README (lines ~44, ~1068) — **the Action's new
   modes fail with the v5.2.0 binary**; delete `.claude/handoff/`.
5. Optional, discussed earlier: deps diff on the fast loader; the
   `check` tree loader (`fingerprinter.go` ~line 685) on it after a
   parity gate; precomputed std export data in the sandbox image.

Commands (from repo root):

```sh
go build -o /tmp/mutate ./tools/mutate
mut() { /tmp/mutate -base origin/main -workers 3 -timeout 5m -goflags -shuffle=on "$@"; }
mut -pkgs ./pkg/analysis/topology -timeout 60s -run '^(TestClassifyCallTarget|TestSplitWords|TestCapabilityGuards|TestChecks|TestSecuritySettings|TestErrorExits|TestCalleeCapability|TestExtractTopology|TestStringExtraction)$' > mut-topology.txt
mut -pkgs ./pkg/api -files 'deps\.go$' -run TestDepsDiff > mut-deps.txt
mut -pkgs ./pkg/api -files '(risk|batch|diff)\.go$' -run 'TestAssessTopologyDelta|TestTargetPackage|TestDiffRisk|TestDiffBatch|TestDiff_' > mut-api.txt
mut -pkgs ./pkg/diff -files 'loader\.go$' -run TestLoadSource > mut-loader.txt
mut -pkgs ./pkg/diff -files '(fingerprinter|package_functions)\.go$' -tests ./pkg/diff,./pkg/api > mut-diff.txt
mut -pkgs ./internal/cli,./cmd/sfw -tests ./internal/cli,./cmd/sfw > mut-cli.txt
grep -H '^killed' mut-*.txt; grep -h '^SURVIVED' mut-*.txt
# recheck survivors against full suites (code must be unchanged since the run):
mut -pkgs ./pkg/api -tests ./pkg/api,./internal/cli,./internal/actiontest -retest mut-deps.txt
```

Add `-race` to `-goflags` only on linux/amd64 (cgo is switched on for it).
Re-running a group after edits: start fresh, since `-retest` matches by
file:line.

## Known limitations (documented in README)

- deps diff disables cgo; a dependency package with no Go files left
  without cgo fails the whole command. C code is hashed, not analyzed.
- Under the sandbox, a local `replace` outside the inputs' module/.git
  roots is not mounted; `--no-sandbox` works.
- Reach analysis does not follow interface or dynamic calls.

## Environment gotchas

- `pkill -f`/`pgrep -f` match your own shell: bracket the pattern
  (`[t]ools/mutate`) and kill by PID.
- The module cache is read-only: test helpers chmod it before cleanup.
- Overlays under GOMODCACHE are refused by the go command;
  `GOTOOLCHAIN=local` makes a newer `go` line in go.mod fail.
- Topology tests load all cases of a test in one go/packages call
  (`signals_test.go: functions/topologies`); keep it that way, since
  per-case loads made mutation runs 8× slower.
