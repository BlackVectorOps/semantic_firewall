# Handoff: semantic_firewall, branch `ccr-33d08e80-zi15zu` (PR #39)

Written at the end of a long session for the next agent. Read all of it
before touching anything. **Delete `.claude/handoff/` before PR #39 merges.**

## Where things stand (session 3, head `c4f655f`)

- Repo `BlackVectorOps/semantic_firewall`, Go module `.../v5`, Go 1.26.3.
- Work branch `ccr-33d08e80-zi15zu`, draft **PR #39** (title still says WIP).
  Session 2 worked on `ccr-2e562674-eku5cl` first, opened PR #40, then the
  user said to move to #39: #39's branch was fast-forwarded and #40 closed.
  If your session is assigned another branch, ask before pushing to #39's.
- CI green on every commit through `c4f655f`; PR mergeable, no reviews.
  Working tree clean. Pair 6 is mid-mutation (see "Pair 6" below):
  resume there.
- Session 3 (this one): noise evaluation, loader speed (own design, the
  user's request), persistent type cache, import pruning, `go.work`
  honored, pairs 4 and 5. Details in "Loader speed work", "Workspaces",
  "Pair 4" and "Pair 5" below.
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

Mutation status: pairs 1, 2 and 3 closed. `deps.go` (575 mutants on
`dea05fc`): every survivor is in the accepted classes below.

Next, in order (the user asked "are we ready for review or merge"; the
answer was: not until these four pairs are done):
1. Done in session 3: pair 4 `api/risk.go`+`api/batch.go` (`4e6f2a4`,
   `19ae6d8`, `473c660`, `36a68c9`; see "Pair 4" below).
2. Done in session 3: pair 5 `diff/loader.go`+`purge.go` (`f2fb53c`,
   `49f8c2b`, `40dbfdc`; see "Pair 5" below). Open for the user: whether
   to code the constant-len divergence (documented, not fixed).
3. Pair 6 `api/diff.go`+`cli/diff_logic.go`: fixes and tests pushed,
   mutation retest unfinished (see "Pair 6" below; finish it first). Then
   pair 7
   `diff/fingerprinter.go`+`diff/package_functions.go` (fingerprinter's
   session-3 code FingerprintPackagesWhere, functionPosition,
   WorkspaceFile/HardenedEnvFor is closed) and pair 8
   `internal/cli/deps.go`+`cmd/sfw/main.go` (the user split the old
   catch-all "pair 7 the rest" into these two).
3. Done in session 2: the noise evaluation. `eval_compare.py` (several sfw
   builds on the same pairs per commit) and `analyze.py` here; run with Go
   >= the repos' go lines first on PATH (the container's default `go` was
   1.24, which broke half the loads; GOTOOLCHAIN=local pins PATH's go).
   Result on 776 loadable commits of the 10 repos: v5.2.0 16 flagged
   commits, branch 34 before the fixes in `fffe517`, 20 after (46
   alerts), every alert judged in that commit message. ErrorExits stays
   a label. Remaining branch false positives: functions moved across
   files (batch mode could pair them; not built).
4. Decided in session 3: `go.work` is honored (see Workspaces below).
5. PR #39's title and body were refreshed in session 3 (the user asked);
   keep its "Remaining" list current as pairs close. It stays a draft
   until the user says otherwise. Before merge: delete `.claude/handoff/`.
   At release the user bumps `SFW_VERSION`/README pins and publishes the
   tag.
6. Deferred, reported to the user: share the check-helper search across
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
(`SFW_PARITY_CORPUS=<roots>` runs the corpus check, which also loads every
file of each module as one batch).

Loader speed work (session 3; the user asked for our own design, not
another model's). Measured on a 62-file pocketbase batch
(`scratchpad/bench`, `-batch pbb.pairs`) and single diffs, outputs
byte-identical to the pre-change build each step:
- `loadMetadata`: go/packages ran one `go list -deps` per `file=` query,
  serially (its TODO "one query per directory"); now one run over the
  queried directories, roots picked as go/packages picks them, per-file
  fallback where it would build an ad-hoc package. Batch 13.98 s -> 3.3 s.
- `inFile` resolved symlinks per function per file (2.7 s CPU);
  `pathResolver` memoizes.
- `FingerprintPackagesWhere`: only the diffed files' functions are
  canonicalized. Batch -> 1.85 s (1.2 s warm in-process).
- Parse ahead: keys from metadata first, then every root file and
  uncached dependency parses while imports type-check; a shared dep's
  parse lives in its `depCache` entry (`sync.Once`). Single pbs diff
  1.02 -> ~0.85 s; batch is CPU-bound, unchanged.
Accepted equivalent mutants: parse-ahead scheduling (loader.go
`l.parseAhead(roots)` and its switch cases; only speed changes), `take`
dropping the syntax (memory), the `strictMode` literal `false` in
api/diff.go and api/batch.go (strict mode only panics on an SSA
instruction type the canonicalizer does not handle; it handles all).
Persistent type cache (`pkg/diff/typecache.go`, user approved the
design: "local run gets the cache with sfw writing the entries"):
content-addressed entries (executable hash, path/name/sizes/Go
version/GODEBUG, file SHA-256s, import keys) of shared dependencies,
gcexportdata payload + SHA-256, decoded against the package's transitive
imports and rejected if it refers to anything else. Never stores a
package with errors or an ill-typed import (a bug the tests caught: go/types
reports nothing for uses of invalid types). Phases in `prepareStored`:
digests in parallel, keys, entries fetched in parallel (a miss starts
parsing). Policy (`internal/cli/typecache.go`, called from main): on/off
via SFW_TYPE_CACHE, default on only at a terminal outside CI; gVisor
workers see it read-only at /sfwtypes (`internal/sandbox`), so sandboxed
code can never write an entry. Warm single pbs diff ~30% faster (CLI
1.7 s -> 1.19 s on the post-restart VM); outputs identical in every mode.
Accepted mutants: read's length boundary (an empty payload never
decodes), touch boundary, the export error check (gcexportdata.Write does
not fail even on invalid types), Close-error handling; CreateTemp failure
is tested only as non-root (CI).
Import pruning (`neededImports`, `declaredImports`, `pruneImports`): a
dependency loads only the imports its purged declarations name; parsing
is discovery-driven (parseAhead covers roots only). gin single diffs ~19%
faster, pocketbase ~4%, batch ~3%; outputs identical; corpus parity
holds. Divergence (README): a package only a dependency's bodies import
cannot make roots ill-typed. Cache entries (format 2) store the needed
list. Two races found and fixed (decode's view = needed closure only;
loadSource waits for prefetches). Mutation over typecache.go + loader.go
vs f9412f4: remaining survivors are all speed-only or equivalent:
loader.go parseAhead's unsafe check, shared-vs-own parse of needed,
neededView's visited/unsafe skip, prepareStored's filter and phases,
Once-guarded digest/key/fetch calls already done, decode of a nil
payload, releasing a payload; typecache.go executableID internals,
digest read error, a body without its NUL (nil payload anyway),
CreateTemp as root, Close/Rename chaining, removing an already renamed
temp file, length/touch/trim boundaries.
Workspaces (session 3, `46a2a59`, `a6e1702`, `9f23f48`; the user chose
to honor go.work): `diff.WorkspaceFile` finds the governing go.work as the
go command does but stops at the first `.git` entry (the Action's base
worktree sits inside the head's checkout); every loader env passes it as
GOWORK (`HardenedEnvFor`). deps diff treats the workspace's other modules
as local replacements named `use ./dir` from the go.work, so a `use` of
a directory taking a dependency's path reads `v1.0.0 -> use ./shadow`;
a `go work vendor` tree loads from the workspace vendor dir.
`SandboxExec` mounts the go.work's directory. The Action's deps mode now
also triggers on go.work/go.work.sum and runs `go mod download` with the
same bounded search (unbounded, the base download found the head's
go.work, fetched nothing, and deps diff failed; an Action test proves
it). Accepted mutants: WorkspaceFile's Abs error (Getwd), workspacePath's
ToSlash (Linux), SandboxExec's workspace mount forced on (mounts the cwd,
already mounted).
Pair 4 (session 3): the session-2 hunter's reproducers survived in its
worktree; a new hunter found five more. All ten fixed, each with a test
that fails on the old code:
- Unguarded: a new target fires when every old call of its class was
  guarded (guarded exec.Command swapped for unguarded os.StartProcess
  scored 5). A new version past the 2000-block guard limit reports
  GuardsUnknown(target), +10 (padding hid a deleted guard, scored 9).
- raisesTLSVersion excuses a new weak bound only if the lower old bound
  is gone (a second config lowered beside a kept TLS 1.0 one was hidden).
- hmac.Equal <-> subtle.ConstantTimeCompare is the same check.
- Check keys split before type arguments (a generic interface's check
  swapped to a no-op package read as ReplacedCheck, 0).
- equalButFirstCase compares first runes, not bytes (non-ASCII names).
- CalculateTopologyDelta agrees with Diff for added/removed functions
  (addedDelta/removedDelta shared with diff.go).
- batch: a file keeps only its own packages' functions (a //line decoy
  in another package replaced a changed function: the Action uses batch);
  groups also key on the governing go.work (a submodule's .git stops
  Diff's search); a non-disk FileSystem loads each file on its own.
- actiontest now removes its 46 MB sfw build (24 leaked runs filled the
  disk together with the mutation tool's build cache: give mutate its own
  GOCACHE and delete it after each file).
A replay of all 1,950 files (776 commits, 10 repos) through dc19ef3 and
the fixed build is byte-identical: no new alerts. gin's deps upgrade is
identical too (1 alert: go-urn's generated tables as Obfuscation:HIGH).
Mutation (`-base 778bf19^`, whole files, survivors retested on full
suites): accepted equivalents in risk.go: the structural cap boundary
(9 stays 9), `ownModule != ""` forced (no capability key has an empty
package), matchingCheck's "same" flag beside an empty match (the caller
tests the match first), packageBase's `i > 0` (no import path element
starts with ".v"). In batch.go: path de-duplication, the claim and the
workspace memo (speed), `len(wellTyped) > 0` (speed), the Abs fallback
(Getwd), strictMode. Removed as unreachable: guard-map filtering in
withoutModuleTargets, targetPackage (splitCheckKey's package), an origin
walk in inFileOf (every fingerprinted function has its package).
Pair 5 (session 3): purge.go is no longer verbatim x/tools (header says
how). Fixed: a pending "[...]" was forgotten at semicolons inside the
element type's own struct/interface body (also upstream, x/tools
v0.48.0), so a dependency's multi-line `[...]struct{...}{...}` table
became [0]T and a root indexing it was ill-typed; the "[...]" now
records its brace depth. Purged regions keep their line breaks
(dependency errors named wrong lines). loadMetadata lists a batch file by
file when the batched graph has a go list error (a module missing from
the cache got a made-up file and a "redeclared" error). Documented, not
coded (README "Loading", loadSource doc): errors inside a dependency's
composite literals, or in a package only they name, are not reported
(tested); `len`/`cap` of a sized array literal holding a call becomes
constant (contrived: `1 << len([8]int{f()})`), which can fail a constant
check where go/packages loads. Fixing that needs the original source
re-checked with imports pruning dropped: put to the user. Mutation:
purge.go's only survivor is `top < 0` -> `<= 0` (no token at 0); the
changed loader lines all killed. Corpus parity: chi, gin, echo, casbin,
cobra, pocketbase identical (4,753 functions).
Pair 6 (session 3, IN PROGRESS): fixes pushed with failing-on-old tests
(`c9b3c72`, `6043283`, `d7a32ff`, `a2e02a0`, `d949d5b`, `c4f655f`; commit
messages list each): sfw diff "" path is the absent side; functions belong
to the file they are written in (//line ignored, PositionFor(.., false));
declared inits pair by content with their closures (contentGroup);
DiffWithFS uses readDiffInput (Abs fallback); sandbox mounts only existing
inputs, mounts a rootless or linked-out batch input itself, mounts the
go.mod dir; empty diff prints "functions": []; CompareFunctions has one
no-SSA path (NewZipper's error); TestDiff_Summary asserts the whole
summary; fake runsc tests (diff_sandbox_test.go) cover the sandbox branch.
Mutation state when the user stopped the run (re-run with an isolated
GOCACHE, delete it after; -retest only matches unchanged lines):
- diff.go retest (lines < 226, full ./pkg/api suite): 53 mutants, 33
  killed, 20 survived, NOT yet classified: 33 (strictMode), 77 x2, 82 x3,
  83, 85, 114, 118, 135, 136, 141, 160, 161, 165, 176 x2, 179 x2. Judged
  so far: 77/114/118/135/136/160/161 are nil-topology/nil-SSA guards
  (a load never fingerprints a function without blocks: probed);
  82-83 is an unreachable safety net (probed: a same-named callee from
  another package changes the fingerprint, scores 20). 141 (added risk
  exactly 10?), 165, 176, 179 (percent guards: an empty diff with
  total 0 would give NaN under `>=`) need a look or a test.
- Not run yet: diff.go fresh pass over CompareFunctions (`-base a2e02a0`,
  9 mutants); batch.go retest (`-base 6ff3b15 -retest mut6-batch.txt`;
  189-191 now covered by diff_absfs_test/diff_resolve_test, proven by
  hand; 190/191 kill only via the message, the loader also fails closed);
  diff_logic.go retest (27 old survivors, likely killed by d7a32ff);
  sandbox_adapter.go fresh pass (`-base 6ff3b15`, file changed after the
  first run); topology_match/fingerprinter retest (6, likely killed by
  TestContentGroup).
  Full ./pkg/api suite is ~70 s per mutant: the whole retest is 2-3 h.
Then: record accepted equivalents here, update PR body (Testing list,
Remaining), mark pair 6 closed.
Pair 7 (session 4, hunted by the session itself, no sub-agent): three
bugs, each reproduced against both loaders and the go command, fixed with
tests that fail on the old code (TestDiff_FilesOutsideTheHostBuild's new
cases, TestDiff_VendoredModule, TestDiffBatch_OnePairOutsideTheHostBuild,
TestVendorDir, TestFingerprintTree_Vendored, TestFingerprintSource_Vendored,
TestLoadPackagesWithDeps_VendoredModule; TestLoadSource_ErrorParity's
vendored case had asserted the bug and now asserts the load):
- Vendored modules could not be diffed: GetHardenedEnv's
  GOFLAGS=-mod=readonly overrode the go command's default vendor mode, so
  a tree whose deps are only in vendor/ failed with "missing go.sum entry"
  in diff, batch, tree mode and scan (deps diff had its own -mod=vendor).
  `diff.VendorDir(dir)` now implements the go command's rule (vendor dir
  exists; go.mod go >= 1.14, or go.work go >= 1.22 for the workspace's
  vendor dir); HardenedEnvFor appends -mod=vendor; deps.go uses VendorDir
  (it used to key on vendor/modules.txt alone); scan.go uses HardenedEnvFor
  (so it honors go.work too).
- A file the host build excludes that is the only Go file of its
  directory (a windows-only package), or lies outside any module, was
  loaded as go list's ad-hoc `command-line-arguments` package under the
  host GOOS/GOARCH: its platform API undefined, its sizes the host's, and
  the documented retry never ran because packagesContain was true. The
  build configuration is now chosen before the first load. A file with
  siblings in a module was already handled. batch.go excludes ad-hoc
  packages from a group so a one-pair batch equals Diff.
- A `//go:build ignore` script beside a package's files could not be
  diffed at all: `ignore` was supplied as -tags, which breaks the standard
  library (its generators carry it). `ignore` is never a custom tag; a
  file in no configuration's package is loaded alone (pattern = the file
  path), as `go build file.go` builds it.
Not bugs (checked): generic functions/methods and their closures, blank
functions, legacy `// +build` lines, range-over-func closure positions.
Mutation over the pair 7 files: see below (state at handoff time).
Pair 8 (session 4, hunted directly): `sfw deps diff "" .` cleaned "" to
"." and reported the working directory diffed against itself as no change,
exit 0 (a caller whose base-directory variable came out empty would pass
silently). RunDepsDiff and RunDepsDiffLogic now reject an empty directory
(TestRunDepsDiff_EmptyDirectory; the worker case in
TestWorkerDepsAndBatchArgs). Probed and left as is: `sfw check ""` and
`sfw scan ""` act on the working directory (more work, not less); `--`
before the deps diff directories is accepted; the audit's empty commit
message is accepted; a lone `sfw diff <one file>` prints usage.

Next levers, measured: `diffResults` runs pairs serially (0.37 s of the
batch); GC is ~25% of CPU (GOGC=200 gives 5-15%); `BuildSSAFromPackages`
builds root packages one at a time; API-closure import pruning would skip
~45% of dependency packages but only 14-36% of bytes.

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
`ellipsis = false` on `;` and `top < 0`. In `deps.go`: the callee,
direct-target and reach caches; the SSA-build recover; `p.Module != nil`;
max boundaries; `strictMode` (both trees use the same mode); the
`followed` filter where components are built (the merge filters again);
the regular-file fast path of `isRegular`; WalkDir, open and read errors
and `defer Close` (root cannot provoke them); `ParseFile` returning nil
(never, for a file that can be read).

Coverage (user's phone, `-coverpkg=./...`): 68.9% total; branch files
mostly 90–100%. Real gaps to test:
- `topology.IsVerificationCall` 55.6% (ed25519, x509, tls, bcrypt,
  filepath.IsLocal branches) — table test it.
- `api.readDiffInput`: closed in pair 4 (TestDiffBatch_InputRules).
- `diff/loader.go`: `appendLoadError` 62.5%, `hasImportCycle` 82.4%.
- `api.CalculateTopologyDelta`: closed in pair 4.
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
