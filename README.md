# Semantic Firewall

**Detect logic corruption that bypasses code reviews.**

[![Go Reference](https://pkg.go.dev/badge/github.com/BlackVectorOps/semantic_firewall.svg)](https://pkg.go.dev/github.com/BlackVectorOps/semantic_firewall)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Marketplace](https://img.shields.io/badge/Marketplace-Semantic%20Firewall-blue.svg)](https://github.com/marketplace/actions/semantic-firewall)
[![Semantic Check](https://github.com/BlackVectorOps/semantic_firewall/actions/workflows/semantic-check.yml/badge.svg)](https://github.com/BlackVectorOps/semantic_firewall/actions/workflows/semantic-check.yml)

---

Semantic Firewall generates deterministic fingerprints of your Go code's **behavior**, not its bytes. It uses **Scalar Evolution (SCEV)** analysis to prove that syntactically different loops are mathematically identical, and a **Semantic Zipper** to diff architectural changes without the noise.

---

## Quick Start

```bash
# Install
go install github.com/BlackVectorOps/semantic_firewall/cmd/sfw@latest

# Fingerprint a file
sfw check ./main.go

# Semantic diff between two versions
sfw diff old_version.go new_version.go
```

**Check Output:**
```json
{
  "file": "./main.go",
  "functions": [
    { "function": "main", "fingerprint": "005efb52a8c9d1e3..." }
  ]
}
```

**Diff Output (The Zipper):**
```json
{
  "summary": {
    "semantic_match_pct": 92.5,
    "preserved": 12,
    "modified": 1
  },
  "functions": [
    {
      "function": "HandleLogin",
      "status": "modified",
      "added_ops": ["Call <log.Printf>", "Call <net.Dial>"],
      "removed_ops": []
    }
  ]
}
```

---

## Why Use This?

**"Don't unit tests solve this?"** No. Unit tests verify *correctness* (does input A produce output B?). `sfw` verifies *intent* and *integrity*.

- A developer refactors a function but secretly adds a network call → **unit tests pass, `sfw` fails.**
- A developer changes a `switch` to a Strategy Pattern → **`git diff` shows 100 lines changed, `sfw diff` shows zero logic changes.**

| Traditional Tooling | Semantic Firewall |
|---------------------|-------------------|
| **Git Diff** — Shows lines changed (whitespace, renaming = noise) | **sfw check** — Verifies control flow graph identity |
| **Unit Tests** — Verify input/output (blind to side effects) | **sfw diff** — Isolates actual logic drift from cosmetic changes |

**Use cases:**
- **Supply chain security** — Detect backdoors like the xz attack that pass code review
- **Safe refactoring** — Prove your refactor didn't change behavior
- **CI/CD gates** — Block PRs that alter critical function logic

---

## CI Integration: Blocker & Reporter Modes

`sfw` supports two distinct CI roles:

1. **Blocker Mode:** When a PR claims to be a refactor (via title or `semantic-safe` label), `sfw` enforces strict semantic equivalence. Any logic change fails the build.

2. **Reporter Mode:** On feature PRs, `sfw` runs a semantic diff and generates a drift report (e.g., "Semantic Match: 80%"), helping reviewers focus on the code where behavior actually changed.

### GitHub Action (Easiest)

Drop this into your workflow for **Blocker Mode**—enforces semantic immutability on every PR:

```yaml
- uses: BlackVectorOps/semantic_firewall@v1
  with:
    path: './'
    go-version: '1.24'
```

> **Note:** The Marketplace Action runs `sfw check` (Blocker Mode). For semantic diff reports (Reporter Mode), use the CLI configuration below.

### Advanced: Full Workflow with Reporter Mode

```yaml
name: Semantic Firewall

on:
  pull_request:
    branches: [ "main" ]
    types: [opened, synchronize, reopened, labeled]

jobs:
  semantic-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Install sfw
        run: go install github.com/BlackVectorOps/semantic_firewall/cmd/sfw@latest

      - name: Determine Mode
        id: mode
        run: |
          if [[ "${{ contains(github.event.pull_request.labels.*.name, 'semantic-safe') }}" == "true" ]] || \
             [[ "${{ contains(github.event.pull_request.title, 'refactor') }}" == "true" ]]; then
            echo "mode=BLOCKER" >> $GITHUB_OUTPUT
          else
            echo "mode=REPORTER" >> $GITHUB_OUTPUT
          fi

      - name: Run Blocker Check
        if: steps.mode.outputs.mode == 'BLOCKER'
        run: sfw check ./

      - name: Run Reporter Diff
        if: steps.mode.outputs.mode == 'REPORTER'
        run: |
          BASE_SHA=${{ github.event.pull_request.base.sha }}
          git diff --name-only "$BASE_SHA" HEAD -- '*.go' | while read file; do
            [ -f "$file" ] || continue
            git show "$BASE_SHA:$file" > old.go 2>/dev/null || touch old.go
            sfw diff old.go "$file" | jq .
            rm old.go
          done
```

---

## Library Usage

```go
import semanticfw "github.com/BlackVectorOps/semantic_firewall"

src := `package main
func Add(a, b int) int { return a + b }
`

results, err := semanticfw.FingerprintSource("example.go", src, semanticfw.DefaultLiteralPolicy)
if err != nil {
    log.Fatal(err)
}

for _, r := range results {
    fmt.Printf("%s: %s\n", r.FunctionName, r.Fingerprint)
}
```

---

## Technical Deep Dive

<details>
<summary><strong>Click to expand: SCEV & The Zipper</strong></summary>

### How It Works

1. **Parse** — Load Go source into SSA (Static Single Assignment) form
2. **Canonicalize** — Normalize variable names, branch ordering, loop structures
3. **Fingerprint** — SHA-256 hash of the canonical IR

The result: semantically equivalent code produces identical fingerprints.

### Scalar Evolution (SCEV) Analysis

Standard hashing is brittle—changing `for i := 0` to `for range` breaks the hash. `sfw` solves this with an SCEV engine (`scev.go`) that algebraically solves loops:

- **Induction Variable Detection:** Classifies loop variables as Add Recurrences: $\{Start, +, Step\}$
- **Trip Count Derivation:** Proves that a `range` loop and an index loop iterate the same number of times
- **Loop Invariant Hoisting:** Invariant expressions (e.g., `len(s)`) are virtually hoisted, so manual optimizations don't alter fingerprints

**Result:** Refactor loop syntax freely. If the math is the same, the fingerprint is the same.

### The Semantic Zipper

When logic *does* change (e.g., architectural refactors), fingerprint comparison fails. The Zipper algorithm (`zipper.go`) takes two SSA graphs and "zips" them together starting from function parameters:

- **Anchor Alignment:** Parameters and free variables establish deterministic entry points
- **Forward Propagation:** Traverses use-def chains to match semantically equivalent nodes
- **Divergence Isolation:** Reports exactly what changed (e.g., "added `Call <net.Dial>`, preserved all assignments")

**Result:** A semantic changelog that ignores renaming, reordering, and helper extraction.

### Security Hardening

- **Cycle Detection:** Prevents stack overflow DoS from malformed cyclic graphs
- **IR Injection Prevention:** Sanitizes string literals and struct tags to prevent fake instruction injection
- **NaN-Safe Comparisons:** Limits branch normalization to integer/string types to avoid floating-point edge cases

</details>

---

## License

MIT License — See [LICENSE](LICENSE) for details.
