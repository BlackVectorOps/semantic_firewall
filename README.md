# Semantic Attestation: A Deterministic Approach to Supply Chain Integrity

**Version:** 0.2.0
**Author:** Kyle McAllister
**Date:** January 10, 2026

## Abstract

Modern software supply chain security relies heavily on cryptographic signatures that verify **provenance** (who signed it) but fail to verify **intent** (what the code actually does). This fragility allows malicious actors to introduce subtle logic corruption that bypasses traditional diff reviews and signature checks. This paper introduces the **Semantic Attestation Authority (SAA)**, a framework that utilizes Static Single Assignment (SSA) canonicalization and Scalar Evolution (SCEV) analysis to generate deterministic fingerprints of software logic. We demonstrate that this method can mathematically attest to the semantic equivalence of refactored code while detecting logic corruption, effectively decoupling software identity from its syntactic representation.

## 1. Introduction: The Limits of Syntactic Verification

Current integrity mechanisms (e.g., GPG, Sigstore) operate strictly at the byte level. If a developer changes a variable name from `key` to `entropy`, the binary hash changes entirely. This fragility means that "security" is often synonymous with "bit-perfect reproduction." This is insufficient for detecting subtle logic tampering—such as the `xz` backdoor—where the syntax is valid, the signature is valid, but the semantics are malicious.

This paper proposes a shift from **Syntactic Integrity** to **Semantic Integrity**, defined as:

> *The property whereby two programs are considered identical if and only if their control flow graphs and data dependencies produce the same side effects, regardless of register allocation, variable naming, or loop structure.*

## 2. Architecture of the Semantic Firewall

The Semantic Firewall operates on a three-stage pipeline designed to distill raw source code into a canonical Intermediate Representation (IR). By operating on the SSA graph rather than the AST, we eliminate syntactic noise early in the pipeline.

### 2.1 The Canonicalization Engine
The core of the system is a deterministic transformation engine (`canonicalizer.go`) that normalizes Go source code.

* **Virtual Control Flow:** We utilize a virtualized representation of basic blocks to enforce deterministic ordering of independent branches. This mitigates non-determinism in compiler block ordering without mutating the underlying SSA graph, preserving thread safety during analysis.
* **Register Renaming:** All SSA values are mapped to canonical names (e.g., `v0`, `v1`, `p0`) based on topological order. This eliminates noise from developer naming choices, ensuring that `func(a int)` and `func(b int)` produce identical IR.
* **Instruction Normalization:** Operations are standardized to handle commutativity. Binary operations like `ADD` and `MUL` are sorted by the hash weight of their operands, ensuring $a + b$ fingerprints identically to $b + a$.

### 2.2 Scalar Evolution (SCEV) Analysis
To handle loop variance (e.g., `for i := 0; i < n` vs `for range`), we implement a Scalar Evolution analysis engine (`scev.go`) capable of solving loop trip counts symbolically.

* **Induction Variable Detection:** The engine identifies loops and classifies induction variables into basic Add Recurrences: $\{Start, +, Step\}$.
* **Trip Count Derivation:** We statically compute loop trip counts using ceiling division formulas (e.g., $\lceil(Diff + Step - 1) / Step\rceil$). This allows the system to verify that two loops iterate the same number of times regardless of their increment strategy (e.g., `i++` vs `i+=2`).
* **Loop Invariant Code Motion:** Invariant calls (such as `len(s)` inside a loop) are virtually hoisted to the pre-header, ensuring that optimization levels or manual hoisting do not alter the fingerprint.

## 3. Security & Determinism

To prevent the Attestation Authority itself from becoming an attack vector, strictly enforced defensive measures are integrated into the core pipeline.

### 3.1 Cycle Detection & DoS Prevention
Recursive analysis of logic graphs creates a risk of Stack Overflow Denial of Service (DoS) attacks via malformed cyclic graphs. I have implemented a robust renamer that detects recursion cycles during stringification (`stack[v]`), ensuring the analysis terminates even when processing hostile, self-referential code structures.

### 3.2 IR Injection Prevention
A unique class of vulnerabilities involves injecting fake IR instructions via string literals or struct tags. The Semantic Firewall sanitizes all type definitions and string constants (using quoted literals `%q`), preventing attackers from "breaking out" of the data layer to inject malicious control flow instructions into the canonical output.

### 3.3 Logic Inversion Protection
When normalizing control flow (e.g., converting `a >= b` to `a < b`), strict type checking is enforced. We limit virtual branch swapping to integers and strings. This prevents semantic corruption in floating-point operations where $NaN$ behavior makes standard inversion unsafe due to unordered comparison rules (i.e., `!(a < b)` does not imply `a >= b` if `a` is `NaN`).

## 4. Case Study: Semantic Attestation

 The framework's capability is verified using a controlled reference implementation of a sensitive data wipe function.

1.  **Reference Implementation:** The "Golden Logic."
2.  **Refactored Implementation:** Variables renamed (`key` $\rightarrow$ `entropy`), loops altered (`range` $\rightarrow$ `index`), and helper functions extracted.
3.  **Compromised Implementation:** Data wipe logic removed, but the function signature and control flow structure were superficially maintained.

**Results:**
* The **Refactored** version produced a hash identical to the Reference version: `005efb52...`.
* The **Compromised** version produced a divergent hash: `82281950...`.

This confirms the system successfully decoupled syntax from semantics, allowing for automated acceptance of safe refactors while instantaneously flagging genuine logic tampering.

## 5. Conclusion

The Semantic Attestation Authority provides a necessary layer of verification above standard cryptographic signing. By fingerprinting the *behavior* of code rather than its *bytes*, organizations can automate the acceptance of non-functional refactors while creating a robust "Semantic Firewall" for the software supply chain.
