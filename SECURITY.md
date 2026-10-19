# Security Policy


## Supported Versions


I adhere to Semantic Versioning. Fixes, security fixes included, ship only in the newest release of the current major version. Nothing is backported to an older release or an older major: upgrade to the newest 7.x release to get a fix.


| Version | Supported | Status | End of support |
| :--- | :---: | :--- | :--- |
| 7.x | :white_check_mark: | **Active Support** in the newest 7.x release. Diff and deletion signals, `sfw deps diff`, batch diff, source loader and type cache, LLM audit, Malware Scanner, PebbleDB, Sandbox, Entropy Engine, GitHub Action. | At least 12 months after 8.0.0 is released |
| 6.x | :warning: | **Advisories only, no fixes.** Upgrade to 7.x; the module path is now `/v7`. | 2027-10-18 |
| 5.x | :warning: | **Advisories only, no fixes.** Upgrade to 7.x; the module path is now `/v7`. | 2027-10-18 |
| 1.x to 4.x | :x: | **End of Life.** Not supported. | Ended |
| < 1.0 | :x: | **End of Life.** Pre-release versions are not supported. | Ended |


### End-of-support policy

- When a new major version is released, the previous one moves to advisories only for at least 12 months from that release. A critical bug that affects it is announced in an advisory that names it, and the fix ships in the new major.
- Every end-of-support date is announced in the table above at least 12 months before it, and is never moved earlier. A date can move later.
- A version in advisories-only support gets no fixes, so a critical bug stays open in it and a CI gate still running it can pass changes the newest release flags. Past its end-of-support date it gets no advisories either. Upgrade.


### What counts as critical

A bug is critical when it lets a change through a check the version already ships, with no error:
- **Fail-open diffs:** `sfw diff` or `sfw check` drops, hides or misattributes a changed function, or reports it as unchanged or removed when it is not.
- **Bypass of a shipped signal:** a change that a signal of that version is documented to score (a new capability call, a removed check, obfuscation) scores lower than its rule says.
- **Sandbox escape:** analyzed code runs or writes outside the gVisor sandbox's mounts.
- **Action passes on a failure:** the GitHub Action reports success when `sfw` failed or analyzed nothing.

A critical bug gets a fix in an out-of-band release of the newest 7.x, and an advisory naming every affected version, including those in advisories-only support. False positives, crashes that fail the run, and speed fixes are not critical.


## Reporting a Vulnerability


I take the security of the Semantic Firewall (`sfw`) extremely seriously. If you discover a vulnerability in the canonicalizer, the SCEV analysis engine, the fingerprinting logic, the risk scoring, the dependency analysis, the sandbox or the LLM audit, please follow the procedure below.


### **DO NOT open a public GitHub Issue**


Publicly disclosing a vulnerability can put the supply chain of users relying on `sfw` at risk.

Also it's rude. Don't be rude.


### Preferred Method: Private Vulnerability Reporting

Please use GitHub's **Private Vulnerability Reporting** feature. This is the fastest way to reach me and keeps the report secure.


1. Go to the [Security tab](https://github.com/BlackVectorOps/semantic_firewall/security) of this repository.

2. Click on "Report a vulnerability".

3. Provide details regarding the exploit vector (e.g., a specific Go construct that creates a fingerprint collision or bypasses logic verification).


### Alternative Method: Email

If you cannot use GitHub reporting, you may email me directly.


* **Email:** blackvectorops@protonmail.com


## What Qualifies as a Vulnerability?


The Semantic Firewall is designed to detect logic changes. A vulnerability in this context generally falls into one of these categories:


1.  **Semantic Collision:** You can demonstrate two pieces of Go code with **divergent business logic** that produce the **same** semantic fingerprint.

    * *Note:* Two pieces of code with the *same* logic but different syntax (e.g., `for` vs `range`) producing the same fingerprint is a feature, not a bug.

2.  **Canonicalizer Injection:** You can inject IR instructions or break out of the string/type sanitization layer to alter the resulting hash.

3.  **Detection Bypass:** A change that removes a guard or a verification check, weakens a TLS, cookie or SSH setting, or adds a capability call, and that `sfw diff` scores as low risk where the README says it should not. Examples: a deleted guard that does not raise `Unguarded`, or a check swapped for a no-op that reads as `ReplacedCheck`.

4.  **Dependency Blind Spot:** A dependency change that `sfw deps diff` neither diffs nor lists under `unanalyzed`. Examples: code reachable through a file, build tag, `go.work` entry or vendored copy that the tool silently skips.

5.  **Sandbox or Cache Escape:** Analyzed code that runs, writes outside its mounts, or writes a persistent type cache entry from inside the gVisor sandbox, or a cache entry that `sfw` accepts for a different source.

6.  **Audit Injection:** Source, a commit message or a tool result that gets `sfw audit` to return `MATCH` for a flagged change by passing instructions to the model through the prompt-injection sentinel and the nonce fences.

Known limits documented in the README (functions moved across files, interface and dynamic calls in reach analysis, errors inside a dependency's function bodies) are not vulnerabilities on their own. A bypass that builds on one of them still qualifies.


## Response Timeline


As a solo maintainer, I aim to prioritize security reports above all other issues.


* **Acknowledgment:** I aim to acknowledge reports within 24 hours.

* **Triage:** I will assess the severity and impact within 5 business days.

* **Patch:** Fixes will be released as soon as they are verified and pass regression testing.


## Disclosure Policy


I follow a 90 day responsible disclosure timeline. I ask that you allow me reasonable time to patch the vulnerability before public disclosure. In return, I will:


* Credit you in the release notes and security advisory (unless you prefer anonymity).

* Keep you updated on the status of the fix.
