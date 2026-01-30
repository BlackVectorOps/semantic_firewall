# Security Policy


## Supported Versions


I adhere to Semantic Versioning. Security patches will be backported to the current major version.


| Version | Supported | Status |
| :--- | :---: | :--- |
| 3.0.x | :white_check_mark: | **Active Support.** Malware Scanner, PebbleDB, Sandbox, Entropy Engine. |
| x.x.x | :warning:          | **Maintenance.** Diff/Check features only. |
| < 1.0 | :x: | **End of Life.** Pre-release versions are not supported. |


## Reporting a Vulnerability


I take the security of the Semantic Firewall (`sfw`) extremely seriously. If you discover a vulnerability in the canonicalizer, the SCEV analysis engine, or the fingerprinting logic, please follow the procedure below.


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


The Semantic Firewall is designed to detect logic changes. A vulnerability in this context generally falls into two categories:


1.  **Semantic Collision:** You can demonstrate two pieces of Go code with **divergent business logic** that produce the **same** semantic fingerprint.

    * *Note:* Two pieces of code with the *same* logic but different syntax (e.g., `for` vs `range`) producing the same fingerprint is a feature, not a bug.

2.  **Canonicalizer Injection:** You can inject IR instructions or break out of the string/type sanitization layer to alter the resulting hash.


## Response Timeline


As a solo maintainer, I aim to prioritize security reports above all other issues.


* **Acknowledgment:** I aim to acknowledge reports within 24 hours.

* **Triage:** I will assess the severity and impact within 5 business days.

* **Patch:** Fixes will be released as soon as they are verified and pass regression testing.


## Disclosure Policy


I follow a 90 day responsible disclosure timeline. I ask that you allow me reasonable time to patch the vulnerability before public disclosure. In return, I will:


* Credit you in the release notes and security advisory (unless you prefer anonymity).

* Keep you updated on the status of the fix.
