# Security Policy

## Supported versions

Security fixes are provided for the [latest GitHub Release](https://github.com/hawkeye-Leo/hawkeye-tfe/releases/latest) only.

## Reporting a vulnerability

Email [hawkeye18485@gmail.com](mailto:hawkeye18485@gmail.com) with the subject `[Hawkeye TFE Security]`.

Please do not open public issues for unfixed vulnerabilities.

Include:

- Driver version or Release tag
- Windows version and build number
- Steps to reproduce
- Impact (privilege required, local vs remote, crash vs exploitable behavior)
- Whether the protected path was in use

## Scope

**In scope:** vulnerabilities in Hawkeye TFE that allow privilege escalation, unintended access to plaintext or ciphertext outside the documented protect path, kernel crashes, or deadlocks exploitable by a local user beyond documented research use.

**Out of scope:**

- Use on systems you do not own or are not explicitly authorized to administer
- Claims that the XOR research cipher provides production-grade confidentiality
- Driver load blocked by test signing, Memory Integrity / HVCI, Secure Boot, or similar policy
- Behavior that requires Administrator privileges to install the filter when used as documented

## Process

We acknowledge reports when possible and ship fixes in a future Release. We may credit reporters with their permission.

## Authorized use

Use Hawkeye TFE only on systems you own or are explicitly authorized to administer. This is a research minifilter, not a general-purpose encryption product.
