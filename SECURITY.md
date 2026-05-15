# Security Policy — Nulkratos-Core

## Supported Versions

| Version | Supported |
|---|---|
| Live at nulkratos-core.web.app | ✅ Active |

## Reporting a Vulnerability

Nulkratos-Core is a zero-knowledge encrypted messenger. Security is the entire point.
If you find a vulnerability — however small — please report it responsibly.

**Email:** nulkratos@gmail.com  
**Response time:** Within 72 hours  
**Disclosure policy:** We ask for 14 days to patch before public disclosure

### What to include in your report

- Description of the vulnerability
- Steps to reproduce
- Which component is affected (crypto, UI, Firebase rules, etc.)
- Potential impact
- Suggested fix if you have one

### What we consider in scope

- Cryptographic implementation weaknesses
- Key derivation or storage issues
- Firebase security rules bypasses
- Authentication or PIN verification bypasses
- Cross-channel linkage or metadata leakage
- Page Integrity verifier weaknesses
- XSS or code injection in the app

### What we consider out of scope

- Attacks that require physical access to the victim's unlocked device
- Social engineering attacks
- Attacks on Firebase infrastructure itself (report to Google)
- Denial of service against the Firebase backend

### Responsible Disclosure

We commit to:
- Acknowledging your report within 72 hours
- Keeping you informed of our progress
- Crediting you in release notes (if you want credit)
- Not taking legal action against good-faith security researchers

Thank you for helping keep Nulkratos-Core users safe.

© 2025 Nulkratos-Core
