# ⬡ Nulkratos-Core

**Zero-knowledge encrypted messenger. No app. No account. No phone number. Runs in your browser.**

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Live](https://img.shields.io/badge/Live-nulkratos--core.web.app-00f5ff)](https://nulkratos-core.web.app)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-00ff87)](https://nulkratos-core.web.app)
[![KDF](https://img.shields.io/badge/KDF-Argon2id%2064MB-00ff87)](https://nulkratos-core.web.app)
[![Zero Knowledge](https://img.shields.io/badge/Architecture-Zero--Knowledge-00f5ff)](https://nulkratos-core.web.app)

---

> **⚠️ COPYRIGHT NOTICE — READ BEFORE ANYTHING ELSE**
> This repository is published for **transparency and security auditing only**.
> Deploying, hosting, redistributing, or forking this software is **strictly prohibited**.
> The only authorized instance is **[https://nulkratos-core.web.app](https://nulkratos-core.web.app)**.
> See [LICENSE](LICENSE) for full terms. Violations will be pursued under copyright law.

---

## What is Nulkratos-Core?

Nulkratos-Core is a browser-based zero-knowledge encrypted messenger. Two people can communicate privately using nothing but a shared **Channel ID** and a **6-digit PIN** — agreed out-of-band. No account creation, no phone number, no email, no app install, no identity of any kind.

Every message is encrypted inside your browser before it touches the internet. The server — Google Firebase Firestore — acts as a blind relay. It physically cannot read your messages. Neither can we.

**Use it now:** [https://nulkratos-core.web.app](https://nulkratos-core.web.app)

---

## Why This Exists

Every other private messaging app requires something that links to your identity:

| App | Requires | Anonymous? |
|---|---|---|
| Signal | Phone number | ❌ |
| Telegram | Phone number | ❌ |
| WhatsApp | Phone number | ❌ |
| Session | App install + account ID | Partial |
| SimpleX | App install | Partial |
| **Nulkratos-Core** | **Nothing** | **✅ Fully** |

---

## Security Architecture

### Key Derivation
```
PIN + Channel ID
      │
      ▼
 Argon2id (64MB RAM, 3 iterations)
      │
      ├──► Main AES Key (via HKDF)
      │         └──► Encrypts sender names
      │
      └──► Ratchet Material (via HKDF)
                └──► Per-message sub-keys (HKDF chain)
```

### Per-Message Encryption
```
Message Text
     │
     ▼
Pad to 512-byte blocks  ← hides message length
     │
     ▼
AES-256-GCM (unique sub-key per message index)
     │
     ▼
+ Random 96-bit IV
+ Bucketed timestamp ±5 min
+ 2–5 random decoy fields
+ Mixed with chaff messages
     │
     ▼
Stored in Firestore (indistinguishable from noise)
```

### What Firestore Sees

| Field | Value | Readable? |
|---|---|---|
| `channel_id` (doc path) | SHA-256 hash | ❌ |
| `message.c` | AES-256-GCM ciphertext | ❌ |
| `message.i` | Random 96-bit IV | ❌ |
| `sender.sc/si` | Encrypted sender name | ❌ |
| `_bt` | Bucketed timestamp ±5min | ❌ |
| `_chaff` | Dummy messages mixed in | ❌ |
| `createdBy` | Ephemeral per-channel random ID | ❌ |
| `createdAt` | Bucketed timestamp ±5min | ❌ |
| `lastSeen` | Bucketed timestamp ±5min | ❌ |
| `pinArgon2` | Argon2id hash | ❌ |
| Names / Message content | Never stored | ❌ |

**The server is a blind relay. Every field is either encrypted, hashed, or noise.**

---

## Security Features

- 🔑 **Argon2id key derivation** — 64MB memory-hard, 3 iterations. Brute-force is computationally infeasible.
- 🔒 **AES-256-GCM** — authenticated encryption. Tampering is detected and rejected.
- ⚙️ **HKDF forward-secret ratchet** — every message uses a unique derived sub-key. Compromising one message reveals nothing about others.
- 👻 **Chaff injection** — random dummy messages sent at unpredictable intervals. Traffic analysis reveals nothing.
- 🕐 **Timestamp blinding** — all timestamps bucketed to ±5 minute windows. Exact activity timing is hidden.
- 🎭 **Decoy fields** — 2–5 random encrypted fields per message obscure message structure.
- 🛡️ **Page Integrity verifier** — SHA-256 hash of the full app source. Both parties can verify they're running the same unmodified code.
- 🔐 **Non-extractable CryptoKey** — derived keys are marked non-extractable in WebCrypto. JavaScript cannot read them back out.
- 🧹 **Auto session lock** — keys wiped from memory on tab hide or lock.
- 📱 **Zero install** — runs in Chrome, Firefox, Safari, Edge, and Tor Browser.

---

## How To Use

### Starting a Channel
1. Go to [https://nulkratos-core.web.app](https://nulkratos-core.web.app)
2. Click **Create New Channel**
3. Enter a unique Channel ID, your name, your contact's name, and choose a 6-digit PIN
4. Share the Channel ID with your contact (it's not secret)
5. Share the PIN through a **separate, trusted channel** — face-to-face or phone call. Never digitally.

### Joining a Channel
1. Go to [https://nulkratos-core.web.app](https://nulkratos-core.web.app)
2. Enter the Channel ID, your name, and the PIN
3. Click **Enter Secure Channel**

### Maximum Privacy
- Use **Tor Browser** for full IP anonymisation
- Stack with a **no-log VPN** for additional network-layer privacy
- Use **private/incognito** browsing mode
- Verify the **Page Integrity hash** matches your contact's hash (⋯ menu → Page Integrity)
- Share Channel ID and PIN **out-of-band** — never over the channel you're trying to protect

---

## Browser Requirements

| Requirement | Minimum |
|---|---|
| Browser | Chrome 90+, Firefox 88+, Safari 15+, Edge 90+ |
| WebCrypto API | Required (all modern browsers) |
| JavaScript | Required |
| RAM | 256MB free (Argon2id uses 64MB per login) |
| Connection | Any speed |

---

## Security Audit

This repository is published specifically to allow independent security auditing of the cryptographic implementation. If you find a vulnerability:

**Report to:** nulkratos@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will respond within 72 hours and credit responsible disclosures.

---

## Frequently Asked Questions

**Can you read my messages?**
No. All encryption happens in your browser. Your PIN and derived keys never leave your device. We receive only AES-256-GCM ciphertext — mathematically impossible to decrypt without your PIN.

**What if I forget my PIN?**
Your messages are permanently unrecoverable. The PIN is the only key. There is no reset, no recovery, no backdoor. This is by design.

**Is this open source?**
The source is published here for transparency and security auditing. However, deploying, redistributing, or forking is not permitted. See [LICENSE](LICENSE).

**Why not make it fully open source?**
Allowing deployment means users could be directed to malicious clones. The Page Integrity verifier only works as a trust anchor if there is one canonical deployment. Full open-source deployment rights would undermine that guarantee.

**Can I self-host it?**
No. See [LICENSE](LICENSE). The only authorized instance is [https://nulkratos-core.web.app](https://nulkratos-core.web.app). Self-hosting a modified version could introduce backdoors — use the Page Integrity verifier to confirm you're on the real app.

---

## Stack

- **Cryptography:** WebCrypto API (native browser), argon2-browser (WASM)
- **Database:** Google Firebase Firestore (blind relay — sees only ciphertext)
- **Hosting:** Firebase Hosting
- **Frontend:** Vanilla JS ES Modules, no frameworks
- **Fonts:** Google Fonts (Share Tech Mono, Exo 2, Rajdhani)

---

## Legal

© 2025 Nulkratos-Core. All Rights Reserved.

This software is proprietary. See [LICENSE](LICENSE) for complete terms.

Deploying, redistributing, or forking this software without written permission is a copyright violation and will result in DMCA takedown notices.

The only authorized deployment: **[https://nulkratos-core.web.app](https://nulkratos-core.web.app)**

Contact: nulkratos@gmail.com
