# cloak — content roadmap

What's shipped, what's specced, and what's queued. Order reflects priority, not
strict sequence — anything in the queued sections can move up if a bundle calls
for it.

## Shipped

| Algorithm | Family | Slug | Lesson |
|---|---|---|---|
| RSA | Asymmetric | `rsa` | `encrypt-decrypt` |
| Hybrid Encryption | Asymmetric | `hybrid` | `kek-pattern` |
| AES | Symmetric | `aes` | `aes-128` |
| Triple DES | Symmetric | `triple-des` | `why-3des` |
| Blowfish | Symmetric | `blowfish` | `feistel-rounds` |
| Twofish | Symmetric | `twofish` | `aes-finalist` |
| HSM | Key management | `hsm` | `key-vaults` |

7 algorithms, 7 lessons, 4 bundles wired into the landing.

## Specced — ready to implement

These 5 specs cover the highest-leverage missing primitives. Each one unlocks
multiple bundles. Specs land first; implementation follows the spec → plan →
subagent-driven pattern used for the prior overnight lessons.

| # | Algorithm | Family | Slug | Why next | Bundles unlocked |
|---|---|---|---|---|---|
| 1 | SHA-256 | Hash (new) | `sha256` | Foundational. Used by HMAC, Ed25519, every PoW chain, every cert fingerprint. | "Hashing for developers" |
| 2 | HMAC | Hash | `hmac` | 50-line lesson that builds on SHA-256. Teaches the MAC concept. Length-extension attack is the pedagogical hook. | extends hashing bundle |
| 3 | X25519 | Asymmetric | `x25519` | Modern key exchange. TLS 1.3, Signal, WireGuard, SSH all use this. | "How TLS 1.3 works", "How WireGuard works" |
| 4 | Ed25519 | Asymmetric | `ed25519` | Modern signatures. SSH, Git, GitHub, blockchains. Faster + simpler than RSA-PSS or ECDSA. | completes TLS/SSH bundles |
| 5 | ChaCha20-Poly1305 | Symmetric | `chacha20-poly1305` | Modern AEAD. The cipher TLS 1.3 picked when AES-GCM doesn't fit (mobile, no AES-NI). Pedagogically cleaner than AES — pure ARX, no S-boxes. | "How TLS 1.3 works", "How WireGuard works" |

Specs live in `docs/superpowers/specs/2026-05-25-*-lesson-design.md`.

After these 5 land, catalog is 12 algorithms. The catalog reaches the point
where the bundles "How TLS 1.3 works" and "How WireGuard works" can ship,
which roughly doubles the landing's narrative coverage.

## Queued — directions for after the next 5

These are the four directions surfaced when picking what to spec next.
Each one is a self-contained batch; pick whichever feels most useful first.

### A. Post-quantum primer

NIST finalized ML-KEM (Kyber) and ML-DSA (Dilithium) in 2024 as the
post-quantum replacements for ECDH and ECDSA. Hash-based signatures
(SPHINCS+ / SLH-DSA) are also a finalist with very different tradeoffs.

| Algorithm | Slug | Why |
|---|---|---|
| Kyber (ML-KEM) | `kyber` | The PQ KEK replacement. Toy lattice with small dimensions. |
| Dilithium (ML-DSA) | `dilithium` | The PQ signature scheme. Same lattice family as Kyber. |
| SPHINCS+ (SLH-DSA) | `sphincs-plus` | Hash-based signatures — Merkle-tree-of-WOTS construction. Beautiful pedagogically; concretizes "why Merkle trees matter" in a way Bitcoin's hand-wave doesn't. |

Bundle unlocked: **"PQ migration primer"** — Kyber → Dilithium with a closing
discussion of hybrid (classical + PQ) deployment strategy. Populates the
currently-empty `pq` family section on the landing.

### B. Attacks & vulnerabilities

Different lesson format from the rest of the site: you *exploit* the algorithm
rather than execute it. Pedagogically the most memorable batch — these explain
WHY the rest of the catalog is designed the way it is.

| Lesson | Slug | Why |
|---|---|---|
| Padding oracle attack (CBC) | `padding-oracle` | Decrypt CBC ciphertext without the key, one byte at a time, by abusing the server's error response. Interactive; user actually runs the attack against a simulated server. |
| ECB penguin | `ecb-penguin` | Visual — encrypt a bitmap of Tux under ECB mode, show that the outline is preserved. The single best 30-second argument against ECB. |
| Length extension | `length-extension` | Forge `H(secret \|\| message \|\| extension)` from `H(secret \|\| message)`. Motivates HMAC retroactively. Could be a sequel to the HMAC lesson once that ships. |
| Bleichenbacher 1998 | `bleichenbacher` | Padding oracle against RSA PKCS#1 v1.5. Why OAEP exists. The pedagogically pure version of "why padding matters." |

Bundle unlocked: **"Why crypto looks weird"** — a tour of attacks that
motivates the design choices in the rest of the catalog.

### C. Modes & KDFs

The practical-developer gap. "How do I hash my users' passwords?" "What mode
do I use with AES?" Most working developers need answers here more than they
need to walk SHA-256.

| Lesson | Slug | Why |
|---|---|---|
| Block cipher modes | `cipher-modes` | ECB → CBC → CTR → GCM in one lesson. Show ECB's failure (penguin), CBC's IV requirement, CTR's parallelism, GCM's AEAD bonus. Could be a sibling lesson to AES rather than a standalone algorithm. |
| PBKDF2 | `pbkdf2` | The first password-hashing function most developers meet. Walks through the iteration story. |
| Argon2 | `argon2` | The modern winner. Memory-hard. Why memory-hardness matters (GPU resistance). |
| HKDF | `hkdf` | The key derivation function used everywhere in TLS 1.3. Two phases: extract + expand. |
| bcrypt | `bcrypt` | Historical. Builds on Blowfish (we already have that lesson) — could be a fast extension rather than a full standalone. |

Bundle unlocked: **"Password hashing done right"** — PBKDF2 → bcrypt → Argon2.
And: **"Compose your own AEAD"** — modes lesson + HMAC + how AEAD constructions
came to be.

### D. Classical signatures + DH

Fills the gap between RSA basics and Ed25519. Mostly pedagogical: you'd rarely
build new systems with these, but they're cited everywhere and form the
historical foundation.

| Lesson | Slug | Why |
|---|---|---|
| Diffie-Hellman (mod p) | `diffie-hellman` | Classical 1976 paper. Math is just modular exponentiation. Useful scaffolding before X25519 (the X25519 spec already includes a DH warmup step; this would be the standalone deep dive). |
| ECDSA | `ecdsa` | The signature scheme everyone wishes they could replace with Ed25519. Famous footguns: nonce reuse, the Sony PS3 disaster. |
| RSA-PSS | `rsa-pss` | Modern padded RSA signatures. Could be a continuation of the existing RSA lesson rather than a standalone. |

Bundle unlocked: **"Signatures, classical to modern"** — DH → ECDSA → Ed25519.

## Beyond — speculative

Things that probably belong on the site eventually but haven't been triaged:

- **Protocols (not algorithms):** TLS 1.3 handshake walkthrough, Signal X3DH +
  Double Ratchet, PGP. These are *compositions* of catalog algorithms and are
  better served by bundle landing pages with prose than as new "algorithm"
  entries. Requires building the bundle-landing-page upgrade first (currently
  bundles deep-link to the first algorithm; a real bundle page would walk the
  arc).
- **Side-channel deep dive:** timing attacks, cache attacks, power analysis.
  Most of the content is conceptual; not many interactive demos work in a
  browser.
- **Zero-knowledge proofs:** Schnorr, zk-SNARKs. Massive topic; probably its
  own site eventually.
- **MPC and homomorphic encryption.** Same — eventually own site.
- **Historical:** Caesar, Vigenère, Enigma, one-time pad. Probably ship as a
  bundle "Pre-modern cryptography" once the core catalog is settled. Caesar +
  Vigenère were on Hriday's mental list at the start of the project.

## Editorial principles

- Each lesson walks math step by step, then ends with a runnable Python script.
- No black-box "use this library" lessons — always show the math underneath.
- Pedagogical simplifications are allowed; they MUST be flagged explicitly in
  lesson copy ("This page uses AES in place of the real 3DES used by payment
  HSMs — the property we care about is identical").
- New algorithms slot into existing bundles via slug list updates in
  `core/bundles.py`. New bundles get added to the same file.
- Algorithm.family is a coarse grouping for the landing's "All algorithms"
  section. When in doubt, use an existing value; only add new families when
  they justify their own section (e.g., `hash` for SHA-256 + HMAC).
