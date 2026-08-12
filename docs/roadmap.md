# cloak — content roadmap

What's shipped and what's still open. Order reflects priority, not strict
sequence — anything in the open sections can move up if a bundle calls for it.

## Shipped — 34 algorithms, 12 bundles

Everything from the original five-batch build-out plus the attacks batch, the
post-quantum batch, and the Linux password-hashing trio. Every lesson follows
the spec → plan → subagent-driven pattern; specs and plans live in
`docs/superpowers/`.

| Algorithm | Family | Slug | Lesson |
|---|---|---|---|
| RSA | Asymmetric | `rsa` | `encrypt-decrypt` |
| Hybrid Encryption | Asymmetric | `hybrid` | `wrap-and-send` |
| AES | Symmetric | `aes` | `four-transformations` |
| Triple DES | Symmetric | `triple-des` | `why-3des` |
| HSM | Key management | `hsm` | `key-vaults` |
| Blowfish | Symmetric | `blowfish` | `feistel-rounds` |
| Twofish | Symmetric | `twofish` | `aes-finalist` |
| SHA-256 | Hash & MAC | `sha256` | `walk-the-hash` |
| Elliptic curves | Asymmetric | `elliptic-curves` | `curves-visually` |
| HMAC | Hash & MAC | `hmac` | `mac-the-message` |
| X25519 | Asymmetric | `x25519` | `key-exchange-on-a-curve` |
| Ed25519 | Asymmetric | `ed25519` | `sign-with-edwards` |
| ChaCha20-Poly1305 | Symmetric | `chacha20-poly1305` | `arx-aead` |
| Block Cipher Modes | Symmetric | `cipher-modes` | `modes-around-aes` |
| Padding Oracle Attack | Symmetric | `padding-oracle` | `decrypt-without-the-key` |
| Password Hashing | Hash & MAC | `password-hashing` | `slow-on-purpose` |
| Diffie-Hellman | Asymmetric | `diffie-hellman` | `the-1976-handshake` |
| ECDSA | Asymmetric | `ecdsa` | `the-ps3-disaster` |
| Kyber (ML-KEM) | Post-quantum | `kyber` | `lattice-kem` |
| SHA-3 (Keccak) | Hash & MAC | `sha3` | `the-sponge` |
| HKDF | Hash & MAC | `hkdf` | `extract-then-expand` |
| Length Extension Attack | Hash & MAC | `length-extension` | `forge-without-the-key` |
| Classical ciphers | Historical | `classical-ciphers` | `before-modern` |
| Schnorr signatures | Asymmetric | `schnorr` | `four-line-signature` |
| Dilithium (ML-DSA) | Post-quantum | `dilithium` | `lattice-signatures` |
| SPHINCS+ (SLH-DSA) | Post-quantum | `sphincs-plus` | `hash-based-signatures` |
| Bleichenbacher Attack | Asymmetric | `bleichenbacher` | `million-message-attack` |
| Hash Collisions | Hash & MAC | `collisions` | `same-hash-different-data` |
| Birthday Attack | Hash & MAC | `birthday-attack` | `square-root-of-n` |
| RSA-PSS | Asymmetric | `rsa-pss` | `padded-rsa-signing` |
| bcrypt | Hash & MAC | `bcrypt` | `slowed-down-blowfish` |
| yescrypt | Hash & MAC | `yescrypt` | `the-default-nobody-noticed` |
| GOST-yescrypt | Hash & MAC | `gost-yescrypt` | `same-engine-russian-paperwork` |
| Argon2id | Hash & MAC | `argon2id` | `the-one-the-committee-picked` |

Bundles (journeys) on the landing: How TLS 1.3 works · How HTTPS works ·
Why crypto looks weird · Post-quantum primer · Hashing for developers ·
First cryptography lesson · Signatures old to new · Key exchange classical to
modern · Elliptic curve deep dive · How card payments work · Block ciphers
old to new · How Linux stores your password.

Notes on how earlier roadmap items landed:

- PBKDF2 and the ECB penguin shipped inside `password-hashing` and
  `cipher-modes` respectively rather than as standalone lessons.
- Argon2 shipped as `argon2id` (the deployed variant), completing the
  `$y$` / `$gy$` / `$argon2id$` Linux `crypt(5)` story with yescrypt and
  GOST-yescrypt.
- The "bundle landing page upgrade" shipped as journey essay pages
  (`/journeys/<slug>/`) with per-station prose.
- Caesar/Vigenère/one-time pad shipped as `classical-ciphers`; Enigma did not.

## Open — ideas not yet triaged into specs

- **Enigma** — the rotor machine deserves an interactive treatment; would
  extend the Historical family beyond `classical-ciphers`.
- **Protocol walkthroughs as first-class content:** TLS 1.3 handshake
  step-by-step, Signal X3DH + Double Ratchet, PGP. Journey essays cover some
  of this narratively; a wizard-style protocol walkthrough is a bigger lift.
- **Side-channel deep dive:** timing attacks, cache attacks, power analysis.
  Mostly conceptual; few interactive demos work in a browser.
- **Zero-knowledge proofs:** Schnorr identification shipped as scaffolding;
  zk-SNARKs and friends are probably their own site eventually.
- **MPC and homomorphic encryption** — same; eventually their own site.
- **Housekeeping:** older algorithm cards render a literal `##` from their
  `intro_template` markdown headings on the landing; the fixture tests'
  copy-pasted lexicographic PK sort deserves a one-pass cleanup.

## Editorial principles

- Each lesson walks math step by step, then ends with a runnable Python script.
- No black-box "use this library" lessons — always show the math underneath.
- Pedagogical simplifications are allowed; they MUST be flagged explicitly in
  lesson copy ("This page uses AES in place of the real 3DES used by payment
  HSMs — the property we care about is identical"). In-browser demos state
  plainly what is real and what is synthetic, next to cited real-implementation
  numbers (see bcrypt's timing demo and the yescrypt/argon2id memory mixer).
- New algorithms slot into existing bundles via slug list updates in
  `core/bundles.py`. New bundles get added to the same file.
- Algorithm.family is a coarse grouping for the landing's "All algorithms"
  section. When in doubt, use an existing value; only add new families when
  they justify their own section (e.g., `hash` for SHA-256 + HMAC).
