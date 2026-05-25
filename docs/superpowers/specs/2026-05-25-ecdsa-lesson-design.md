# ECDSA Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach ECDSA as a 7-step lesson centered on the **Sony PS3 disaster (2010)** — the textbook example of why ECDSA's per-signature nonce `k` must never repeat. The lesson walks signing/verification math, then hands the learner two signatures produced with the same `k` on a toy curve and asks them to recover the private key. ECDSA is NIST's elliptic-curve signature standard (FIPS 186-2, 2000), shipped in TLS certificates on P-256, Bitcoin on secp256k1, Ethereum, JWT-ES256, code signing, and most modern PKI. It is the older sibling Ed25519 was designed to replace.

Pedagogically this slots in after Ed25519. The framing "Ed25519 made nonce reuse impossible by construction; here is what nonce reuse looked like on the older standard" connects the two lessons. The PS3 attack is concrete, famous, and runnable in a browser on a small curve.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. X25519 (designed)
9. Ed25519 (designed)
10. **ECDSA** (this design)
11. ChaCha20-Poly1305 (next)
12. Caesar / Vigenère (future)

ECDSA after Ed25519 is deliberate: learners arrive knowing that signatures can be deterministic and safe, then meet the older, randomized scheme and feel the disaster.

## Non-goals

- Real P-256 / secp256k1 ECDSA implementation in JS. We demo on a toy curve so the math is tractable; full curves are referenced for the codegen only.
- Full ECC point-addition formulas. Covered in the X25519 spec; this lesson references but does not repeat.
- Threshold ECDSA / multi-party signing (GG18, GG20, FROST-ECDSA family). Out of scope.
- The lattice-attack literature on biased nonces (Howgrave-Graham–Smart, Nguyen–Shparlinski). Pedagogically the same idea as PS3 but harder to walk; mentioned in step 6 as a sidebar.
- Signature malleability (`(r, s)` vs `(r, n − s)`) and Bitcoin's BIP-62 fix. One-line callout in step 6.
- ECDSA on binary curves (FIPS 186-2 Koblitz curves). Mentioned by name, not taught.
- Post-quantum replacements (Dilithium, SPHINCS+). Recap callout only.

## User experience

The lesson lives at `/algorithms/ecdsa/learn/the-ps3-disaster/`. ECDSA appears as a new card on the landing page. `family: asymmetric`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | What ECDSA is and where it lives: TLS server certificates (P-256), Bitcoin (secp256k1), Ethereum (same), JWT-ES256, Apple/Microsoft code signing, modern PKI. Compares to Ed25519 (the user has just done it): ECDSA is older (FIPS 186-2, 2000), NIST-blessed, originally randomized; RFC 6979 later added a deterministic variant. Frame the arc: math, then the PS3 disaster, then why people still ship ECDSA. |
| 2 | `curve-recap` | `info` | Brief ECC vocabulary refresh — the user has seen X25519 and Ed25519, reuse terms. Curves used by ECDSA: NIST P-256 (US gov / TLS), secp256k1 (Bitcoin, Ethereum), P-384 (TLS high-assurance), P-521 (overkill but FIPS-approved). Group has prime order `n`, generator `G`, point arithmetic `k · G`. One-paragraph callout: "ECDSA doesn't care which curve as long as the group is prime-order; pick the curve, you get a signature scheme." |
| 3 | `sign-mechanics` | `info` | Signing on message `m`, private key `d ∈ [1, n−1]`:<br>1. `e = SHA-256(m)`, truncated to `bitlen(n)`.<br>2. Pick random nonce `k ∈ [1, n−1]`.<br>3. `R = k · G`; take `r = R.x mod n` (retry if 0).<br>4. `s = k⁻¹ · (e + r · d) mod n` (retry if 0).<br>5. Signature is `(r, s)`.<br>**Critical callout:** `k` must be uniformly random AND unique per signature. Reusing `k` across two different messages — even partially leaking `k` — reveals `d`. |
| 4 | `verify-mechanics` | `info` | Verification given `(m, (r, s))` and public key `Q = d · G`:<br>1. `e = SHA-256(m)`.<br>2. `w = s⁻¹ mod n`.<br>3. `u1 = e · w mod n`, `u2 = r · w mod n`.<br>4. `P = u1 · G + u2 · Q`.<br>5. Valid iff `P.x mod n == r`.<br>Sketch of why: `P = (u1 + u2·d) · G`. Substitute `u1 = e·s⁻¹`, `u2 = r·s⁻¹`: `(e + r·d) · s⁻¹ · G = k · G = R`. Equality holds iff the signer knew `d`. |
| 5 | `the-ps3-attack` | `input-numeric` | THE INTERACTIVE STEP. Sony PS3 (2010): used the same `k` for every signature. Math: given `(r, s1)` on `m1` and `(r, s2)` on `m2` — same `r` because same `k` — subtract:<br>`s1 − s2 ≡ k⁻¹ · (e1 − e2) (mod n)`<br>so `k ≡ (e1 − e2) · (s1 − s2)⁻¹ (mod n)`.<br>Once `k` is recovered: `d ≡ r⁻¹ · (s1 · k − e1) (mod n)`.<br>Page presents two pre-computed signatures on a toy curve (parameters below) with the same `k`. Asks the user for `k`. Validator checks; on success the page auto-derives `d` and renders "✓ Sony's private signing key, recovered — `d = NN`." |
| 6 | `aftermath-and-defenses` | `info` | What happened: at 27C3 (Dec 2010), fail0verflow demoed the attack live; Sony's PS3 firmware signing key was recoverable; jailbreaks shipped within days. The fix everyone adopted: **RFC 6979 — deterministic ECDSA**, replacing random `k` with `k = HMAC-SHA256(d, e)`. Same `(key, message)` ⇒ same `k` ⇒ same signature; different message ⇒ different `k` derived from the message itself, never the RNG. This is the trick Ed25519 bakes in by design. Modern libraries default to it (pyca/cryptography on every backend; Bitcoin's libsecp256k1 since 2014; OpenSSL since 3.2). Sidebar: lattice attacks on biased nonces (a few bits of `k` leak per signature ⇒ d recoverable from ~100 signatures); signature malleability and BIP-62. |
| 7 | `done` | `info` | Recap. Codegen renders Python using `cryptography.hazmat.primitives.asymmetric.ec` — generate P-256 key, sign, verify, tampered-verify catches `InvalidSignature`. Note pyca uses RFC 6979 deterministic-k internally. Forward-link: ChaCha20-Poly1305 — "you have RSA, ECDSA, Ed25519, X25519. Time to encrypt the actual messages those signatures sign with a modern AEAD." |

### Step 5 in detail — the toy curve and the attack

**Curve choice.** Standard textbook curve (Stallings, *Cryptography and Network Security* 7e, §10.4): `y² ≡ x³ + x + 6 (mod 11)`. With base point `G = (2, 7)` the group has order `n = 13` (prime). This is genuinely runnable in JS BigInt with negligible code, and matches what learners googling "small ECDSA example" will find.

Order `n = 13` is tight (k ∈ [1, 12]) but workable — and the tightness is itself pedagogical, since the user can verify by hand. If during implementation the curve feels too cramped (e.g., wanting larger `e` values that don't trivially equal each other mod 13), fall back to `y² ≡ x³ + 2x + 3 (mod 97)` or `y² ≡ x³ + 3 (mod 199)`; both have prime order in the 80–220 range. Implementation picks one set of parameters and bakes them into the validator. Spec recommendation: **start with p=11, a=1, b=6, G=(2,7), n=13** and only escalate if learner-message arithmetic makes the attack values uncomfortably small.

**Pre-baked attack scenario (with n=13).** Choose `d = 7` (private key), `k = 3` (the reused nonce). Then `R = 3·G = (8, 3)` on this curve (Stallings table); `r = 8 mod 13 = 8`. Use two message hashes `e1 = 4`, `e2 = 10`. Compute:
- `s1 = 3⁻¹ · (4 + 8·7) mod 13 = 9 · (4 + 56) mod 13 = 9 · 8 mod 13 = 72 mod 13 = 7`
- `s2 = 3⁻¹ · (10 + 8·7) mod 13 = 9 · (10 + 56) mod 13 = 9 · 1 mod 13 = 9`

(Here `3⁻¹ mod 13 = 9` because `3 · 9 = 27 ≡ 1 mod 13`.)

Attack:
- `s1 − s2 = 7 − 9 = −2 ≡ 11 (mod 13)`.
- `(s1 − s2)⁻¹ ≡ 11⁻¹ ≡ 6 (mod 13)` (since `11 · 6 = 66 ≡ 1 mod 13`).
- `e1 − e2 = 4 − 10 = −6 ≡ 7 (mod 13)`.
- `k = (e1 − e2) · (s1 − s2)⁻¹ = 7 · 6 = 42 ≡ 3 (mod 13)`. ✓ matches.

Key recovery:
- `r⁻¹ ≡ 8⁻¹ ≡ 5 (mod 13)` (since `8 · 5 = 40 ≡ 1`).
- `d = 5 · (7 · 3 − 4) mod 13 = 5 · 17 mod 13 = 5 · 4 mod 13 = 20 mod 13 = 7`. ✓

The validator parses the user's integer for `k`, accepts `3` (or any representative `≡ 3 mod 13`), then automatically computes and reveals `d = 7`. Bake both into state.

**Page layout for step 5:**

> Sony's PS3 signed every firmware update with the same `k`. Here are two signatures on the toy curve `y² = x³ + x + 6 mod 11`, generator `G = (2, 7)`, group order `n = 13`:
>
> | message hash | r | s |
> |---|---|---|
> | e₁ = 4 | 8 | 7 |
> | e₂ = 10 | 8 | 9 |
>
> Same `r` means same `k`. Solve for `k`:
> `k ≡ (e₁ − e₂) · (s₁ − s₂)⁻¹ (mod n)`
>
> [ input: k = ____ ] [ Recover ]

On correct input the right-hand panel reveals: "✓ k = 3. Substituting into `d = r⁻¹ · (s·k − e) mod n` gives **d = 7** — Sony's private signing key."

## Architecture

### New algorithm record

`algorithms/ecdsa/fixtures.json`. Algorithm PK 17, slug `ecdsa`, name `ECDSA`, family `asymmetric`. Lesson PK 17, slug `the-ps3-disaster`, title `ECDSA: the PS3 disaster`. Steps PKs 171–177.

### New algorithm module directory

`static/algorithms/ecdsa/`:

| File | Responsibility |
|---|---|
| `validators.js` | `recover_k` validator (math sync, BigInt-backed) + `info` + walkthroughs. |
| `codegen.js` | `full_script` emits Python using `cryptography.hazmat.primitives.asymmetric.ec` — keygen on P-256, sign, verify, tampered-verify catches `InvalidSignature`. Comment notes RFC 6979 deterministic-k default. |
| `ecdsa_demo.js` | Tiny ECDSA on the toy curve. BigInt point-add / scalar-mul; modular inverse via extended Euclid; signs / verifies / recovers-d helpers used by step 5. ~120 lines. |
| `tests/*.test.js` | Validator + codegen + demo tests. |

### Validators

| Key | Validates | Writes |
|---|---|---|
| `recover_k` | Parses integer; reduces mod n; equals the canonical k (3 with the recommended params). On success, auto-computes d and writes both. | `{ecdsa_recovered_k, ecdsa_recovered_d}` |
| `info` | Always ok | `{}` |

The validator writing two state keys at once (k and the auto-derived d) matches the spirit of validators that "advance the worked example" (cf. RSA's `compute_phi` / `compute_d` chain). Implementation: validator imports `recoverDFromK` from `ecdsa_demo.js`.

### State namespace

`ecdsa_` prefix. Picked over `ec_` because `ec_` is too generic (would clash with a hypothetical ECDH-on-P256 lesson) and over `dsa_` because ECDSA ≠ classical DSA.

### Template changes

Step 5 is `input-numeric` with extra context above (the two-row signatures table) and an auto-revealed result panel below (d-recovery display). Both belong in a slug-keyed branch in `core/templates/core/lesson.html` for `the-ps3-attack`. The signature-table data is hardcoded in the template (driven off the bake-in constants), not state-driven. The d-recovery panel renders when `ecdsa_recovered_d` is set.

No shared partial extraction needed; this is a one-off layout.

## Data flow

```
Step 1–4 (info)        no input. state empty.

Step 5 (the-ps3-attack)  input: integer k
                       ↓ recover_k validator
                       state += {
                         ecdsa_recovered_k: 3,
                         ecdsa_recovered_d: 7,   // auto-derived
                       }

Step 6 (aftermath)     info, no input.

Step 7 (done)          info. Codegen is self-contained — does not read
                       per-user state.
```

## Error handling

### Step 5 — `recover_k`

- Not parseable → `"Enter an integer."`
- Out of range / non-positive after mod n → reduce mod n and compare (so `16 ≡ 3 mod 13` accepts; `0` rejects with `"k cannot be 0 — it has no modular inverse."`).
- Wrong value → `"Not quite. (e₁ − e₂) · (s₁ − s₂)⁻¹ mod 13 = (4 − 10) · (7 − 9)⁻¹ mod 13. Watch the signs: differences can be negative — reduce mod 13 before inverting."`

## Testing

### JS validator tests

- `recover_k` accepts `3`, `16` (= 3 + 13), `-10` (≡ 3 mod 13).
- `recover_k` rejects `0`, `4`, non-integer strings.
- On accept, writes both `ecdsa_recovered_k = 3` and `ecdsa_recovered_d = 7`.

### JS codegen tests

- `full_script({})` contains `ec.generate_private_key(ec.SECP256R1())`, `.sign(`, `.public_key().verify(`, `ec.ECDSA(hashes.SHA256())`, and an `InvalidSignature` except branch around a tampered-signature call.

### JS ecdsa_demo tests

- Point arithmetic: `G + G == 2·G`, `13·G == identity`.
- `sign(m, d, k)` deterministic for fixed inputs; matches the baked `(r, s)` values for `(d=7, k=3, e=4)` and `(d=7, k=3, e=10)`.
- `recoverK(e1, e2, s1, s2, n) == 3`.
- `recoverD(r, s, k, e, n) == 7`.

### Fixture-load test

- Extend `core/tests/test_fixtures.py`: algorithm row PK 17, lesson row PK 17, 7 step rows with the slugs `intro`, `curve-recap`, `sign-mechanics`, `verify-mechanics`, `the-ps3-attack`, `aftermath-and-defenses`, `done`.

### Manual smoke

- Walk all 7 steps. Step 5: enter `3` → expect the d-recovery panel to render `d = 7`. Enter `16` → same accept. Enter `0` → see the "no modular inverse" error. Enter `4` → see the hint about signs.
- Step 7: run the generated Python locally; expect a clean sign → verify, then `InvalidSignature` on the tampered branch.

## Files touched

| File | Change |
|---|---|
| `algorithms/ecdsa/fixtures.json` | CREATE |
| `static/algorithms/ecdsa/validators.js` | CREATE |
| `static/algorithms/ecdsa/codegen.js` | CREATE |
| `static/algorithms/ecdsa/ecdsa_demo.js` | CREATE |
| `static/algorithms/ecdsa/tests/validators.test.js` | CREATE |
| `static/algorithms/ecdsa/tests/codegen.test.js` | CREATE |
| `static/algorithms/ecdsa/tests/ecdsa_demo.test.js` | CREATE |
| `core/templates/core/lesson.html` | MODIFY — slug-keyed branch for `the-ps3-attack` (signatures table + d-recovery panel). |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No model changes — `asymmetric` family already exists.

## Open questions / deferred

- **Toy curve sizing.** Spec recommends Stallings's `(p=11, a=1, b=6, G=(2,7), n=13)` — small enough for hand math, big enough for the attack to be unambiguous. If during implementation the n=13 group order makes message hashes uncomfortable (e₁ and e₂ both reduce mod 13 and the choice space is small), escalate to `p=97` or `p=199` curve. Decision deferred to implementation; validator constants are the single source of truth either way.
- **Showing point arithmetic at step 5.** Tempting to also display `R = 3·G = (8, 3)` and let the user verify `r = 8`. Decided no — would inflate the step. The signatures are presented as given; the attack is the focus.
- **A verify-it-yourself interactive step.** Considered adding an interactive "verify a real signature" step using Web Crypto's P-256. Decided skip — verify-mechanics info plus the codegen cover it without adding another input form.
- **The lattice-attack sidebar in step 6.** Mentioned but not walked. A follow-up "biased nonces" lesson could pair with this one if learners ask.
- **Bitcoin / secp256k1 detour.** Tempted to add a sidebar about Android's 2013 SecureRandom bug that drained Bitcoin wallets via the same nonce-reuse mechanism. Recommended: keep step 6 focused on PS3 + RFC 6979 + the lattice sidebar; the Android bug gets a one-sentence mention ("the same mistake hit Android Bitcoin wallets in 2013") rather than its own block.
