# Ed25519 Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach Ed25519 as a 7-step lesson that introduces **digital signatures on the Edwards form of Curve25519** (RFC 8032). The arc walks from "what's a signature, and why is it different from a MAC" through the EdDSA signing/verification math, into an interactive Web Crypto sign/verify panel, and ends with a Python codegen using `cryptography.hazmat.primitives.asymmetric.ed25519`.

Pedagogically this slots in after X25519 (key exchange on the Montgomery form of the same curve). The framing "same curve, different form, different job" makes the connection tangible: X25519 derives a shared secret, Ed25519 produces public-verifiable signatures. Real-world hooks — SSH default key type since 2014, Git/GitHub commit signing, Solana, Cardano, NEAR, JWT-EdDSA — anchor the abstraction.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. X25519 (designed)
9. **Ed25519** (this design)
10. ChaCha20-Poly1305 (next; forward-linked from this lesson)
11. Caesar / Vigenère (future)

The X25519 lesson already plants the Curve25519 vocabulary; this lesson rides on that. The next planned entry is ChaCha20-Poly1305 — signatures and key exchange both assume an AEAD does the bulk encryption.

## Non-goals

- Ed448 — mentioned in passing, not taught.
- Full Edwards-curve point addition formulas. Geometric intuition only; learners chasing the math get pointed at RFC 8032 §5.1.
- Ed25519ph / Ed25519ctx prehash variants. Briefly named so learners recognize them, not walked.
- BIP32-style HD wallet key derivation on Ed25519 (SLIP-0010). Out of scope.
- Post-quantum signature replacements (Dilithium, SPHINCS+). Called out in the recap as future-proofing, not taught.
- Batch verification, low-order subgroup attacks, malleability edge cases — RFC 8032 §8 territory, deferred.

## User experience

The lesson lives at `/algorithms/ed25519/learn/sign-with-edwards/`. Ed25519 appears as a new card on the landing page. `family: asymmetric`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | What a digital signature is. Contrast with MAC: a MAC requires the verifier to hold the shared secret; a signature lets *anyone* with the public key verify, while only the private-key holder could produce it. Where Ed25519 ships: SSH (default since OpenSSH 6.5, 2014), Git commit signing, GitHub web-of-trust, Solana/Cardano/NEAR, JWT-EdDSA (RFC 8037). Why Ed25519 vs RSA-PSS or ECDSA: smaller, faster, deterministic — no per-signature nonce means no nonce-reuse footguns like the Sony PS3 ECDSA disaster (CVE-2010-Sony). |
| 2 | `key-derivation` | `info` | Private key = 32 random bytes. Hash with SHA-512 → 64 bytes. First 32 bytes (clamped, like X25519: clear bits 0/1/2 of byte 0, clear bit 7 of byte 31, set bit 6) become the scalar `s`. Last 32 bytes become the "prefix" `p` used to make signing deterministic. Public key `A = s · G`, where G is the Edwards basepoint — same curve as X25519, different basepoint, different coordinate system. High-level math; no point-addition walk. |
| 3 | `sign-mechanics` | `info` | EdDSA sign on message m:<br>1. `r = SHA-512(p ‖ m) mod L` — deterministic nonce, no RNG.<br>2. `R = r · G` — commitment point.<br>3. `k = SHA-512(R ‖ A ‖ m) mod L` — challenge.<br>4. `s_sig = (r + k · s) mod L`.<br>5. Signature = `(R, s_sig)` — exactly 64 bytes.<br>Callout: same key + same message ⇒ identical signature. Reproducibility is a feature, and it eliminates the entire class of nonce-reuse attacks. |
| 4 | `verify-mechanics` | `info` | Verify on `(m, sig)`: parse `R` and `s_sig`. Recompute `k = SHA-512(R ‖ A ‖ m) mod L`. Check `s_sig · G == R + k · A` as Edwards points. Sketch of why: substitute `s_sig = r + k·s`, then `(r + k·s) · G = r·G + k·(s·G) = R + k·A`. Equality holds iff the signer knew `s`. |
| 5 | `sign-and-verify` | `input-text` (sign/verify) | Interactive. On first load, the page generates a non-extractable Ed25519 keypair via `crypto.subtle.generateKey({name: "Ed25519"}, true, ["sign", "verify"])`. Public key bytes displayed as hex. User types a message → **Sign** → page shows 128-hex-char signature. User clicks **Verify** with the original signature → "valid." User edits any one hex character of the signature → **Verify** → "invalid." Mirrors the HSM lesson's sign/verify panel. |
| 6 | `vs-rsa-comparison` | `info` | Side-by-side table — Ed25519 vs RSA-PSS-2048:<br>- Private key: 32 B vs ~1200 B<br>- Public key: 32 B vs 256 B<br>- Signature: 64 B vs 256 B<br>- Sign: ~30K/sec vs ~700/sec (typical laptop)<br>- Verify: ~10K/sec vs ~30K/sec (RSA wins here)<br>- Security level: ~128-bit vs ~112-bit<br>- Deterministic: yes vs no (RSA-PSS uses random salt)<br>Conclusion: Ed25519 strictly better for new code, except verify-heavy workloads (many TLS clients verifying one server cert) where RSA-PSS verify speed still matters. |
| 7 | `done` | `info` | Recap. Codegen using `cryptography.hazmat.primitives.asymmetric.ed25519`. Forward-link to ChaCha20-Poly1305: "you've got key exchange, signatures, and key wrapping — now let's encrypt the actual messages with a modern AEAD." Side-note: Shor's algorithm breaks Ed25519 along with RSA/ECDSA; Dilithium and SPHINCS+ are the PQ-safe replacements. |

### Step 5 in detail

On step entry the wizard calls `crypto.subtle.generateKey({name: "Ed25519"}, true, ["sign", "verify"])` and stores `{privateKey, publicKey}` in the wizard component (not persisted to state — keys are ephemeral, same posture as the HSM lesson). Public-key bytes are exported via `crypto.subtle.exportKey("raw", publicKey)` and shown as 64 hex chars in the prompt panel.

User actions:
- **Sign:** Types text into the message input → clicks **Sign** → wizard calls `crypto.subtle.sign({name: "Ed25519"}, privateKey, encode(message))` → 64-byte signature written to state as `ed25_last_signature` (hex) and displayed.
- **Verify:** Types (or edits) hex into the signature input → types the message → clicks **Verify** → wizard parses hex, calls `crypto.subtle.verify({name: "Ed25519"}, publicKey, sigBytes, msgBytes)` → boolean result written as `ed25_verify_result` and displayed as a green "valid" / red "invalid" pill.

**Browser support note:** Ed25519 in Web Crypto requires Chrome 110+, Safari 17+, Firefox 130+ (shipped Sept 2024). On unsupported browsers, the step renders a fallback panel: "This step needs a 2024+ browser. The math in steps 2–4 still applies; the Python codegen on step 7 will run anywhere." Detection: `try { await crypto.subtle.generateKey({name: "Ed25519"}, …) } catch { /* fallback */ }`.

## Architecture

### New algorithm record

`algorithms/ed25519/fixtures.json`. Algorithm PK 11. Lesson PK 11. Steps PKs 111–117.

### New algorithm module directory

`static/algorithms/ed25519/`:

| File | Responsibility |
|---|---|
| `validators.js` | `ed25519_operation` validator (multi-mode: sign / verify) + `info` + walkthroughs. |
| `codegen.js` | `full_script` emits Python using `cryptography.hazmat.primitives.asymmetric.ed25519`: keygen, sign, verify, tampered verify with `InvalidSignature` catch. |
| `ed25519_simulator.js` | Web Crypto wrapper: `generateKeypair()`, `sign(message)`, `verify(message, sigHex)`, `getPublicKeyHex()`. Mirrors `hsm/hsm_simulator.js`. |
| `tests/*.test.js` | Validator + codegen tests. Web Crypto path skipped in Node (verified via Playwright). |

### Validators

| Key | Validates | Writes |
|---|---|---|
| `ed25519_operation` | multi-input `{op, message, signature?}` — `op ∈ {"sign","verify"}`; runs Web Crypto Ed25519 op; verify requires 128-hex-char signature | `{ed25_last_op, ed25_last_input, ed25_last_signature, ed25_verify_result, ed25_op_error}` |
| `info` | always ok | `{}` |

Shape mirrors the HSM lesson's `hsm_operation` validator exactly — multi-mode dispatch by `op` field, permissive on input content, the "incorrect" outcome (verify=false) is information, not an error.

### State namespace

`ed25_` prefix. Picked over `ed_` to leave room for an Ed448 lesson later, and over `ed25519_` to keep keys short.

### Template changes

Step 5 needs a slug-keyed branch in `core/templates/core/lesson.html` for `sign-and-verify`. UX is identical in shape to the HSM lesson's `simulated-hsm` branch: message input, conditional signature input (shown only when op=verify), Sign + Verify buttons, result pill, public-key display.

**Decision: extract a shared `sign-verify-panel` partial.** Rather than copy-paste the HSM branch with a different slug, factor the markup into a parameterized include — `{% include "core/_sign_verify_panel.html" with state_prefix="ed25_" public_key=ed25_public_key %}`. The HSM lesson's branch refactors to use it too (one-line change in `lesson.html`, no behavior change). Net: one partial, two slug-keyed call sites. If the partial extraction balloons in scope during implementation, fall back to a sibling branch (copy + edit) — noted in open questions.

## Data flow

```
Step 1–4 (info)         no input. state empty for the lesson body.

Step 5 (sign-and-verify) init: wizard calls crypto.subtle.generateKey for
                              Ed25519. {privateKey, publicKey} live in the
                              wizard component (not persisted).
                        input: { op: "sign"|"verify", message, signature? }
                        ↓ ed25519_operation validator (async — awaits Web Crypto)
                        state += {
                          ed25_last_op,
                          ed25_last_input,
                          ed25_last_signature,    // set on sign
                          ed25_verify_result,     // set on verify
                          ed25_op_error,          // on malformed hex etc.
                        }

Step 6 (vs-rsa)         info, no input.

Step 7 (done)           info. Codegen reads no per-user state — script is
                        self-contained.
```

## Error handling

### Step 5 — `ed25519_operation`

- Empty message → `"Type something to sign or verify."`
- Sign op, Web Crypto throws → catch, surface `"Browser couldn't sign — Ed25519 needs Chrome 110+, Safari 17+, or Firefox 130+."`
- Verify op, signature not 128 hex chars → `"Ed25519 signatures are exactly 64 bytes (128 hex characters)."`
- Verify op, signature parses but verify returns false → not an error; write `ed25_verify_result: false`, render "invalid" pill.
- Verify op, Web Crypto throws on malformed bytes → catch, render "invalid" pill (don't expose the underlying error).

### Cross-step

The Ed25519 keypair regenerates on every page load (not persisted — keys live in the wizard component). Mirrors the HSM lesson. Plain-English help on step 5: "Refreshing this page makes a new key. Old signatures won't verify against the new one — that's expected." Resuming users with `current_step_order >= 5` simply get a fresh key on rehydrate.

## Testing

### JS validator tests
- `ed25519_operation` shape tests: returns the expected state keys for each op.
- Hex parsing rejects (odd length, non-hex chars, wrong byte length).
- Web Crypto path skipped in Node (same constraint as AES and HSM lessons).

### JS codegen tests
- `full_script({ed25_last_input: "hi"})` contains `ed25519.Ed25519PrivateKey.generate()`, `.sign(`, `.public_key().verify(`, and an `InvalidSignature` catch block around a tampered-signature branch.

### JS ed25519_simulator tests
- Smoke only: `generateKeypair()` resolves to an object with `privateKey` and `publicKey` keys. Don't assert on key bytes — they're CryptoKey handles.

### Fixture-load test
- Extend `core/tests/test_fixtures.py` with Ed25519 lesson assertions (algorithm row, lesson row, 7 step rows with correct slugs).

### Manual smoke
- Walk all 7 steps in Chrome 110+ and Safari 17+. Step 5: sign "hello", verify (should pass), flip one hex char of the signature, verify again (should fail). Open devtools → inspect wizard component → confirm `privateKey` is an opaque `CryptoKey`.
- Walk step 5 on a deliberately old browser (or stubbed `crypto.subtle`) → confirm fallback panel renders.

## Files touched

| File | Change |
|---|---|
| `algorithms/ed25519/fixtures.json` | CREATE |
| `static/algorithms/ed25519/validators.js` | CREATE |
| `static/algorithms/ed25519/codegen.js` | CREATE |
| `static/algorithms/ed25519/ed25519_simulator.js` | CREATE |
| `static/algorithms/ed25519/tests/validators.test.js` | CREATE |
| `static/algorithms/ed25519/tests/codegen.test.js` | CREATE |
| `core/templates/core/_sign_verify_panel.html` | CREATE (shared partial) |
| `core/templates/core/lesson.html` | MODIFY — slug-keyed branch for `sign-and-verify`; refactor `simulated-hsm` branch to use the shared partial |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No model changes — `asymmetric` already in `FAMILY_CHOICES`, added during the HSM design pass.

## Open questions / deferred

- **Shared partial vs sibling branch.** Recommendation: extract `_sign_verify_panel.html` and have both Ed25519 and HSM render it with a `state_prefix` argument. If during implementation the partial accretes too many flags (HSM has an unwrap mode Ed25519 doesn't), fall back to a sibling slug-keyed branch — duplicate ~30 lines of template for clarity. Hriday to confirm at PR time.
- **Keypair persistence.** Regenerate on every load. Matches the HSM lesson's posture; the alternative (stash a non-extractable handle in IndexedDB) adds complexity for negligible pedagogical value. Note in step 5 help.
- **Showing the actual signing math.** Probably no — `s_sig = (r + k · s) mod L` walked symbolically in step 3 is plenty. A "compute one scalar multiplication" interactive step on the Edwards basepoint would balloon scope and require either a curve library in JS or hand-curated values. Curious readers get pointed at RFC 8032 §5.1.6.
- **Ed25519ph / Ed25519ctx.** Mentioned in step 7's recap but not taught. A follow-up "prehash and context strings" lesson could cover them if learners ask.
- **PQ-signature lesson.** The recap forward-links to Dilithium/SPHINCS+ as future work; no concrete plan yet.
