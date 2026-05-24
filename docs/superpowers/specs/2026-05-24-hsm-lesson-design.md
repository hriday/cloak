# How to Use an HSM — Design

**Date:** 2026-05-24
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach the **HSM (Hardware Security Module) pattern** — what an HSM is, why production systems use them, and how the operations-only API works in practice. Unlike the algorithm lessons, this is a **conceptual lesson with light interactivity**: the user doesn't compute a cipher by hand; instead they walk through the *use pattern* (wrap key, unwrap key, sign, verify), see a simulated HSM "vault" they can't peek into, and read real cloud-KMS code samples (AWS, GCP, Azure).

This is the natural follow-up to the hybrid encryption lesson, which taught the KEK (Key Encryption Key) pattern at its simplest level. HSMs generalize that into key hierarchies that production systems actually use.

## Curriculum position

Final entry (so far) in the planned arc:

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. Caesar / Vigenère (future)
8. **HSM** (this design)

The hybrid lesson already forward-links to this one ("This pattern is called a KEK — see the upcoming HSM lesson").

## Non-goals

- Implementing a real HSM. The "simulated HSM" is JS that *behaves like* an opaque key vault; anyone can read the JS source. We're teaching the API pattern, not the security guarantee.
- Cryptographic agility, PKCS#11, KMIP wire format — operational details out of scope.
- FIPS 140-3 certification process.
- HSM cluster topology, partition management.
- TPM / Secure Enclave / TEE comparisons (could be a separate future lesson).
- A working AWS / GCP / Azure connection — code samples are *unrunnable in-browser*; learner copies them to their own environment.

## User experience

The lesson lives at `/algorithms/hsm/learn/key-vaults/`. HSM appears as a new card on the landing page. `family` is `hsm` — but wait, the Algorithm model only allows `asymmetric / symmetric / pq`. **Adding `hsm` as a fourth family choice is needed** (one-line model change + migration). Alternative: classify as `asymmetric` since HSMs primarily wrap asymmetric private keys. Spec leans toward **the model change** for clarity, but the migration is a noted dependency.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | What an HSM is: a physical device (or cloud service) that holds private keys and exposes only *operations* — wrap, unwrap, sign, verify. The key bytes never leave the device. Used by payment processors, CAs, banks, anyone with high-value secrets. |
| 2 | `the-vault-analogy` | `info` | Mental model: imagine a vault you can put things into and ask questions about, but never open. You can ask the vault to *sign* a document. You can ask it to *unwrap* a key. You can't ask "what's the private key?" There is no such API. |
| 3 | `operations-api` | `info` | The standard ops: `generate_key`, `wrap` (encrypt a data key with an HSM-held KEK), `unwrap`, `sign`, `verify`. Maybe `encrypt` / `decrypt`. The API surface is intentionally tiny — the smaller it is, the harder it is to misuse. |
| 4 | `simulated-hsm` | `input-text` | Interactive: shows a fake HSM that "holds" an RSA private key (truly hidden from view, even though it lives in JS — we just don't `console.log` it). User submits a message; the HSM signs it. User submits a wrapped key; the HSM unwraps it. Output panel shows the signature / unwrapped key. Code-of-honor demo. |
| 5 | `kek-hierarchy` | `info` | The full pattern: a Master Key (root, in the HSM) wraps a Tenant KEK (also in the HSM). The Tenant KEK wraps Data Encryption Keys (DEKs). DEKs do the actual encryption of customer data. Rotation and revocation happen at the KEK layer without re-encrypting all the data. |
| 6 | `real-world-kms` | `info` | Code samples (Python + AWS / GCP / Azure SDK) for the same operations against a real cloud KMS. Boto3 (`kms.encrypt`, `kms.decrypt`), google-cloud-kms, azure-keyvault-keys. Learner can copy these. |
| 7 | `where-required` | `info` | Compliance contexts where HSMs are *required*, not just recommended: PCI DSS (payment processing), FIPS 140-2/3 (US federal), Common Criteria, eIDAS (EU). |
| 8 | `done` | `info` | Recap + back-links. Forward-link mentions key ceremony / split-knowledge / quorum auth as topics for a future "HSM administration" lesson. |

### Step 4 in detail (the only interactive step)

The simulated HSM is implemented as a small client-side wrapper around the browser's Web Crypto API. On lesson init, the wizard generates an RSA-2048 keypair via `crypto.subtle.generateKey` with `extractable: false`. The private key reference lives in the wizard component; **even with browser devtools, the raw key bytes can't be extracted** (Web Crypto enforces non-extractable keys).

User actions on step 4:
- **Sign a message:** types text → wizard calls `crypto.subtle.sign({name: "RSA-PSS"}, privateKey, bytes)` → displays signature as hex.
- **Verify a signature:** types message + signature → wizard calls `crypto.subtle.verify(...)` → displays "valid" or "invalid."
- **Unwrap a wrapped key:** types a hex blob → wizard calls `crypto.subtle.unwrapKey(...)` → displays the unwrapped key fingerprint (not the bytes; the unwrapped key is also non-extractable).

The user can NEVER make the wizard reveal the private key. That's the lesson. The narration says: "this is how a real HSM behaves — even with full access to the operations API, the key material is unreachable."

## Architecture

### Required model change (out of scope of normal lesson plumbing)

`core/models.py` Algorithm.FAMILY_CHOICES needs `("hsm", "HSM")` added. New migration generated. Small but unavoidable.

### New algorithm record

`algorithms/hsm/fixtures.json`. PK 5 (3DES will take 4). Lesson PK 5. Steps PKs 51-58.

### New algorithm module directory

`static/algorithms/hsm/`:

| File | Responsibility |
|---|---|
| `validators.js` | One actionable validator (`sign_or_verify_or_unwrap` — multi-mode based on input shape) + `info` + walkthroughs. |
| `codegen.js` | `full_script` emits a Python script using `boto3` to wrap/sign with AWS KMS. Other vendors shown as snippets in the prompt template, not codegen. |
| `hsm_simulator.js` | The Web Crypto-backed simulated HSM. Exports `generateVaultKey()`, `sign(message)`, `verify(message, sig)`, `wrapKey(key)`, `unwrapKey(blob)`. |
| `tests/*.test.js` | Light tests; the Web Crypto path isn't unit-tested (same constraint as AES). |

### Validators

Step 4 is genuinely interactive but doesn't have a "correct answer" to validate — it's exploratory. The validator is permissive: it accepts any text input for sign/verify/unwrap, runs the corresponding Web Crypto operation, and writes the result to state for display. The "incorrect" outcome (e.g., a verify that returns false) is information, not an error.

### State namespace

`h_` prefix (e.g., `h_vault_id`, `h_last_op`, `h_last_signature`, `h_verify_result`).

Wait — `h_` is already used by the hybrid lesson. To avoid collision: use **`hsm_`** prefix instead.

### Template changes

`lesson.html` gets a new slug-keyed branch for `simulated-hsm` with a small UI: three buttons (Sign / Verify / Unwrap), a text input, and a result display.

## Data flow

```
Step 1-3 (info)         no input. state remains empty for the lesson body.
Step 4 (simulated-hsm)  init: wizard creates a non-extractable RSA-2048 keypair
                              via crypto.subtle.generateKey. Stored in wizard
                              component (not in persisted state — keys are ephemeral).
                        input: user picks an operation + provides input.
                        ↓ corresponding Web Crypto call
                        ↓ output written to state for display
                        state += { hsm_last_op, hsm_last_input, hsm_last_output }

Step 5-7 (info)         no input. state unchanged.
Step 8 (done)           info. Recap.
```

## Error handling

### Step 4 — simulated HSM operations

- Empty input → `"Type something to sign / verify / unwrap."`
- Verify with malformed signature → catch the Web Crypto error, display "Signature invalid (parse error)."
- Unwrap with garbage → catch and display "Couldn't unwrap — input isn't a valid wrapped key blob."
- Web Crypto not available (very old browser) → step 4 shows a fallback message: "This step requires a modern browser with Web Crypto. Try Chrome / Firefox / Safari."

### Cross-step

The simulated keypair is regenerated on every page load (it's stored in the wizard component, not persisted). Resuming users get a fresh key — any prior signatures they generated will no longer verify. Acceptable for a teaching lesson; mention it in step 4's plain-English help.

## Testing

### JS validator tests
- Light — mostly that operations return the expected shape (sign returns hex string, verify returns boolean).
- Skip Web Crypto in Node (degrade gracefully).

### JS hsm_simulator tests
- Smoke: `generateVaultKey()` returns a key object (don't assert on key bytes — they're hidden by design).
- Skip the crypto-subtle-dependent tests; verify manually via Playwright.

### Fixture-load test
- Extend test_fixtures.py with HSM lesson assertions.

### Manual smoke
- Walk all 8 steps. Step 4: sign "hello", verify the signature (should pass), tamper one byte, verify again (should fail).
- Open devtools → try to read the private key from the wizard component → confirm it's an opaque `CryptoKey` object, not raw bytes.

## Files touched

| File | Change |
|---|---|
| `core/models.py` | MODIFY — add `("hsm", "HSM")` to Algorithm.FAMILY_CHOICES |
| `core/migrations/0005_alter_algorithm_family.py` | CREATE (auto-generated) |
| `algorithms/hsm/fixtures.json` | CREATE |
| `static/algorithms/hsm/validators.js` | CREATE |
| `static/algorithms/hsm/codegen.js` | CREATE |
| `static/algorithms/hsm/hsm_simulator.js` | CREATE |
| `static/algorithms/hsm/tests/validators.test.js` | CREATE |
| `core/templates/core/lesson.html` | MODIFY — slug-keyed branch for `simulated-hsm` |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

## Open questions / deferred

- **Family choice** — adding `hsm` to FAMILY_CHOICES is the cleanest, but is "hsm" really a family of algorithms? It's a pattern. Alternative: classify as `asymmetric` since the underlying crypto is RSA. **Recommendation: add `hsm` to choices for clarity.** Reviewer (Hriday) can override this in the morning.
- **Real KMS integration** — code samples only; no actual SDK calls from the lesson. A future "deploy a real KMS" lab could be a separate piece.
- **Key ceremony** — split-knowledge, quorum auth, M-of-N — too operational for v1. Deferred to a future "HSM administration" lesson.
- **TPM / Secure Enclave / TEE** — different threat models from a network-attached HSM. Could be a separate "client-side secure hardware" lesson.
