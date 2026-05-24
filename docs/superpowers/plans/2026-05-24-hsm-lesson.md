# HSM Lesson — Implementation Plan

> Use superpowers:subagent-driven-development.

**Goal:** 8-step conceptual lesson with one interactive Web Crypto step (sign/verify/unwrap) on a non-extractable RSA-2048 keypair.

**Architecture:** New `algorithms/hsm/` + `static/algorithms/hsm/` module. Requires adding `("hsm", "HSM")` to `Algorithm.FAMILY_CHOICES` (model migration). The "simulated HSM" is a Web Crypto wrapper exposing sign/verify/unwrap with a key generated `extractable: false`. Spec: `docs/superpowers/specs/2026-05-24-hsm-lesson-design.md`.

---

## Task 1: Add `"hsm"` family choice + migration

**Files:** `core/models.py`, auto-generated migration

- [ ] Add `("hsm", "HSM")` to `Algorithm.FAMILY_CHOICES` (between `pq` and any new line).
- [ ] Run `.venv/bin/python manage.py makemigrations core` → expect a new `0005_alter_algorithm_family.py`.
- [ ] Run `.venv/bin/python manage.py migrate core`.
- [ ] Verify pytest still 72 passing.
- [ ] Commit `feat(core): allow 'hsm' as Algorithm family`.

## Task 2: `hsm_simulator.js` — Web Crypto wrapper

**Files:** `static/algorithms/hsm/hsm_simulator.js`

- [ ] Exports: `generateVaultKey()`, `sign(message)`, `verify(message, sigHex)`, `unwrapKey(blobHex)`.
- [ ] Uses `crypto.subtle.generateKey({name: "RSA-PSS", modulusLength: 2048, ...}, false, ["sign", "verify"])` — `extractable: false` is the load-bearing pedagogy.
- [ ] Stores the keypair in a module-level let so it persists across function calls within one page load.
- [ ] Skips tests (no unit tests for Web Crypto path; manual smoke covers it).
- [ ] Commit `feat(hsm): hsm_simulator.js — Web Crypto vault`.

## Task 3: Validators + walkthroughs

**Files:** `static/algorithms/hsm/validators.js` + `tests/validators.test.js`

- [ ] `info` validator.
- [ ] `hsm_operation` validator (permissive): accepts any non-empty input, runs sign / verify / unwrap based on which "operation type" the user selected (multi-input shape: `{op: "sign"|"verify"|"unwrap", input: text, sig: optional}`). On success writes `{hsm_last_op, hsm_last_input, hsm_last_output, hsm_verify_result}`.
- [ ] Walkthroughs for `hsm_operation` (3 rungs explaining what the user just demonstrated).
- [ ] Validator is async (Web Crypto) — wizard already supports async validators from AES.
- [ ] In Node tests, only test the validation paths (empty input rejected). Skip the encryption-result tests.
- [ ] Commit `feat(hsm): validators`.

## Task 4: Codegen

**Files:** `static/algorithms/hsm/codegen.js` + `tests/codegen.test.js`

- [ ] `full_script(state)` emits Python using `boto3` (AWS KMS) sample: encrypt/decrypt with a KMS-held key. Comments note that `pip install boto3` and AWS credentials are required.
- [ ] Per-step stubs return `""`.
- [ ] Tests for the boto3 imports + `kms.encrypt` / `kms.decrypt` calls in output.
- [ ] Commit `feat(hsm): codegen — boto3 AWS KMS sample`.

## Task 5: Template branch for `simulated-hsm` step

**Files:** `core/templates/core/lesson.html`

- [ ] Add a slug-keyed branch for `step.slug === 'simulated-hsm'` showing:
  - 3 buttons (Sign / Verify / Unwrap)
  - Text input
  - Optional second input for "signature" field when verifying
  - Result display panel showing `state.hsm_last_op`, `state.hsm_last_output`, etc.
- [ ] Buttons call `check()` with `multiInput.op` set to the chosen operation.
- [ ] Commit `feat(hsm): template branch for simulated-hsm step`.

## Task 6: Fixtures + fixture-load test

**Files:** `algorithms/hsm/fixtures.json` + extend `core/tests/test_fixtures.py`

- [ ] Algorithm pk=5, lesson pk=5, steps pks=51-58 (8 steps).
- [ ] intro_template under 200 chars.
- [ ] Slugs: `intro, the-vault-analogy, operations-api, simulated-hsm, kek-hierarchy, real-world-kms, where-required, done`.
- [ ] step 4 is the only `input-text` kind (with operation buttons added via template branch).
- [ ] Run loaddata; verify 10 objects installed.
- [ ] Append `test_hsm_fixture_loads` to `test_fixtures.py`.
- [ ] Commit `feat(hsm): fixtures + fixture-load test`.

## Task 7: Manual smoke

- [ ] Visit `/algorithms/hsm/learn/key-vaults/`.
- [ ] Walk all 8 steps. Step 4: sign "hello", copy the signature, verify → should pass. Tamper a byte, verify → should fail.
- [ ] Open devtools console; confirm `Alpine.$data(...).hsm_simulator?.privateKey` is an opaque CryptoKey (no raw bytes).
- [ ] Fix any issues; commit if needed.

## Verification

- [ ] All tests green.
- [ ] HSM card on landing.
- [ ] Step 4 sign/verify/unwrap roundtrip works.
- [ ] Other lessons unaffected.
