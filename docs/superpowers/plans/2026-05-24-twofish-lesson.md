# Twofish Lesson — Implementation Plan

> Use superpowers:subagent-driven-development.

**Goal:** 6-step Twofish comparison lesson (AES vs Twofish) + whitening single-step interactive + Python codegen via `pycryptodome`.

**Architecture:** New `algorithms/twofish/` + `static/algorithms/twofish/`. Lightest lesson; mostly info. Requires adding `pycryptodome` to `requirements.txt`. Spec: `docs/superpowers/specs/2026-05-24-twofish-lesson-design.md`.

---

## Task 1: Add pycryptodome dependency

**Files:** `requirements.txt`

- [ ] Append `pycryptodome>=3.20` to requirements.txt.
- [ ] Rebuild dev image: `docker compose -f docker-compose.prod.yml build` (or skip if not needed locally; the dependency is only used in Python codegen output, not by the running app).
- [ ] Commit `chore(deps): add pycryptodome for Twofish lesson codegen`.

## Task 2: Validators + walkthroughs

**Files:** `static/algorithms/twofish/validators.js` + `tests/validators.test.js`

- [ ] Create directory: `mkdir -p /Users/hriday/code/enc_algo/static/algorithms/twofish/tests`
- [ ] `whitening` validator: byte parse (hex/decimal), equals `0x5F` (= `0x6A XOR 0x35`). Wrong-value hint shows the math.
- [ ] `pick_twofish_message`: standard.
- [ ] `info`: pass-through.
- [ ] `walkthroughs.whitening`: 3 rungs ending in `0x5F`.
- [ ] Tests.
- [ ] Commit `feat(twofish): validators + walkthroughs`.

## Task 3: Codegen

**Files:** `static/algorithms/twofish/codegen.js` + `tests/codegen.test.js`

- [ ] `full_script(state)` emits Python: `from Crypto.Cipher import Twofish; from Crypto.Random import get_random_bytes; ...` showing key generation + encrypt + decrypt with `Twofish.MODE_CBC` and PKCS7-equivalent padding (manually padded since pycryptodome doesn't ship a padding helper for raw block ciphers in the same shape).
- [ ] Per-step stubs return `""`.
- [ ] Tests for the Twofish import + assert.
- [ ] Commit `feat(twofish): codegen.js`.

## Task 4: Fixtures + fixture-load test

**Files:** `algorithms/twofish/fixtures.json` + extend `core/tests/test_fixtures.py`

- [ ] Algorithm pk=7, lesson pk=7, steps pks=71-76.
- [ ] intro_template under 200 chars.
- [ ] Slugs: `intro, vs-aes, key-dependent-sboxes, whitening, encrypt-a-message, done`.
- [ ] Step 2 (vs-aes) prompt contains a markdown table comparing AES and Twofish (from the spec).
- [ ] Run loaddata; verify 8 objects installed.
- [ ] Append `test_twofish_fixture_loads` to `test_fixtures.py`.
- [ ] Commit `feat(twofish): fixtures + fixture-load test`.

## Task 5: Manual smoke

- [ ] Visit `/algorithms/twofish/learn/aes-finalist/`.
- [ ] Walk all 6 steps; whitening accepts hex + decimal.
- [ ] Fix any issues.

## Verification

- [ ] All tests green.
- [ ] Twofish card on landing.
- [ ] Lesson walks end-to-end.
- [ ] Total algorithms on landing: 7 (RSA, Hybrid, AES, 3DES, Blowfish, Twofish, HSM) if all four new lessons ship.
