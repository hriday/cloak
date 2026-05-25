# Kyber (ML-KEM) Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach Kyber / ML-KEM as an 8-step lesson that builds a post-quantum key encapsulation mechanism from scratch: classical lattices and Learning-With-Errors first, then polynomial rings, then a toy Kyber keygen / encapsulation / decapsulation, then the real parameter sets and TLS 1.3 hybrid deployment. The lesson ends with Python codegen using `kyber-py` (with `pqcrypto` mentioned as an alternative).

This is the site's first **post-quantum** lesson and the first algorithm in the `pq` family. The pedagogical premise is that learners arriving here already know X25519 (the previous lesson). Kyber is framed throughout as "what replaces X25519 when Shor's algorithm shows up" — same goal (two parties end up with a shared secret), different hard problem (module-lattice instead of discrete log).

The math is the hardest of any lesson on the site. We tame it with toy parameters (`q=257, n=4, k=2`) chosen so the noise budget actually closes by hand and so coefficient arithmetic stays single-byte.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. X25519 (designed)
9. Ed25519 (future, signatures on Curve25519)
10. **Kyber / ML-KEM** (this design)
11. Dilithium / ML-DSA (future, PQ signatures)
12. SPHINCS+ (future, hash-based PQ signatures)
13. Caesar / Vigenère (future)

Pedagogically: comes immediately after X25519 so the "key exchange / KEM" mental model is fresh. The framing "X25519 dies the day a quantum computer boots; Kyber survives it" makes the motivation obvious and sets up the future Dilithium lesson (which is to Ed25519 what Kyber is to X25519).

## Non-goals

- Real Kyber512 / Kyber768 / Kyber1024 implementation in JS. The reference parameters (`q=3329`, `n=256`, `k=2/3/4`) are too much code and the centered-binomial noise distribution is subtle. Use toy parameters end-to-end.
- The full Number Theoretic Transform (NTT) used for fast polynomial multiplication in production Kyber. The lesson uses schoolbook polynomial multiplication on the toy size.
- The Fujisaki-Okamoto transform that lifts CPA-secure Kyber.CPAPKE into the IND-CCA2 ML-KEM construction. Mentioned, not walked.
- The full module-LWE / module-SIVP security reduction. Referenced; not taught.
- Compression (`Compress_q`, `Decompress_q`) of ciphertexts. Real Kyber compresses `u` and `v` to save bytes; the lesson skips this — toy params don't need it.
- Multi-bit encapsulation. Real Kyber encapsulates a 256-bit shared secret per call; the toy version encapsulates **one bit** at a time, which is enough to teach the structure.
- Dilithium (PQ signatures) — separate future lesson.
- SPHINCS+ (hash-based PQ signatures) — separate future lesson.
- Hybrid KEX as its own step. X25519+Kyber hybrid is mentioned in step 7's prose but not walked as a separate computation.

## User experience

The lesson lives at `/algorithms/kyber/learn/lattice-kem/`. Kyber appears as the **first** card under a newly populated "Post-Quantum" section on the landing page (the `pq` family choice exists in `core/models.py` already; this lesson finally puts a row in it). `family: pq`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | Why post-quantum. Peter Shor's 1994 algorithm runs on a fault-tolerant quantum computer and breaks RSA, classical DH, ECDH, ECDSA, EdDSA in polynomial time — every public-key primitive taught on the site up to this point. Quantum-safe families: **lattice-based** (Kyber, Dilithium), **code-based** (Classic McEliece), **hash-based** (SPHINCS+), **isogeny-based** (SIKE — broken classically in 2022, cautionary tale). NIST PQC competition 2016 → 2024: Kyber won as the KEM. Standardized as **ML-KEM** in FIPS 203, August 2024. Already deployed: Chrome, Firefox, and Cloudflare ship TLS 1.3 hybrid KEX combining X25519 with ML-KEM-768 (`X25519MLKEM768`). |
| 2 | `lwe-warmup` | `info` (with widget) | Learning With Errors, the underlying hard problem. Given a matrix `A` and a vector `b` such that `b ≈ A·s + e mod q` for some small secret `s` and small noise `e`, recover `s`. Without `e`, this is Gaussian elimination (easy). With `e`, even small noise destroys the linear-algebra approach — and the problem is believed hard for quantum computers too. Worked toy: `q=17`, `A = [[1,4],[3,2]]`, `s = [2,1]`, `e = [0,1]`, then `b = A·s + e = [6, 9] mod 17`. The widget shows the equation; no input required. Then says: "now imagine A is 1000×1000 and the entries are mod 3329 — that's the real Kyber regime." |
| 3 | `polynomial-rings` | `info` | Module-LWE upgrades plain LWE by replacing integers with polynomials. The ring is `R_q = Z_q[X]/(X^n + 1)`. For toy: `q = 257`, `n = 4`. A "polynomial" is 4 coefficients in `[0, 257)`. Addition is coefficient-wise mod 257. Multiplication is normal polynomial product reduced modulo `X^4 + 1` — which means **`X^4 = −1`**: anything of degree ≥ 4 wraps around with a sign flip. Worked example: `(1 + 2X) · (3 + X^3) = 3 + X^3 + 6X + 2X^4 = 3 + 6X + X^3 + 2·(−1) = 1 + 6X + X^3` in R_257. |
| 4 | `keygen` | `info` (with widget) | Toy Kyber keygen, `q=257, n=4, k=2`:<br>1. Sample random matrix `A` (k×k of polynomials in R_q, uniform coefficients).<br>2. Sample small secret vector `s ∈ R_q^k` (coefficients in `{−1, 0, 1}`).<br>3. Sample small error vector `e ∈ R_q^k` (coefficients in `{−1, 0, 1}`).<br>4. Compute `t = A·s + e mod q`.<br>5. Public key: `(A, t)`. Private key: `s`.<br>The page seeds a fixed PRNG so the same `A, s, e, t` render every visit. Each polynomial is rendered as a 4-coefficient row. |
| 5 | `encapsulation` | `input-numeric` | Toy encapsulation. Sender does:<br>1. Pick a 1-bit message `m ∈ {0, 1}`. Encode as a polynomial: `m̂ = m · ⌊q/2⌉ = m · 128` in coefficient 0.<br>2. Sample small randomness `r ∈ R_q^k` and small errors `e1 ∈ R_q^k`, `e2 ∈ R_q` (all coefficients in `{−1, 0, 1}`).<br>3. Compute `u = Aᵀ·r + e1 mod q`.<br>4. Compute `v = tᵀ·r + e2 + m̂ mod q`.<br>5. Ciphertext is `(u, v)`.<br>Interactive: the page fixes all of `A, t, r, e1, e2, m` to the toy values from step 4 and the lesson seed; the page computes `u` fully and shows it; the page asks the learner to compute **one coefficient of v** (specifically `v[0]`, the constant term — the one carrying the message bit). Validator parses an integer in `[0, 257)` and checks against the canonical answer. |
| 6 | `decapsulation` | `info` | Recipient's side: compute `m' = v − sᵀ·u mod q`. Each coefficient should now be `≈ m̂[i] + small_noise`. Decode bit-by-bit: each coefficient is rounded — if it's closer to `0`, the bit is `0`; if it's closer to `q/2 = 128`, the bit is `1`. Equivalently: `bit = 1 iff coefficient ∈ [64, 192]` for `q = 257`. The page walks the recipient's full computation on the lesson's toy ciphertext, shows each coefficient of `v − sᵀ·u`, points at coefficient 0 (which should land near 128 since `m=1`), and decodes back to `m=1`. Explains the noise budget: products of two `{−1,0,1}` polynomials in `R_257[X]/(X^4+1)` have coefficients bounded by `n·k = 8` in magnitude, the noise sum is bounded by roughly `2·n·k + 1 = 17`, well below `q/4 ≈ 64`. |
| 7 | `real-kyber-and-hybrid` | `info` | Real Kyber: three parameter sets. **Kyber512** (`k=2`, ~AES-128 security), **Kyber768** (`k=3`, ~AES-192, ML-KEM-768 in FIPS 203, the default for TLS), **Kyber1024** (`k=4`, ~AES-256). All use `q=3329`, `n=256`. Public key ~800 / ~1184 / ~1568 bytes; ciphertext ~768 / ~1088 / ~1568 bytes. Much larger than X25519's 32-byte keys — bytes-on-the-wire cost is real, but still well within TLS handshake budgets. Real Kyber wraps the toy CPAPKE construction in the **Fujisaki–Okamoto** transform to get IND-CCA2 (the M-LWE assumption + FO ⇒ chosen-ciphertext security). **Hybrid deployment:** TLS 1.3 `X25519MLKEM768` (Cloudflare, Chrome 124+, Firefox 132+) sends both an X25519 public key and an ML-KEM-768 public key; both sides derive both shared secrets; the two secrets are concatenated and HKDF-extracted. The combined secret is safe as long as **either** primitive holds — quantum-safe if Kyber holds, classically-safe if Kyber breaks. |
| 8 | `done` | `info` | Recap of what was learned: LWE → Module-LWE → Kyber. Codegen renders Python using `kyber-py` (pure-Python, easy `pip install`). Sample script: generate keypair, encapsulate, decapsulate, assert shared secrets match. Comment shows the `pqcrypto` alternative (`pip install pqcrypto`, wraps NIST reference C code). Forward-links: **Dilithium / ML-DSA** (PQ signatures, also lattice-based, also FIPS-standardized in 2024 as FIPS 204); **SPHINCS+ / SLH-DSA** (hash-based PQ signatures, FIPS 205, conservative fallback that relies only on hash security). |

### Toy parameters — locked-in choice with noise-budget proof

The recommended toy parameters are **`q = 257`, `n = 4`, `k = 2`**, with all small-noise coefficients sampled from `{−1, 0, 1}` (uniform). Justification:

- **Why not `q=17`.** With `q=17`, the noise tolerance is `q/4 ≈ 4`. Products of two polynomials with `{−1,0,1}` coefficients in `R_q[X]/(X^4+1)` have coefficients bounded by `n = 4` in magnitude. The decryption noise is `e^T·r − s^T·e1 + e2`, which sums `2k = 4` such products plus one small polynomial: max magnitude `2·k·n + 1 = 17`. That **already exceeds `q = 17`** — the noise blows past the modulus, not just past `q/4`. Decryption is not reliable. Confirmed by trying a couple of seeds.
- **Why `q=257`.** Noise tolerance is `q/4 ≈ 64`. Max decryption noise stays at `2·k·n + 1 = 17`. **17 < 64** by a comfortable margin; correctness holds for every choice of small `r, e, e1, e2` from `{−1,0,1}`.
- **Why `n=4`.** Smallest size where the cyclotomic `X^4 + 1` is non-trivial and shows real wrap-around. Polynomials fit on one screen line.
- **Why `k=2`.** Same `k` as Kyber512 (smallest real parameter set), so the structural claim "this is just toy Kyber512" holds. Matrix is 2×2 of polynomials — small enough to render, big enough to look like a module.
- **Coefficient encoding `m · ⌊q/2⌉ = m · 128`.** With `q=257`, midpoint is `128.5`, rounded down to `128`. Decoding threshold: bit is 1 iff coefficient is in `[⌊q/4⌉, ⌊3q/4⌉] = [64, 192]`.

### Step 5 in detail — `encapsulation`

The lesson uses a seeded PRNG so every visitor sees the same numbers. With seed `cloak-kyber-v1`, the toy keygen yields specific `A`, `s`, `e`, `t`; encapsulation samples a specific `r`, `e1`, `e2`. The actual values are generated at lesson-build time and frozen into the static module (`static/algorithms/kyber/toy_vectors.js`), with a test that re-derives them from the seed and asserts equality (so the spec doesn't drift from the implementation).

Prompt (with concrete numbers filled in at render time from the frozen vectors):

> Public parameters: `q = 257`, `n = 4`, `k = 2`. Public key `(A, t)` from the previous step. We're sending the bit `m = 1`, encoded as the polynomial `[128, 0, 0, 0]`.
>
> The randomness for this encapsulation:
>
> - `r = ([r0_coefs], [r1_coefs])`
> - `e1 = ([e1_0_coefs], [e1_1_coefs])`
> - `e2 = [e2_coefs]`
>
> The ciphertext component `u = Aᵀ·r + e1 mod 257`. (Shown computed.)
>
> The ciphertext component `v = tᵀ·r + e2 + m̂ mod 257`. **Compute v[0]** (the constant-term coefficient — the one carrying the message bit).
>
> All polynomial multiplication is in `R_257[X]/(X^4 + 1)` — degree-4 terms wrap around with a sign flip.

Validator: parses an integer in `[0, 257)`, equals the canonical `v[0]` for the frozen vectors. Hint walks the dot product coefficient by coefficient.

The page renders the full `v` (all four coefficients) **after** the user submits, so they can see the message bit landing in coefficient 0 (`v[0] ≈ 128 + small_noise`) versus coefficients 1, 2, 3 (just small noise around 0).

### Step 6 in detail — `decapsulation`

No input. The page renders the recipient's full computation:

1. Compute `sᵀ·u mod 257`. Show the result polynomial.
2. Compute `v − sᵀ·u mod 257`. Show the result polynomial.
3. For each of the 4 coefficients, classify: `[64, 192]` → bit 1, else bit 0.
4. Show: coefficient 0 lands in `[64, 192]` → bit 1. Coefficients 1, 2, 3 are small noise near 0 → bit 0 (but for one-bit encapsulation only coefficient 0 carries the message; the others are noise).
5. Recovered `m = 1`. Matches the sender. ✅

A "noise budget" callout box explains why this worked: `m' = m̂ + (e^T·r − s^T·e1 + e2) mod q`; the noise term is bounded by `2·k·n + 1 = 17` and `17 < q/4 = 64`, so rounding is safe.

## Architecture

### New algorithm record

`algorithms/kyber/fixtures.json`. Algorithm PK 18, slug `kyber`, name `Kyber (ML-KEM)`, family `pq`. Lesson PK 18, slug `lattice-kem`, title `"Kyber: post-quantum key encapsulation"`. Steps PKs 181–188.

### New algorithm module directory

`static/algorithms/kyber/`:

| File | Responsibility |
|---|---|
| `kyber_demo.js` | Toy Kyber primitives: poly_add, poly_mul (schoolbook + reduce mod `X^4+1`), matvec_mul, matT_mul, dot, sample_small, sample_uniform. ~150–200 lines. |
| `toy_vectors.js` | Frozen vectors `{A, s, e, t, r, e1, e2, m, u, v}` for the lesson, derived from a seeded PRNG at build time. The test in `tests/toy_vectors.test.js` re-runs the seeded derivation and asserts equality so this file can't silently drift. |
| `validators.js` | `encap_coefficient` + `info` + walkthrough hints. |
| `codegen.js` | `full_script` emits Python using `kyber-py`. Comment block notes the `pqcrypto` alternative. |
| `tests/*.test.js` | Validator, codegen, kyber_demo (round-trip on the toy vectors), and toy_vectors regeneration tests. |

`kyber_demo.js` exposes pure functions; `toy_vectors.js` is data; the page calls into both to render polynomials.

### Validators

| Key | Validates | Writes |
|---|---|---|
| `encap_coefficient` | parses integer in `[0, 257)`, equals canonical `v[0]` for the frozen vectors | `{kyber_v_coeff: int}` |
| `info` | always ok | `{}` |

### State namespace

`kyber_` prefix.

## Data flow

```
Step 1 (intro)                  info. state empty.
Step 2 (lwe-warmup)             info, widget renders fixed LWE example. state empty.
Step 3 (polynomial-rings)       info, widget renders polynomial mul example. state empty.
Step 4 (keygen)                 info, widget renders A, s, e, t from frozen vectors. state empty.

Step 5 (encapsulation)          input: integer (one coefficient of v)
  ↓ encap_coefficient validator
state += { kyber_v_coeff: <int> }

Step 6 (decapsulation)          info. widget walks v - sᵀ·u, shows recovered m=1. state unchanged.
Step 7 (real-kyber-and-hybrid)  info. state unchanged.
Step 8 (done)                   info. codegen renders kyber-py script.
```

## Codegen

Per-step codegen builds toward a single runnable Python script. Final `full_script` (step 8) target:

```python
# pip install kyber-py
# Alternative: pip install pqcrypto  (wraps the NIST reference C implementation)

from kyber_py.ml_kem import ML_KEM_768

# 1. Keygen
ek, dk = ML_KEM_768.keygen()
print(f"public key:  {len(ek)} bytes")
print(f"private key: {len(dk)} bytes")

# 2. Encapsulate (sender side)
K_sender, ct = ML_KEM_768.encaps(ek)
print(f"ciphertext:  {len(ct)} bytes")
print(f"shared key:  {K_sender.hex()}")

# 3. Decapsulate (recipient side)
K_recipient = ML_KEM_768.decaps(dk, ct)
print(f"recovered:   {K_recipient.hex()}")

assert K_sender == K_recipient, "shared keys must agree"
```

The codegen module emits this script with a comment header summarizing the toy parameters the lesson walked through, so the learner sees the bridge from "what we just did by hand at `q=257, n=4, k=2`" to "what `kyber-py` does at `q=3329, n=256, k=3`."

## Error handling

### Step 5 — `encap_coefficient`
- Not parseable → `"Enter an integer."`
- Out of `[0, 257)` → `"Coefficients in R_257 are integers from 0 to 256."`
- Wrong value → `"Compute (tᵀ·r)[0] + e2[0] + m̂[0] mod 257. The dot product tᵀ·r is a polynomial; take its constant term. Add e2[0] and m̂[0] = 128. Reduce mod 257. Expected: <answer>."` (The hint is rendered with the actual numeric trail from the frozen vectors at template-render time.)

## Template branches

Steps 2, 3, 4, 5, 6 all need to render polynomials and matrices of polynomials. Rather than adding five per-step partials, introduce **one** partial `partials/step_kyber_panel.html` that takes a `panel_kind` (`"lwe" | "polymul" | "keygen" | "encap" | "decap"`) and renders the appropriate widget. The partial is dispatched from `lesson.html` by step slug. The Alpine component `kyberPanel` reads from `static/algorithms/kyber/toy_vectors.js` and `kyber_demo.js`.

This mirrors how X25519's `step_exchange.html` and `step_clamp.html` were added (one partial per visual concern), but consolidates because all five Kyber widgets share the same primitives (polynomial / matrix rendering) and adding five files for visually similar content is overkill.

No `core/models.py` change. No `Step.kind` change — steps 2, 3, 4, 6 are `info` (with a widget rendered by the partial), and step 5 is `input-numeric` (with the same widget plus the input).

## Testing

### JS validator tests
- `encap_coefficient` happy: accepts the canonical `v[0]`, accepts integer string with whitespace, accepts decimal.
- `encap_coefficient` rejections: out of `[0, 257)`, unparseable, wrong value (off by one, off by `q`).

### JS codegen tests
- `full_script({})` contains `from kyber_py.ml_kem import ML_KEM_768`, `ML_KEM_768.keygen()`, `.encaps(`, `.decaps(`, and `assert K_sender == K_recipient`.

### `kyber_demo.js` tests
- Polynomial multiplication: `(1 + 2X)·(3 + X^3) mod (X^4+1) = 1 + 6X + X^3` (in R_257).
- `X^4 = -1` wraparound: `X · X^3 mod (X^4 + 1) = -1 = q-1`.
- Round-trip test: starting from the frozen `(A, s, e, t, r, e1, e2, m=1)`, compute `u, v`, then decapsulate, then assert recovered bit equals `1`. This is the load-bearing test — it confirms the toy parameters actually work end-to-end on the lesson's frozen vectors.
- Noise budget: for 100 random `{−1,0,1}` choices of `(r, e1, e2)` against the frozen `(A, s, e)`, assert decryption always recovers `m`.

### `toy_vectors.js` regeneration test
- Re-derive `(A, s, e, t, r, e1, e2, u, v)` from the seed `cloak-kyber-v1`; assert byte-for-byte equality with the checked-in `toy_vectors.js`. Prevents accidental drift if someone tweaks the demo code.

### Fixture-load test
- Extend `core/tests/test_fixtures.py` to load `algorithms/kyber/fixtures.json` and assert 1 Algorithm (slug `kyber`, family `pq`) + 1 Lesson + 8 Step rows with the expected slugs and orders.

### Manual smoke
- Walk all 8 steps in Chrome. Verify the polynomial widgets render readably (4 coefficients per polynomial, matrices in a grid). Submit the correct `v[0]` on step 5 and confirm the post-submit reveal of the full `v` makes the "bit landed in coefficient 0" point visually obvious. Run the final Python script with `pip install kyber-py` and confirm the assertion passes.

## Files touched

| File | Change |
|---|---|
| `algorithms/kyber/fixtures.json` | CREATE |
| `static/algorithms/kyber/kyber_demo.js` | CREATE |
| `static/algorithms/kyber/toy_vectors.js` | CREATE |
| `static/algorithms/kyber/validators.js` | CREATE |
| `static/algorithms/kyber/codegen.js` | CREATE |
| `static/algorithms/kyber/tests/kyber_demo.test.js` | CREATE |
| `static/algorithms/kyber/tests/toy_vectors.test.js` | CREATE |
| `static/algorithms/kyber/tests/validators.test.js` | CREATE |
| `static/algorithms/kyber/tests/codegen.test.js` | CREATE |
| `core/templates/core/partials/step_kyber_panel.html` | CREATE |
| `core/templates/core/lesson.html` | MODIFY (route Kyber steps to the new partial) |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No changes to `core/models.py` (the `pq` family choice already exists; `kind` choices cover everything).

## Open questions / deferred

- **Codegen library choice.** Spec commits to `kyber-py` (pure Python, no compilation, single `pip install`, actively maintained as of 2025, supports ML-KEM-512/768/1024 with the FIPS 203 spec). `pqcrypto` is the runner-up — it wraps the NIST C reference implementations so it's the closest to "what production uses," but requires a C toolchain to install on some platforms. The codegen mentions `pqcrypto` as a comment alternative. If `pyca/cryptography` ships ML-KEM in 45.x (proposed; not yet stable), a future spec revision can switch the codegen to `cryptography` for consistency with the rest of the site's lessons.
- **Hybrid KEX as its own step.** Considered and rejected. The hybrid X25519+Kyber computation is not very interesting visually — you just run two key exchanges and concatenate. Step 7's prose covers the deployment story, which is the load-bearing thing. If learner feedback shows the hybrid construction needs more depth, a follow-up "hybrid KEX" step (or even its own mini-lesson) is the right add.
- **Noise distribution.** The lesson samples small-noise coefficients uniformly from `{−1, 0, 1}`. Real Kyber uses a centered binomial distribution `η = 2` or `η = 3` (which gives values in `{−η, ..., η}` with a binomial-shaped probability). The spec mentions this in step 6's noise-budget callout and step 7's "real Kyber" panel; the toy code stays uniform `{−1, 0, 1}` for simplicity and because the variance difference doesn't change the pedagogical point at `n=4, k=2`.
- **NTT.** Real Kyber uses the Number Theoretic Transform for `O(n log n)` polynomial multiplication. Toy uses schoolbook `O(n²)` because `n=4`. Mentioned in the step 7 "real Kyber" panel as one of the reasons real implementations are fast; not taught.
- **One-bit vs multi-bit encapsulation.** Real Kyber encapsulates a 256-bit shared secret in a single call by encoding all 256 bits across the coefficients of a degree-256 polynomial (each coefficient carries one bit, with the `0 ↔ ⌊q/2⌉` encoding the toy uses for one bit). The lesson encapsulates one bit and points out that "the real thing does this 256 times in parallel via the polynomial structure" — visually identical, just bigger.
