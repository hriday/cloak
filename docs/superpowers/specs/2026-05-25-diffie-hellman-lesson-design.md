# Diffie-Hellman (classical) Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach classical Diffie-Hellman (mod-p) as a 7-step lesson that builds the 1976 handshake from first principles: the problem (two strangers, a public channel, an eavesdropper), the math primer (modular exponentiation), the protocol itself, a hand-computed exchange with small numbers, the discrete-log assumption that makes it secure, real-world parameter choices (RFC 3526 groups, Logjam, the move to ECDH), and a Python codegen using `cryptography.hazmat.primitives.asymmetric.dh`.

The X25519 lesson already includes a short DH warmup step. This lesson is the deeper, standalone treatment: more math, more history, more context on why mod-p DH still matters even after ECDH took over. Pedagogically it pairs with X25519 — a learner can do either first, but doing this one first makes X25519 feel like an optimization of an already-understood idea.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. X25519 (designed) — includes a brief DH warmup step
9. **Diffie-Hellman (classical)** (this design) — the deeper standalone DH treatment
10. Ed25519 (future)
11. Kyber / ML-KEM (future PQ-KEM lesson — the forward-link from this one)
12. Caesar / Vigenère (future)

Pedagogically: classical DH is the conceptual ancestor of every modern key-exchange primitive. Even if production code rarely uses mod-p DH directly anymore, the *idea* (commutative exponentiation in a public group) is load-bearing. The lesson explicitly forward-links to X25519 (same idea, different group, smaller params, immune to precomputation attacks) and to Kyber (the post-quantum replacement).

## Non-goals

- The full algebraic structure (cyclic groups, generators of subgroups, quadratic residues). Mentioned briefly; not formalized.
- Static vs ephemeral DH (DHE) — covered as a one-paragraph sidebar in the recap.
- Authenticated DH (signing the exchange to prevent MITM). Mentioned in passing; "TLS 1.3 bundle territory."
- ECDH and X25519 — already taught in the X25519 lesson; this lesson links forward, doesn't re-teach.
- Active MITM attacks. Mentioned in a sentence; no dedicated step.
- A JS animation of the discrete-log brute force. Considered and skipped — adds complexity without much pedagogical lift.
- Implementing modular exponentiation by hand for the walkthrough. Python's `pow(B, a, p)` and JS's `BigInt` exponent loop both do it; learners don't need to build it.

## User experience

The lesson lives at `/algorithms/diffie-hellman/learn/the-1976-handshake/`. Diffie-Hellman appears as a new card on the landing page. `family: asymmetric`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | The problem: Alice and Bob have never met. They want to encrypt messages with the same key. Eve listens to every byte sent. How? Pre-1976 answer: physical key exchange (courier, locked briefcase). Whitfield Diffie + Martin Hellman's 1976 paper "New Directions in Cryptography" introduced a math trick that lets them agree over a public channel. THE foundational paper of modern public-key crypto — Turing Award 2015. |
| 2 | `modular-exp` | `info` (with widget) | Math primer: modular exponentiation. `g^x mod p`. Worked example with `g=5`, `p=23`, `x=6`: `5^6 = 15625`, `15625 mod 23 = 8`. Why mod p? Without it, `g^x` grows exponentially. With it, the value stays in `[0, p-1]`, but recovering `x` from `g^x mod p` is *hard* — that's the discrete log problem, the assumption this whole lesson sits on. |
| 3 | `the-handshake` | `info` | The protocol step by step. Public params: prime `p`, generator `g`. (1) Alice picks secret `a`, sends `A = g^a mod p`. (2) Bob picks secret `b`, sends `B = g^b mod p`. (3) Alice computes `s = B^a mod p = g^(ab) mod p`. (4) Bob computes `s = A^b mod p = g^(ab) mod p`. Both arrive at the same `s`. Eve sees `p, g, A, B` but cannot compute `g^(ab)` without solving discrete log. The key insight: exponentiation commutes — `(g^a)^b = (g^b)^a` — and that's the entire trick. |
| 4 | `do-a-handshake` | `input-numeric` | Interactive. Page fixes `p=23`, `g=5`, Alice's secret `a=6` (computes `A=8`), Bob's secret `b=15` (computes `B=19`). User computes the shared secret `s = B^a mod p = 19^6 mod 23`. Validator accepts `2`. Hint walks the modular exponentiation step by step. |
| 5 | `discrete-log` | `info` | The security assumption. Given `p, g, y = g^x mod p`, find `x`. For small `p` (like 23), brute force trivially — try `x=1, 2, 3, ...` until `g^x mod p = y`. For `p ≈ 2^2048`, no known classical algorithm runs in reasonable time. The best general method is the General Number Field Sieve (sub-exponential). Note: Shor's algorithm on a fault-tolerant quantum computer solves discrete log in polynomial time — same fate as RSA. Post-quantum KEMs (Kyber) are the future-proof replacement. |
| 6 | `real-world-params` | `info` | What real DH looks like in production. RFC 3526 well-known groups: Group 14 = 2048-bit MODP prime, Group 15 = 3072-bit, Group 16 = 4096-bit, etc. Why standardized public groups? Two reasons: (1) it lets peers skip parameter negotiation, and (2) it prevents each implementer rolling their own prime, which is risky — a maliciously chosen prime can be backdoored (Dual_EC_DRBG-style). Logjam attack (2015): 512-bit groups had been *precomputed* by attackers; 1024-bit groups were within reach of nation-state budgets; 2048-bit is the recommended floor. The industry shift to ECDH (X25519): smaller params, faster, no precomputation attack surface because each curve point is essentially unique to the exchange. |
| 7 | `done` | `info` | Recap of the 1976 handshake. Codegen renders Python using `cryptography.hazmat.primitives.asymmetric.dh` showing a 2048-bit DH exchange between two parties with assert-equal at the end. Forward-links: X25519 (same idea, on a curve, smaller keys, immune to Logjam-style precomputation), Kyber / ML-KEM (the post-quantum replacement when Shor's algorithm lands). Sidebar: static vs ephemeral DH (DHE) — production TLS uses ephemeral so each session gets forward secrecy. |

### Step 2 in detail — `modular-exp` widget

Inline panel renders the worked example with intermediate values:

```
5^1 mod 23 =  5
5^2 mod 23 = 25 mod 23 =  2
5^3 mod 23 = 10
5^4 mod 23 = 50 mod 23 =  4
5^5 mod 23 = 20
5^6 mod 23 = 100 mod 23 = 8
```

No input — the step is `info`, and the widget exists just to make modular exponentiation concrete before the user is asked to do one themselves in step 4.

### Step 4 in detail — `do-a-handshake`

Prompt:

> Alice and Bob agreed on public parameters `p = 23`, `g = 5`. Alice picked her secret `a = 6` and sent Bob `A = g^a mod p = 5^6 mod 23 = 8`. Bob picked his secret `b = 15` and sent Alice `B = g^b mod p = 5^15 mod 23 = 19`.
>
> You are Alice. Compute the shared secret `s = B^a mod p = 19^6 mod 23`.

Validator: parses an integer, equals `2`. Hint walks the math:

`19² mod 23 = 361 mod 23 = 16. 19⁴ = 16² mod 23 = 256 mod 23 = 3. 19⁶ = 19⁴ · 19² mod 23 = 3 · 16 mod 23 = 48 mod 23 = 2.`

Note: this is intentionally the *same* worked example used in the X25519 lesson's `do-a-dh` step. If a learner did X25519 first, this step is a quick refresher. If they did this one first, the X25519 lesson's DH warmup will feel familiar by design.

## Architecture

### New algorithm record

`algorithms/diffie-hellman/fixtures.json`. Algorithm PK 16, slug `diffie-hellman`, name `Diffie-Hellman`, family `asymmetric`. Lesson PK 16, slug `the-1976-handshake`, title `"Diffie-Hellman: the 1976 handshake"`. Steps PKs 161–167.

`Algorithm.intro_template` is `max_length=200`; the path (e.g. `core/algorithms/diffie-hellman/intro.html`) fits trivially.

### New algorithm module directory

`static/algorithms/diffie-hellman/`:

| File | Responsibility |
|---|---|
| `validators.js` | `dh_compute`, `info`, plus walkthrough hints. |
| `codegen.js` | `full_script` emits Python using `cryptography.hazmat.primitives.asymmetric.dh`. Per-step lines accumulate the running snippet. |
| `tests/*.test.js` | Validator + codegen tests. |

No separate math module is needed: the only arithmetic the JS does is `pow(B, a, p)`, which a small `BigInt` modular-exponentiation helper inside `validators.js` covers in ~10 lines.

### Validators

| Key | Validates | Writes |
|---|---|---|
| `dh_compute` | parses integer, equals `2` | `{dh_alice_secret: 6, dh_bob_secret: 15, dh_shared: 2}` |
| `info` | always ok | `{}` |

### State namespace

`dh_` prefix.

## Data flow

```
Step 1, 2, 3 (info)       no input. state empty.

Step 4 (do-a-handshake)   input: integer
  ↓ dh_compute validator
state += { dh_alice_secret: 6, dh_bob_secret: 15, dh_shared: 2 }

Step 5, 6 (info)          no input. May interpolate dh_shared in lead-in copy
                          ("you just computed s=2 in a 23-element group — now
                          imagine that group has 2^2048 elements").

Step 7 (done)             info. Codegen uses the running script accumulated
                          across steps + final state to render the full .py.
```

## Codegen

Per-step lines build up to a single runnable script. Final `full_script` (step 7) target:

```python
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Generate 2048-bit DH parameters. In production, prefer a well-known RFC 3526
# group (Group 14 = 2048-bit MODP) to avoid per-peer parameter generation.
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Each party generates a private key and derives a public key.
alice_priv = parameters.generate_private_key()
bob_priv   = parameters.generate_private_key()

alice_pub = alice_priv.public_key()
bob_pub   = bob_priv.public_key()

# Each party computes the shared secret using their private key
# and the peer's public key. They must agree.
alice_shared = alice_priv.exchange(bob_pub)
bob_shared   = bob_priv.exchange(alice_pub)
assert alice_shared == bob_shared, "DH agreement failed"

print("Alice pub :", alice_pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode())
print("Bob pub   :", bob_pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode())
print("shared    :", alice_shared.hex())

# In real systems, never use the raw shared secret as a symmetric key.
# Run it through HKDF (or similar KDF) to derive AES / ChaCha20 / HMAC keys.
```

The codegen module emits this script with the small-number values from step 4 (`p=23, g=5, a=6, b=15, s=2`) as a leading comment block — "here's the same idea with toy numbers" — so the downloaded script cross-references the lesson the learner just walked.

## Error handling

### Step 4 — `dh_compute`
- Not parseable → `"Enter a whole number."`
- Negative or out of `[0, p-1]` → `"The shared secret is in [0, 22]."`
- Wrong value → `"Compute 19^6 mod 23. Hint: 19² mod 23 = 16, 19⁴ mod 23 = 3, 19⁶ = 19⁴ · 19² mod 23 = 48 mod 23 = 2."`

### Info steps
- No errors. "Continue" advances unconditionally.

## Template branches

Step 2's widget (the `5^k mod 23` table) is presentational only and can live in the step's `prompt_template` as a fenced code block — no new partial needed. All seven steps reuse existing `lesson.html` branches (`info` and `input-numeric`).

No template changes.

## Testing

### JS validator tests
- `dh_compute` happy: accepts `2`, `"2"`, `" 2 "`.
- `dh_compute` rejections: `"abc"`, `"3"`, negative, empty.
- `dh_compute` writes `dh_alice_secret`, `dh_bob_secret`, `dh_shared`.

### JS codegen tests
- `full_script` against a fixed `state` snapshot contains: `from cryptography.hazmat.primitives.asymmetric import dh`, `generate_parameters(generator=2, key_size=2048)`, `.exchange(`, `assert alice_shared == bob_shared`, and a comment line mentioning the toy `p=23, g=5` numbers.
- Per-step codegen lines append cleanly (no duplicate imports across steps).

### Fixture-load test
- Extend `core/tests/test_fixtures.py` to load `algorithms/diffie-hellman/fixtures.json` and assert 1 Algorithm + 1 Lesson + 7 Step rows with the expected slugs and orders.

### Manual smoke
- Walk all 7 steps; verify step 4 accepts `2` and rejects everything else with the hinted walkthrough.
- Run the downloaded Python script with `cryptography` installed; confirm `alice_shared == bob_shared` and that hex prints.

## Files touched

| File | Change |
|---|---|
| `algorithms/diffie-hellman/fixtures.json` | CREATE |
| `static/algorithms/diffie-hellman/validators.js` | CREATE |
| `static/algorithms/diffie-hellman/codegen.js` | CREATE |
| `static/algorithms/diffie-hellman/tests/validators.test.js` | CREATE |
| `static/algorithms/diffie-hellman/tests/codegen.test.js` | CREATE |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No changes to `core/models.py`, `core/views.py`, or `lesson.html` — the lesson reuses existing `info` and `input-numeric` step kinds.

## Open questions / deferred

- **MITM attacks.** An active attacker who can intercept and rewrite `A` and `B` defeats unauthenticated DH trivially (classic key-substitution). Step 6 mentions this in one sentence ("real deployments authenticate the exchange — TLS 1.3 signs it with the server's certificate"). A dedicated MITM step felt like scope creep for a lesson whose load-bearing idea is "exponentiation commutes." Recommend keeping it a mention.
- **Discrete-log brute-force animation.** A JS widget that visibly tries `x=1, 2, 3, ...` against a small `y = g^x mod p` would be fun and reinforce step 5's "easy for small p, hard for big p" framing. Skipped for now — adds module surface area, and the prose explanation is already clear. Could be a follow-up if learners want it.
- **Static vs ephemeral DH (DHE).** Covered as a one-paragraph sidebar in step 7. Real TLS uses DHE so each session gets forward secrecy. A standalone "forward secrecy" lesson is the right home for the full treatment.
- **HKDF after the raw shared secret.** Real systems never use raw DH output as a symmetric key. The codegen has a closing comment about this; the full treatment belongs in a future HKDF lesson (same as X25519 defers it).
- **Why `g=2` in `generate_parameters`.** The `cryptography` library accepts `generator=2` or `generator=5`. The lesson uses `g=2` in the Python (production default) and `g=5` in the toy example (small enough to enumerate). The codegen comment notes the discrepancy is intentional.
