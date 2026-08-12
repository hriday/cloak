# yescrypt, gost-yescrypt, argon2id lessons — Design

**Date:** 2026-08-12
**Status:** Approved

## Goal

Add three password-hashing lessons — yescrypt, gost-yescrypt, argon2id — as
separate algorithm cards. Together with the existing password-hashing survey
and bcrypt lessons, they complete the modern Linux `crypt(5)`/libxcrypt story:
these three are exactly the "strong" hash methods behind the `$y$`, `$gy$`,
and `$argon2id$` prefixes in `/etc/shadow`.

## Decisions (from brainstorming)

1. **Three separate lessons**, one algorithm card each (like bcrypt), not an
   extension of the survey lesson.
2. **Light, bcrypt-style interactivity**: mostly narrative info steps with one
   substantive interactive moment per lesson. No canvas, no heavy widgets.
3. **Linux-flavored framing**: each lesson shows its real `/etc/shadow` hash
   format, names where you'd meet it (Fedora/Debian defaults, GOST
   compliance), and the Done-step codegen produces a script usable against a
   real shadow entry.
4. **Approach A — synthetic demos, shared core** (chosen over "no demo code"
   and "real WASM/JS implementations"): follow the bcrypt lesson's honesty
   pattern — a toy in-browser demo with the right *shape*, next to cited
   real-implementation benchmark numbers. No real yescrypt/argon2 in the
   browser.

## Catalog placement

Three new `Algorithm` rows, family `hash`, status `live`:

| slug | name | order | PK | lesson slug |
|---|---|---|---|---|
| `yescrypt` | yescrypt | 32 | 32 | `the-default-nobody-noticed` |
| `gost-yescrypt` | GOST-yescrypt | 33 | 33 | `same-engine-russian-paperwork` |
| `argon2id` | Argon2id | 34 | 34 | `the-one-the-committee-picked` |

Step PKs follow the house convention: `<algo-pk> * 10 + order` (e.g. yescrypt
steps 321–327). Landing page grows to 34 cards.

**New bundle** in `core/bundles.py`: slug `how-linux-stores-your-password`,
title "How Linux stores your password", algorithms
`["password-hashing", "bcrypt", "yescrypt", "gost-yescrypt", "argon2id"]`,
with per-station prose walking from "why not SHA-256" through
`/etc/shadow` formats to the modern defaults.

## Lesson structures

All steps use existing `Step.kind` values. `intro_template` stays under the
model's 200-char ceiling.

### yescrypt — "The default nobody noticed" (7 steps)

| # | slug | kind | validator | notes |
|---|---|---|---|---|
| 1 | intro | info | info | `$y$` in `/etc/shadow`; default in Fedora 35+, Debian 11+, Ubuntu 22.04+; most-deployed password hash almost nobody has heard of |
| 2 | scrypt-lineage | info | info | Colin Percival's scrypt (2009) → Solar Designer's yescrypt (PHC finalist, special recognition); why memory-hardness kills GPU/ASIC cracking economics |
| 3 | feel-the-memory | input-numeric | memory_cost | Interactive. Dropdown of memory sizes (e.g. 1, 4, 16, 64 MiB) + password field. Toy mixer runs; shows wall-time + bytes touched next to cited real-yescrypt timings |
| 4 | anatomy-of-a-y-hash | info | info | Decode `$y$j9T$SALT$HASH`: `j9T` params encoding, itoa64 alphabet, where salt ends and hash begins |
| 5 | rom-and-scale | info | info | yescrypt's optional ROM (multi-GiB shared table) for large-scale auth servers; why that feature exists |
| 6 | yescrypt-vs-argon2 | info | info | Same goal, different bets; why libxcrypt shipped yescrypt as default while OWASP recommends argon2id |
| 7 | done | info | done | Full script via codegen; real-world notes |

### gost-yescrypt — "Same engine, Russian paperwork" (6 steps)

| # | slug | kind | validator | notes |
|---|---|---|---|---|
| 1 | intro | info | info | `$gy$`; exists for Russian regulatory (GOST) compliance; same yescrypt engine inside |
| 2 | streebog | info | info | GOST R 34.11-2012 "Streebog" hash in one screen; role as a national-standard SHA-2 analog |
| 3 | the-wrapper | info | info | The construction: HMAC-Streebog around the yescrypt core — compliance by wrapping, not by reinventing the KDF |
| 4 | spot-the-difference | choose-from-list | spot_difference | Interactive. Same password/salt/params rendered as `$y$...` and `$gy$...`; learner picks which field changed (prefix + hash output; salt/params identical). Custom three-button branch (stock choose-from-list renderer is RSA-specific) |
| 5 | when-to-use | info | info | Honest scoping: required for Russian-market compliance, otherwise use yescrypt/argon2id; note some distros compile libxcrypt without GOST |
| 6 | done | info | done | ctypes script with `$gy$` prefix + graceful "GOST not enabled" handling |

### argon2id — "The one the committee picked" (8 steps)

| # | slug | kind | validator | notes |
|---|---|---|---|---|
| 1 | intro | info | info | Password Hashing Competition 2015 winner; `$argon2id$` in shadow (when libxcrypt has it), and everywhere in app frameworks |
| 2 | why-id | info | info | Argon2d (GPU-resistant, side-channel-leaky) vs Argon2i (side-channel-safe, weaker vs cracking) vs the id hybrid: first half data-independent, second half data-dependent |
| 3 | the-block-matrix | info | info | m KiB of 1-KiB blocks arranged in p lanes × columns; t passes of Blake2b-based mixing |
| 4 | feel-the-memory | input-numeric | memory_cost | Interactive. Same shared toy mixer, argon2-flavored param labels (m in KiB) + cited real argon2id timings |
| 5 | anatomy-of-an-argon2-hash | info | info | Decode `$argon2id$v=19$m=65536,t=3,p=4$SALT$HASH` — self-describing params, base64 fields |
| 6 | tuning | input-numeric | tuning_math | Interactive numeric: given the common web-backend params m=65536 KiB, t=3, p=4, answer "how many MiB of RAM does ONE login consume?" (answer: 64 — the point being m is *total* memory; t multiplies time, p splits lanes, neither adds RAM). Plain numeric input, no custom branch |
| 7 | argon2-vs-the-rest | info | info | vs bcrypt (no memory knob), vs yescrypt (deployed default), OWASP/RFC 9106 parameter guidance |
| 8 | done | info | done | argon2-cffi script |

## JS modules

New directories under `static/algorithms/`:

**`yescrypt/`**
- `memhard_demo.js` — the shared toy memory-hard mixer. Allocates N 1-KiB
  blocks in a `Uint32Array`, does a sequential fill pass then a
  data-dependent random-read/mix pass (scrypt's ROMix shape). Returns
  `{ms, bytesTouched, blocks, digestHex}`. Exports `CITED_YESCRYPT_MS` and
  `CITED_ARGON2ID_MS` tables (benchmark numbers from real libxcrypt /
  argon2-cffi runs on a typical 2024 laptop, clearly labeled as cited).
  Header comment mirrors `bcrypt_demo.js`: states plainly that this is NOT
  yescrypt/argon2, and why the shape is honest (memory allocated and touched
  is real; the mixing function is not).
  Node ≥19-compatible for `node --test`.
- `validators.js` — `memory_cost` (input `{password, memoryMiB}`; runs the
  mixer, writes `ys_*` state keys), `info`, `done`.
- `codegen.js` — `full_script(state)`: dependency-free Linux Python script
  using `ctypes` → `libcrypt.so.1` `crypt_r` with a `$y$` setting string,
  hashing + verifying the learner's password at their chosen params;
  comments explain the setting-string encoding.

**`gost-yescrypt/`**
- `validators.js` — `spot_difference` (choose-from-list answer check),
  `info`, `done`. Imports nothing heavy.
- `codegen.js` — same ctypes approach with `$gy$`; catches the null return
  from `crypt_r` and prints "your libxcrypt was built without GOST support"
  with the Fedora/Debian package note.

**`argon2id/`**
- `validators.js` — `memory_cost` (imports the mixer from
  `../yescrypt/memhard_demo.js`, writes `a2_*` state keys), `tuning_math`
  (checks the RAM arithmetic), `info`, `done`.
- `codegen.js` — `argon2-cffi` script: `PasswordHasher` with the learner's
  m/t/p, hash, verify, `check_needs_rehash`, timing printout.

Import precedent: hybrid's `math.js` re-exports from `rsa/math.js`.

## Wizard + template integration (small, follows bcrypt exactly)

`static/core/wizard.js`:
- NO `DEMO_FILENAMES` entries: the template branches only call `check()`;
  the validators import the mixer directly (precedent: hkdf, hybrid,
  length-extension have no demo entry). The argon2id re-export shim is
  therefore not needed either.
- `hasCustomInputBranch` SLUGS: add `"feel-the-memory"` (shared by yescrypt
  and argon2id) and `"spot-the-difference"` (gost-yescrypt).
- `MULTI_INPUT_SLUGS`: add `"feel-the-memory"` (`{password, memoryMiB}`).
  `spot-the-difference` stays single-input (`inputValue`).
- `EXPLORATORY_SLUGS`: add both `"feel-the-memory"` and
  `"spot-the-difference"` — their branches render their own Continue, so a
  successful check must not auto-advance past the result panel.

`core/templates/core/lesson.html`:
- The default `input-numeric` renderer does not consult
  `hasCustomInputBranch` (bcrypt's `time-the-cost` currently double-renders
  a stray "your answer" box) and the stock `choose-from-list` renderer is
  hardwired to RSA's `coprimeOptions`. Fix both guards:
  `!hasCustomInputBranch(step)` is added to the `input-numeric` and
  `choose-from-list` conditions.
- TWO new input branches: `feel-the-memory` (password + memory picker +
  run button) and `spot-the-difference` (three choice buttons). Plus result
  panels. `tuning` uses the stock numeric renderer; no other branches.

No model, view, or API changes. No Python validator mirrors (JS-only house
pattern for post-RSA lessons; server-side `progress_service` has no sequence
for these algorithms, so state is accepted as-is — same as bcrypt).

## Error handling

- Mixer guards: cap memory dropdown at 64 MiB; catch allocation failure and
  return a hint ("your browser refused the allocation — pick a smaller
  size") rather than crashing the step.
- Password guard: same printable-ASCII/≤200-char check as bcrypt's
  `checkPassword`, same hint wording shape.
- Codegen scripts degrade clearly: ctypes scripts detect non-Linux
  (`libcrypt.so.1` missing) and print what to install/where to run; `$gy$`
  script additionally handles GOST-less libxcrypt.

## Testing

- `core/tests/test_fixtures.py`: one loader test per new algorithm
  (structure: 1 algorithm + 1 lesson + N steps, PK scheme, kinds,
  `intro_template` ≤ 200 chars) — same shape as the chacha20 fixture test.
- Landing/catalog test updated: 34 live algorithms; new bundle appears and
  resolves all five slugs.
- `static/algorithms/yescrypt/tests/`: `node --test` for the mixer
  (deterministic digest for fixed inputs, bytesTouched math, allocation cap)
  and `memory_cost` validator (happy path + each hint).
- `static/algorithms/gost-yescrypt/tests/` and `argon2id/tests/`: validator
  unit tests (`spot_difference` right/wrong, `tuning_math` arithmetic,
  `memory_cost` state keys).
- Codegen tests: `full_script` output contains the learner's params and the
  key API calls (string assertions, like existing codegen tests).

## Out of scope

- No changes to the existing password-hashing survey or bcrypt lesson
  content (their cross-references still read correctly).
- No real yescrypt/argon2 implementations in the browser (WASM or JS).
- No server-side validation sequences in `progress_service.py`.
