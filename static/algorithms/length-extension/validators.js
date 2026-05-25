// Validators for the length-extension lesson.
//
// One substantive validator:
//   run_attack — button-press. Runs the full forge against the in-page
//                vulnerable server, then re-runs the server's own
//                verifyRequest on the forged (request, sig) and reports
//                whether the server accepts it. The "server accepts"
//                bit is the entire lesson — if it's false, the attack
//                didn't work.
//
// Plus the conventional pass-through `info` validator and the
// `walkthroughs` object that drives the 3-rung help panel.

import { forge } from "./lenext_attack.js";
import {
  givenPair,
  verifyRequest,
  SECRET_LENGTH,
  ATTACK_EXTENSION,
  ORIGINAL_REQUEST,
} from "./vulnerable_server.js";
import { bytesToHex } from "./sha256_mutable.js";

// ---- run_attack ----------------------------------------------------------

// Button-press validator. Input is ignored — the page just clicks "Run
// the attack" and we run the full forge end-to-end. We then ASK the
// server to verify the forged (request, sig) — that round-trip is the
// proof. We stash everything (original pair, glue padding, forged
// request, forged sig, server accept bit) into state for the page UI.

export async function run_attack(_input, _state) {
  let result, accepts;
  try {
    const { request, signature } = givenPair();
    result = forge(request, signature, SECRET_LENGTH, ATTACK_EXTENSION);
    // The load-bearing line. We re-call the server's verify function
    // with the forged (request, sig) — pass the raw bytes (not a
    // string), because the glue padding contains non-UTF-8 bytes.
    accepts = verifyRequest(result.forgedRequest, result.forgedSig);
  } catch (e) {
    return {
      ok: false,
      hint:
        "The forge module failed mid-run — refresh and retry. " +
        "Original: " + (e && e.message ? e.message : String(e)),
    };
  }

  if (!accepts) {
    // The lesson is busted if this ever fires. Report loudly.
    return {
      ok: false,
      hint:
        "The forged signature did NOT verify against the server — " +
        "this should never happen on a correctly-implemented attack. " +
        "Please report this lesson page as broken.",
    };
  }

  return {
    ok: true,
    value: {
      lenext_original: ORIGINAL_REQUEST,
      lenext_signature: result.originalSig,
      lenext_extension: ATTACK_EXTENSION,
      lenext_secret_len: SECRET_LENGTH,
      lenext_glue_padding_hex: result.gluePaddingHex,
      lenext_forged_request: result.forgedRequestHex,
      lenext_forged_signature: result.forgedSig,
      lenext_server_accepts: true,
    },
  };
}

// ---- info ----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs --------------------------------------------------------

export const walkthroughs = {
  run_attack: (_state) => [
    `**The setup:** The page hosts a vulnerable server with a 13-byte secret (\`"correct-horse"\`) that signs API requests as \`sig = SHA-256(secret || request)\`. The attacker observes one (request, sig) pair: \`request="user=alice&amount=10"\`, sig published. The attacker wants to forge a signature for \`request + "&amount=100000"\` to drain the account — without ever seeing the secret.`,
    `**Why it works:** SHA-256 is a Merkle-Damgard hash, which means the published 32-byte digest IS the internal chaining state at the moment the hasher finalized. Given \`sig = SHA-256(secret || request)\`, the attacker initializes a fresh SHA-256 from those 32 bytes of state — effectively *resuming* the hasher mid-stream. They then feed the extension and finalize, producing the digest the server would have produced if it had hashed \`secret || request || gluePadding || extension\`.`,
    `**The forge:** (1) Compute the SHA-256 glue padding for an input of length \`13 + len(request)\` — that's 0x80, zero bytes, and an 8-byte big-endian bit length. (2) Resume SHA-256 from \`sig\` as state, with the byte counter set to \`13 + len(request) + len(gluePadding)\`. (3) Update with the extension, finalize. (4) The forged request the server sees is \`request || gluePadding || extension\` — raw binary in the middle, which most URL parsers happily eat. (5) Server's \`verifyRequest(forgedRequest, forgedSig)\` returns \`true\`. No secret needed.`,
  ],
};
