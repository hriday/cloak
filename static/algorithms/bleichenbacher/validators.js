// Validators for the Bleichenbacher attack lesson.
//
// One substantive validator:
//   run_attack — runs the full Bleichenbacher search against the in-page
//                simulator and writes the recovered plaintext + total
//                query count + modulus bits to state. Button-press shaped:
//                ignores its input.
//
// Plus the conventional `info` validator and the `walkthroughs` object
// that drives the 3-rung help panel.

import { runAttack, stripPadding } from "./bleich_attack.js";
import {
  targetCiphertext,
  publicKey,
  getPlaintext,
  N,
  K,
} from "./bleich_simulator.js";

// ---- run_attack -----------------------------------------------------------
//
// Step 5's button-press validator. Runs the attack to completion, writes
// the recovered plaintext + total query count + modulus bit length to
// state. The page UI can separately observe live progress by calling
// `runAttack` directly with its own progressCallback — this validator
// produces the final state write so progress survives a step-advance or
// reload.
//
// The attack's worst-case runtime for our toy params is well under a
// second in modern browsers, so we don't bother with cooperative yields
// here — the runAttack module already awaits between queries.

export async function run_attack(_input, _state) {
  let result;
  try {
    result = await runAttack();
  } catch (e) {
    return {
      ok: false,
      hint:
        "The Bleichenbacher attack failed to converge — refresh the step and retry. " +
        "Original: " + (e && e.message ? e.message : String(e)),
    };
  }

  if (!result || !(result.plaintext instanceof Uint8Array)) {
    return {
      ok: false,
      hint: "Attack did not produce a recovered plaintext. Refresh and retry.",
    };
  }

  // Strip the PKCS#1 v1.5 padding to reveal the ASCII message. If the
  // recovered padding doesn't parse (shouldn't happen for our fixed
  // simulator) we still surface the raw hex so the user can see what
  // came back.
  let asString = null;
  try {
    const msgBytes = stripPadding(result.plaintext);
    asString = new TextDecoder("utf-8", { fatal: false }).decode(msgBytes);
  } catch (_e) {
    asString = null;
  }

  const paddedHex = Array.from(result.plaintext)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Modulus bit length — useful pedagogical context (this is a toy 60-bit
  // RSA; real Bleichenbacher targets are 2048-bit).
  const modulusBits = N.toString(2).length;

  return {
    ok: true,
    value: {
      bleich_recovered_plaintext: asString,
      bleich_recovered_padded_hex: paddedHex,
      bleich_total_queries: result.totalQueries,
      bleich_modulus_bits: modulusBits,
      bleich_conforming_s_count: result.conformingSValues.length,
      bleich_target_ct: targetCiphertext().toString(),
      bleich_n: N.toString(),
      bleich_k: K,
    },
  };
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ---------------------------------------------------------

export const walkthroughs = {
  run_attack: (_state) => [
    `**The setup:** The page has a toy RSA keypair (modulus ~60 bits, exponent e=17) and a fixed ciphertext c = m^e mod n where m is the PKCS#1 v1.5 encoding of a short message. The oracle's API is one function: \`query(c)\` returns \`"conforming"\` if RSA-decrypting c yields a value in [2B, 3B) (i.e. starts with 0x00 0x02), \`"bad"\` otherwise. That's the *entire* leak — one bit per query. Your job is to recover m.`,
    `**The multiplicative trick:** RSA is multiplicatively homomorphic — (m·s)^e ≡ m^e · s^e ≡ c · s^e (mod n). So for any s, the attacker can construct c' = c · s^e mod n whose decryption is m·s mod n. Querying the oracle with c' tells you whether m·s mod n is PKCS-conforming. Each "conforming" answer is a linear constraint on m: \`2B + r·n ≤ m·s < 3B + r·n\` for some integer r, which means m lies in a narrower interval. The attack iterates: find s, intersect intervals, repeat. After ~log₂(B) iterations the interval shrinks to a single value.`,
    `**Why it took the industry 19 years to fix:** Bleichenbacher published in 1998; ROBOT (Böck-Somorovsky-Young, 2017) found ~3% of HTTPS hosts still vulnerable. The reason: any side-channel that distinguishes "PKCS-conforming after decrypt" from "decryption produced garbage" — *any*, including timing — works as the oracle. TLS 1.2's countermeasure (return a random fake premaster secret on bad padding, continue with the handshake, fail the Finished MAC) is hard to implement correctly. TLS 1.3 dropped RSA key exchange entirely. OAEP padding (PKCS#1 v2.x) is the modern v1.5 replacement and has provable security against this attack.`,
  ],
};
