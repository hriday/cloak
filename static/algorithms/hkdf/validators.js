// Validators for the HKDF lesson.
//
// The lesson is largely info steps walking through Extract and Expand. The
// single substantive validator is `derive_keys` — a button-driven step that
// derives four TLS-style keys from a fixed PRK and writes them into state
// for the page to render. Plus the usual `info` pass-through and the
// `walkthroughs` 3-rung help panel.

import { deriveTlsKeys, TLS_KEY_LABELS, TLS_KEY_LENGTHS } from "./hkdf_demo.js";

// ---- derive_keys ----------------------------------------------------------
//
// Button-press validator: the page calls this when the user clicks "Derive
// TLS keys". The actual input is ignored (the form sends whatever — the
// validator's job is to run the four Expand calls and stash hex blobs in
// state). On environments without Web Crypto we degrade gracefully and
// return ok=true with null OKMs, matching the pattern used in the HMAC and
// X25519 validators.

export async function derive_keys(_input, _state) {
  // Fixed seed so the lesson is repeatable across page loads. The lesson
  // copy makes this explicit — in production, PRK comes from extracting
  // over a real shared secret (e.g. an X25519 output), not a string.
  const seed = "x25519-shared-secret-stand-in";

  let result = null;
  let cryptoError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      result = await deriveTlsKeys(seed);
    }
  } catch (e) {
    cryptoError = String(e && e.message ? e.message : e);
  }

  if (cryptoError) {
    return {
      ok: false,
      hint:
        "HKDF derivation failed. This step requires a modern browser with " +
        "Web Crypto's HMAC primitive. (" + cryptoError + ")",
    };
  }

  if (!result) {
    // No crypto.subtle at all — fall back to a structurally-valid response
    // so the step still advances and the page can show placeholders.
    return {
      ok: true,
      value: {
        hkdf_seed_used:   seed,
        hkdf_prk:         null,
        hkdf_client_key:  null,
        hkdf_server_key:  null,
        hkdf_client_iv:   null,
        hkdf_server_iv:   null,
      },
    };
  }

  return {
    ok: true,
    value: {
      hkdf_seed_used:   result.seed,
      hkdf_prk:         result.prkHex,
      hkdf_client_key:  result.clientKey,
      hkdf_server_key:  result.serverKey,
      hkdf_client_iv:   result.clientIv,
      hkdf_server_iv:   result.serverIv,
    },
  };
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ---------------------------------------------------------

export const walkthroughs = {
  derive_keys: (_state) => [
    `**The setup:** the page is holding a fixed PRK derived once from a fake "shared secret" via \`PRK = HMAC-SHA256(salt, IKM)\`. In real TLS 1.3 the IKM is the 32-byte X25519 output you saw in the [X25519 lesson](/algorithms/x25519/learn/key-exchange-on-a-curve/) — here we stand in for it with a fixed string so the demo is repeatable.`,
    `**The four calls:** clicking the button runs \`Expand(PRK, "${TLS_KEY_LABELS.clientKey}", ${TLS_KEY_LENGTHS.clientKey})\`, \`Expand(PRK, "${TLS_KEY_LABELS.serverKey}", ${TLS_KEY_LENGTHS.serverKey})\`, \`Expand(PRK, "${TLS_KEY_LABELS.clientIv}", ${TLS_KEY_LENGTHS.clientIv})\`, and \`Expand(PRK, "${TLS_KEY_LABELS.serverIv}", ${TLS_KEY_LENGTHS.serverIv})\`. Four independent outputs of the right shape for AES-128-GCM in TLS 1.3 (16-byte keys, 12-byte IVs).`,
    `**Read what you got:** the four hex blobs are completely uncorrelated even though they came from the same PRK — that's the *info separation* property. And re-clicking the button gives you the *same* four blobs because PRK is fixed and Expand is deterministic. In production each new TLS connection has a fresh PRK (from a fresh X25519 exchange) so each connection's four keys are fresh too, but the per-PRK determinism is what makes the protocol auditable.`,
  ],
};
