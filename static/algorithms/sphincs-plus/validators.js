// Validators for the SPHINCS+ (SLH-DSA) lesson.
//
// One substantive validator:
//   sphincs_operation — sign or verify a UTF-8 message using the toy
//                       SPHINCS-like construction (8 WOTS+ keys under a
//                       single height-3 Merkle tree). The keypair is
//                       derived deterministically from LESSON_SEED_STRING
//                       so the same root, the same leaves, and the same
//                       interactive signatures appear across page reloads
//                       and in the test suite.
//
// Plus the conventional pass-through `info` validator and a `walkthroughs`
// object that drives the 3-rung help panel on the sign-and-verify step.
//
// Like ed25519_operation and hsm_operation, this validator is *permissive*:
// a failed verify is information (the result pill goes red), not an error.
// We return ok:true with the result on state so the wizard renders the
// outcome below the inputs.

import {
  N_BYTES,
  NUM_CHUNKS,
  NUM_LEAVES,
  TREE_HEIGHT,
  W,
  bytesToHex,
  hexToBytes,
  sphincsKeygen,
  sphincsSign,
  sphincsVerify,
  lessonSeedBytes,
} from "./sphincs_demo.js";

// Cache the lesson keypair across operations. Like ed25519's
// _keypairPromise, this is module-scope so sign+verify within the same
// session share keys; the test helper `_resetForTests` clears it so each
// test starts from a clean slate.
let _keypairPromise = null;

function loadKeypair() {
  if (!_keypairPromise) {
    _keypairPromise = (async () => {
      const seed = await lessonSeedBytes();
      return sphincsKeygen(seed);
    })().catch((e) => {
      _keypairPromise = null; // let next call retry
      throw e;
    });
  }
  return _keypairPromise;
}

// Test-only: drop the cached keypair so unit tests can start fresh.
export function _resetForTests() {
  _keypairPromise = null;
}

// ---- signature serialisation ---------------------------------------------
//
// Hex form for transport on the page. Layout:
//   leafIndex (1 hex char, 0..7)
//   wotsSig:  NUM_CHUNKS * N_BYTES bytes = 8 * 16 = 128 bytes = 256 hex chars
//   authPath: TREE_HEIGHT * N_BYTES bytes = 3 * 16 = 48 bytes = 96 hex chars
//
// Total length: 1 + 256 + 96 = 353 hex chars. This is the string the user
// sees on screen after signing and pastes back into the verify form.
//
// Real SPHINCS+ signatures are 7856–49856 bytes; the toy is ~176 bytes,
// which is small enough to read on one terminal line but big enough to
// make the "huge signature" point of the next lesson step land visually.

export const SIG_HEX_LEN = 1 + NUM_CHUNKS * N_BYTES * 2 + TREE_HEIGHT * N_BYTES * 2;

export function serializeSignature(sig) {
  if (sig.leafIndex < 0 || sig.leafIndex >= NUM_LEAVES) {
    throw new Error("leafIndex out of range");
  }
  let out = sig.leafIndex.toString(16); // 1 nibble — 0..7
  for (const elt of sig.wotsSig) {
    out += bytesToHex(elt);
  }
  for (const sib of sig.authPath) {
    out += bytesToHex(sib);
  }
  return out;
}

export function deserializeSignature(hex) {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (clean.length !== SIG_HEX_LEN) {
    throw new Error("bad signature length: " + clean.length + " (expected " + SIG_HEX_LEN + ")");
  }
  if (!/^[0-9a-f]+$/.test(clean)) {
    throw new Error("invalid hex");
  }
  const leafIndex = parseInt(clean[0], 16);
  if (leafIndex >= NUM_LEAVES) {
    throw new Error("leafIndex out of range");
  }
  const wotsSig = new Array(NUM_CHUNKS);
  const chunkChars = N_BYTES * 2;
  let off = 1;
  for (let i = 0; i < NUM_CHUNKS; i++) {
    wotsSig[i] = hexToBytes(clean.slice(off, off + chunkChars));
    off += chunkChars;
  }
  const authPath = new Array(TREE_HEIGHT);
  for (let i = 0; i < TREE_HEIGHT; i++) {
    authPath[i] = hexToBytes(clean.slice(off, off + chunkChars));
    off += chunkChars;
  }
  return { leafIndex, wotsSig, authPath };
}

// ---- sphincs_operation ---------------------------------------------------
//
// Input: { op: "sign" | "verify", message, signature? }
// On verify, signature must be exactly SIG_HEX_LEN hex chars.
//
// Output: { ok, value: { sphincs_last_op, sphincs_last_input,
//                        sphincs_signature, sphincs_verify_result,
//                        sphincs_leaf_index, sphincs_root, sphincs_op_error } }

export async function sphincs_operation(input, _state) {
  const op = input?.op;
  const message = (input?.message ?? "").trim();
  const signature = (input?.signature ?? "").trim().toLowerCase();

  if (op !== "sign" && op !== "verify") {
    return { ok: false, hint: "Pick an operation: sign or verify." };
  }
  if (!message) {
    return { ok: false, hint: "Type something to sign or verify." };
  }
  if (op === "verify") {
    if (!signature) {
      return { ok: false, hint: "Verify needs the signature too — paste the hex output from a prior sign." };
    }
    if (signature.length !== SIG_HEX_LEN) {
      return {
        ok: false,
        hint:
          "Toy SPHINCS+ signatures are exactly " +
          SIG_HEX_LEN +
          " hex characters (" +
          (SIG_HEX_LEN / 2) +
          " bytes: 1-nibble leaf index + 8 WOTS+ chain elements + 3 Merkle siblings).",
      };
    }
    if (!/^[0-9a-f]+$/.test(signature)) {
      return { ok: false, hint: "Signature must be lowercase hex (0-9, a-f)." };
    }
  }

  let sigHex = null;
  let verifyResult = null;
  let leafIndex = null;
  let rootHex = null;
  let opError = null;

  try {
    const { pk, sk } = await loadKeypair();
    rootHex = bytesToHex(pk.root);
    const msgBytes = new TextEncoder().encode(message);

    if (op === "sign") {
      const sig = await sphincsSign(msgBytes, sk);
      leafIndex = sig.leafIndex;
      sigHex = serializeSignature(sig);
    } else {
      try {
        const sig = deserializeSignature(signature);
        leafIndex = sig.leafIndex;
        verifyResult = await sphincsVerify(msgBytes, sig, pk);
      } catch (e) {
        // Malformed structure (already past the cheap hex/length checks
        // above — this catches deeper inconsistencies like an
        // out-of-range leaf index). Surface as a failed verify.
        verifyResult = false;
      }
    }
  } catch (e) {
    opError = String(e?.message || e);
  }

  return {
    ok: true,
    value: {
      sphincs_last_op: op,
      sphincs_last_input: message,
      sphincs_signature: sigHex,
      sphincs_verify_result: verifyResult,
      sphincs_leaf_index: leafIndex,
      sphincs_root: rootHex,
      sphincs_op_error: opError,
    },
  };
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ---------------------------------------------------------
//
// Three rungs for `sphincs_operation`. Each builds on the previous so a
// learner who stalls after rung 1 can climb without re-reading the prose.

export const walkthroughs = {
  sphincs_operation: (_state) => [
    `**The method:** The page derived a master seed at mount time and built a tiny SPHINCS+ from it — eight WOTS+ keypairs (one per Merkle leaf) under a single height-3 Merkle root. SHA-256 (truncated to 16 bytes for the toy's n = 128 security level) is the *only* primitive. No lattice, no number theory. The root you see displayed is the public key; the eight WOTS+ secret-key vectors are the private key, and they never leave this page.`,

    `Try this: pick **Sign**, type 'hello', click Check. Two things come back — a leaf index (0..7) derived deterministically from H(message), and a ${SIG_HEX_LEN}-hex-character signature that bundles the WOTS+ chain elements (8 × 16 bytes) plus the Merkle authentication path (3 × 16 bytes). Now pick **Verify**, paste the same 'hello' + that signature → 'valid'. Flip one hex character in either the message or the signature → 'invalid'. The Merkle root re-derived from the verifier's recomputation no longer matches the published one.`,

    `**The point:** WOTS+ alone signs *one* message — sign a second and the revealed chain elements leak enough to forge. The Merkle tree on top gives you 2^h independent one-time keys committed to by a single root, lifting the construction to a many-time signature. Real SPHINCS+ stacks 60+ layers of these trees into a *hypertree* with a few-time FORS scheme at the bottom — same building blocks, just more of them. Every check above happens by hashing alone: if SHA-256 is collision-resistant, the signature is unforgeable.`,
  ],
};
