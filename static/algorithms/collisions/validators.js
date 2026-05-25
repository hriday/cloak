// Validators for the Hash Collisions lesson.
//
// Two substantive validators:
//   compute_md5_collision — button-press. Hashes both Wang/Stevens blobs,
//                           confirms the digests match the published value,
//                           and stashes the proof (the matched hash and a
//                           short preview of each blob) into state.
//   compute_sha1_collision — fact-check button. Records the published
//                            SHAttered PDF hash and lets the user verify
//                            externally via shasum / openssl.
//
// Plus the conventional pass-through `info` validator and the
// `walkthroughs` object that drives the 3-rung help panel.

import {
  getMd5CollidingBlobs,
  md5Hash,
  MD5_COLLISION_HASH,
  byteDiffCount,
  SHATTERED_PUBLISHED_HASH,
  SHATTERED_PDF_BYTES,
  getSha1CollidingFactSheet,
} from "./coll_demo.js";

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- compute_md5_collision ----------------------------------------------

// Button-press validator. Input is ignored — the page just clicks the
// "Hash both" button and we run MD5 on both Wang/Stevens blobs end-to-end.
// The load-bearing assertion is that the two digests are EQUAL and match
// the published Wang/Stevens hash `79054025255fb1a26e4bc422aef54eb4`. If
// either assertion fires, the lesson is busted — report loudly.

export async function compute_md5_collision(_input, _state) {
  const { blob1, blob2 } = getMd5CollidingBlobs();
  let h1, h2;
  try {
    h1 = await md5Hash(blob1);
    h2 = await md5Hash(blob2);
  } catch (e) {
    return {
      ok: false,
      hint:
        "The MD5 module failed mid-run — refresh and retry. " +
        "Original: " + (e && e.message ? e.message : String(e)),
    };
  }

  if (h1 !== MD5_COLLISION_HASH || h2 !== MD5_COLLISION_HASH || h1 !== h2) {
    // Lesson is broken if we get here.
    return {
      ok: false,
      hint:
        `MD5 collision verification FAILED. Expected both blobs to hash to ` +
        `${MD5_COLLISION_HASH}, got blob1=${h1}, blob2=${h2}. ` +
        `Please report this lesson page as broken.`,
    };
  }

  const diffBytes = byteDiffCount(blob1, blob2);
  return {
    ok: true,
    value: {
      coll_md5_hash: h1,
      coll_md5_match: true,
      coll_md5_blob1_first16: bytesToHex(blob1.slice(0, 16)),
      coll_md5_blob2_first16: bytesToHex(blob2.slice(0, 16)),
      coll_md5_blob_bytes: blob1.length,
      coll_md5_byte_diff_count: diffBytes,
    },
  };
}

// ---- compute_sha1_collision --------------------------------------------

// Button-press / record-the-fact validator. The SHAttered colliding PDFs
// are 422 KB each — too large to embed inline. The user confirms the
// published hash; the lesson stashes it for the Done-step recap and Python
// codegen.

export function compute_sha1_collision(_input, _state) {
  const facts = getSha1CollidingFactSheet();
  return {
    ok: true,
    value: {
      coll_sha1_hash: facts.publishedHash,
      coll_sha1_pdf_bytes: facts.pdfBytes,
      coll_sha1_download: facts.downloadUrl,
      coll_sha1_verify_cmd: facts.verifyCommand,
    },
  };
}

// ---- info ---------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs -------------------------------------------------------

export const walkthroughs = {
  compute_md5_collision: (_state) => [
    `**The setup:** The page bundles two 128-byte messages — call them BLOB_1 and BLOB_2 — published by Wang & Yu (EUROCRYPT 2005) and refined by Marc Stevens. They differ in exactly 6 bytes (positions 19, 45, 59, 83, 109, 123). Click **Hash both** to run MD5 on each one separately.`,
    `**What you'll see:** Both blobs hash to the same MD5 digest: \`${MD5_COLLISION_HASH}\`. Two distinct byte sequences, same 128-bit fingerprint. This is what "broken collision resistance" means in practice — the attacker who built this pair did NOT have to search 2⁶⁴ inputs (the birthday bound). They used differential cryptanalysis to construct the collision in seconds on a 2007 laptop.`,
    `**The proof:** \`md5(BLOB_1) == md5(BLOB_2) == ${MD5_COLLISION_HASH}\`, and \`BLOB_1 != BLOB_2\` (6-byte diff). The Done-step Python codegen reproduces this with stdlib \`hashlib.md5\` so you can re-verify in any Python 3 environment in 5 lines.`,
  ],
  compute_sha1_collision: (_state) => [
    `**The setup:** SHAttered (Stevens et al., Google + CWI Amsterdam, 2017) produced two real PDF files — \`shattered-1.pdf\` and \`shattered-2.pdf\`, each ${SHATTERED_PDF_BYTES.toLocaleString()} bytes — that render as visibly different images but share the same SHA-1 digest. The colliding PDFs are too large (422 KB each) to embed in this lesson page, so we don't bake them inline.`,
    `**What to verify:** The published SHA-1 of BOTH PDFs is \`${SHATTERED_PUBLISHED_HASH}\`. Click **Record the published hash** to lock this fact into the lesson state. You can confirm externally: download both PDFs from https://shattered.io and run \`shasum -a 1 shattered-1.pdf shattered-2.pdf\` — same hash, different files.`,
    `**The cost:** SHAttered required ~2⁶³·¹ SHA-1 computations — that's 6,500 CPU-years and 110 GPU-years of compute, sponsored by Google. Far below SHA-1's nominal 2⁸⁰ collision security. Two years later (2019), Leurent and Peyrin (LeurentPeyrin "SHA-1 is a Shambles", 2020) reduced this to a chosen-prefix collision at 2⁶³·⁴ — well within reach of a determined attacker with cloud budget.`,
  ],
};
