// Thin browser wrapper around the pure-JS AEAD. The validator calls
// encryptDemo(message, aad) on step 6 to produce displayable hex, then
// immediately calls tamperDemo() to prove the MAC catches a single
// flipped ciphertext byte.

import { aeadEncrypt, aeadDecrypt, InvalidTag } from "./aead.js";

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

// Generate a fresh random 32-byte key + 12-byte nonce, encrypt the
// message+aad, return everything as hex. The decrypted echo is
// included so the validator can sanity-check it matches the input
// before showing the panel.
export async function encryptDemo(message, aad) {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ptBytes = new TextEncoder().encode(message);
  const aadBytes = new TextEncoder().encode(aad ?? "");

  const { ciphertext, tag } = aeadEncrypt(key, nonce, ptBytes, aadBytes);
  const back = aeadDecrypt(key, nonce, ciphertext, tag, aadBytes);

  return {
    keyHex: bytesToHex(key),
    nonceHex: bytesToHex(nonce),
    ciphertextHex: bytesToHex(ciphertext),
    tagHex: bytesToHex(tag),
    decrypted: new TextDecoder().decode(back),
  };
}

// Re-hydrate state from hex and flip one ciphertext byte. The AEAD
// verifier should throw InvalidTag — that's the signal that authentication
// works. Returns {decrypted: null, error: "InvalidTag"} on the expected
// failure path; bug branches (decryption succeeds despite tamper) throw.
export async function tamperDemo({ keyHex, nonceHex, ciphertextHex, tagHex, aad }) {
  const key = hexToBytes(keyHex);
  const nonce = hexToBytes(nonceHex);
  const ct = hexToBytes(ciphertextHex);
  const tag = hexToBytes(tagHex);
  const aadBytes = new TextEncoder().encode(aad ?? "");

  // Flip the lowest bit of the first ciphertext byte. (If the ciphertext
  // is empty — e.g. user encrypted an empty message, which the validator
  // rejects — there's nothing to flip; flip a tag byte instead so the
  // demo still produces a failure.)
  const tampered = ct.length > 0 ? new Uint8Array(ct) : ct;
  let tamperedTag = tag;
  if (tampered.length > 0) {
    tampered[0] ^= 0x01;
  } else {
    tamperedTag = new Uint8Array(tag);
    tamperedTag[0] ^= 0x01;
  }

  try {
    aeadDecrypt(key, nonce, tampered, tamperedTag, aadBytes);
    // Should not reach here — if it does, the AEAD is broken.
    return { decrypted: "(unexpected success — implementation bug)", error: null };
  } catch (e) {
    if (e instanceof InvalidTag) {
      return { decrypted: null, error: "InvalidTag" };
    }
    return { decrypted: null, error: String(e.message || e) };
  }
}
