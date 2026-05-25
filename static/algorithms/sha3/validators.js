// Validators for the SHA-3 (Keccak) lesson.
//
// Mirrors static/algorithms/sha256/validators.js — same input shapes and
// {ok, value, hint} return convention used by the wizard.

// Canonical SHA3-256 of the empty string. Cited from step 5 and the
// walkthrough so they stay in sync if anyone ever (somehow) needs to change
// the well-known value.
export const SHA3_EMPTY_HEX = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

// Accept either a raw hex string or a {hex: "..."} object. The template
// branch at integration time wires a Compute button that calls
// sha3_demo.hashEmpty() and writes the result into the wizard's
// sentenceInput; the validator just confirms the right value made it through.
function _extractHex(input) {
  if (input == null) return "";
  if (typeof input === "string") return input.trim().toLowerCase();
  if (typeof input === "object" && typeof input.hex === "string") {
    return input.hex.trim().toLowerCase();
  }
  return "";
}

export function walk_empty_sha3(input, _state) {
  const hex = _extractHex(input);
  if (hex === "") {
    return { ok: false, hint: "Press the Compute button — the lesson's bundled Keccak runs SHA3-256 on the empty input." };
  }
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    return { ok: false, hint: "A SHA3-256 digest is exactly 64 hex characters (256 bits). What you pasted doesn't match." };
  }
  if (hex !== SHA3_EMPTY_HEX) {
    return { ok: false, hint: `Unexpected result. The SHA3-256 of the empty string is a fixed, well-known value: ${SHA3_EMPTY_HEX}.` };
  }
  return { ok: true, value: { sha3_empty_hex: SHA3_EMPTY_HEX } };
}

export function pick_sha3_sentence(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) {
    return { ok: false, hint: "Type a sentence (any printable ASCII)." };
  }
  if (s.length > 500) {
    return { ok: false, hint: "Keep it under 500 characters." };
  }
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Stick to printable ASCII for the demo — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  // The Keccak digest is computed by the template branch on submit and
  // written to state.sha_message_hex separately (the shared template branch
  // reads that key). Here we just lock in the message itself.
  return { ok: true, value: { sha_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  walk_empty_sha3: (_state) => [
    `**The setup:** SHA3-256 takes any input — including the empty string — and produces a 256-bit (64-hex-character) digest. The empty string is a canonical FIPS 202 test vector: every correct SHA3-256 implementation produces the same value for it.`,
    `**What to do:** Click the **Compute** button. The lesson's bundled Keccak runs SHA3-256 on zero input bytes and pastes the hex result into the input field. (Web Crypto's \`subtle.digest\` doesn't ship SHA3-256 in most browsers as of 2026, so the lesson uses a small in-page Keccak implementation.)`,
    `**Answer:** \`${SHA3_EMPTY_HEX}\`. You can verify this from a terminal: \`printf "" | openssl dgst -sha3-256\` (OpenSSL 1.1.1+) or in Python: \`import hashlib; hashlib.sha3_256(b"").hexdigest()\`.`,
  ],
};
