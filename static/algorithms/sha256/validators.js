// Canonical SHA-256 of the empty string — referenced from step 5 and the
// walkthrough so they stay in sync if anyone ever (somehow) needs to change
// the well-known value.
export const SHA_EMPTY_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Accept either a raw hex string or a {hex: "..."} / {computed: true, hex: "..."}
// object. The template branch at integration time wires a Compute button that
// calls sha_demo.hashEmpty() and writes the result into the wizard's
// sentenceInput; the validator just confirms the right value made it through.
function _extractHex(input) {
  if (input == null) return "";
  if (typeof input === "string") return input.trim().toLowerCase();
  if (typeof input === "object" && typeof input.hex === "string") {
    return input.hex.trim().toLowerCase();
  }
  return "";
}

export function walk_empty_hash(input, _state) {
  const hex = _extractHex(input);
  if (hex === "") {
    return { ok: false, hint: "Press the Compute button — your browser will run SHA-256 on the empty input." };
  }
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    return { ok: false, hint: "A SHA-256 digest is exactly 64 hex characters (256 bits). What you pasted doesn't match." };
  }
  if (hex !== SHA_EMPTY_HEX) {
    return { ok: false, hint: `Unexpected result. The SHA-256 of the empty string is a fixed, well-known value: ${SHA_EMPTY_HEX}.` };
  }
  return { ok: true, value: { sha_empty_hex: SHA_EMPTY_HEX } };
}

export function pick_sha_sentence(input, _state) {
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
  // The Web Crypto digest is computed by the template branch on submit and
  // written to state.sha_message_hex separately. Here we just lock in the
  // message itself.
  return { ok: true, value: { sha_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  walk_empty_hash: (_state) => [
    `**The setup:** SHA-256 takes any string — including the empty string — and produces a 256-bit (64-hex-character) digest. The empty string is a canonical test vector: every correct SHA-256 implementation produces the same value for it.`,
    `**What to do:** Click the **Compute** button. Your browser calls \`crypto.subtle.digest("SHA-256", new Uint8Array(0))\` — the digest of zero input bytes — and pastes the hex result into the input field.`,
    `**Answer:** \`${SHA_EMPTY_HEX}\`. You can verify this from a terminal: \`printf "" | shasum -a 256\` (macOS) or \`echo -n "" | sha256sum\` (Linux).`,
  ],
};
