// Browser Web Crypto wrappers for the SHA-256 lesson.
//
// Step 5 (walk-empty) calls hashEmpty() on a button press.
// Step 6 (avalanche) calls bitDiff("hello", "Hello") on step load and
// renders the result as two 16x16 bit grids with differing bits highlighted.
// Step 7 (hash-a-sentence) calls hashHex(userMessage) on submit.
//
// Node ≥19 ships crypto.subtle globally, so these functions are unit-testable
// without a browser.

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBinary(hex) {
  // Convert a 64-char hex string (256 bits) to a 256-char binary string.
  // Used by the avalanche bit-grid widget.
  let out = "";
  for (let i = 0; i < hex.length; i++) {
    out += parseInt(hex[i], 16).toString(2).padStart(4, "0");
  }
  return out;
}

export async function hashHex(message) {
  const bytes = new TextEncoder().encode(message);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(buf));
}

export async function hashEmpty() {
  return hashHex("");
}

export async function bitDiff(s1, s2) {
  const [hex1, hex2] = await Promise.all([hashHex(s1), hashHex(s2)]);
  const bits1 = hexToBinary(hex1);
  const bits2 = hexToBinary(hex2);
  let diffMask = "";
  let diffCount = 0;
  for (let i = 0; i < 256; i++) {
    if (bits1[i] === bits2[i]) {
      diffMask += "0";
    } else {
      diffMask += "1";
      diffCount += 1;
    }
  }
  return { hex1, hex2, bits1, bits2, diffMask, diffCount };
}
