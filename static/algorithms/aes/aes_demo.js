// Browser Web Crypto wrapper for step 7. Generates a 128-bit AES key
// and 12-byte IV, encrypts with AES-GCM, decrypts to confirm,
// returns all four artifacts as hex strings.

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function encryptMessage(plaintext) {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 128 },
    true,   // extractable so we can export and display the key bytes
    ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ptBytes = new TextEncoder().encode(plaintext);
  const ctBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ptBytes);
  const recoveredBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ctBuffer);
  const recovered = new TextDecoder().decode(recoveredBuffer);
  const keyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return {
    keyHex: bytesToHex(keyBytes),
    ivHex: bytesToHex(iv),
    ciphertextHex: bytesToHex(new Uint8Array(ctBuffer)),
    recovered,
  };
}
