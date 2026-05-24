// Simulated HSM: holds a non-extractable RSA-PSS keypair via Web Crypto.
// The "vault" private key cannot be dumped to JS — Web Crypto's
// extractable:false flag enforces this even with full devtools access.
//
// Operations exposed: sign(message), verify(message, sigHex),
// vaultPublicKeyPem() (the public key is not secret).
//
// This file is the pedagogical centerpiece of the HSM lesson.
// Don't add a function that exports the private key. That's the point.

let _vaultPromise = null;

async function getOrGenerateVault() {
  if (!_vaultPromise) {
    _vaultPromise = crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      false,                  // extractable: false — KEY MATERIAL CANNOT BE EXPORTED
      ["sign", "verify"]
    );
  }
  return _vaultPromise;
}

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

// Sign a UTF-8 string. Returns hex signature.
export async function sign(message) {
  const { privateKey } = await getOrGenerateVault();
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    privateKey,
    data
  );
  return bytesToHex(new Uint8Array(sig));
}

// Verify a UTF-8 message + hex signature. Returns boolean.
export async function verify(message, signatureHex) {
  const { publicKey } = await getOrGenerateVault();
  const data = new TextEncoder().encode(message);
  let sigBytes;
  try { sigBytes = hexToBytes(signatureHex); } catch { return false; }
  return await crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    publicKey,
    sigBytes,
    data
  );
}

// Export the PUBLIC key as PEM. The public key is not secret — anyone
// can use it to verify signatures.
export async function vaultPublicKeyPem() {
  const { publicKey } = await getOrGenerateVault();
  const der = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  // Base64 encode + 64-char-line wrap
  const b64 = btoa(String.fromCharCode(...der));
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

// Pedagogical: deliberately throws to demonstrate that the API has NO way
// to extract the private key. Use this in lesson copy as the "see, you
// can't get it out" moment.
export async function tryExtractPrivate() {
  const { privateKey } = await getOrGenerateVault();
  try {
    await crypto.subtle.exportKey("pkcs8", privateKey);
    // If somehow it didn't throw (extractable:true bug?), still refuse:
    throw new Error("vault refused: key marked non-extractable");
  } catch (e) {
    throw new Error(
      "The vault refused. Web Crypto's extractable:false flag makes this impossible from JS. " +
      "Real HSMs enforce the same property in hardware. Original error: " + (e.message || e)
    );
  }
}
