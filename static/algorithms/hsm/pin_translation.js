// Simulated payments HSM zone-translation. Demonstrates how a PIN block
// hops terminal → acquirer → network → issuer, getting re-encrypted under
// a different key at each boundary, while the underlying PIN never appears
// in cleartext outside the HSM call.
//
// Pedagogical only. Real payment HSMs (Thales payShield, Atalla) use 3DES
// per ANSI X9.24 with per-transaction unique keys (DUKPT) and never use a
// fixed IV. We use AES-128-CBC with a zero IV because the lesson is about
// the *zone-translation pattern*, not the cipher details. ISO 9564 Format 0
// is followed for the PIN block construction.

let _zoneKeys = null;

// Build an 8-byte ISO 9564 Format 0 PIN block.
// PIN field (8 bytes / 16 nibbles): 0 | L | P P P P P P... | F F F...
//   where L is the PIN length, followed by the PIN digits, F-padded to 16 nibbles.
// PAN field (8 bytes): 0x0000 + rightmost 12 digits of PAN excluding the check digit.
// Returns PIN_field XOR PAN_field as a Uint8Array(8).
export function buildPinBlock(pin, pan) {
  if (typeof pin !== "string" || !/^[0-9]{4,12}$/.test(pin)) {
    throw new Error("pin must be 4-12 ASCII digits");
  }
  if (typeof pan !== "string" || !/^[0-9]{13,}$/.test(pan)) {
    throw new Error("pan must be at least 13 ASCII digits");
  }

  // PIN field as 16 hex nibbles, then packed to 8 bytes.
  const pinHex = ("0" + pin.length.toString(16) + pin).padEnd(16, "F").toUpperCase();
  const pinField = hexToBytes(pinHex);

  // PAN field: drop the check digit (rightmost), take the rightmost 12 of what's left.
  const panWithoutCheck = pan.slice(0, -1);
  const pan12 = panWithoutCheck.slice(-12).padStart(12, "0");
  const panHex = "0000" + pan12;
  const panField = hexToBytes(panHex);

  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[i] = pinField[i] ^ panField[i];
  return out;
}

// Lazily generate three AES-128 zone keys: tpk (terminal), zpk1 (acquirer↔network),
// zpk2 (network↔issuer). Marked extractable so the validator can show fingerprints.
// In a real HSM these would be non-extractable and live only in tamper-resistant
// hardware; we relax it here purely for display.
export async function ensureZoneKeys() {
  if (!_zoneKeys) {
    const tpkRaw = crypto.getRandomValues(new Uint8Array(16));
    const zpk1Raw = crypto.getRandomValues(new Uint8Array(16));
    const zpk2Raw = crypto.getRandomValues(new Uint8Array(16));
    const [tpk, zpk1, zpk2] = await Promise.all([
      crypto.subtle.importKey("raw", tpkRaw, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]),
      crypto.subtle.importKey("raw", zpk1Raw, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]),
      crypto.subtle.importKey("raw", zpk2Raw, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]),
    ]);
    _zoneKeys = { tpk, zpk1, zpk2 };
  }
  return _zoneKeys;
}

// Encrypt the 8-byte PIN block under tpk. PKCS7 padding lifts it to 16 bytes
// of ciphertext (32 hex chars). Uses a fixed zero IV — illustrative only;
// ISO 9564.4 requires a fresh random IV per real PIN-block encryption.
export async function terminalEncrypt(pinBlock8) {
  if (!(pinBlock8 instanceof Uint8Array) || pinBlock8.length !== 8) {
    throw new Error("pinBlock8 must be a Uint8Array of length 8");
  }
  const { tpk } = await ensureZoneKeys();
  const iv = new Uint8Array(16); // zero IV — pedagogical simplification
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, tpk, pinBlock8);
  return bytesToHex(new Uint8Array(ct));
}

// Decrypt under fromKeyName, immediately re-encrypt under toKeyName.
// The cleartext PIN block exists only as a local variable inside this
// function — mimicking the call boundary of a real HSM "translate" command.
export async function translate(ciphertextHex, fromKeyName, toKeyName) {
  const keys = await ensureZoneKeys();
  const fromKey = keys[fromKeyName];
  const toKey = keys[toKeyName];
  if (!fromKey) throw new Error(`unknown fromKeyName: ${fromKeyName}`);
  if (!toKey) throw new Error(`unknown toKeyName: ${toKeyName}`);

  const iv = new Uint8Array(16);
  const ctBytes = hexToBytes(ciphertextHex);
  const cleartext = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, fromKey, ctBytes);
  const reCt = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, toKey, cleartext);
  return bytesToHex(new Uint8Array(reCt));
}

// Decrypt under zpk2, extract the PIN from the resulting PIN block, compare.
// Returns false on any decryption / parse failure (instead of throwing).
export async function issuerVerify(ciphertextHex, expectedPin, pan) {
  let pinBlock;
  try {
    const { zpk2 } = await ensureZoneKeys();
    const iv = new Uint8Array(16);
    const ctBytes = hexToBytes(ciphertextHex);
    const pt = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, zpk2, ctBytes);
    pinBlock = new Uint8Array(pt);
  } catch {
    return false;
  }
  if (pinBlock.length !== 8) return false;

  // Reconstruct the PAN field and XOR back out to recover the PIN field.
  let panField;
  try {
    if (typeof pan !== "string" || !/^[0-9]{13,}$/.test(pan)) return false;
    const panWithoutCheck = pan.slice(0, -1);
    const pan12 = panWithoutCheck.slice(-12).padStart(12, "0");
    panField = hexToBytes("0000" + pan12);
  } catch {
    return false;
  }

  const pinField = new Uint8Array(8);
  for (let i = 0; i < 8; i++) pinField[i] = pinBlock[i] ^ panField[i];
  const pinHex = bytesToHex(pinField).toUpperCase();

  // First nibble should be 0 (format-0 marker), second nibble is PIN length.
  if (pinHex[0] !== "0") return false;
  const len = parseInt(pinHex[1], 16);
  if (!Number.isFinite(len) || len < 4 || len > 12) return false;
  const pin = pinHex.slice(2, 2 + len);
  if (!/^[0-9]+$/.test(pin)) return false;
  // Trailing nibbles should be F-padding.
  const tail = pinHex.slice(2 + len);
  if (!/^F*$/.test(tail)) return false;

  return pin === expectedPin;
}

// Return the last 8 hex chars of each zone key's raw bytes, for display
// only. Real HSMs never expose key bytes — even fingerprints are a teaching
// liberty here.
export async function keyFingerprints() {
  const keys = await ensureZoneKeys();
  const [tpkRaw, zpk1Raw, zpk2Raw] = await Promise.all([
    crypto.subtle.exportKey("raw", keys.tpk),
    crypto.subtle.exportKey("raw", keys.zpk1),
    crypto.subtle.exportKey("raw", keys.zpk2),
  ]);
  return {
    tpk: bytesToHex(new Uint8Array(tpkRaw)).slice(-8),
    zpk1: bytesToHex(new Uint8Array(zpk1Raw)).slice(-8),
    zpk2: bytesToHex(new Uint8Array(zpk2Raw)).slice(-8),
  };
}

// ---- helpers ----

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
