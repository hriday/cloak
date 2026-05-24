// Generates the Python Twofish demo shown on the Done step.

export function full_script(state) {
  const messageLiteral = JSON.stringify(state.tf_message ?? "hello twofish");
  return [
    "# Twofish — AES finalist (Schneier et al.). 128-bit block, key sizes 128/192/256 bits.",
    "# Not available in pyca/cryptography, so we use pycryptodome.",
    "# Install: `pip install pycryptodome`.",
    "",
    "from Crypto.Cipher import Twofish",
    "from Crypto.Random import get_random_bytes",
    "",
    "# 16-byte (128-bit) key. Twofish also accepts 24- or 32-byte keys.",
    "key = get_random_bytes(16)",
    "# Twofish has a 128-bit block, so the IV is 16 bytes (matches AES, NOT Blowfish's 8).",
    "iv = get_random_bytes(16)",
    "",
    `plaintext_bytes = b${messageLiteral}`,
    "",
    "# Manual PKCS#7 padding to the 16-byte Twofish block boundary.",
    "pad_len = 16 - (len(plaintext_bytes) % 16)",
    "padded = plaintext_bytes + bytes([pad_len]) * pad_len",
    "",
    "cipher = Twofish.new(key, Twofish.MODE_CBC, iv)",
    "ct = cipher.encrypt(padded)",
    "",
    "# CBC keeps internal chaining state, so re-init a fresh cipher for decryption.",
    "cipher2 = Twofish.new(key, Twofish.MODE_CBC, iv)",
    "pt_padded = cipher2.decrypt(ct)",
    "",
    "# Strip PKCS#7 padding by reading the last byte.",
    "pt = pt_padded[:-pt_padded[-1]]",
    "assert pt == plaintext_bytes",
    "",
    `print("key:", key.hex())`,
    `print("iv :", iv.hex())`,
    `print("ct :", ct.hex())`,
    `print("decrypted:", pt.decode())`,
  ].join("\n");
}

// Info / non-actionable steps emit nothing for the inline code panel.
export function intro(_state) { return ""; }
export function vs_aes(_state) { return ""; }
export function key_dependent_sboxes(_state) { return ""; }
export function whitening(_state) { return ""; }
export function encrypt_a_message(_state) { return ""; }
export function done(_state) { return ""; }
