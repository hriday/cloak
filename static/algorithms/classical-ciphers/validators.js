// Validators for the Classical Ciphers lesson.
//
// Two interactive steps:
//
// 1. caesar_decrypt (step 3): the user is shown a Caesar-encrypted message
//    and must either type the plaintext (case-insensitive) OR enter the
//    integer shift. Brute-forcing a Caesar cipher with key space 26 is
//    trivial — that's the point of the step.
//
// 2. vigenere_break (step 6): button-driven. The page shows a fixed
//    Vigenère ciphertext with a known key length; the user clicks
//    "Run frequency analysis" and the validator runs
//    breakVigenereByFrequency against the fixed ciphertext, writing the
//    recovered key and plaintext into state. The "input" is just a
//    sentinel (any non-empty string).

import {
  caesarEncrypt,
  caesarDecrypt,
  vigenereEncrypt,
  breakVigenereByFrequency,
} from "./cc_demo.js";

// ---- Step 3: break a Caesar cipher ---------------------------------------
// The known plaintext for the puzzle and the shift we used to produce it.
// These are exported so the codegen and walkthrough can stay in sync.
export const CAESAR_PLAINTEXT = "this is a secret message";
export const CAESAR_SHIFT = 3;
// Display the ciphertext in uppercase — the iconic Caesar look. The
// validator normalizes case, so a lowercase guess still validates.
export const CAESAR_CIPHERTEXT = caesarEncrypt(CAESAR_PLAINTEXT, CAESAR_SHIFT).toUpperCase();
// = "WKLV LV D VHFUHW PHVVDJH"

function _normalizePlain(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

export function caesar_decrypt(input, _state) {
  const raw = input == null ? "" : String(input).trim();
  if (raw === "") {
    return { ok: false, hint: "Type the plaintext, or the shift (a number 1-25)." };
  }
  // First: is it an integer? If so, treat as a shift guess.
  if (/^-?\d+$/.test(raw)) {
    const shift = parseInt(raw, 10);
    if (!Number.isFinite(shift)) {
      return { ok: false, hint: "Enter a whole number between 1 and 25." };
    }
    const normalized = ((shift % 26) + 26) % 26;
    if (normalized === CAESAR_SHIFT) {
      return {
        ok: true,
        value: {
          cc_caesar_shift: CAESAR_SHIFT,
          cc_caesar_plaintext: CAESAR_PLAINTEXT,
          cc_caesar_ciphertext: CAESAR_CIPHERTEXT,
        },
      };
    }
    // Show what their guess would decrypt to — feeds the brute-force intuition.
    const attempt = caesarDecrypt(CAESAR_CIPHERTEXT, normalized);
    return {
      ok: false,
      hint: `Shift ${normalized} gives \`${attempt}\` — that's not English. Try a different shift (the key space is only 26).`,
    };
  }
  // Otherwise: try matching against the plaintext (case- and space-insensitive).
  if (_normalizePlain(raw) === _normalizePlain(CAESAR_PLAINTEXT)) {
    return {
      ok: true,
      value: {
        cc_caesar_shift: CAESAR_SHIFT,
        cc_caesar_plaintext: CAESAR_PLAINTEXT,
        cc_caesar_ciphertext: CAESAR_CIPHERTEXT,
      },
    };
  }
  return {
    ok: false,
    hint: "That doesn't match. Either type the plaintext (English sentence) or the integer shift (1-25).",
  };
}

// ---- Step 6: break Vigenère by frequency analysis ------------------------
//
// Fixed lesson values. The ciphertext is long enough (>100 letters) that
// chi-squared frequency analysis recovers `LEMON` cleanly on the first try.
// The plaintext is a public-domain Lincoln excerpt — sample text only.
export const VIGENERE_KEY = "LEMON";
export const VIGENERE_PLAINTEXT =
  "Four score and seven years ago our fathers brought forth on this " +
  "continent a new nation conceived in liberty and dedicated to the " +
  "proposition that all men are created equal. Now we are engaged in " +
  "a great civil war testing whether that nation or any nation so " +
  "conceived and so dedicated can long endure.";
export const VIGENERE_CIPHERTEXT = vigenereEncrypt(VIGENERE_PLAINTEXT, VIGENERE_KEY);
export const VIGENERE_KEYLEN = VIGENERE_KEY.length;

export function vigenere_break(input, _state) {
  const raw = input == null ? "" : String(input).trim();
  if (raw === "") {
    return {
      ok: false,
      hint: "Click the Run frequency analysis button below to break the cipher.",
    };
  }
  const { key, plaintext } = breakVigenereByFrequency(
    VIGENERE_CIPHERTEXT,
    VIGENERE_KEYLEN
  );
  return {
    ok: true,
    value: {
      cc_vigenere_ciphertext: VIGENERE_CIPHERTEXT,
      cc_vigenere_keylen: VIGENERE_KEYLEN,
      cc_vigenere_recovered_key: key,
      cc_vigenere_plaintext: plaintext,
      cc_vigenere_true_key: VIGENERE_KEY,
    },
  };
}

// ---- Generic info validator ----------------------------------------------
export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- Walkthroughs --------------------------------------------------------
export const walkthroughs = {
  caesar_decrypt: (_state) => [
    `**The method:** A Caesar cipher shifts every letter by some fixed amount k. There are only 26 possible shifts, so you can try every one until the output looks like English. This is called *brute force* — the key space is too small to hide in.`,
    `**Walking the work:** Take the first word of the ciphertext, \`${CAESAR_CIPHERTEXT.split(" ")[0]}\`. Try shifting each letter back by 1, 2, 3, ... For shift = 1 you get \`${caesarDecrypt(CAESAR_CIPHERTEXT.split(" ")[0], 1)}\`. Shift = 2 → \`${caesarDecrypt(CAESAR_CIPHERTEXT.split(" ")[0], 2)}\`. Shift = 3 → \`${caesarDecrypt(CAESAR_CIPHERTEXT.split(" ")[0], 3)}\`. One of these is an English word.`,
    `**Answer:** shift = **${CAESAR_SHIFT}**, plaintext = **${CAESAR_PLAINTEXT.toUpperCase()}**. Type either one and we'll accept it.`,
  ],
  vigenere_break: (_state) => [
    `**The method:** Vigenère with key length N is N independent Caesar ciphers, woven together. Split the ciphertext into N "streams" — stream i contains letters at positions i, i+N, i+2N, ... Each stream was encrypted with a single Caesar shift. Break each stream by trying every shift and picking the one whose letter frequencies match English best.`,
    `**Walking the work:** Key length is **${VIGENERE_KEYLEN}**. So stream 0 = letters 0, ${VIGENERE_KEYLEN}, ${VIGENERE_KEYLEN * 2}, ... of the ciphertext. Compute the letter frequency of stream 0, then try all 26 shifts and pick the one whose shifted distribution is closest to English's (E ~12.7%, T ~9.1%, A ~8.2%, ...). That shift is the first letter of the key. Repeat for streams 1, 2, 3, 4.`,
    `**Answer:** the recovered key is **${VIGENERE_KEY}**. Just click the Run frequency analysis button — the page will do all 5 chi-squared scans for you.`,
  ],
};
