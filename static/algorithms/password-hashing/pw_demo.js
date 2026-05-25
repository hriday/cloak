// Browser Web Crypto wrappers for the Password Hashing lesson.
//
// Step 2 (naive-sha256-failure) renders sha256TimedHex("password123") on load
// to show the cost of a single SHA-256 — typically <1 ms.
//
// Step 3 (pbkdf2) calls pbkdf2Hex(password, iterations) on submit with the
// iteration count picked from the dropdown. The validator measures wall time
// and writes the (password, iter, hex, salt, ms) tuple into wizard state.
//
// Step 6 (compare-hashes) calls compareAll(password) on load. SHA-256 and
// PBKDF2 (1k + 100k) run live; bcrypt and Argon2id return CITED numbers
// (real bcrypt/Argon2 in JS/WASM is ~30-150 KB and would block the main
// thread for hundreds of ms). Cited rows carry `cited: true`.
//
// Node >=19 ships crypto.subtle globally, so these are unit-testable without
// a browser. The Argon2id/bcrypt cited rows have no runtime dependency.

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function nowMs() {
  // performance.now() in browsers + Node >=16; fall back to Date.now().
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

// Cited timing numbers — measured on a typical 2024 laptop in published
// benchmarks. Kept as a single source of truth so the step-4 widget and the
// step-6 comparison chart agree. Format strings match what `argon2-cffi` and
// `bcrypt` emit so the UI has something realistic to render.
export const CITED = {
  bcrypt_12_ms: 250,
  bcrypt_12_hash: "$2b$12$Rj4Xb1n6q0KQpD8eYxLuKO<cited-not-computed-in-browser>",
  argon2id_default_ms: 500,
  argon2id_default_hash:
    "$argon2id$v=19$m=65536,t=3,p=4$<cited-not-computed-in-browser>",
};

// Single SHA-256 of a password string. Returns {hex, ms}. Used by step 2 to
// drive home that a fast hash is the wrong primitive for password storage.
export async function sha256TimedHex(password) {
  const bytes = new TextEncoder().encode(String(password));
  const t0 = nowMs();
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  const t1 = nowMs();
  return {
    hex: bytesToHex(new Uint8Array(buf)),
    ms: t1 - t0,
  };
}

// PBKDF2-HMAC-SHA256 with a fresh random 16-byte salt and 32-byte output.
// Returns {hex, salt_hex, ms}. The wall-clock measurement is the whole
// point of step 3 — learners watch ms scale linearly with the iteration
// count (1k, 10k, 100k, 1M).
export async function pbkdf2Hex(password, iterations) {
  const iter = Number(iterations);
  if (!Number.isFinite(iter) || iter < 1) {
    throw new Error("iterations must be a positive number");
  }
  const pwBytes = new TextEncoder().encode(String(password));
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const t0 = nowMs();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    pwBytes,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
    baseKey,
    256 // 32 bytes
  );
  const t1 = nowMs();

  return {
    hex: bytesToHex(new Uint8Array(bits)),
    salt_hex: bytesToHex(salt),
    ms: t1 - t0,
  };
}

// Step 6 — run SHA-256 + PBKDF2-1k + PBKDF2-100k live against `password`,
// and emit cited rows for bcrypt-12 and Argon2id-default so the bar chart
// has all five algorithms. Returns an array in the order the chart wants
// (fastest to slowest), so the UI just maps over it.
export async function compareAll(password) {
  const pw = String(password);
  const sha = await sha256TimedHex(pw);
  const pbkdf2_1k = await pbkdf2Hex(pw, 1000);
  const pbkdf2_100k = await pbkdf2Hex(pw, 100000);
  return [
    { algo: "SHA-256",         hex: sha.hex,                          ms: sha.ms,         cited: false },
    { algo: "PBKDF2-1k",       hex: pbkdf2_1k.hex,                    ms: pbkdf2_1k.ms,   cited: false },
    { algo: "PBKDF2-100k",     hex: pbkdf2_100k.hex,                  ms: pbkdf2_100k.ms, cited: false },
    { algo: "bcrypt-12",       hex: CITED.bcrypt_12_hash,             ms: CITED.bcrypt_12_ms,        cited: true },
    { algo: "Argon2id-default", hex: CITED.argon2id_default_hash,     ms: CITED.argon2id_default_ms, cited: true },
  ];
}
