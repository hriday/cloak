// A pedagogically-vulnerable web service. It "authenticates" requests by
// signing them with naive H(secret || request) — the construction every
// crypto textbook warns against. The attacker observes one signed request
// and forges a second, longer one without knowing the secret.
//
// Pretend this module is a backend server. From the attacker's POV:
//   - SECRET is hidden — but its LENGTH (13 bytes) is assumed/guessable.
//     A real attacker iterates plausible lengths until verifyRequest
//     accepts; we hand them the length here to keep the lesson focused
//     on the attack mechanic rather than length-discovery brute force.
//   - signRequest is the server-side signing endpoint. The attacker never
//     calls it directly — they only see one (request, sig) pair that the
//     server emitted to a legitimate client (givenPair).
//   - verifyRequest is the server-side check the attacker is trying to
//     pass with a forged (request, sig).
//
// The attack target. The server signs URL-encoded API requests like
// "user=alice&amount=10". The attacker wants to append "&amount=100000"
// and have the server's verifyRequest still return true — which means
// they need a new signature for the longer request, computed without
// knowing the secret.

import { Sha256, sha256, bytesToHex, hexToBytes } from "./sha256_mutable.js";

// The server's shared secret. Real services would draw this from a
// secrets manager; here it's hard-coded so the lesson can demonstrate
// the attack deterministically.
export const SECRET = "correct-horse"; // 13 bytes
export const SECRET_LENGTH = new TextEncoder().encode(SECRET).length;

// The original signed request the attacker observes. Built so that
// appending "&amount=100000" produces an obviously bad outcome — the
// attacker drains the account.
export const ORIGINAL_REQUEST = "user=alice&amount=10";

// The extension the attacker wants to append. Anything starting with
// "&" turns into an extra URL parameter; query-string parsers that take
// the LAST value of a repeated key (PHP, Express with default settings)
// silently let amount=100000 win.
export const ATTACK_EXTENSION = "&amount=100000";

// Compute the naive MAC: SHA-256(SECRET || request). Returns hex.
//
// This is the construction the lesson attacks. NEVER use it for real
// authentication — use HMAC or any AEAD instead. (Both alternatives
// are immune to length extension; see steps 5/6 of the lesson.)
export function signRequest(request) {
  const secretBytes = new TextEncoder().encode(SECRET);
  const reqBytes = new TextEncoder().encode(String(request));
  const combined = new Uint8Array(secretBytes.length + reqBytes.length);
  combined.set(secretBytes, 0);
  combined.set(reqBytes, secretBytes.length);
  return bytesToHex(sha256(combined));
}

// Server-side verification: recompute SHA-256(SECRET || request),
// compare to the supplied hex tag. Returns boolean. The whole point of
// the lesson is that a forged (request, sig) can pass this check.
//
// `request` can be a string OR a Uint8Array — the latter matters
// because the forged "request as the server sees it" contains the
// internal glue padding (0x80, zero bytes, length field), which is not
// valid UTF-8. A real HTTP framework probably treats query strings as
// bytes too — most parsers, on encountering invalid UTF-8 in a query
// string, either fail open (accept the request, scrub the bad bytes)
// or fail closed (reject — which would actually save us here). The
// lesson assumes the request body is bytes-in, bytes-out: the server
// passes whatever the client sent through to sha256(SECRET || ...).
export function verifyRequest(request, sigHex) {
  let reqBytes;
  if (request instanceof Uint8Array) {
    reqBytes = request;
  } else {
    reqBytes = new TextEncoder().encode(String(request));
  }
  const secretBytes = new TextEncoder().encode(SECRET);
  const combined = new Uint8Array(secretBytes.length + reqBytes.length);
  combined.set(secretBytes, 0);
  combined.set(reqBytes, secretBytes.length);
  const expected = bytesToHex(sha256(combined));
  // Real servers must use constant-time compare; here we don't care
  // since the attack doesn't go through the comparison.
  return expected === String(sigHex).toLowerCase();
}

// The single (request, sig) pair the attacker observes. This is the
// only artifact the attacker starts the attack with — no secret, no
// other examples, no oracle.
export function givenPair() {
  return {
    request: ORIGINAL_REQUEST,
    signature: signRequest(ORIGINAL_REQUEST),
  };
}
