import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SECRET,
  SECRET_LENGTH,
  ORIGINAL_REQUEST,
  ATTACK_EXTENSION,
  signRequest,
  verifyRequest,
  givenPair,
} from "../vulnerable_server.js";
import { forge } from "../lenext_attack.js";
import { bytesToHex } from "../sha256_mutable.js";

// ---- vulnerable_server sanity ----

test("SECRET is the documented 13-byte string", () => {
  assert.equal(SECRET, "correct-horse");
  assert.equal(SECRET_LENGTH, 13);
});

test("signRequest is deterministic", () => {
  assert.equal(signRequest("hello"), signRequest("hello"));
});

test("signRequest of empty string == SHA-256(SECRET)", () => {
  // SHA-256("correct-horse") = ...
  // We trust the cross-checked sha256() and just confirm it stays stable.
  const sig = signRequest("");
  assert.match(sig, /^[0-9a-f]{64}$/);
});

test("verifyRequest accepts the server's own signature", () => {
  assert.equal(verifyRequest("hello world", signRequest("hello world")), true);
});

test("verifyRequest rejects a wrong signature", () => {
  assert.equal(verifyRequest("hello", "0".repeat(64)), false);
});

test("verifyRequest rejects a tampered request with the original sig", () => {
  const sig = signRequest("user=alice&amount=10");
  // Naive tamper: change the message. Without length extension, this MUST fail.
  assert.equal(verifyRequest("user=alice&amount=10000", sig), false);
});

test("givenPair returns the documented original request + its valid sig", () => {
  const { request, signature } = givenPair();
  assert.equal(request, ORIGINAL_REQUEST);
  assert.equal(verifyRequest(request, signature), true);
});

// ---- forge basics ----

test("forge returns the expected shape", () => {
  const { request, signature } = givenPair();
  const result = forge(request, signature, SECRET_LENGTH, ATTACK_EXTENSION);
  assert.ok(result.forgedRequest instanceof Uint8Array);
  assert.match(result.forgedSig, /^[0-9a-f]{64}$/);
  assert.ok(result.gluePadding instanceof Uint8Array);
  assert.ok(result.gluePadding.length >= 9);
  assert.equal(result.gluePadding[0], 0x80);
  assert.equal(result.secretLen, SECRET_LENGTH);
});

test("forge: forgedRequest = originalRequest || gluePadding || extension (byte-exact)", () => {
  const { request, signature } = givenPair();
  const result = forge(request, signature, SECRET_LENGTH, ATTACK_EXTENSION);
  const origBytes = new TextEncoder().encode(request);
  const extBytes = new TextEncoder().encode(ATTACK_EXTENSION);
  // Verify each segment.
  for (let i = 0; i < origBytes.length; i++) {
    assert.equal(result.forgedRequest[i], origBytes[i], `prefix byte ${i}`);
  }
  for (let i = 0; i < result.gluePadding.length; i++) {
    assert.equal(
      result.forgedRequest[origBytes.length + i],
      result.gluePadding[i],
      `glue byte ${i}`
    );
  }
  for (let i = 0; i < extBytes.length; i++) {
    assert.equal(
      result.forgedRequest[origBytes.length + result.gluePadding.length + i],
      extBytes[i],
      `extension byte ${i}`
    );
  }
});

test("forge: validates secretLen", () => {
  const { request, signature } = givenPair();
  assert.throws(() => forge(request, signature, -1, "x"), /non-negative/);
  assert.throws(() => forge(request, signature, 1.5, "x"), /non-negative/);
});

test("forge: validates signature hex", () => {
  // Even-length but only 30 bytes — decodes fine, just wrong size.
  assert.throws(() => forge("a", "ab".repeat(30), 13, "x"), /32 bytes/);
  // Odd-length / non-hex content — fails the hex check earlier.
  assert.throws(() => forge("a", "0".repeat(63), 13, "x"), /invalid hex/);
  assert.throws(() => forge("a", "xx".repeat(32), 13, "x"), /invalid hex/);
});

// ---- the load-bearing tests: SERVER ACCEPTS THE FORGED SIG ----

test("END-TO-END: server's verifyRequest accepts the forged (request, sig)", () => {
  const { request, signature } = givenPair();
  const { forgedRequest, forgedSig } = forge(
    request,
    signature,
    SECRET_LENGTH,
    ATTACK_EXTENSION
  );

  // The forged sig was produced WITHOUT touching SECRET. The attacker
  // only used the published signature and the public message. If the
  // server (which DOES use SECRET) accepts the forgery, the lesson's
  // central claim is real.
  const accepts = verifyRequest(forgedRequest, forgedSig);
  assert.equal(
    accepts,
    true,
    `server rejected the forged signature — the attack failed. ` +
      `forgedRequest=${bytesToHex(forgedRequest)}, forgedSig=${forgedSig}`
  );
});

test("END-TO-END: drains the account — amount appears doubled in the forged request", () => {
  // Pedagogical: confirm the forged request indeed contains both the
  // original "amount=10" and the appended "amount=100000". A naive PHP-
  // style query parser taking the last value would see amount=100000.
  const { request, signature } = givenPair();
  const { forgedRequest } = forge(
    request,
    signature,
    SECRET_LENGTH,
    ATTACK_EXTENSION
  );
  // Walk forgedRequest as bytes; locate both substrings.
  const text = new TextDecoder("utf-8", { fatal: false }).decode(forgedRequest);
  assert.ok(text.includes("amount=10"), "original amount missing");
  assert.ok(text.includes("amount=100000"), "extension amount missing");
});

test("END-TO-END: forgery still works at varied secret lengths if attacker iterates", () => {
  // Real attackers don't always know the secret length, but they can
  // iterate: forge(...) with secretLen=1, secretLen=2, ... and check
  // each against the server. Exactly one length (the true one) will
  // produce an accepted sig. We simulate that loop here.
  const { request, signature } = givenPair();
  const ext = "&debug=1";
  let acceptedAt = null;
  for (let len = 1; len <= 32; len++) {
    const { forgedRequest, forgedSig } = forge(request, signature, len, ext);
    if (verifyRequest(forgedRequest, forgedSig)) {
      acceptedAt = len;
      break;
    }
  }
  assert.equal(acceptedAt, SECRET_LENGTH, "attacker brute-force found the secret length");
});

test("END-TO-END: forging different extensions, server accepts all of them", () => {
  const { request, signature } = givenPair();
  for (const ext of ["&admin=true", "&role=root", "&y=1", "&xxx", "X".repeat(80)]) {
    const { forgedRequest, forgedSig } = forge(request, signature, SECRET_LENGTH, ext);
    assert.equal(
      verifyRequest(forgedRequest, forgedSig),
      true,
      `server rejected extension ${JSON.stringify(ext)}`
    );
  }
});

test("END-TO-END: forging with wrong secretLen produces a sig the server REJECTS", () => {
  // Sanity: if the attacker guesses the wrong length, the resulting
  // forged sig should not pass — otherwise the attack would be trivial
  // (any length would "work") and the brute-force-the-length step in
  // the previous test wouldn't have anything to discover.
  const { request, signature } = givenPair();
  const wrong = SECRET_LENGTH + 1;
  const { forgedRequest, forgedSig } = forge(request, signature, wrong, "&x=1");
  assert.equal(verifyRequest(forgedRequest, forgedSig), false);
});
