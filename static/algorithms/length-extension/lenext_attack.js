// The length-extension forge.
//
// Given:
//   - originalRequest:  the message the server already signed (string)
//   - originalSigHex:   the signature SHA-256(SECRET || originalRequest)
//   - secretLen:        the assumed byte-length of SECRET (the attacker
//                       either knows or brute-forces this)
//   - extension:        the bytes the attacker wants to append (string
//                       or Uint8Array)
//
// Produce:
//   - forgedRequest:    the message the SERVER will see as authenticated
//                       — equal to (originalRequest || gluePadding ||
//                       extension), returned as a Uint8Array because
//                       the gluePadding contains non-UTF-8 bytes
//   - forgedSig:        the new SHA-256 tag, hex-encoded, that the
//                       server will accept for forgedRequest
//   - gluePadding:      the internal padding bytes the attacker had to
//                       interpolate (returned so the lesson UI can show
//                       them)
//   - secretLen:        echoed back for the validator
//
// The mechanic.
//
//   originalSig = SHA-256(SECRET || originalRequest)
//
// SHA-256 is Merkle-Damgard: the published digest IS the chaining state
// at the end of compression. So `originalSig`, viewed as 32 bytes of
// state, is the EXACT state the hasher would be in after processing
// (SECRET || originalRequest || internal_padding) — that internal
// padding being the same bytes the SHA-256 spec mandates for any input
// of length (secretLen + originalRequest.length).
//
// The attacker can therefore:
//   1. Compute gluePadding = the SHA-256 padding for an input of length
//      (secretLen + originalRequest.length).
//   2. Resume a SHA-256 from `originalSig` as the state, with the byte
//      counter set to (secretLen + originalRequest.length + gluePadding.length)
//      — that's the total bytes the original hasher had absorbed at the
//      moment its state equalled `originalSig`.
//   3. Feed `extension` into the resumed hasher and finalize. That
//      produces SHA-256(SECRET || originalRequest || gluePadding ||
//      extension), which equals the legitimate signature the server
//      would produce for the forged request — without the attacker
//      ever seeing SECRET.
//
// The "forged request" the server receives is (originalRequest ||
// gluePadding || extension). It contains the raw SHA-256 padding bytes
// (0x80 etc.) right in the middle — which is fine, because the server
// just hashes them as more bytes. Real-world attacks confirm this works
// against URL parsers (query strings happily eat the binary garbage
// between the original params and the extension's "&extra=value"
// payload).

import {
  Sha256,
  computeGluePadding,
  bytesToHex,
  hexToBytes,
} from "./sha256_mutable.js";

// The forge. Returns the forged request bytes + the forged signature.
//
// Parameters:
//   originalRequest:  string or Uint8Array
//   originalSigHex:   hex string of the legitimate SHA-256 signature
//   secretLen:        positive integer
//   extension:        string or Uint8Array; the bytes to append
//
// Returns:
//   {
//     forgedRequest: Uint8Array,        // what the server hashes
//     forgedRequestHex: string,         // hex of forgedRequest
//     forgedSig: string,                // hex of the new SHA-256 tag
//     gluePadding: Uint8Array,          // the internal padding bytes
//     gluePaddingHex: string,
//     secretLen: number,                // echoed back
//     originalRequest: string|Uint8Array,
//     originalSig: string,
//     extension: Uint8Array,
//   }
//
// Throws on invalid input shapes.
export function forge(originalRequest, originalSigHex, secretLen, extension) {
  if (!Number.isInteger(secretLen) || secretLen < 0) {
    throw new Error("forge: secretLen must be a non-negative integer");
  }
  // Normalize inputs to bytes.
  const origBytes =
    originalRequest instanceof Uint8Array
      ? originalRequest
      : new TextEncoder().encode(String(originalRequest));
  const extBytes =
    extension instanceof Uint8Array
      ? extension
      : new TextEncoder().encode(String(extension));
  const originalSig = hexToBytes(originalSigHex);
  if (originalSig.length !== 32) {
    throw new Error("forge: originalSigHex must decode to 32 bytes");
  }

  // 1. The glue padding SHA-256 would have appended to (SECRET || originalRequest).
  const gluePadding = computeGluePadding(secretLen + origBytes.length);

  // 2. Resume SHA-256 from the captured state. The byte counter starts at
  //    the total bytes the original hasher had absorbed when its state was
  //    equal to `originalSig`: secretLen + origBytes.length + gluePadding.length.
  const totalBefore = secretLen + origBytes.length + gluePadding.length;
  if (totalBefore % 64 !== 0) {
    // This should never happen by construction — computeGluePadding ensures
    // (msgLen + gluePadding.length) is a multiple of 64. We guard anyway.
    throw new Error(
      `forge: internal bug — totalBefore=${totalBefore} not a multiple of 64`
    );
  }

  // 3. Feed extension into the resumed hash and finalize.
  const forgedSigBytes = Sha256.fromState(originalSig, totalBefore)
    .update(extBytes)
    .finalize();

  // 4. Assemble the forged request the server will see.
  const forgedRequest = new Uint8Array(
    origBytes.length + gluePadding.length + extBytes.length
  );
  forgedRequest.set(origBytes, 0);
  forgedRequest.set(gluePadding, origBytes.length);
  forgedRequest.set(extBytes, origBytes.length + gluePadding.length);

  return {
    forgedRequest,
    forgedRequestHex: bytesToHex(forgedRequest),
    forgedSig: bytesToHex(forgedSigBytes),
    gluePadding,
    gluePaddingHex: bytesToHex(gluePadding),
    secretLen,
    originalRequest:
      typeof originalRequest === "string" ? originalRequest : origBytes,
    originalSig: String(originalSigHex).toLowerCase(),
    extension: extBytes,
  };
}
