// Block-cipher-modes lesson validators.
//
// - cbc_walk: sentinel validator. The CBC walk step writes "run" into the
//   input via a button; we accept any non-empty token. The demo wrapper
//   in the template branch is responsible for setting `mode_iv_hex`,
//   `mode_plaintext`, and `mode_ct_blocks` on the wizard state before the
//   user clicks Encrypt-then-Continue.
//
// - pick_a_mode: multi-input {s1, s2, s3} with per-scenario validation.
//   Scenario s2 ("DB column where identical plaintext must look different")
//   accepts CBC OR GCM — both are correct; the spec calls this out as the
//   "anything-but-ECB" scenario with CBC as the canonical answer.

const VALID_MODES = new Set(["ECB", "CBC", "CTR", "GCM"]);

function _normalize(s) {
  if (s === null || s === undefined) return "";
  return String(s).trim().toUpperCase();
}

export function cbc_walk(input, _state) {
  const s = input == null ? "" : String(input).trim();
  if (s === "") {
    return { ok: false, hint: "Click the Encrypt button to run the walk-through." };
  }
  return { ok: true, value: {} };
}

export function pick_a_mode(input, _state) {
  const s1 = _normalize(input?.s1);
  const s2 = _normalize(input?.s2);
  const s3 = _normalize(input?.s3);

  if (!s1 || !s2 || !s3) {
    return { ok: false, hint: "Pick a mode for each scenario." };
  }
  for (const [label, v] of [["s1", s1], ["s2", s2], ["s3", s3]]) {
    if (!VALID_MODES.has(v)) {
      return { ok: false, hint: `Unknown mode "${v}" for ${label}. Pick one of: ECB, CBC, CTR, GCM.` };
    }
  }

  // Scenario 1 — HTTP body over an untrusted network: needs auth → GCM.
  if (s1 !== "GCM") {
    return { ok: false, hint: "Sending data over an untrusted network needs integrity. CBC and CTR provide confidentiality but not authentication — anyone can flip bits undetected. GCM provides both." };
  }

  // Scenario 2 — DB column, identical plaintext must look different.
  // ECB violates the requirement; CTR is fine for confidentiality but the
  // spec calls it out as a poor idiomatic fit; CBC or GCM accepted.
  if (s2 === "ECB") {
    return { ok: false, hint: "ECB encrypts identical plaintext blocks to identical ciphertext — exactly what this scenario forbids." };
  }
  if (s2 === "CTR") {
    return { ok: false, hint: "CTR is fine for confidentiality but database fields are short, often fit in one block, and rarely need streaming. CBC or GCM is more idiomatic here." };
  }
  // s2 ∈ {CBC, GCM} both pass.

  // Scenario 3 — random-access per-record disk encryption, integrity elsewhere → CTR.
  if (s3 !== "CTR") {
    return { ok: false, hint: "CTR allows random access (jump to block i by encrypting counter i). CBC requires reading all prior blocks. GCM is fine but adds an authentication tag this scenario does not need." };
  }

  return {
    ok: true,
    value: {
      mode_scenario_1: s1,
      mode_scenario_2: s2,
      mode_scenario_3: s3,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// No step-level walkthroughs for this lesson — the interactive steps are
// either button-driven (cbc-walk) or have inline scenario hints (pick-a-mode).
export const walkthroughs = {};
