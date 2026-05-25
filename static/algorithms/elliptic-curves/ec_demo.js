// Curve math + plot-data helpers + animation orchestrator for the
// "Elliptic curves, visually" lesson.
//
// Canvas drawing primitives + RAF-based animations live in ./ec_canvas.js;
// we re-export them here so the wizard's single-module `demo` slot exposes
// both the math and the canvas helpers (`demo.runAddAnimation`, etc.).
// The two files are split for editing sanity, not for any runtime reason.
export * from "./ec_canvas.js";
//
// Two arithmetic regimes share one set of formulas:
//   - Over the reals (mod=null): operations use Number arithmetic; the
//     results are floating-point and intended for a smooth SVG plot.
//   - Over a finite field F_p (mod=p): operations use BigInt so we never
//     drop bits on the modular inverse. Returns plain Numbers since the
//     prime is small (we use p=17 for the scatter step).
//
// Point at infinity is represented as `null`. Every public function tolerates
// it as an input ("identity") and may return it ("vertical line").

// ---- displayed-curve defaults -------------------------------------------
//
// The visual lesson uses `y² = x³ - 3x + 5` for steps 3-5 because:
//   * 4·(-3)³ + 27·5² = -108 + 675 = 567 > 0  → non-singular, one component
//   * the interesting points (P+Q and 2P for our preset picks) stay inside
//     the plotted [-3, 3] × [-3, 3] window.
// Step 2 ("the curve") cycles through several (a, b) presets via a button.
export const DEFAULT_A = -3;
export const DEFAULT_B = 5;

// The finite-field scatter step uses the very-small secp256k1-shape curve
// y² ≡ x³ + 7 (mod 17). 13 affine points + the point at infinity = 14.
export const FF_A = 0;
export const FF_B = 7;
export const FF_P = 17;

// ---- helpers ------------------------------------------------------------

function _mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

// Extended Euclid in BigInt — returns a^{-1} mod m. Throws if gcd != 1
// (only happens here if `a` ≡ 0 mod m).
function _modInverseBig(a, m) {
  const aa = _mod(a, m);
  if (aa === 0n) throw new Error("no inverse for 0");
  let [old_r, r] = [aa, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error(`${a} has no inverse mod ${m}`);
  return _mod(old_s, m);
}

// ---- point addition / doubling -----------------------------------------
//
// Both branches implement the standard short-Weierstrass formulas:
//   P != Q  : s = (yQ - yP) / (xQ - xP)
//   P == Q  : s = (3·xP² + a) / (2·yP)
//   then    : xR = s² - xP - xQ,   yR = s·(xP - xR) - yP
// Over the reals this is float arithmetic; over F_p the slope's denominator
// becomes a modular inverse.

export function pointAdd(p1, p2, a, mod = null) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  if (mod === null) {
    if (Math.abs(p1.x - p2.x) < 1e-12) {
      if (Math.abs(p1.y + p2.y) < 1e-9) return null;   // P + (-P) = O
      return pointDouble(p1, a, null);
    }
    const s = (p2.y - p1.y) / (p2.x - p1.x);
    const xR = s * s - p1.x - p2.x;
    const yR = s * (p1.x - xR) - p1.y;
    return { x: xR, y: yR };
  }
  // Finite field: lift to BigInt.
  const m = BigInt(mod);
  const aB = BigInt(a);
  const x1 = _mod(BigInt(p1.x), m), y1 = _mod(BigInt(p1.y), m);
  const x2 = _mod(BigInt(p2.x), m), y2 = _mod(BigInt(p2.y), m);
  if (x1 === x2) {
    if (_mod(y1 + y2, m) === 0n) return null;
    return pointDouble(p1, a, mod);
  }
  const num = _mod(y2 - y1, m);
  const den = _modInverseBig(x2 - x1, m);
  const s = _mod(num * den, m);
  const xR = _mod(s * s - x1 - x2, m);
  const yR = _mod(s * (x1 - xR) - y1, m);
  return { x: Number(xR), y: Number(yR) };
}

export function pointDouble(p, a, mod = null) {
  if (p === null) return null;
  if (mod === null) {
    if (Math.abs(p.y) < 1e-12) return null;            // tangent vertical
    const s = (3 * p.x * p.x + a) / (2 * p.y);
    const xR = s * s - 2 * p.x;
    const yR = s * (p.x - xR) - p.y;
    return { x: xR, y: yR };
  }
  const m = BigInt(mod);
  const aB = BigInt(a);
  const x = _mod(BigInt(p.x), m), y = _mod(BigInt(p.y), m);
  if (y === 0n) return null;
  const num = _mod(3n * x * x + aB, m);
  const den = _modInverseBig(2n * y, m);
  const s = _mod(num * den, m);
  const xR = _mod(s * s - 2n * x, m);
  const yR = _mod(s * (x - xR) - y, m);
  return { x: Number(xR), y: Number(yR) };
}

// ---- scalar mult --------------------------------------------------------
//
// Double-and-add. `onStep`, if supplied, gets called once per loop iteration
// with `{ bit, action, current, accumulator }` so the animated step can
// render the binary-bit ladder live.

export function scalarMul(k, p, a, mod = null, onStep = null) {
  if (k === 0 || p === null) return null;
  let kk = k < 0 ? -k : k;
  let addend = p;
  let result = null;
  let bitIndex = 0;
  while (kk > 0) {
    const bit = kk & 1;
    if (onStep) onStep({
      bitIndex,
      bit,
      action: bit ? "add" : "skip",
      addend,
      accumulator: result,
    });
    if (bit) result = pointAdd(result, addend, a, mod);
    addend = pointDouble(addend, a, mod);
    kk >>= 1;
    bitIndex++;
  }
  // For k < 0: negate result. Skip — callers in this lesson pass k > 0.
  return result;
}

// ---- plot data for the SVG curve ---------------------------------------
//
// Returns an SVG path string for `y = sqrt(x^3 + ax + b)` (upper branch)
// plus the mirrored lower branch. Skips x values where the cubic is
// negative so the path doesn't render through imaginary territory. The
// caller is responsible for the SVG transform (curve-coords → pixel-coords).

export function plotCurvePath(a, b, xMin, xMax, samples = 240) {
  const step = (xMax - xMin) / samples;
  // Sample upper branch left-to-right, then lower branch right-to-left, so
  // a single path can outline the full curve. When the cubic dips below 0
  // we close the in-progress sub-path and start fresh on the other side.
  const segments = [];
  let current = [];
  for (let i = 0; i <= samples; i++) {
    const x = xMin + i * step;
    const y2 = x * x * x + a * x + b;
    if (y2 < 0) {
      if (current.length > 0) {
        segments.push(current);
        current = [];
      }
      continue;
    }
    current.push({ x, y: Math.sqrt(y2) });
  }
  if (current.length > 0) segments.push(current);

  let d = "";
  for (const seg of segments) {
    if (seg.length < 2) continue;
    // Upper branch L→R.
    d += `M ${seg[0].x} ${seg[0].y}`;
    for (let i = 1; i < seg.length; i++) {
      d += ` L ${seg[i].x} ${seg[i].y}`;
    }
    // Lower branch R→L (mirror y).
    for (let i = seg.length - 1; i >= 0; i--) {
      d += ` L ${seg[i].x} ${-seg[i].y}`;
    }
    d += " Z";
  }
  return d;
}

// ---- finite-field enumeration ------------------------------------------
//
// Brute-force: for each x in [0, p), compute y² = x³ + ax + b mod p, then
// scan y in [0, p) for a match. p is small (17 in this lesson) so the
// quadratic cost is irrelevant.

export function finiteFieldPoints(a, b, p) {
  const pts = [];
  for (let x = 0; x < p; x++) {
    const rhs = ((((x * x) % p) * x) % p + a * x % p + b) % p;
    const target = ((rhs % p) + p) % p;
    for (let y = 0; y < p; y++) {
      if ((y * y) % p === target) pts.push({ x, y });
    }
  }
  return pts;
}

// ---- geometric helper for the addition animation ----------------------
//
// Given two points on the curve (and the curve's a, b), return the third
// intersection of the line PQ with the curve — before reflection. For a
// secant line: x3 = s² - x1 - x2. For doubling, the tangent at P has the
// same formula. The returned point's y is on the line, not reflected.

export function findThirdIntersection(p1, p2, a, b) {
  let s;
  if (Math.abs(p1.x - p2.x) < 1e-12 && Math.abs(p1.y - p2.y) < 1e-12) {
    // Tangent at P.
    s = (3 * p1.x * p1.x + a) / (2 * p1.y);
  } else {
    s = (p2.y - p1.y) / (p2.x - p1.x);
  }
  const yInt = p1.y - s * p1.x;
  const xR = s * s - p1.x - p2.x;
  const yR = s * xR + yInt;          // y on the line — *not* reflected
  return { x: xR, y: yR, slope: s, yIntercept: yInt };
}

// ---- animation orchestrator -------------------------------------------
//
// Drives an Alpine-bound state object through the 4-phase add/double
// animation. The template owns the SVG; this function just flips flags
// and writes intermediate coords on a timer so the template's CSS
// transitions + x-bind do the actual visual work.
//
// Phases:
//   0  idle           — initial state
//   1  line drawn     — chord PQ (or tangent at P) is visible
//   2  third found    — faint circle at the third intersection
//   3  drop-down      — dashed vertical to reflection
//   4  result          — green dot at P+Q
//
// Returns a Promise that resolves once phase 4 is reached so tests / callers
// can await the full animation.

export function animatedAdd(state, p1, p2, a, b, durations = {}) {
  const d = {
    line:    durations.line    ?? 800,
    third:   durations.third   ?? 500,
    drop:    durations.drop    ?? 500,
    final:   durations.final   ?? 300,
  };
  const third = findThirdIntersection(p1, p2, a, b);
  const reflection = { x: third.x, y: -third.y };

  state.phase = 0;
  state.p1 = p1;
  state.p2 = p2;
  state.thirdPoint = third;
  state.reflection = reflection;
  state.lineSlope = third.slope;
  state.lineYIntercept = third.yIntercept;
  state.resultPoint = null;

  return new Promise((resolve) => {
    setTimeout(() => { state.phase = 1; }, 30);
    setTimeout(() => { state.phase = 2; }, 30 + d.line);
    setTimeout(() => { state.phase = 3; }, 30 + d.line + d.third);
    setTimeout(() => {
      state.phase = 4;
      state.resultPoint = reflection;
      resolve(reflection);
    }, 30 + d.line + d.third + d.drop);
  });
}

// Doubling is the same animation, just with `p2 = p1`. Kept as a separate
// export so callers don't have to think about which formula to invoke.
export function animatedDouble(state, p, a, b, durations = {}) {
  return animatedAdd(state, p, p, a, b, durations);
}

// ---- preset curves for step 2 ("the curve" widget) --------------------
//
// Each preset is well-behaved (non-singular, fits the [-3, 3] viewport
// or larger as noted) and chosen to show variety.
export const CURVE_PRESETS = Object.freeze([
  { a: -3, b: 5, label: "y² = x³ − 3x + 5", window: 3.2 },
  { a: -7, b: 6, label: "y² = x³ − 7x + 6  (two components — an oval + a branch)", window: 4.2 },
  { a: -2, b: 2, label: "y² = x³ − 2x + 2", window: 3.2 },
  { a:  0, b: 7, label: "y² = x³ + 7  (secp256k1, the Bitcoin curve, over the reals)", window: 4.0 },
]);

// Convenience: is this (a, b) pair non-singular? 4a³ + 27b² ≠ 0.
export function isNonSingular(a, b) {
  return (4 * a * a * a + 27 * b * b) !== 0;
}
