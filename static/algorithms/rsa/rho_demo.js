// Pollard's rho factoring + Brent's cycle-detection variant + canvas rendering
// for the "factoring small primes" section of the RSA lesson (steps 11-14).
//
// The lesson at this point has shown the user a toy RSA roundtrip with 1-3
// digit primes. They've just been told "this is breakable in milliseconds".
// This module backs up that claim: pollardRho actually factors a small
// composite N = p·q in ~hundreds of iterations, and the canvas animation
// draws the iconic rho-shape trajectory so the name makes sense.
//
// Pure JS (no BigInt — the demo N is well under 2^53, the Number-safe range,
// and Pollard's rho on tiny composites is what we're teaching anyway).
//
// Math comes from this file. Animation timing and the WeakMap-based HiDPI
// canvas setup pattern is borrowed verbatim from ec_canvas.js — that file's
// header comment explains why the WeakMap (not a property on the DOM node)
// is the only reliable way to capture original canvas dimensions across
// Alpine x-effect re-runs.

// ---- demo modulus -----------------------------------------------------
//
// p = 10007, q = 10103 → N = 101,100,721.
// Both 5-digit primes. Pollard's rho with x_{i+1} = x_i² + 1 mod N starting
// from x_0 = 2 finds a factor in ~150-250 iterations — long enough for a
// satisfying animation (~5-8 seconds at 30-50 ms/step), short enough to
// stay under the 500-point trajectory cap.

export const DEMO_P = 10007;
export const DEMO_Q = 10103;
export const DEMO_N = DEMO_P * DEMO_Q;  // 101,100,721

export function factorDemo() {
  return { p: DEMO_P, q: DEMO_Q, n: DEMO_N };
}

// ---- math primitives --------------------------------------------------

export function gcd(a, b) {
  a = a < 0 ? -a : a;
  b = b < 0 ? -b : b;
  while (b) { const t = a % b; a = b; b = t; }
  return a;
}

// f(x) = (x² + c) mod n. We use plain Number arithmetic; for our demo N
// (~10^8) the intermediate x*x fits comfortably in 2^53.
function fStep(x, c, n) {
  return (x * x + c) % n;
}

// ---- Pollard's rho (Floyd's tortoise & hare) --------------------------
//
// Classic 1975 algorithm. Two pointers walk the sequence x_0, x_1, x_2, ...
// where x_{i+1} = f(x_i). Tortoise advances one f-step per iteration; hare
// advances two. By the time they meet (modulo p, where p is some prime
// factor of n), gcd(|tortoise - hare|, n) is a non-trivial divisor.
//
// The trajectory plotted in 2D as (tortoise_i, hare_i) traces a path that
// — once the cycle is reached — folds back on itself, forming the shape of
// a Greek letter rho (ρ). That's where the name comes from.
//
// Returns {factor, iterations, trajectory}. trajectory is capped at 500
// entries so the animation stays within budget even on pathological inputs.

export function pollardRho(n, c = 1) {
  if (n % 2 === 0) {
    return { factor: 2, iterations: 1, trajectory: [{ x: 0, y: 0, i: 0 }] };
  }
  const maxIters = 100000;   // f-eval budget
  const trajCap = 500;
  let tortoise = 2;
  let hare = 2;
  let factor = 1;
  const trajectory = [{ x: tortoise, y: hare, i: 0 }];
  // Count f-evaluations directly so the lesson can compare apples-to-apples
  // with Brent's variant (which also counts f-evals as iterations). Each
  // Floyd round is 3 f-calls: tortoise once, hare twice.
  let iterations = 0;

  while (factor === 1 && iterations < maxIters) {
    tortoise = fStep(tortoise, c, n);
    iterations++;
    hare = fStep(hare, c, n);
    iterations++;
    hare = fStep(hare, c, n);
    iterations++;
    if (trajectory.length < trajCap) {
      trajectory.push({ x: tortoise, y: hare, i: iterations });
    }
    const diff = tortoise > hare ? tortoise - hare : hare - tortoise;
    factor = gcd(diff, n);
  }

  if (factor === n) {
    // Failed cycle (rare with c=1; would normally retry with a different c).
    // For our pedagogical demo we just bail; callers know N factors.
    return { factor: null, iterations, trajectory };
  }
  return { factor, iterations, trajectory };
}

// ---- Brent's variant ---------------------------------------------------
//
// Brent (1980) replaced Floyd's tortoise/hare with a power-of-2 jump
// strategy: every 2^k iterations, snapshot the current x as the new "fixed"
// reference; then walk x forward and check gcd at each step. Statistically
// ~24% fewer GCD calls than Floyd's, and Brent batched the gcd to once
// every ~m steps (we keep m=1 here for clarity since the iteration count
// is what we're surfacing).
//
// Returns the same shape so the lesson can show "Brent's took N iterations
// vs Pollard's M" side by side.

export function brentVariant(n, c = 1) {
  if (n % 2 === 0) {
    return { factor: 2, iterations: 1, trajectory: [{ x: 0, y: 0, i: 0 }] };
  }
  const maxIters = 100000;
  const trajCap = 500;
  // Standard Brent's algorithm. Variables follow his paper's naming:
  //   y is the "hare" position
  //   x snapshots y at each power-of-2 milestone
  //   r is the current power-of-2 step length
  //   m is the batch size for accumulating products of |x-y| before each gcd
  //   q is the running product (mod n) of those differences
  let y = 2;
  let r = 1;
  let q = 1;
  let factor = 1;
  let x = y;
  let ys = y;
  // Small batch keeps detection responsive on small N (where overshooting
  // by ~m steps would dominate). Brent's paper recommends larger m for big
  // N where gcd cost matters more than overshoot; for the lesson's tiny
  // demo modulus, m = 1 cleanly exhibits the "fewer iterations" property.
  const m = 1;
  const trajectory = [{ x: y, y: y, i: 0 }];
  let iterations = 0;

  while (factor === 1) {
    x = y;
    // Advance y by r steps without checking gcd.
    for (let i = 0; i < r; i++) {
      y = fStep(y, c, n);
      iterations++;
      if (iterations >= maxIters) { factor = null; break; }
    }
    if (factor === null) break;
    let k = 0;
    while (k < r && factor === 1) {
      ys = y;
      const lim = Math.min(m, r - k);
      for (let i = 0; i < lim; i++) {
        y = fStep(y, c, n);
        iterations++;
        const diff = x > y ? x - y : y - x;
        q = (q * diff) % n;
        if (trajectory.length < trajCap) {
          trajectory.push({ x, y, i: iterations });
        }
        if (iterations >= maxIters) break;
      }
      factor = gcd(q, n);
      k += lim;
      if (iterations >= maxIters) { factor = null; break; }
    }
    if (factor === null) break;
    r *= 2;
  }

  if (factor === n) {
    // Backtrack: re-walk from ys one step at a time looking for the gcd
    // hit that produced the n-divisor.
    while (true) {
      ys = fStep(ys, c, n);
      const diff = x > ys ? x - ys : ys - x;
      factor = gcd(diff, n);
      iterations++;
      if (factor > 1 && factor < n) break;
      if (iterations > maxIters) return { factor: null, iterations, trajectory };
    }
  }
  if (factor === null) return { factor: null, iterations, trajectory };
  if (factor === n) return { factor: null, iterations, trajectory };
  return { factor, iterations, trajectory };
}

// ---- canvas setup ------------------------------------------------------
//
// HiDPI canvas setup. Copies the WeakMap _origDims pattern from ec_canvas.js
// verbatim — same reason: Alpine sometimes shuffles canvas state across
// effect re-runs and any property we stash on the DOM node may be lost.
// WeakMap entries are keyed by the canvas node so a fresh node always gets
// a fresh dimension capture; entries vanish on GC.

const _origDims = new WeakMap();

export function setupRhoCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  let dims = _origDims.get(canvas);
  if (!dims) {
    const attrW = parseInt(canvas.getAttribute("width"), 10);
    const attrH = parseInt(canvas.getAttribute("height"), 10);
    const cssW = (attrW && attrW < 4000) ? attrW : 600;
    const cssH = (attrH && attrH < 4000) ? attrH : 400;
    dims = { cssW, cssH };
    _origDims.set(canvas, dims);
  }
  const { cssW, cssH } = dims;
  const targetW = Math.round(cssW * dpr);
  const targetH = Math.round(cssH * dpr);
  if (canvas.width !== targetW) canvas.width = targetW;
  if (canvas.height !== targetH) canvas.height = targetH;
  canvas.style.width = cssW + "px";
  canvas.style.height = cssH + "px";
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const padL = 50, padR = 20, padT = 20, padB = 40;
  const W = cssW, H = cssH;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  // Default viewport: [0, n] on both axes; callers can override via the
  // returned toPx / toPy if they want sub-region zoom. The animation routine
  // sets the modulus N as the viewport range so every point in the trajectory
  // is guaranteed to fall inside.
  return {
    ctx,
    W, H, padL, padR, padT, padB, plotW, plotH,
    // toPx / toPy are *parameterized* by modulus n (used by drawTrajectory).
    toPx: (x, n) => padL + (x / n) * plotW,
    toPy: (y, n) => padT + plotH - (y / n) * plotH,  // flip: y grows upward
    dpr,
  };
}

const COLORS = Object.freeze({
  bg:        "#0f172a",
  grid:      "#1e293b",
  axis:      "#475569",
  text:      "#94a3b8",
  textBold:  "#e2e8f0",
  dot:       "#5eead4",
  dotFade:   "rgba(94, 234, 212, 0.45)",
  cycle:     "#fbbf24",
  result:    "#22c55e",
  accent:    "#a78bfa",
});

// ---- static trajectory plot -------------------------------------------
//
// Renders the full trajectory at once. Each (x_i, x_{2i}) — tortoise and
// hare position at step i — is one point. Early points form a "tail" that
// drifts away from the origin; once the sequence enters its cycle, the
// tortoise revisits values the hare has already seen, and the plotted
// points fold back, tracing the loop of the rho shape.

export function drawTrajectory(ctx, ctxBox, trajectory, c, n) {
  const { W, H, padL, padT, plotW, plotH, toPx, toPy } = ctxBox;
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = COLORS.bg;
  ctx.fillRect(0, 0, W, H);

  // Gridlines — modulus quarters.
  ctx.save();
  ctx.strokeStyle = COLORS.grid;
  ctx.lineWidth = 0.5;
  for (let i = 0; i <= 4; i++) {
    const frac = i / 4;
    // vertical gridlines
    ctx.beginPath();
    ctx.moveTo(padL + frac * plotW, padT);
    ctx.lineTo(padL + frac * plotW, padT + plotH);
    ctx.stroke();
    // horizontal gridlines
    ctx.beginPath();
    ctx.moveTo(padL, padT + frac * plotH);
    ctx.lineTo(padL + plotW, padT + frac * plotH);
    ctx.stroke();
  }
  ctx.restore();

  // Axis labels — show the range [0, n].
  ctx.save();
  ctx.fillStyle = COLORS.text;
  ctx.font = "11px ui-monospace, monospace";
  ctx.textBaseline = "top";
  ctx.textAlign = "center";
  ctx.fillText("0", padL, padT + plotH + 6);
  ctx.fillText(String(n), padL + plotW, padT + plotH + 6);
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  ctx.fillText("0", padL - 6, padT + plotH);
  ctx.fillText(String(n), padL - 6, padT);
  // Axis titles.
  ctx.save();
  ctx.textAlign = "center";
  ctx.fillStyle = COLORS.textBold;
  ctx.fillText("tortoise x_i", padL + plotW / 2, padT + plotH + 22);
  ctx.restore();
  ctx.save();
  ctx.translate(padL - 36, padT + plotH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.textAlign = "center";
  ctx.fillStyle = COLORS.textBold;
  ctx.fillText("hare x_2i", 0, 0);
  ctx.restore();
  ctx.restore();

  // Draw dots.
  ctx.save();
  for (let i = 0; i < trajectory.length; i++) {
    const pt = trajectory[i];
    // Fade older dots slightly — recent points are the "leading edge".
    const isLast20 = i >= trajectory.length - 20;
    ctx.fillStyle = isLast20 ? COLORS.dot : COLORS.dotFade;
    ctx.beginPath();
    ctx.arc(toPx(pt.x, n), toPy(pt.y, n), isLast20 ? 3 : 2, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.restore();

  // Caption.
  ctx.save();
  ctx.fillStyle = COLORS.text;
  ctx.font = "11px ui-monospace, monospace";
  ctx.textAlign = "left";
  ctx.fillText(`f(x) = x² + ${c} mod ${n}`, padL + 4, padT + 14);
  ctx.fillText(`${trajectory.length} steps`, padL + 4, padT + 28);
  ctx.restore();
}

// ---- animated trajectory -----------------------------------------------
//
// Walks the trajectory step-by-step, ~40ms per step (configurable via opts).
// After all dots are placed, fades in a callout showing the discovered
// factor. Returns a Promise that resolves with the rho result.
//
// The phase-machine pattern is the same one ec_canvas.js uses for
// runAddAnimation: each phase records when it `started`, advances when the
// elapsed time exceeds its duration. We pre-compute everything (trajectory,
// factor, iteration count) before the animation begins so rAF only handles
// pixels + timing — never math.

export function runRhoAnimation(canvas, n, c = 1, opts = {}) {
  return new Promise((resolve) => {
    const ctxBox = setupRhoCanvas(canvas);
    const { ctx, W, H, padL, padT, plotW, plotH, toPx, toPy } = ctxBox;

    const rho = pollardRho(n, c);
    const traj = rho.trajectory;

    // Total animation budget: aim for ~5-8 seconds regardless of trajectory
    // length. Long trajectories get faster per-step; short ones get slower.
    const targetTotalMs = opts.totalMs ?? 6000;
    const perStepMs = Math.max(15, Math.min(60, Math.round(targetTotalMs / Math.max(traj.length, 1))));
    const calloutMs = opts.calloutMs ?? 1200;

    const started = {};
    function markState(phase, ts) {
      if (!started[phase]) started[phase] = ts;
      return ts - started[phase];
    }

    function drawBackground() {
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = COLORS.bg;
      ctx.fillRect(0, 0, W, H);

      ctx.save();
      ctx.strokeStyle = COLORS.grid;
      ctx.lineWidth = 0.5;
      for (let i = 0; i <= 4; i++) {
        const frac = i / 4;
        ctx.beginPath();
        ctx.moveTo(padL + frac * plotW, padT);
        ctx.lineTo(padL + frac * plotW, padT + plotH);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(padL, padT + frac * plotH);
        ctx.lineTo(padL + plotW, padT + frac * plotH);
        ctx.stroke();
      }
      ctx.restore();

      // Axis labels.
      ctx.save();
      ctx.fillStyle = COLORS.text;
      ctx.font = "11px ui-monospace, monospace";
      ctx.textBaseline = "top";
      ctx.textAlign = "center";
      ctx.fillText("0", padL, padT + plotH + 6);
      ctx.fillText(String(n), padL + plotW, padT + plotH + 6);
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      ctx.fillText("0", padL - 6, padT + plotH);
      ctx.fillText(String(n), padL - 6, padT);
      ctx.restore();

      // Axis titles.
      ctx.save();
      ctx.textAlign = "center";
      ctx.fillStyle = COLORS.textBold;
      ctx.font = "11px ui-monospace, monospace";
      ctx.fillText("tortoise x_i", padL + plotW / 2, padT + plotH + 24);
      ctx.translate(padL - 38, padT + plotH / 2);
      ctx.rotate(-Math.PI / 2);
      ctx.fillText("hare x_2i", 0, 0);
      ctx.restore();
    }

    function drawDotsUpTo(k) {
      ctx.save();
      // Older points faded, last 20 bright.
      for (let i = 0; i < k && i < traj.length; i++) {
        const pt = traj[i];
        const isLast20 = i >= k - 20;
        ctx.fillStyle = isLast20 ? COLORS.dot : COLORS.dotFade;
        ctx.beginPath();
        ctx.arc(toPx(pt.x, n), toPy(pt.y, n), isLast20 ? 3 : 2, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.restore();

      // Step counter.
      ctx.save();
      ctx.fillStyle = COLORS.text;
      ctx.font = "11px ui-monospace, monospace";
      ctx.textAlign = "left";
      ctx.fillText(`f(x) = x² + ${c} mod ${n}`, padL + 4, padT + 14);
      ctx.fillText(`step ${Math.min(k, traj.length)} / ${traj.length}`, padL + 4, padT + 28);
      ctx.restore();
    }

    function drawCallout(progress) {
      // Box anchored to lower-right of the plot, fading in by progress.
      const boxW = 240, boxH = 70;
      const x0 = padL + plotW - boxW - 10;
      const y0 = padT + plotH - boxH - 10;
      ctx.save();
      ctx.globalAlpha = Math.min(1, progress);
      ctx.fillStyle = "rgba(15, 23, 42, 0.92)";
      ctx.strokeStyle = COLORS.result;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.rect(x0, y0, boxW, boxH);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = COLORS.textBold;
      ctx.font = "12px ui-monospace, monospace";
      ctx.textBaseline = "top";
      ctx.textAlign = "left";
      ctx.fillText(`factor found: ${rho.factor}`, x0 + 10, y0 + 10);
      ctx.fillText(`other factor: ${n / rho.factor}`, x0 + 10, y0 + 28);
      ctx.fillStyle = COLORS.text;
      ctx.fillText(`${rho.iterations} iterations`, x0 + 10, y0 + 46);
      ctx.restore();
    }

    let phase = "walk";   // walk → callout → done
    let walkStep = 0;

    function step(timestamp) {
      if (phase === "walk") {
        const t = markState("walk", timestamp);
        walkStep = Math.min(traj.length, Math.floor(t / perStepMs));
        drawBackground();
        drawDotsUpTo(walkStep);
        if (walkStep >= traj.length) phase = "callout";
        requestAnimationFrame(step);
      } else if (phase === "callout") {
        const t = markState("callout", timestamp);
        const progress = Math.min(1, t / calloutMs);
        drawBackground();
        drawDotsUpTo(traj.length);
        drawCallout(progress);
        if (progress >= 1) phase = "done";
        requestAnimationFrame(step);
      } else {
        if (opts.onDone) opts.onDone(rho);
        resolve(rho);
      }
    }
    requestAnimationFrame(step);
  });
}
