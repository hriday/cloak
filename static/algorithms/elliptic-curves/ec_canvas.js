// Canvas + requestAnimationFrame renderers for the "Elliptic curves,
// visually" lesson. Replaces the prior static-SVG widget partial; sidesteps
// two Alpine-bound bugs (no x-data scopes inside <svg>, no Django {# … #}
// inside x-data HTML attributes) by driving every visualization through
// imperative canvas drawing.
//
// Pattern borrowed from the open-source viz at curves.xargs.org (MIT) —
// each animation is a small state machine inside a single `requestAnimationFrame`
// loop. Each phase has a duration in ms; we record `started[phase]` on the
// first frame it runs and finish when `timestamp - started[phase]` exceeds
// the phase's duration.
//
// Math comes from ./ec_demo.js. This file owns nothing arithmetic — only
// pixels and timing.

import {
  pointAdd, pointDouble, scalarMul,
  finiteFieldPoints,
  findThirdIntersection,
  plotCurvePath,
  DEFAULT_A, DEFAULT_B, FF_A, FF_B, FF_P,
  CURVE_PRESETS, isNonSingular,
} from "./ec_demo.js";

// ---- color palette -----------------------------------------------------
//
// Tuned for the lesson's dark background (--code-bg). Keep tone consistent
// across canvases so muscle memory carries between steps:
//   red    = P (the operand whose tangent or slope is drawn)
//   blue   = Q (the second operand)
//   orange = third intersection on the line (the *unreflected* point)
//   green  = the result point — what P+Q (or 2P, k·P) actually equals
//   teal   = the curve itself
const COLORS = Object.freeze({
  curve:     "#5eead4",
  axis:      "#666",
  grid:      "#1e293b",
  text:      "#888",
  textBold:  "#cbd5e1",
  P:         "#ef4444",
  Q:         "#60a5fa",
  third:     "#fbbf24",
  result:    "#22c55e",
  chord:     "#fbbf24",
  reflect:   "#ef4444",
  accent:    "#a78bfa",
});

// Standard easing — smoothstep. Cubic in [0,1], symmetric, 0 → 0 and 1 → 1.
// Matches the xargs reference's `easeInOut`.
export function easeInOut(t) {
  if (t <= 0) return 0;
  if (t >= 1) return 1;
  return t * t * (3 - 2 * t);
}

// ---- HiDPI + viewport setup -------------------------------------------
//
// Canvas backing stores get scaled by devicePixelRatio so the lines stay
// crisp on retina screens. The DPR setup is idempotent — we stash the last
// DPR we applied on the canvas DOM node so re-calling `setupCanvas` from a
// click handler (e.g., replay) doesn't double-scale the buffer.
//
// The returned `{toPx, toPy}` map curve coordinates (math space) to canvas
// pixel coordinates. We render with `transform(1,0,0,1,0,0)` in the CSS
// pixel coordinate system after `ctx.scale(dpr, dpr)`, so callers do not
// need to think about devicePixelRatio.
// Original logical (CSS-pixel) dimensions per canvas, captured at first
// setupCanvas() call. We use a module-level WeakMap rather than a property
// on the DOM node because (a) Alpine sometimes shuffles canvas state across
// effect re-runs and the property gets lost, (b) browser-cached state from
// a previous (buggy) version of this code can leave the canvas with stale
// `_dprApplied` set but bogus dimensions, locking out re-setup. The WeakMap
// is keyed by the *current* canvas node so a fresh node always gets a fresh
// dimension capture; the entry vanishes automatically when the node is GC'd.
const _origDims = new WeakMap();

export function setupCanvas(canvas, viewport) {
  const dpr = window.devicePixelRatio || 1;
  // Capture original CSS-pixel dimensions on first call. We read them from
  // canvas.getAttribute('width'/'height') — those are the *HTML attribute*
  // values the template specified. Note: canvas.width and the HTML attribute
  // are normally synonyms, but once we assign to canvas.width below it would
  // become impossible to recover the original. So we record them ONCE per
  // canvas DOM node into the WeakMap and trust that as the source of truth.
  let dims = _origDims.get(canvas);
  if (!dims) {
    const attrW = parseInt(canvas.getAttribute("width"), 10);
    const attrH = parseInt(canvas.getAttribute("height"), 10);
    // Sanity: if the attribute is missing or nonsensical, fall back to a
    // safe default. Real values come from the template (e.g., 600x400, 380x380).
    const cssW = (attrW && attrW < 4000) ? attrW : 600;
    const cssH = (attrH && attrH < 4000) ? attrH : 400;
    dims = { cssW, cssH };
    _origDims.set(canvas, dims);
  }
  const { cssW, cssH } = dims;
  // Always re-assert the backing-store + CSS dimensions every call. Cheap
  // when already correct (browser no-op), self-healing if anything reset them.
  const targetW = Math.round(cssW * dpr);
  const targetH = Math.round(cssH * dpr);
  if (canvas.width !== targetW) canvas.width = targetW;
  if (canvas.height !== targetH) canvas.height = targetH;
  canvas.style.width  = cssW + "px";
  canvas.style.height = cssH + "px";
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  // Pixel-space layout: padding inside the canvas so axis labels have room.
  const padL = 30, padR = 30, padT = 20, padB = 20;
  const W = cssW, H = cssH;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  const { xMin, xMax, yMin, yMax } = viewport;
  const xRange = xMax - xMin;
  const yRange = yMax - yMin;
  function toPx(x) { return padL + ((x - xMin) / xRange) * plotW; }
  function toPy(y) { return padT + ((yMax - y) / yRange) * plotH; }

  return {
    ctx, toPx, toPy,
    W, H, padL, padR, padT, padB, plotW, plotH,
    dpr,
  };
}

// ---- low-level drawing primitives -------------------------------------

export function drawAxes(ctx, ctxBox, viewport) {
  const { toPx, toPy, W, H, padL, padT, plotW, plotH } = ctxBox;
  ctx.save();
  ctx.lineWidth = 0.5;
  ctx.strokeStyle = COLORS.axis;

  // x-axis (only if y=0 is inside the viewport)
  if (viewport.yMin <= 0 && viewport.yMax >= 0) {
    const y0 = toPy(0);
    ctx.beginPath();
    ctx.moveTo(padL, y0);
    ctx.lineTo(padL + plotW, y0);
    ctx.stroke();
  }
  // y-axis (only if x=0 is inside the viewport)
  if (viewport.xMin <= 0 && viewport.xMax >= 0) {
    const x0 = toPx(0);
    ctx.beginPath();
    ctx.moveTo(x0, padT);
    ctx.lineTo(x0, padT + plotH);
    ctx.stroke();
  }

  // Axis labels
  ctx.fillStyle = COLORS.text;
  ctx.font = "11px ui-monospace, monospace";
  ctx.textBaseline = "middle";
  if (viewport.yMin <= 0 && viewport.yMax >= 0) {
    ctx.fillText("x", padL + plotW - 10, toPy(0) + 10);
  }
  if (viewport.xMin <= 0 && viewport.xMax >= 0) {
    ctx.fillText("y", toPx(0) + 6, padT + 8);
  }
  ctx.restore();
}

// Plot y² = x³ + ax + b. Sample the cubic across the viewport's x-range and
// stroke both branches. Where the cubic dips below zero, the curve is
// imaginary — we end the current path and start a fresh one on the far
// side so a two-component curve (e.g., a=-7, b=6) renders cleanly.
export function drawCurve(ctx, ctxBox, a, b, viewport, samples = 400) {
  const { toPx, toPy } = ctxBox;
  ctx.save();
  ctx.lineWidth = 2;
  ctx.strokeStyle = COLORS.curve;
  ctx.lineJoin = "round";

  const step = (viewport.xMax - viewport.xMin) / samples;
  // Collect contiguous segments where y² >= 0
  const segments = [];
  let current = [];
  for (let i = 0; i <= samples; i++) {
    const x = viewport.xMin + i * step;
    const y2 = x * x * x + a * x + b;
    if (y2 < 0) {
      if (current.length > 0) { segments.push(current); current = []; }
      continue;
    }
    current.push({ x, y: Math.sqrt(y2) });
  }
  if (current.length > 0) segments.push(current);

  for (const seg of segments) {
    if (seg.length < 2) continue;
    ctx.beginPath();
    // upper branch L→R
    ctx.moveTo(toPx(seg[0].x), toPy(seg[0].y));
    for (let i = 1; i < seg.length; i++) {
      ctx.lineTo(toPx(seg[i].x), toPy(seg[i].y));
    }
    // lower branch R→L (mirror y)
    for (let i = seg.length - 1; i >= 0; i--) {
      ctx.lineTo(toPx(seg[i].x), toPy(-seg[i].y));
    }
    ctx.closePath();
    ctx.stroke();
  }
  ctx.restore();
}

// Filled circle + optional label
export function drawDot(ctx, ctxBox, x, y, color, label) {
  const { toPx, toPy } = ctxBox;
  ctx.save();
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(toPx(x), toPy(y), 5, 0, Math.PI * 2);
  ctx.fill();
  if (label) {
    ctx.fillStyle = color;
    ctx.font = "13px ui-monospace, monospace";
    ctx.textBaseline = "alphabetic";
    ctx.fillText(label, toPx(x) + 9, toPy(y) - 6);
  }
  ctx.restore();
}

// Animated line drawn from p1 toward p2 with progress ∈ [0, 1]. Extends
// in BOTH directions past the segment so the chord visually crosses the
// curve at the third intersection, mimicking how a geometer sketches it.
export function drawLineProgressive(ctx, ctxBox, p1, p2, viewport, progress, color = COLORS.chord) {
  const { toPx, toPy } = ctxBox;
  const dx = p2.x - p1.x;
  const dy = p2.y - p1.y;
  // Extend past both endpoints by 50% of the viewport width.
  const extend = (viewport.xMax - viewport.xMin) * 0.5;
  // Direction unit vector in curve coords.
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const ux = dx / len, uy = dy / len;
  const reach = extend;
  const startX = p1.x - ux * reach;
  const startY = p1.y - uy * reach;
  const endX   = p2.x + ux * reach;
  const endY   = p2.y + uy * reach;
  // Interpolate end toward start by `1 - progress`. So at progress=0, the
  // line is invisible (zero length); at progress=1 it spans the full
  // extended segment.
  const e = easeInOut(progress);
  const curEndX = startX + (endX - startX) * e;
  const curEndY = startY + (endY - startY) * e;

  ctx.save();
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.setLineDash([4, 3]);
  ctx.beginPath();
  ctx.moveTo(toPx(startX), toPy(startY));
  ctx.lineTo(toPx(curEndX), toPy(curEndY));
  ctx.stroke();
  ctx.restore();
}

// Static line at full extent (no progressive draw)
function drawLineFull(ctx, ctxBox, p1, p2, viewport, color = COLORS.chord) {
  drawLineProgressive(ctx, ctxBox, p1, p2, viewport, 1, color);
}

// Vertical dashed line (the "reflect" step). Animates from (x, yFrom) down
// to (x, yFrom + (yTo - yFrom) * progress).
function drawVerticalProgressive(ctx, ctxBox, x, yFrom, yTo, progress, color = COLORS.reflect) {
  const { toPx, toPy } = ctxBox;
  const e = easeInOut(progress);
  const curY = yFrom + (yTo - yFrom) * e;
  ctx.save();
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.setLineDash([3, 2]);
  ctx.beginPath();
  ctx.moveTo(toPx(x), toPy(yFrom));
  ctx.lineTo(toPx(x), toPy(curY));
  ctx.stroke();
  ctx.restore();
}

// ---- static rendering for non-animated steps --------------------------

// Step 2 ("the curve"): plot the default curve y² = x³ - 3x + 5 with axes.
// Called via x-init so the canvas paints itself the moment it mounts.
export function drawStatic(canvas, a, b, viewport) {
  const ctxBox = setupCanvas(canvas, viewport);
  const { ctx, W, H } = ctxBox;
  ctx.clearRect(0, 0, W, H);
  drawAxes(ctx, ctxBox, viewport);
  drawCurve(ctx, ctxBox, a, b, viewport);
}

// Step 6 (finite-field scatter): grid + all (x,y) ∈ [0,p)² satisfying
// y² ≡ x³+ax+b (mod p). Returns the list of points so a later animation
// (the DLP step) can reuse them.
export function drawFiniteField(canvas, a, b, p) {
  const ctxBox = setupCanvas(canvas, { xMin: -1, xMax: p, yMin: -1, yMax: p });
  const { ctx, toPx, toPy, W, H } = ctxBox;
  ctx.clearRect(0, 0, W, H);

  // Grid lines
  ctx.save();
  ctx.strokeStyle = COLORS.grid;
  ctx.lineWidth = 0.5;
  for (let i = 0; i < p; i++) {
    ctx.beginPath();
    ctx.moveTo(toPx(i), toPy(0));
    ctx.lineTo(toPx(i), toPy(p - 1));
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(toPx(0), toPy(i));
    ctx.lineTo(toPx(p - 1), toPy(i));
    ctx.stroke();
  }
  ctx.restore();

  // Axis labels — sparse, just the corners and midpoint
  ctx.save();
  ctx.fillStyle = COLORS.text;
  ctx.font = "10px ui-monospace, monospace";
  ctx.textAlign = "center";
  for (const v of [0, Math.floor(p / 2), p - 1]) {
    ctx.fillText(String(v), toPx(v), toPy(-0.6));
    ctx.textAlign = "right";
    ctx.fillText(String(v), toPx(-0.3), toPy(v) + 3);
    ctx.textAlign = "center";
  }
  ctx.restore();

  const points = finiteFieldPoints(a, b, p);
  ctx.save();
  ctx.fillStyle = COLORS.curve;
  for (const pt of points) {
    ctx.beginPath();
    ctx.arc(toPx(pt.x), toPy(pt.y), 3.5, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.restore();
  return { points, ctxBox };
}

// ---- the addition animation -------------------------------------------
//
// 4 phases:
//   1. drawLine  — chord from P to Q grows from zero length to full
//   2. linePause — chord stays, third intersection (orange) appears
//   3. negate    — dashed vertical drops from (−R) down to (+R)
//   4. done      — hold the final picture briefly
//
// We redraw the curve + base dots every frame because canvas has no DOM
// (so partially-clearing the chord would leave artifacts).

export function runAddAnimation(canvas, a, b, P, Q, viewport, opts = {}) {
  return new Promise((resolve) => {
    const ctxBox = setupCanvas(canvas, viewport);
    const { ctx, W, H } = ctxBox;

    const duration = Object.assign({
      drawLine: 1000,
      linePause: 600,
      negate: 800,
      done: 600,
    }, opts.duration || {});

    const third = findThirdIntersection(P, Q, a, b);
    const negR = { x: third.x, y: third.y };       // before reflection — on the line
    const R = { x: third.x, y: -third.y };          // after reflection — actual P+Q

    const started = {};
    const finished = {};

    function markState(phase, timestamp) {
      if (!started[phase]) started[phase] = timestamp;
      return timestamp - started[phase];
    }

    function redrawBase() {
      ctx.clearRect(0, 0, W, H);
      drawAxes(ctx, ctxBox, viewport);
      drawCurve(ctx, ctxBox, a, b, viewport);
      drawDot(ctx, ctxBox, P.x, P.y, COLORS.P, "P");
      drawDot(ctx, ctxBox, Q.x, Q.y, COLORS.Q, "Q");
    }

    function step(timestamp) {
      redrawBase();
      if (!finished.drawLine) {
        const t = markState("drawLine", timestamp);
        const progress = Math.min(1, t / duration.drawLine);
        drawLineProgressive(ctx, ctxBox, P, Q, viewport, progress);
        if (progress >= 1) finished.drawLine = timestamp;
      } else if (!finished.linePause) {
        drawLineFull(ctx, ctxBox, P, Q, viewport);
        drawDot(ctx, ctxBox, negR.x, negR.y, COLORS.third, "−R");
        const t = markState("linePause", timestamp);
        if (t >= duration.linePause) finished.linePause = timestamp;
      } else if (!finished.negate) {
        drawLineFull(ctx, ctxBox, P, Q, viewport);
        drawDot(ctx, ctxBox, negR.x, negR.y, COLORS.third, "−R");
        const t = markState("negate", timestamp);
        const progress = Math.min(1, t / duration.negate);
        drawVerticalProgressive(ctx, ctxBox, R.x, negR.y, R.y, progress);
        if (progress >= 1) {
          drawDot(ctx, ctxBox, R.x, R.y, COLORS.result, "P+Q");
          finished.negate = timestamp;
        }
      } else if (!finished.done) {
        drawLineFull(ctx, ctxBox, P, Q, viewport);
        drawDot(ctx, ctxBox, negR.x, negR.y, COLORS.third, "−R");
        // Final reflect line stays at full length
        drawVerticalProgressive(ctx, ctxBox, R.x, negR.y, R.y, 1);
        drawDot(ctx, ctxBox, R.x, R.y, COLORS.result, "P+Q");
        const t = markState("done", timestamp);
        if (t >= duration.done) finished.done = timestamp;
      }

      if (!finished.done) {
        requestAnimationFrame(step);
      } else {
        if (opts.onDone) opts.onDone(R);
        resolve(R);
      }
    }
    requestAnimationFrame(step);
  });
}

// ---- the doubling animation -------------------------------------------
//
// Same shape as runAddAnimation, but starts with the tangent line at P
// (we use findThirdIntersection(P, P, …) — same Vieta formula, slope
// from the implicit derivative). 3 phases (no separate Q dot).

export function runDoubleAnimation(canvas, a, b, P, viewport, opts = {}) {
  return new Promise((resolve) => {
    const ctxBox = setupCanvas(canvas, viewport);
    const { ctx, W, H } = ctxBox;

    const duration = Object.assign({
      drawLine: 1000,
      linePause: 600,
      negate: 800,
      done: 600,
    }, opts.duration || {});

    const third = findThirdIntersection(P, P, a, b);
    const negR  = { x: third.x, y: third.y };
    const R     = { x: third.x, y: -third.y };

    // Construct a synthetic "Q" along the tangent so we can reuse
    // drawLineProgressive. Place it at (negR.x, negR.y) — far enough away
    // from P that the line spans the curve cleanly.
    const Q = { x: negR.x, y: negR.y };

    const started = {};
    const finished = {};
    function markState(phase, ts) {
      if (!started[phase]) started[phase] = ts;
      return ts - started[phase];
    }

    function redrawBase() {
      ctx.clearRect(0, 0, W, H);
      drawAxes(ctx, ctxBox, viewport);
      drawCurve(ctx, ctxBox, a, b, viewport);
      drawDot(ctx, ctxBox, P.x, P.y, COLORS.P, "P");
    }

    function step(timestamp) {
      redrawBase();
      if (!finished.drawLine) {
        const t = markState("drawLine", timestamp);
        const progress = Math.min(1, t / duration.drawLine);
        drawLineProgressive(ctx, ctxBox, P, Q, viewport, progress, COLORS.accent);
        if (progress >= 1) finished.drawLine = timestamp;
      } else if (!finished.linePause) {
        drawLineFull(ctx, ctxBox, P, Q, viewport, COLORS.accent);
        drawDot(ctx, ctxBox, negR.x, negR.y, COLORS.third, "−2P");
        const t = markState("linePause", timestamp);
        if (t >= duration.linePause) finished.linePause = timestamp;
      } else if (!finished.negate) {
        drawLineFull(ctx, ctxBox, P, Q, viewport, COLORS.accent);
        drawDot(ctx, ctxBox, negR.x, negR.y, COLORS.third, "−2P");
        const t = markState("negate", timestamp);
        const progress = Math.min(1, t / duration.negate);
        drawVerticalProgressive(ctx, ctxBox, R.x, negR.y, R.y, progress);
        if (progress >= 1) {
          drawDot(ctx, ctxBox, R.x, R.y, COLORS.result, "2P");
          finished.negate = timestamp;
        }
      } else if (!finished.done) {
        drawLineFull(ctx, ctxBox, P, Q, viewport, COLORS.accent);
        drawDot(ctx, ctxBox, negR.x, negR.y, COLORS.third, "−2P");
        drawVerticalProgressive(ctx, ctxBox, R.x, negR.y, R.y, 1);
        drawDot(ctx, ctxBox, R.x, R.y, COLORS.result, "2P");
        const t = markState("done", timestamp);
        if (t >= duration.done) finished.done = timestamp;
      }

      if (!finished.done) {
        requestAnimationFrame(step);
      } else {
        if (opts.onDone) opts.onDone(R);
        resolve(R);
      }
    }
    requestAnimationFrame(step);
  });
}

// ---- scalar multiplication animation (double-and-add ladder) ----------
//
// Decomposes k LSB-first; each iteration shows the current addend (yellow)
// and accumulator (green) as labeled dots. We pause briefly between bits
// so the user can read the bit-by-bit picture. Optionally calls onStep
// once per bit so the template can sync a bit-ladder readout.

export function runScalarMultAnimation(canvas, a, b, k, P, viewport, opts = {}) {
  return new Promise((resolve) => {
    const ctxBox = setupCanvas(canvas, viewport);
    const { ctx, W, H } = ctxBox;

    const perBitMs = (opts.duration && opts.duration.perBit) ?? 900;

    // Precompute every step so we can render snapshots without re-doing math
    // inside the animation loop.
    const steps = [];
    let kk = k;
    let addend = P;
    let acc = null;
    let bitIndex = 0;
    while (kk > 0) {
      const bit = kk & 1;
      const before = { acc, addend };
      if (bit) acc = pointAdd(acc, addend, a, null);
      const next = pointDouble(addend, a, null);
      steps.push({ bitIndex, bit, before, after: { acc, addend: next } });
      addend = next;
      kk >>= 1;
      bitIndex++;
    }
    const finalResult = acc;

    const startedAt = {};
    let currentStep = 0;

    function inViewport(pt) {
      if (!pt) return false;
      return pt.x >= viewport.xMin && pt.x <= viewport.xMax
          && pt.y >= viewport.yMin && pt.y <= viewport.yMax;
    }

    function draw(stepIdx, localProgress) {
      ctx.clearRect(0, 0, W, H);
      drawAxes(ctx, ctxBox, viewport);
      drawCurve(ctx, ctxBox, a, b, viewport);
      drawDot(ctx, ctxBox, P.x, P.y, COLORS.P, "P");
      if (stepIdx >= steps.length) {
        if (inViewport(finalResult)) {
          drawDot(ctx, ctxBox, finalResult.x, finalResult.y, COLORS.result, `${k}·P`);
        }
        return;
      }
      const s = steps[stepIdx];
      // Show accumulator (green) and addend (yellow) for THIS step's BEFORE state
      if (inViewport(s.before.acc)) {
        drawDot(ctx, ctxBox, s.before.acc.x, s.before.acc.y, COLORS.result, "acc");
      }
      if (inViewport(s.before.addend)) {
        drawDot(ctx, ctxBox, s.before.addend.x, s.before.addend.y, COLORS.third, "addend");
      }
      // Tiny readout in the top-left corner: bit i = N, action
      ctx.save();
      ctx.fillStyle = COLORS.textBold;
      ctx.font = "12px ui-monospace, monospace";
      const action = s.bit ? "add" : "skip";
      ctx.fillText(`bit ${s.bitIndex} = ${s.bit} → ${action}`, 10, 16);
      ctx.restore();
    }

    function step(timestamp) {
      if (!startedAt[currentStep]) {
        startedAt[currentStep] = timestamp;
        if (opts.onStep && currentStep < steps.length) {
          const s = steps[currentStep];
          opts.onStep(s.bitIndex, s.bit, s.before.acc, s.before.addend);
        }
      }
      const t = timestamp - startedAt[currentStep];
      const progress = Math.min(1, t / perBitMs);
      draw(currentStep, progress);
      if (t >= perBitMs) {
        currentStep += 1;
      }
      if (currentStep <= steps.length) {
        requestAnimationFrame(step);
      } else {
        draw(steps.length, 1);
        if (opts.onDone) opts.onDone(finalResult);
        resolve(finalResult);
      }
    }
    requestAnimationFrame(step);
  });
}

// ---- discrete-log orbit (static) --------------------------------------
//
// Draw the F_17 scatter + ALL orbit points 1G..nG at once with numeric
// labels. Static: no rAF loop, no per-frame redraws — those caused
// canvas dimensions to drift catastrophically under various Alpine/
// browser-cache edge cases. The pedagogical point (chaotic walk through
// the scatter) lands fine in a single still image.

export function runDlpOrbitAnimation(canvas, a, b, p, G, _opts = {}) {
  // Compute the full orbit.
  const orbit = [];
  let acc = G;
  for (let k = 1; k <= 32; k++) {
    if (!acc) break;
    orbit.push({ k, x: acc.x, y: acc.y });
    acc = pointAdd(acc, G, a, p);
  }
  // Draw the scatter (one-shot, no rAF).
  const { ctxBox } = drawFiniteField(canvas, a, b, p);
  const { ctx, toPx, toPy } = ctxBox;
  // Overlay all orbit points with k·G labels.
  ctx.save();
  for (const pt of orbit) {
    ctx.fillStyle = COLORS.result;
    ctx.globalAlpha = 0.85;
    ctx.beginPath();
    ctx.arc(toPx(pt.x), toPy(pt.y), 6, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.fillStyle = COLORS.textBold;
    ctx.font = "bold 10px ui-monospace, monospace";
    ctx.fillText(`${pt.k}G`, toPx(pt.x) + 9, toPy(pt.y) - 4);
  }
  ctx.restore();
  // Return a no-op stop handle so existing callers don't break.
  return { stop: () => {} };
}

// Re-export math + presets so callers (templates) get a one-module surface
// via `demo.…`. The lesson's template branches reach into ec_demo for
// PRESET points; we forward them here.
export { CURVE_PRESETS, DEFAULT_A, DEFAULT_B, FF_A, FF_B, FF_P, isNonSingular };
