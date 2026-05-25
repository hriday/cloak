// Smoke tests for the canvas + rAF rendering module. Real animation
// behavior requires a browser (canvas getContext, requestAnimationFrame,
// devicePixelRatio); we exercise only the pure helpers — easing and the
// `setupCanvas` transform-function calculation — under Node's test runner.

import { test } from "node:test";
import assert from "node:assert/strict";
import { easeInOut, setupCanvas } from "../ec_canvas.js";

// ---- easing ------------------------------------------------------------

test("easeInOut: anchor points", () => {
  assert.equal(easeInOut(0), 0);
  assert.equal(easeInOut(1), 1);
  // smoothstep at 0.5 is exactly 0.5 by symmetry
  assert.equal(easeInOut(0.5), 0.5);
});

test("easeInOut clamps outside [0,1]", () => {
  assert.equal(easeInOut(-1), 0);
  assert.equal(easeInOut(2), 1);
});

test("easeInOut is monotonic over [0,1]", () => {
  let prev = -1;
  for (let i = 0; i <= 100; i++) {
    const v = easeInOut(i / 100);
    assert.ok(v >= prev, `easing regressed at i=${i}: ${v} < ${prev}`);
    prev = v;
  }
});

test("easeInOut is symmetric: easeInOut(t) + easeInOut(1-t) = 1", () => {
  for (let i = 0; i <= 100; i++) {
    const t = i / 100;
    const sum = easeInOut(t) + easeInOut(1 - t);
    assert.ok(Math.abs(sum - 1) < 1e-9, `at t=${t}: ${easeInOut(t)} + ${easeInOut(1-t)} = ${sum}`);
  }
});

// ---- setupCanvas -------------------------------------------------------
//
// The function calls `canvas.getContext("2d")` and reads
// devicePixelRatio. We mock both with a minimal shim — Node doesn't have a
// canvas DOM, so we stub the API surface that setupCanvas touches.

function fakeCanvas(cssW, cssH) {
  const ctx = {
    setTransform: () => {},
    clearRect: () => {},
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    stroke: () => {},
    fill: () => {},
    arc: () => {},
    closePath: () => {},
    fillText: () => {},
    save: () => {},
    restore: () => {},
    setLineDash: () => {},
  };
  return {
    width: cssW, height: cssH,
    clientWidth: cssW, clientHeight: cssH,
    style: {},
    getContext: () => ctx,
  };
}

test("setupCanvas returns transform functions that map viewport corners to plot rectangle", () => {
  // Stub window.devicePixelRatio for Node.
  globalThis.window = { devicePixelRatio: 1 };
  const c = fakeCanvas(600, 400);
  const viewport = { xMin: -3.2, xMax: 3.2, yMin: -3.2, yMax: 3.2 };
  const { toPx, toPy, padL, padT, plotW, plotH } = setupCanvas(c, viewport);
  // xMin maps to left edge of plot rect (padL)
  assert.ok(Math.abs(toPx(viewport.xMin) - padL) < 1e-6);
  // xMax maps to right edge (padL + plotW)
  assert.ok(Math.abs(toPx(viewport.xMax) - (padL + plotW)) < 1e-6);
  // yMax maps to top of plot rect (padT) — y axis flipped
  assert.ok(Math.abs(toPy(viewport.yMax) - padT) < 1e-6);
  assert.ok(Math.abs(toPy(viewport.yMin) - (padT + plotH)) < 1e-6);
  // (0,0) lands inside the plot since the viewport spans [-3.2, 3.2]
  const cx = toPx(0), cy = toPy(0);
  assert.ok(cx > padL && cx < padL + plotW);
  assert.ok(cy > padT && cy < padT + plotH);
});

test("setupCanvas applies devicePixelRatio to the backing store", () => {
  globalThis.window = { devicePixelRatio: 2 };
  const c = fakeCanvas(300, 200);
  setupCanvas(c, { xMin: 0, xMax: 1, yMin: 0, yMax: 1 });
  assert.equal(c.width, 600);  // 300 * 2
  assert.equal(c.height, 400); // 200 * 2
  assert.equal(c.style.width, "300px");
  assert.equal(c.style.height, "200px");
});

test("setupCanvas is idempotent: second call with same DPR/size doesn't double-scale", () => {
  globalThis.window = { devicePixelRatio: 2 };
  const c = fakeCanvas(300, 200);
  setupCanvas(c, { xMin: 0, xMax: 1, yMin: 0, yMax: 1 });
  const wAfterFirst = c.width, hAfterFirst = c.height;
  setupCanvas(c, { xMin: 0, xMax: 1, yMin: 0, yMax: 1 });
  assert.equal(c.width, wAfterFirst);
  assert.equal(c.height, hAfterFirst);
});

// ---- re-export wiring --------------------------------------------------
//
// The whole point of the canvas module is to be reachable via
// `import * from "./ec_demo.js"`. Verify the bridge.

test("ec_demo.js re-exports the canvas helpers (one-module surface for the wizard)", async () => {
  const demo = await import("../ec_demo.js");
  for (const fn of ["easeInOut", "setupCanvas", "drawCurve", "drawDot", "drawAxes",
                    "drawLineProgressive", "drawStatic",
                    "runAddAnimation", "runDoubleAnimation",
                    "runScalarMultAnimation", "runDlpOrbitAnimation",
                    "drawFiniteField"]) {
    assert.equal(typeof demo[fn], "function", `expected demo.${fn} to be exported`);
  }
});
