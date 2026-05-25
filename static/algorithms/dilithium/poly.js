// Toy-Dilithium polynomial primitives.
//
// We work in the same ring R_q = Z_q[X] / (X^n + 1) as the Kyber lesson with
// q = 257, n = 4. The two FIPS lattice standards are siblings — they share
// the ring, the wrap rule (X^n = -1), and the small-noise philosophy. What
// changes is the *problem* on top of it: Kyber's KEM rests on Module-LWE
// (given t = A·s + e, recover s); Dilithium's signature rests on Module-SIS
// (find short z, c such that A·z = w + c·t).
//
// Because the ring matches, the primitives in this file are nearly identical
// to `static/algorithms/kyber/poly.js`. The only addition is `polyInfinityNorm`
// — the "is this polynomial short?" check used in rejection sampling, which
// Kyber didn't need. Norm is computed in the *signed* representation: a
// canonical coefficient in [⌈q/2⌉, q) maps to a negative integer (so coeff
// 256 has norm 1, not 256). That's what "short" means in lattice cryptography.
//
// As with Kyber, no NTT, no Montgomery — schoolbook multiplication is fine
// at n = 4 (16 multiplies per polyMul).

export const Q = 257;
export const N = 4;

// Canonical non-negative residue mod q. JS's % gives negative results for
// negative inputs — this normalises to [0, q).
export function mod(x, q = Q) {
  const r = ((x % q) + q) % q;
  return r;
}

// Map a coefficient from canonical [0, q) form to centered (-q/2, q/2] form.
// Used by polyInfinityNorm and by the lesson UI to display small numbers.
export function centered(c, q = Q) {
  const half = Math.floor(q / 2);
  return c > half ? c - q : c;
}

// Coefficient-wise add in R_q.
export function polyAdd(a, b, q = Q) {
  if (a.length !== b.length) {
    throw new Error("polyAdd: length mismatch (" + a.length + " vs " + b.length + ")");
  }
  const out = new Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = mod(a[i] + b[i], q);
  }
  return out;
}

// Coefficient-wise subtract in R_q.
export function polySub(a, b, q = Q) {
  if (a.length !== b.length) {
    throw new Error("polySub: length mismatch (" + a.length + " vs " + b.length + ")");
  }
  const out = new Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = mod(a[i] - b[i], q);
  }
  return out;
}

// Schoolbook multiplication in R_q[X] / (X^n + 1).
// Same as Kyber's polyMul — coefficients past degree n-1 wrap with a sign
// flip because X^n = -1.
export function polyMul(a, b, q = Q) {
  if (a.length !== b.length) {
    throw new Error("polyMul: length mismatch (" + a.length + " vs " + b.length + ")");
  }
  const n = a.length;
  const out = new Array(n).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const k = i + j;
      const term = a[i] * b[j];
      if (k < n) {
        out[k] += term;
      } else {
        out[k - n] -= term;
      }
    }
  }
  for (let i = 0; i < n; i++) {
    out[i] = mod(out[i], q);
  }
  return out;
}

// Scalar multiply a polynomial by an integer scalar.
export function polyScalarMul(p, s, q = Q) {
  return p.map((c) => mod(c * s, q));
}

// k×k matrix of polynomials times a k-vector of polynomials.
// Same as Kyber's matVecMul.
export function matVecMul(matrix, vec, q = Q) {
  const rows = matrix.length;
  const cols = matrix[0].length;
  if (vec.length !== cols) {
    throw new Error("matVecMul: matrix has " + cols + " cols but vec has " + vec.length);
  }
  const n = matrix[0][0].length;
  const out = new Array(rows);
  for (let i = 0; i < rows; i++) {
    let acc = new Array(n).fill(0);
    for (let j = 0; j < cols; j++) {
      acc = polyAdd(acc, polyMul(matrix[i][j], vec[j], q), q);
    }
    out[i] = acc;
  }
  return out;
}

// k×k transpose. Each entry is a polynomial (length-n array) and stays
// intact — we only swap row/column indices.
export function transpose(matrix) {
  const rows = matrix.length;
  const cols = matrix[0].length;
  const out = new Array(cols);
  for (let i = 0; i < cols; i++) {
    out[i] = new Array(rows);
    for (let j = 0; j < rows; j++) {
      out[i][j] = matrix[j][i];
    }
  }
  return out;
}

// Add two k-vectors of polynomials (coefficient-wise).
export function vecAdd(a, b, q = Q) {
  if (a.length !== b.length) {
    throw new Error("vecAdd: length mismatch");
  }
  return a.map((p, i) => polyAdd(p, b[i], q));
}

// Subtract two k-vectors of polynomials.
export function vecSub(a, b, q = Q) {
  if (a.length !== b.length) {
    throw new Error("vecSub: length mismatch");
  }
  return a.map((p, i) => polySub(p, b[i], q));
}

// Scalar-multiply a vector of polynomials by a single polynomial c.
// Each entry becomes c·v[i] in R_q. Used to compute c·s1, c·s2, c·t.
export function vecPolyMul(c, vec, q = Q) {
  return vec.map((v) => polyMul(c, v, q));
}

// Infinity norm of a polynomial — the maximum absolute value of any
// coefficient, in the *signed* representation. A coefficient of 256 in
// canonical [0, 257) form maps to -1 in signed form, so its norm is 1.
//
// This is the load-bearing "is z short enough?" check for Dilithium's
// rejection sampling: the signature is rejected if ||z||_inf is too large
// to be plausibly the product of small noise and a small challenge.
export function polyInfinityNorm(p, q = Q) {
  let max = 0;
  for (const c of p) {
    const v = Math.abs(centered(c, q));
    if (v > max) max = v;
  }
  return max;
}

// Infinity norm of a vector of polynomials — max over all polynomials.
export function vecInfinityNorm(vec, q = Q) {
  let max = 0;
  for (const p of vec) {
    const n = polyInfinityNorm(p, q);
    if (n > max) max = n;
  }
  return max;
}
