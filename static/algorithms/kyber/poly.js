// Toy-Kyber polynomial primitives.
//
// We work in the ring  R_q = Z_q[X] / (X^n + 1)  with the lesson's locked
// toy parameters q = 257, n = 4, k = 2. Every "polynomial" in this module
// is a length-n array of integers; index i is the coefficient on X^i.
//
// Multiplication has one twist: when the schoolbook product spills past
// degree n-1, the (X^n + 1) reduction forces X^n = -1, so a coefficient at
// position (i + j) with i + j >= n wraps back to position (i + j - n) with
// the sign flipped. That single sign-flip rule is the entire reason the
// ring closes — and it's the load-bearing thing the lesson teaches in
// step 3 (`polynomial-rings`).
//
// All arithmetic is mod q (q = 257 here, but the module is parameterised
// so the lesson's "what would happen at q = 17?" detour stays cheap to
// experiment with). The `mod` helper centralises the "JS % gives negative
// results for negative inputs" gotcha — every coefficient that leaves a
// function is in the canonical range [0, q).
//
// No NTT, no Barrett reduction, no Montgomery reduction — schoolbook
// multiplication is O(n^2) and n = 4 makes that 16 multiplies per polyMul,
// which is fine and keeps the code legible.

export const Q = 257;
export const N = 4;

// Canonical non-negative residue mod q. JS's % returns a negative result
// when the left operand is negative — this normalises to [0, q).
export function mod(x, q = Q) {
  const r = ((x % q) + q) % q;
  return r;
}

// Coefficient-wise add in R_q. Both inputs are length-n arrays.
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

// Schoolbook polynomial multiplication in R_q[X] / (X^n + 1).
//
// First form the full (2n-1)-coefficient product, then fold position
// (i + j) >= n back to position (i + j - n) with sign flip, then reduce
// mod q. Because n is small (4), the folding is one cheap pass.
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
        // X^n = -1, so coefficient at position k wraps to (k - n) with sign flip.
        out[k - n] -= term;
      }
    }
  }
  for (let i = 0; i < n; i++) {
    out[i] = mod(out[i], q);
  }
  return out;
}

// k×k matrix of polynomials times a k-vector of polynomials.
//
// `matrix[i][j]` is the polynomial at row i, column j (length-n array).
// `vec[i]` is the i-th polynomial in the vector.
// Result is a k-vector whose i-th entry is  sum_j matrix[i][j] * vec[j].
export function matVecMul(matrix, vec, q = Q) {
  const k = matrix.length;
  if (vec.length !== k) {
    throw new Error("matVecMul: matrix has " + k + " rows but vec has " + vec.length);
  }
  const n = matrix[0][0].length;
  const out = new Array(k);
  for (let i = 0; i < k; i++) {
    let acc = new Array(n).fill(0);
    for (let j = 0; j < k; j++) {
      acc = polyAdd(acc, polyMul(matrix[i][j], vec[j], q), q);
    }
    out[i] = acc;
  }
  return out;
}

// k×k transpose. Each entry is a polynomial (length-n array) and stays
// intact — we only swap row/column indices.
export function transpose(matrix) {
  const k = matrix.length;
  const out = new Array(k);
  for (let i = 0; i < k; i++) {
    out[i] = new Array(k);
    for (let j = 0; j < k; j++) {
      out[i][j] = matrix[j][i];
    }
  }
  return out;
}

// Dot product of two k-vectors of polynomials: sum_i a[i] * b[i].
// Used to compute t^T · r (a polynomial scalar) on the encapsulation side
// and s^T · u on the decapsulation side.
export function vecDot(a, b, q = Q) {
  if (a.length !== b.length) {
    throw new Error("vecDot: length mismatch (" + a.length + " vs " + b.length + ")");
  }
  const n = a[0].length;
  let acc = new Array(n).fill(0);
  for (let i = 0; i < a.length; i++) {
    acc = polyAdd(acc, polyMul(a[i], b[i], q), q);
  }
  return acc;
}
