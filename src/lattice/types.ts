/**
 * Shared types for the GGH trapdoor lab.
 *
 * CONVENTION (fixed once, here, because the literature is split):
 *   Lattices are ROW lattices.  L(B) = { x * B : x in Z^n }, so the ROWS of B
 *   are the basis vectors and a ciphertext is c = m*B + e.
 *
 *   Goldreich-Goldwasser-Halevi (CRYPTO '97) itself uses COLUMNS and writes
 *   c = B*v + e.  Nguyen (CRYPTO '99) and Nguyen-Regev (EUROCRYPT '06) both use
 *   rows.  We follow the two cryptanalysis papers because this lab spends most
 *   of its time inside their algorithms; every formula here is stated in the row
 *   convention and can be compared against those papers directly.
 *
 * Matrices are arrays of Float64Array rows. Every value in an R/U/V/B matrix is
 * an exact integer -- Float64Array is used because it is the fastest dense
 * representation in a browser, not because the values are approximate. Integer
 * exactness is asserted, not assumed: see `allIntegersUnder2p53` in matrix.ts.
 */

/** A dense matrix as an array of rows. All lattice bases here hold exact integers. */
export type Mat = Float64Array[];

/** A dense row vector. */
export type Vec = Float64Array;

/** A deterministic [0,1) generator, so every exhibit is reproducible from a seed. */
export type Rng = () => number;

/**
 * A GGH key pair.
 *
 * `R` is the private, nearly-orthogonal basis -- the trapdoor.
 * `B` is the public basis, U*R for a random unimodular U.
 * `U` and `V` are produced by construction during keygen (V = U^-1), so no
 * numeric conditioning limit applies to them; `invariants.ts` re-derives both
 * from R and B alone and checks the pair exactly.
 */
export interface GghKey {
  /** Lattice dimension. */
  readonly n: number;
  /** Noise half-width: entries of R - k*I are uniform in {-l..l}. */
  readonly l: number;
  /** Diagonal shift: R = k*I + E. */
  readonly k: number;
  /** Private basis (the trapdoor): nearly orthogonal. */
  readonly R: Mat;
  /** Unimodular transform with B = U*R. */
  readonly U: Mat;
  /** V = U^-1, so R = V*B. */
  readonly V: Mat;
  /** Public basis: same lattice as R, badly skewed. */
  readonly B: Mat;
  /** How many candidate R were drawn before one had det coprime to 6. */
  readonly keygenAttempts: number;
}

/** Result of the invariant I1 same-lattice proof. */
export interface SameLatticeProof {
  /** True only if every exact integer check below passed. */
  readonly ok: boolean;
  /** Human-readable statement of what was proved, or which check failed. */
  readonly reason: string;
  /** The recovered U = B*R^-1, for display (I1 requires showing it). */
  readonly U: Mat | null;
  /** The recovered V = R*B^-1. */
  readonly V: Mat | null;
  /** Per-check results, so the UI can show the proof step by step. */
  readonly checks: {
    readonly entriesSafe: boolean;
    readonly uTimesREqualsB: boolean;
    readonly vTimesBEqualsR: boolean;
    readonly uTimesVIsIdentity: boolean;
  };
}

/** A ciphertext together with the error vector that produced it. */
export interface Ciphertext {
  /** c = m*B + e. */
  readonly c: Vec;
  /** The error actually used. Known to the exhibit, never to the attacker code. */
  readonly e: Vec;
  /** The message actually encrypted. */
  readonly m: Vec;
}

/**
 * Invariant I2 for one ciphertext, under one basis.
 *
 * Babai round-off with a basis whose inverse is `basisInv` recovers the correct
 * lattice point whenever `actual < 0.5`, and never when `actual > 0.5`. At
 * exactly 0.5 the outcome depends on the rounding tie rule and on the lattice
 * point's integer coordinate, which this object does not carry -- see
 * `decryptBound` and `roundOffSucceedsExactly` in roundoff.ts, where both
 * outcomes are constructed deliberately. Measured with zero mismatches, and zero
 * ties, over 5,600 ciphertexts. `worstCase` is the maximum of `actual` over
 * EVERY error vector in {+sigma,-sigma}^n, so `worstCase < 0.5` means decryption
 * provably cannot fail.
 */
export interface DecryptBound {
  /** max_j |(e * basisInv)_j| for the error actually used. */
  readonly actual: number;
  /** sigma * max_j sum_i |basisInv[i][j]| -- the max over all e in {+-sigma}^n. */
  readonly worstCase: number;
  /** actual < 0.5 -- sufficient for success, not necessary at the boundary. */
  readonly predictsSuccess: boolean;
  /** worstCase < 0.5 -- decryption cannot fail for ANY error vector. */
  readonly guaranteed: boolean;
  /** 0.5 / actual: how much headroom this ciphertext had. */
  readonly margin: number;
}
