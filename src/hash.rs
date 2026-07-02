//! Poseidon hash chip for Halo2 over BN254.
//!
//! Implements Poseidon with:
//! - Width t = 3 (2 inputs + 1 capacity element)
//! - x^5 S-box
//! - 8 full rounds + 57 partial rounds (production standard for t=3, 128-bit security)
//! - Circulant MDS matrix [[3,1,1],[1,3,1],[1,1,3]]
//! - Round constants stored in fixed columns
//!
//! Gate layout (per full round = 4 rows, per partial round = 2 rows):
//!
//! Full round:
//!   Row 0: input state [s0, s1, s2] assigned (no gate)
//!   Row 1: s_sbox_0 — S-box state[0]: out = (s0 + rc0)^5
//!   Row 2: s_sbox_1 — S-box state[1]: out = (s1 + rc1)^5
//!   Row 3: s_sbox_2 — S-box state[2]: out = (s2 + rc2)^5
//!   Row 4: s_mds — MDS multiplication
//!
//! Partial round:
//!   Row 0: input state assigned (no gate)
//!   Row 1: s_sbox_0 + s_arc_12 — S-box state[0], ARC state[1], state[2]
//!   Row 2: s_mds — MDS multiplication
//!
//! Security: Production-standard Poseidon round count for width 3 over BN254.
//! 8 full rounds + 57 partial rounds = 65 total rounds, matching the round
//! count recommended by the official Poseidon parameter generation script
//! (`generate_parameters_grain.sage 1 0 254 3 8 57`) for 128-bit security.
//! The MDS matrix and round constants here are deterministic and fixed, but
//! they are not the same as the constants produced by the Grain-of-Salt LFSR
//! in the reference script; this is a self-contained implementation. Forging
//! still requires inverting Poseidon over BN254 (assumed hard under the
//! standard Poseidon security assumptions).
//!
//! Constraint cost: ~384 non-linear constraints per hash (vs 3 for the
//! algebraic hash). Still lightweight for a depth-4 Merkle tree.

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

// --- Poseidon parameters ---

const WIDTH: usize = 3;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const FIRST_FULL: usize = FULL_ROUNDS / 2; // 4 full rounds before partial

/// MDS matrix (circulant, MDS over BN254).
const MDS: [[u64; WIDTH]; WIDTH] = [
    [3, 1, 1],
    [1, 3, 1],
    [1, 1, 3],
];

// --- Round constant generation ---

/// Generate deterministic round constants from a fixed seed.
/// Total = (FULL_ROUNDS + PARTIAL_ROUNDS) * WIDTH = 65 * 3 = 195 constants.
#[allow(clippy::needless_range_loop)]
fn round_constants() -> Vec<[Fr; WIDTH]> {
    let mut constants = Vec::with_capacity(FULL_ROUNDS + PARTIAL_ROUNDS);
    let mut state: [u64; 4] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
    ];

    let seed = b"zk-ballot-poseidon-bn254-v1";
    for (i, &b) in seed.iter().enumerate() {
        state[i % 4] ^= b as u64;
        state[i % 4] = state[i % 4].wrapping_mul(0x517cc1b727220a95);
    }

    for _ in 0..(FULL_ROUNDS + PARTIAL_ROUNDS) {
        let mut round_c = [Fr::zero(); WIDTH];
        for j in 0..WIDTH {
            // Rejection sampling: keep mixing until we produce a valid BN254
            // scalar. Fr::from_bytes returns None when the 256-bit interpretation
            // of the bytes is >= the field modulus, so we must not silently
            // fall back to zero (that would collapse the round constant).
            loop {
                // Mix state
                for _ in 0..4 {
                    state[0] = state[0].wrapping_add(state[1]) ^ state[2].wrapping_mul(0x9e3779b97f4a7c15);
                    state[1] = state[1].wrapping_add(state[2]) ^ state[3].wrapping_mul(0x9e3779b97f4a7c15);
                    state[2] = state[2].wrapping_add(state[3]) ^ state[0].wrapping_mul(0x9e3779b97f4a7c15);
                    state[3] = state[3].wrapping_add(state[0]) ^ state[1].wrapping_mul(0x9e3779b97f4a7c15);
                    state[0] = state[0].wrapping_mul(0x9e3779b97f4a7c15);
                    state[1] = state[1].wrapping_mul(0x9e3779b97f4a7c15);
                    state[2] = state[2].wrapping_mul(0x9e3779b97f4a7c15);
                    state[3] = state[3].wrapping_mul(0x9e3779b97f4a7c15);
                }
                // Build a 32-byte value from the 4 u64 state words
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&state[0].to_le_bytes());
                bytes[8..16].copy_from_slice(&state[1].to_le_bytes());
                bytes[16..24].copy_from_slice(&state[2].to_le_bytes());
                bytes[24..32].copy_from_slice(&state[3].to_le_bytes());

                if let Some(fe) = Fr::from_bytes(&bytes).into() {
                    round_c[j] = fe;
                    break;
                }
            }
        }
        constants.push(round_c);
    }
    constants
}

// --- Off-circuit Poseidon ---

/// Off-circuit Poseidon hash matching the on-circuit chip.
/// Takes 2 field elements, outputs state[0] after permutation.
#[allow(clippy::needless_range_loop)]
pub fn hash(a: Fr, b: Fr) -> Fr {
    let constants = round_constants();
    let mut state = [a, b, Fr::zero()];

    for round in 0..(FULL_ROUNDS + PARTIAL_ROUNDS) {
        let is_full = !(FIRST_FULL..FIRST_FULL + PARTIAL_ROUNDS).contains(&round);

        // ARC
        for i in 0..WIDTH {
            state[i] += constants[round][i];
        }

        // S-box
        if is_full {
            for i in 0..WIDTH {
                state[i] = sbox(state[i]);
            }
        } else {
            state[0] = sbox(state[0]);
        }

        // MDS
        state = mds_mul(state);
    }

    state[0]
}

fn sbox(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

fn mds_mul(state: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let mut result = [Fr::zero(); WIDTH];
    for i in 0..WIDTH {
        for j in 0..WIDTH {
            result[i] += state[j] * Fr::from(MDS[i][j]);
        }
    }
    result
}

// --- On-circuit Poseidon chip ---

/// Configuration for the Poseidon hash chip.
#[derive(Clone, Debug)]
pub struct HashConfig {
    pub state: [Column<Advice>; WIDTH],
    pub aux: [Column<Advice>; 3], // t0, t1, t2 (S-box intermediates)
    pub rc: [Column<Fixed>; WIDTH], // round constants
    pub s_sbox_0: Selector,
    pub s_sbox_1: Selector,
    pub s_sbox_2: Selector,
    pub s_arc_12: Selector, // ARC for state[1], state[2] in partial rounds
    pub s_mds: Selector,
}

pub struct HashChip {
    pub(crate) config: HashConfig,
}

impl HashChip {
    /// Configure the chip inside a constraint system.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        state: [Column<Advice>; WIDTH],
        aux: [Column<Advice>; 3],
        rc: [Column<Fixed>; WIDTH],
    ) -> HashConfig {
        let s_sbox_0 = meta.selector();
        let s_sbox_1 = meta.selector();
        let s_sbox_2 = meta.selector();
        let s_arc_12 = meta.selector();
        let s_mds = meta.selector();

        // S-box gate for state[0]: out = (in + rc)^5
        // Constraints (all multiplied by selector s):
        //   aux[0] = state[0]_prev + rc[0]         (ARC + S-box input)
        //   aux[1] = aux[0]^2                       (x^2)
        //   aux[2] = aux[1]^2                       (x^4)
        //   state[0]_cur = aux[2] * aux[0]          (x^5)
        meta.create_gate("poseidon sbox[0]", |meta| {
            let s = meta.query_selector(s_sbox_0);
            let s_in = meta.query_advice(state[0], Rotation::prev());
            let s_out = meta.query_advice(state[0], Rotation::cur());
            let rc0 = meta.query_fixed(rc[0]);
            let t0 = meta.query_advice(aux[0], Rotation::cur());
            let t1 = meta.query_advice(aux[1], Rotation::cur());
            let t2 = meta.query_advice(aux[2], Rotation::cur());

            vec![
                s.clone() * (t0.clone() - (s_in.clone() + rc0)),
                s.clone() * (t1.clone() - t0.clone() * t0.clone()),
                s.clone() * (t2.clone() - t1.clone() * t1.clone()),
                s * (s_out - t2 * t0),
            ]
        });

        // S-box gate for state[1]: out = (in + rc)^5
        meta.create_gate("poseidon sbox[1]", |meta| {
            let s = meta.query_selector(s_sbox_1);
            let s_in = meta.query_advice(state[1], Rotation::prev());
            let s_out = meta.query_advice(state[1], Rotation::cur());
            let rc1 = meta.query_fixed(rc[1]);
            let t0 = meta.query_advice(aux[0], Rotation::cur());
            let t1 = meta.query_advice(aux[1], Rotation::cur());
            let t2 = meta.query_advice(aux[2], Rotation::cur());

            vec![
                s.clone() * (t0.clone() - (s_in.clone() + rc1)),
                s.clone() * (t1.clone() - t0.clone() * t0.clone()),
                s.clone() * (t2.clone() - t1.clone() * t1.clone()),
                s * (s_out - t2 * t0),
            ]
        });

        // S-box gate for state[2]: out = (in + rc)^5
        meta.create_gate("poseidon sbox[2]", |meta| {
            let s = meta.query_selector(s_sbox_2);
            let s_in = meta.query_advice(state[2], Rotation::prev());
            let s_out = meta.query_advice(state[2], Rotation::cur());
            let rc2 = meta.query_fixed(rc[2]);
            let t0 = meta.query_advice(aux[0], Rotation::cur());
            let t1 = meta.query_advice(aux[1], Rotation::cur());
            let t2 = meta.query_advice(aux[2], Rotation::cur());

            vec![
                s.clone() * (t0.clone() - (s_in.clone() + rc2)),
                s.clone() * (t1.clone() - t0.clone() * t0.clone()),
                s.clone() * (t2.clone() - t1.clone() * t1.clone()),
                s * (s_out - t2 * t0),
            ]
        });

        // ARC gate for state[1] and state[2] in partial rounds:
        //   state[1]_cur = state[1]_prev + rc[1]
        //   state[2]_cur = state[2]_prev + rc[2]
        meta.create_gate("poseidon arc[1,2]", |meta| {
            let s = meta.query_selector(s_arc_12);
            let s1_in = meta.query_advice(state[1], Rotation::prev());
            let s1_out = meta.query_advice(state[1], Rotation::cur());
            let s2_in = meta.query_advice(state[2], Rotation::prev());
            let s2_out = meta.query_advice(state[2], Rotation::cur());
            let rc1 = meta.query_fixed(rc[1]);
            let rc2 = meta.query_fixed(rc[2]);

            vec![
                s.clone() * (s1_out.clone() - (s1_in + rc1)),
                s * (s2_out - (s2_in + rc2)),
            ]
        });

        // MDS gate: out[i] = sum_j MDS[i][j] * in[j]
        meta.create_gate("poseidon mds", |meta| {
            let s = meta.query_selector(s_mds);
            let s0 = meta.query_advice(state[0], Rotation::prev());
            let s1 = meta.query_advice(state[1], Rotation::prev());
            let s2 = meta.query_advice(state[2], Rotation::prev());
            let o0 = meta.query_advice(state[0], Rotation::cur());
            let o1 = meta.query_advice(state[1], Rotation::cur());
            let o2 = meta.query_advice(state[2], Rotation::cur());

            let m = |i: usize, j: usize| Expression::Constant(Fr::from(MDS[i][j]));

            vec![
                s.clone() * (o0 - (m(0, 0) * s0.clone()
                    + m(0, 1) * s1.clone()
                    + m(0, 2) * s2.clone())),
                s.clone() * (o1 - (m(1, 0) * s0.clone()
                    + m(1, 1) * s1.clone()
                    + m(1, 2) * s2.clone())),
                s * (o2 - (m(2, 0) * s0
                    + m(2, 1) * s1
                    + m(2, 2) * s2)),
            ]
        });

        HashConfig {
            state,
            aux,
            rc,
            s_sbox_0,
            s_sbox_1,
            s_sbox_2,
            s_arc_12,
            s_mds,
        }
    }

    /// Hash two existing cells, returning the output `AssignedCell`.
    /// Performs the full Poseidon permutation on [a, b, 0].
    pub fn hash_cells(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        a_val: Fr,
        b_val: Fr,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let constants = round_constants();

        // Initialize state: [a, b, 0]
        let mut state_cells: [AssignedCell<Fr, Fr>; WIDTH] = layouter.assign_region(
            || "poseidon: init",
            |mut region| {
                let s0 = region.assign_advice(
                    || "state[0]", self.config.state[0], 0,
                    || a.value().copied(),
                )?;
                let s1 = region.assign_advice(
                    || "state[1]", self.config.state[1], 0,
                    || b.value().copied(),
                )?;
                let s2 = region.assign_advice(
                    || "state[2]", self.config.state[2], 0,
                    || Value::known(Fr::zero()),
                )?;
                region.constrain_equal(a.cell(), s0.cell())?;
                region.constrain_equal(b.cell(), s1.cell())?;
                Ok([s0, s1, s2])
            },
        )?;

        // Track off-circuit state for computing witness values
        let mut state_vals = [a_val, b_val, Fr::zero()];

        #[allow(clippy::needless_range_loop)]
        for round in 0..(FULL_ROUNDS + PARTIAL_ROUNDS) {
            let is_full = !(FIRST_FULL..FIRST_FULL + PARTIAL_ROUNDS).contains(&round);

            // Save pre-ARC state (needed for S-box witness computation)
            let pre_arc = state_vals;

            // Compute off-circuit state: ARC + S-box
            let mut post_sbox = [Fr::zero(); WIDTH];
            if is_full {
                for i in 0..WIDTH {
                    post_sbox[i] = sbox(pre_arc[i] + constants[round][i]);
                }
            } else {
                post_sbox[0] = sbox(pre_arc[0] + constants[round][0]);
                post_sbox[1] = pre_arc[1] + constants[round][1];
                post_sbox[2] = pre_arc[2] + constants[round][2];
            }

            if is_full {
                // Full round: 3 S-box rows + 1 MDS row
                for elem in 0..WIDTH {
                    state_cells = self.apply_sbox(
                        layouter, elem, &state_cells, &pre_arc, &post_sbox, &constants[round],
                    )?;
                }
            } else {
                // Partial round: 1 S-box + ARC row + 1 MDS row
                state_cells = self.apply_sbox_partial(
                    layouter, &state_cells, &pre_arc, &post_sbox, &constants[round],
                )?;
            }

            // MDS
            state_vals = mds_mul(post_sbox);
            state_cells = self.apply_mds(layouter, &state_cells, &state_vals)?;
        }

        Ok(state_cells[0].clone())
    }

    /// Hash a cell with a constant (used for nullifier: H(seed, 0)).
    pub fn hash_cell_const(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedCell<Fr, Fr>,
        a_val: Fr,
        b: Fr,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        // Assign the constant b to a temporary cell, then hash
        let b_cell = layouter.assign_region(
            || "poseidon: const",
            |mut region| {
                region.assign_advice(
                    || "const b", self.config.state[1], 0,
                    || Value::known(b),
                )
            },
        )?;
        self.hash_cells(layouter, a, &b_cell, a_val, b)
    }

    /// Apply S-box to one element (full round).
    /// Uses the s_sbox_{elem} gate.
    fn apply_sbox(
        &self,
        layouter: &mut impl Layouter<Fr>,
        elem: usize,
        state: &[AssignedCell<Fr, Fr>; WIDTH],
        pre_arc: &[Fr; WIDTH],
        new_vals: &[Fr; WIDTH],
        round_c: &[Fr; WIDTH],
    ) -> Result<[AssignedCell<Fr, Fr>; WIDTH], Error> {
        let selector = match elem {
            0 => self.config.s_sbox_0,
            1 => self.config.s_sbox_1,
            2 => self.config.s_sbox_2,
            _ => unreachable!(),
        };

        layouter.assign_region(
            || format!("poseidon: sbox[{}]", elem),
            |mut region| {
                // Row 0: assign input state (copy from previous)
                let s0_prev = region.assign_advice(
                    || "s0_prev", self.config.state[0], 0,
                    || state[0].value().copied(),
                )?;
                let s1_prev = region.assign_advice(
                    || "s1_prev", self.config.state[1], 0,
                    || state[1].value().copied(),
                )?;
                let s2_prev = region.assign_advice(
                    || "s2_prev", self.config.state[2], 0,
                    || state[2].value().copied(),
                )?;
                // Copy-constrain to previous state
                region.constrain_equal(state[0].cell(), s0_prev.cell())?;
                region.constrain_equal(state[1].cell(), s1_prev.cell())?;
                region.constrain_equal(state[2].cell(), s2_prev.cell())?;

                // Row 1: S-box gate
                selector.enable(&mut region, 1)?;

                // Assign round constant
                region.assign_fixed(
                    || "rc", self.config.rc[elem], 1,
                    || Value::known(round_c[elem]),
                )?;

                // Compute S-box intermediates
                let input_val = pre_arc[elem];
                let t0 = input_val + round_c[elem];
                let t1 = t0 * t0;
                let t2 = t1 * t1;

                region.assign_advice(|| "t0", self.config.aux[0], 1, || Value::known(t0))?;
                region.assign_advice(|| "t1", self.config.aux[1], 1, || Value::known(t1))?;
                region.assign_advice(|| "t2", self.config.aux[2], 1, || Value::known(t2))?;

                // Assign output state
                let out = region.assign_advice(
                    || "sbox_out", self.config.state[elem], 1,
                    || Value::known(new_vals[elem]),
                )?;

                // Carry over unchanged state elements
                let mut result = [s0_prev.clone(), s1_prev.clone(), s2_prev.clone()];
                result[elem] = out;

                // Copy unchanged elements from row 0 to row 1
                for i in 0..WIDTH {
                    if i != elem {
                        let carry = region.assign_advice(
                            || format!("carry[{}]", i), self.config.state[i], 1,
                            || state[i].value().copied(),
                        )?;
                        region.constrain_equal(state[i].cell(), carry.cell())?;
                        result[i] = carry;
                    }
                }

                Ok(result)
            },
        )
    }

    /// Apply S-box to state[0] and ARC to state[1], state[2] (partial round).
    fn apply_sbox_partial(
        &self,
        layouter: &mut impl Layouter<Fr>,
        state: &[AssignedCell<Fr, Fr>; WIDTH],
        pre_arc: &[Fr; WIDTH],
        new_vals: &[Fr; WIDTH],
        round_c: &[Fr; WIDTH],
    ) -> Result<[AssignedCell<Fr, Fr>; WIDTH], Error> {
        layouter.assign_region(
            || "poseidon: partial sbox+arc",
            |mut region| {
                // Row 0: assign input state (copy from previous)
                let s0_prev = region.assign_advice(
                    || "s0_prev", self.config.state[0], 0,
                    || state[0].value().copied(),
                )?;
                let s1_prev = region.assign_advice(
                    || "s1_prev", self.config.state[1], 0,
                    || state[1].value().copied(),
                )?;
                let s2_prev = region.assign_advice(
                    || "s2_prev", self.config.state[2], 0,
                    || state[2].value().copied(),
                )?;
                region.constrain_equal(state[0].cell(), s0_prev.cell())?;
                region.constrain_equal(state[1].cell(), s1_prev.cell())?;
                region.constrain_equal(state[2].cell(), s2_prev.cell())?;

                // Row 1: S-box for state[0] + ARC for state[1], state[2]
                self.config.s_sbox_0.enable(&mut region, 1)?;
                self.config.s_arc_12.enable(&mut region, 1)?;

                // Round constants
                region.assign_fixed(|| "rc0", self.config.rc[0], 1, || Value::known(round_c[0]))?;
                region.assign_fixed(|| "rc1", self.config.rc[1], 1, || Value::known(round_c[1]))?;
                region.assign_fixed(|| "rc2", self.config.rc[2], 1, || Value::known(round_c[2]))?;

                // S-box intermediates for state[0]
                let input_val = pre_arc[0];
                let t0 = input_val + round_c[0];
                let t1 = t0 * t0;
                let t2 = t1 * t1;

                region.assign_advice(|| "t0", self.config.aux[0], 1, || Value::known(t0))?;
                region.assign_advice(|| "t1", self.config.aux[1], 1, || Value::known(t1))?;
                region.assign_advice(|| "t2", self.config.aux[2], 1, || Value::known(t2))?;

                // Output state
                let out0 = region.assign_advice(
                    || "sbox_out_0", self.config.state[0], 1,
                    || Value::known(new_vals[0]),
                )?;
                let out1 = region.assign_advice(
                    || "arc_out_1", self.config.state[1], 1,
                    || Value::known(new_vals[1]),
                )?;
                let out2 = region.assign_advice(
                    || "arc_out_2", self.config.state[2], 1,
                    || Value::known(new_vals[2]),
                )?;

                Ok([out0, out1, out2])
            },
        )
    }

    /// Apply MDS matrix multiplication.
    fn apply_mds(
        &self,
        layouter: &mut impl Layouter<Fr>,
        state: &[AssignedCell<Fr, Fr>; WIDTH],
        new_vals: &[Fr; WIDTH],
    ) -> Result<[AssignedCell<Fr, Fr>; WIDTH], Error> {
        layouter.assign_region(
            || "poseidon: mds",
            |mut region| {
                // Row 0: assign input state (S-box outputs from previous region)
                let s0_prev = region.assign_advice(
                    || "mds_in_0", self.config.state[0], 0,
                    || state[0].value().copied(),
                )?;
                let s1_prev = region.assign_advice(
                    || "mds_in_1", self.config.state[1], 0,
                    || state[1].value().copied(),
                )?;
                let s2_prev = region.assign_advice(
                    || "mds_in_2", self.config.state[2], 0,
                    || state[2].value().copied(),
                )?;
                region.constrain_equal(state[0].cell(), s0_prev.cell())?;
                region.constrain_equal(state[1].cell(), s1_prev.cell())?;
                region.constrain_equal(state[2].cell(), s2_prev.cell())?;

                // Row 1: MDS gate
                self.config.s_mds.enable(&mut region, 1)?;
                let o0 = region.assign_advice(
                    || "mds_out_0", self.config.state[0], 1,
                    || Value::known(new_vals[0]),
                )?;
                let o1 = region.assign_advice(
                    || "mds_out_1", self.config.state[1], 1,
                    || Value::known(new_vals[1]),
                )?;
                let o2 = region.assign_advice(
                    || "mds_out_2", self.config.state[2], 1,
                    || Value::known(new_vals[2]),
                )?;

                Ok([o0, o1, o2])
            },
        )
    }
}

impl Chip<Fr> for HashChip {
    type Config = HashConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[cfg(test)]
mod round_constant_tests {
    use super::*;
    use ff::Field;

    #[test]
    fn all_round_constants_are_nonzero_field_elements() {
        let constants = round_constants();
        for (round_idx, round) in constants.iter().enumerate() {
            for (col_idx, c) in round.iter().enumerate() {
                assert!(
                    !bool::from(c.is_zero()),
                    "round constant [{}][{}] is zero", round_idx, col_idx
                );
            }
        }
    }
}
