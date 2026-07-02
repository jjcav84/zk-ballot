//! Merkle-membership chip.
//!
//! Proves that a leaf belongs to a Merkle tree of depth `DEPTH` with a given
//! root. Each level uses a conditional-swap gate to order `(left, right)` from
//! `(current, sibling)` based on a position bit, then hashes the pair using
//! the Poseidon hash chip.

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use crate::hash::{hash as off_circuit_hash, HashChip, HashConfig};

/// Configuration for the Merkle membership chip.
#[derive(Clone, Debug)]
pub struct MerkleConfig {
    pub advice: [Column<Advice>; 5], // pos_bit, current, sibling, left, right
    pub s_swap: Selector,
    pub hash: HashConfig,
}

pub struct MerkleChip {
    pub(crate) config: MerkleConfig,
}

impl MerkleChip {
    /// Configure the chip. `hash_advice` are the 3 state advice columns the
    /// Poseidon hash chip operates on; `swap_advice` are the 5 columns the
    /// swap gate uses.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        hash_state: [Column<Advice>; 3],
        hash_aux: [Column<Advice>; 3],
        hash_rc: [Column<Fixed>; 3],
        swap_advice: [Column<Advice>; 5],
    ) -> MerkleConfig {
        let s_swap = meta.selector();
        let hash = HashChip::configure(meta, hash_state, hash_aux, hash_rc);

        // Booleanity: pos_bit * (1 - pos_bit) = 0
        meta.create_gate("swap: pos_bit boolean", |meta| {
            let s = meta.query_selector(s_swap);
            let pos_bit = meta.query_advice(swap_advice[0], Rotation(1));
            vec![s * pos_bit.clone() * (Expression::Constant(Fr::one()) - pos_bit)]
        });

        // Mux: left = current + pos_bit * (sibling - current)
        meta.create_gate("swap: left = mux", |meta| {
            let s = meta.query_selector(s_swap);
            let pos_bit = meta.query_advice(swap_advice[0], Rotation(1));
            let current = meta.query_advice(swap_advice[1], Rotation(1));
            let sibling = meta.query_advice(swap_advice[2], Rotation(1));
            let left = meta.query_advice(swap_advice[3], Rotation(1));
            vec![s * (left - (current.clone() + pos_bit.clone() * (sibling - current)))]
        });

        // Conservation: right = current + sibling - left
        meta.create_gate("swap: right = conservation", |meta| {
            let s = meta.query_selector(s_swap);
            let current = meta.query_advice(swap_advice[1], Rotation(1));
            let sibling = meta.query_advice(swap_advice[2], Rotation(1));
            let left = meta.query_advice(swap_advice[3], Rotation(1));
            let right = meta.query_advice(swap_advice[4], Rotation(1));
            vec![s * (right - (current + sibling - left))]
        });

        MerkleConfig {
            advice: swap_advice,
            s_swap,
            hash,
        }
    }

    /// Prove membership of `leaf` in a tree with the given `path` (sibling
    /// hashes) and `position` (leaf index). Returns the computed root as an
    /// `AssignedCell` so the caller can constrain it to the public instance.
    ///
    /// `leaf_val` is the off-circuit value of the leaf (needed to compute
    /// intermediate hashes without extracting from `Value`).
    pub fn prove_membership(
        &self,
        layouter: &mut impl Layouter<Fr>,
        leaf_val: Fr,
        leaf_cell: &AssignedCell<Fr, Fr>,
        path: &[Fr],
        position: usize,
        depth: usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        assert_eq!(path.len(), depth, "path length must equal tree depth");

        let hash_chip = HashChip {
            config: self.config.hash.clone(),
        };

        let mut current_val = leaf_val;
        let mut current_cell = leaf_cell.clone();

        for (level, sibling_val) in path.iter().take(depth).enumerate() {
            let pos_bit_val = Fr::from(((position >> level) & 1) as u64);
            let sibling_val = *sibling_val;

            let (left_val, right_val) = if pos_bit_val == Fr::one() {
                (sibling_val, current_val)
            } else {
                (current_val, sibling_val)
            };

            // Swap gate region
            let (left_cell, right_cell) = layouter.assign_region(
                || format!("merkle level {}", level),
                |mut region| {
                    self.config.s_swap.enable(&mut region, 0)?;
                    region.assign_advice(|| "pos_bit", self.config.advice[0], 1, || {
                        Value::known(pos_bit_val)
                    })?;
                    let cur_cell =
                        region.assign_advice(|| "current", self.config.advice[1], 1, || {
                            Value::known(current_val)
                        })?;
                    region.assign_advice(|| "sibling", self.config.advice[2], 1, || {
                        Value::known(sibling_val)
                    })?;

                    // Copy-constrain current to the incoming cell
                    region.constrain_equal(current_cell.cell(), cur_cell.cell())?;

                    let left_cell =
                        region.assign_advice(|| "left", self.config.advice[3], 1, || {
                            Value::known(left_val)
                        })?;
                    let right_cell =
                        region.assign_advice(|| "right", self.config.advice[4], 1, || {
                            Value::known(right_val)
                        })?;

                    Ok((left_cell, right_cell))
                },
            )?;

            // Hash (left, right) -> parent using Poseidon
            current_val = off_circuit_hash(left_val, right_val);
            current_cell = hash_chip.hash_cells(layouter, &left_cell, &right_cell, left_val, right_val)?;
        }

        Ok(current_cell)
    }
}

impl Chip<Fr> for MerkleChip {
    type Config = MerkleConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
