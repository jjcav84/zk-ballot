//! Algebraic hash chip.
//!
//! Implements `H(a, b) = a² + b² + a·b` as a single Halo2 gate. This is **not**
//! cryptographically secure — it is a demo hash chosen for the smallest
//! possible circuit. A production deployment would swap this chip for a
//! Poseidon chip (see `halo2_gadgets::poseidon`) without changing the rest of
//! the circuit; the gate count rises but the public/private interface is
//! identical.

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// Configuration for the hash chip.
#[derive(Clone, Debug)]
pub struct HashConfig {
    pub advice: [Column<Advice>; 3],
    pub s_hash: Selector,
}

/// A chip that constrains `out = a² + b² + a·b`.
pub struct HashChip {
    pub(crate) config: HashConfig,
}

/// Off-circuit hash matching the on-circuit gate.
pub fn hash(a: Fr, b: Fr) -> Fr {
    a * a + b * b + a * b
}

impl HashChip {
    /// Configure the chip inside a constraint system.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        advice: [Column<Advice>; 3],
    ) -> HashConfig {
        let s_hash = meta.selector();

        meta.create_gate("hash: out = a^2 + b^2 + a*b", |meta| {
            let s = meta.query_selector(s_hash);
            let a = meta.query_advice(advice[0], Rotation(1));
            let b = meta.query_advice(advice[1], Rotation(1));
            let out = meta.query_advice(advice[2], Rotation(1));
            // out - (a^2 + b^2 + a*b) = 0
            vec![s * (out - (a.clone() * a.clone() + b.clone() * b.clone() + a * b))]
        });

        HashConfig { advice, s_hash }
    }

    /// Hash two existing cells (via copy constraints), returning the output
    /// `AssignedCell`. Used by the Merkle chip to chain hashes level by level.
    pub fn hash_cells(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        layouter.assign_region(
            || "hash cells",
            |mut region| {
                self.config.s_hash.enable(&mut region, 0)?;
                let a_cell =
                    region.assign_advice(|| "a", self.config.advice[0], 1, || {
                        a.value().copied()
                    })?;
                let b_cell =
                    region.assign_advice(|| "b", self.config.advice[1], 1, || {
                        b.value().copied()
                    })?;
                let out_val = a
                    .value()
                    .and_then(|av| b.value().map(|bv| hash(*av, *bv)));
                let out_cell =
                    region.assign_advice(|| "out", self.config.advice[2], 1, || out_val)?;
                // Copy-constrain inputs to the original cells
                region.constrain_equal(a.cell(), a_cell.cell())?;
                region.constrain_equal(b.cell(), b_cell.cell())?;
                Ok(out_cell)
            },
        )
    }

    /// Hash a cell with a constant, returning the output `AssignedCell`.
    /// Used for the nullifier: `H(nullifier_seed, 0)`.
    pub fn hash_cell_const(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: Fr,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        layouter.assign_region(
            || "hash cell + const",
            |mut region| {
                self.config.s_hash.enable(&mut region, 0)?;
                let a_cell =
                    region.assign_advice(|| "a", self.config.advice[0], 1, || {
                        a.value().copied()
                    })?;
                let _b_cell =
                    region.assign_advice(|| "b", self.config.advice[1], 1, || Value::known(b))?;
                let out_val = a.value().map(|av| hash(*av, b));
                let out_cell =
                    region.assign_advice(|| "out", self.config.advice[2], 1, || out_val)?;
                region.constrain_equal(a.cell(), a_cell.cell())?;
                Ok(out_cell)
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


