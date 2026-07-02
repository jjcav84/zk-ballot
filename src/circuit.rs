//! The vote circuit — ties together Merkle membership, nullifier, boolean
//! vote, and vote commitment.
//!
//! Uses Poseidon hash (width 3, x^5 S-box, 8 full + 57 partial rounds,
//! production-standard parameters for BN254) for all hashing operations.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use crate::hash::{hash as off_circuit_hash, HashChip};
use crate::merkle::MerkleChip;

/// Depth of the voter-registry Merkle tree. 4 → up to 16 voters.
pub const VOTE_TREE_DEPTH: usize = 4;

/// Public inputs: `[merkle_root, nullifier, vote_commitment]`.
pub const NUM_PUBLIC_INPUTS: usize = 3;

/// All the data a voter needs to produce a proof.
#[derive(Clone, Debug)]
pub struct VoteInputs {
    /// Voter's secret (private).
    pub secret: Fr,
    /// Nullifier seed (private). Published as `H(seed, 0)` to prevent double-voting.
    pub nullifier_seed: Fr,
    /// The vote: 0 = no, 1 = yes (private).
    pub vote: Fr,
    /// Sibling hashes from leaf to root (private).
    pub merkle_path: Vec<Fr>,
    /// Leaf index in the tree (private).
    pub position: usize,
}

#[derive(Clone, Debug)]
pub struct VoteConfig {
    /// Columns for witnessing raw private inputs (secret, seed, vote).
    witness_advice: [Column<Advice>; 3],
    /// Poseidon state advice columns (3 elements).
    poseidon_state: [Column<Advice>; 3],
    /// Poseidon S-box auxiliary columns (t0, t1, t2).
    poseidon_aux: [Column<Advice>; 3],
    /// Poseidon round constant fixed columns (3).
    poseidon_rc: [Column<Fixed>; 3],
    /// 5 advice columns for the swap gate.
    swap_advice: [Column<Advice>; 5],
    instance: Column<Instance>,
    s_bool: Selector,
    hash: crate::hash::HashConfig,
    merkle: crate::merkle::MerkleConfig,
}

/// The anonymous-voting circuit.
#[derive(Clone, Debug)]
pub struct VoteCircuit {
    pub inputs: VoteInputs,
}

impl VoteCircuit {
    /// Create a circuit with zero witnesses (for keygen).
    pub fn empty() -> Self {
        Self {
            inputs: VoteInputs {
                secret: Fr::zero(),
                nullifier_seed: Fr::zero(),
                vote: Fr::zero(),
                merkle_path: vec![Fr::zero(); VOTE_TREE_DEPTH],
                position: 0,
            },
        }
    }
}

impl Circuit<Fr> for VoteCircuit {
    type Config = VoteConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Public inputs
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // 3 advice columns for Poseidon state
        let poseidon_state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        // 3 advice columns for Poseidon S-box intermediates
        let poseidon_aux = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        // 3 fixed columns for Poseidon round constants
        let poseidon_rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        // 5 advice columns for the swap gate
        let swap_advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        // 3 advice columns for witnessing raw private inputs
        let witness_advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Enable equality on all advice for copy constraints
        for col in poseidon_state
            .iter()
            .chain(poseidon_aux.iter())
            .chain(swap_advice.iter())
            .chain(witness_advice.iter())
        {
            meta.enable_equality(*col);
        }

        let hash = HashChip::configure(meta, poseidon_state, poseidon_aux, poseidon_rc);
        let merkle = MerkleChip::configure(meta, poseidon_state, poseidon_aux, poseidon_rc, swap_advice);

        // Boolean constraint for the vote: vote * (1 - vote) = 0
        let s_bool = meta.selector();
        meta.create_gate("vote boolean", |meta| {
            let s = meta.query_selector(s_bool);
            let v = meta.query_advice(witness_advice[2], Rotation(1));
            vec![s * v.clone() * (Expression::Constant(Fr::one()) - v)]
        });

        VoteConfig {
            witness_advice,
            poseidon_state,
            poseidon_aux,
            poseidon_rc,
            swap_advice,
            instance,
            s_bool,
            hash,
            merkle,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let hash_chip = HashChip {
            config: config.hash.clone(),
        };
        let merkle_chip = MerkleChip {
            config: config.merkle.clone(),
        };

        // ---- 1. Witness raw private inputs: secret, nullifier_seed ----
        let (secret, seed) = layouter.assign_region(
            || "witness secret + seed",
            |mut region| {
                let secret =
                    region.assign_advice(|| "secret", config.witness_advice[0], 0, || {
                        Value::known(self.inputs.secret)
                    })?;
                let seed =
                    region.assign_advice(|| "seed", config.witness_advice[1], 0, || {
                        Value::known(self.inputs.nullifier_seed)
                    })?;
                Ok((secret, seed))
            },
        )?;

        // ---- 2. Compute leaf = H(secret, seed) ----
        let leaf = hash_chip.hash_cells(&mut layouter, &secret, &seed, self.inputs.secret, self.inputs.nullifier_seed)?;
        let leaf_val = off_circuit_hash(self.inputs.secret, self.inputs.nullifier_seed);

        // ---- 3. Prove Merkle membership of leaf → root ----
        let root_cell = merkle_chip.prove_membership(
            &mut layouter,
            leaf_val,
            &leaf,
            &self.inputs.merkle_path,
            self.inputs.position,
            VOTE_TREE_DEPTH,
        )?;

        // Constrain root == instance[0]
        layouter.constrain_instance(root_cell.cell(), config.instance, 0)?;

        // ---- 4. Compute nullifier = H(seed, 0) and constrain to instance[1] ----
        let nullifier = hash_chip.hash_cell_const(&mut layouter, &seed, self.inputs.nullifier_seed, Fr::zero())?;
        layouter.constrain_instance(nullifier.cell(), config.instance, 1)?;

        // ---- 5. Boolean vote: vote * (1 - vote) = 0 ----
        let vote_cell = layouter.assign_region(
            || "vote boolean",
            |mut region| {
                config.s_bool.enable(&mut region, 0)?;
                region.assign_advice(|| "vote", config.witness_advice[2], 1, || {
                    Value::known(self.inputs.vote)
                })
            },
        )?;

        // ---- 6. Compute vote_commitment = H(vote, secret) → instance[2] ----
        let vote_val = self.inputs.vote;
        let commitment = hash_chip.hash_cells(&mut layouter, &vote_cell, &secret, vote_val, self.inputs.secret)?;
        layouter.constrain_instance(commitment.cell(), config.instance, 2)?;

        Ok(())
    }
}
