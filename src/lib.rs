//! zk-ballot — Anonymous on-chain voting with Halo2 zero-knowledge proofs.
//!
//! The circuit proves, without revealing the voter's identity or their vote:
//!
//! 1. **Merkle membership** — the voter's commitment `H(secret, nullifier_seed)`
//!    is a leaf of a publicly-known voter-registry Merkle tree.
//! 2. **Nullifier** — `H(nullifier_seed)` is published so each voter can vote
//!    at most once (double-voting is prevented without linking the vote to
//!    the voter's leaf).
//! 3. **Boolean vote** — `vote ∈ {0, 1}`.
//! 4. **Vote commitment** — `H(vote, secret)` binds the proof to a specific
//!    ballot without revealing it.
//!
//! Public inputs: `[merkle_root, nullifier, vote_commitment]`
//!
//! Designed for the Thrive / Horizen Genesis Pool (Anonymous Infrastructure
//! category). Horizen is an EVM-compatible Base L3, so the verifying key can
//! be embedded in a Solidity verifier contract and proofs checked on-chain.

pub mod hash;
pub mod merkle;
pub mod circuit;
pub mod tree;
pub mod ballot_energy;

pub use circuit::{VoteCircuit, VoteInputs, VOTE_TREE_DEPTH, NUM_PUBLIC_INPUTS};
pub use tree::MerkleTree;
pub use ballot_energy::{BallotEnergyResult, BallotPotential};
