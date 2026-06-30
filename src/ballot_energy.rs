//! Ballot Energy — adapts the FMD (Financial Molecular Dynamics) route
//! energy scoring framework from the orkid workspace for ranking anonymous
//! voting proofs.
//!
//! In the orkid FMD physics engine (`fmd-physics/src/route_energy.rs`), route
//! energy scores arbitrage paths by:
//!
//!   energy = net_bps * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - gas_penalty)
//!
//! Here, we apply the same thermodynamic framework to anonymous voting proofs.
//! Each Halo2 vote proof is a **negentropy extraction** — converting private,
//! chaotic data (voter identity + ballot) into structured, verifiable order
//! (proof of eligible membership + valid vote) without revealing either.
//!
//! ## The Thermodynamic Framing
//!
//! From the orkid blog posts on blockchain thermodynamics and negentropy:
//!
//! - **Shannon entropy**: H = -sum(p_i * log(p_i)) — uncertainty about which
//!   voter cast the ballot before the proof
//! - **Negentropy = Information** (Brillouin, 1953): N = H_max - H_actual =
//!   D_KL(p_informed || p_uninformed) — the information gained by the proof
//! - **Landauer's principle**: Erasing information costs energy:
//!   E >= k_B * T * ln(2) per bit — each bit of negentropy has a thermodynamic
//!   cost, which the proof generation pays in compute
//! - **MEV closure equation** (orkid formal negentropy model):
//!   dM/dt = a*delta + b*H_M - c*chi(I)*M — information closes arbitrage
//!   opportunities; analogously, the ZK proof "closes" the uncertainty about
//!   voter eligibility
//!
//! ## Negentropy in Anonymous Voting
//!
//! A vote is a **high-entropy state** — without proof, anyone could claim
//! eligibility and cast arbitrary ballots. A ZK vote proof extracts negentropy
//! (verifiable order) from this chaos while **preserving entropy** (privacy):
//!
//! - **Extracted**: The verifier learns the voter is registered (Merkle
//!   membership), hasn't voted before (nullifier), and the vote is valid
//!   (boolean). This collapses the uncertainty about eligibility.
//! - **Preserved**: The verifier does NOT learn which voter cast the ballot
//!   (identity privacy: depth bits of entropy preserved) or what the vote was
//!   (vote privacy: 1 bit of entropy preserved).
//!
//! The negentropy extracted by the proof:
//!
//!   N = constraint_count * tree_depth
//!
//! For the zk-ballot circuit (~20 constraints, depth-4 tree):
//!   N = 20 * 4 = 80 bits
//!
//! This is the Shannon entropy reduction — the amount of uncertainty about
//! voter eligibility eliminated by the proof. The tree depth determines the
//! anonymity set size (2^depth voters), and each constraint contributes ~1
//! bit of negentropy.
//!
//! ## The Energy Formula
//!
//! FMD route energy (orkid):
//!   energy = net_bps * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - gas_penalty)
//!
//! Ballot energy (adapted):
//!   energy = confidence * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - cost_penalty)
//!
//! Where:
//! - confidence: registry trust score (analogous to pool TVL / liquidity depth)
//! - depth_ratio: tree depth as anonymity strength (more voters = more negentropy)
//! - timing_factor: exp(-vote_age / half_life) — recency decay
//! - latency_decay: 1 / (1 + total_latency_ms * decay_rate) — proof gen speed
//! - cost_penalty: on-chain verification cost, normalized
//!
//! ## Committor Function
//!
//! Adapted from the TPS (Transition Path Sampling) committor in the FMD
//! engine, which predicts the probability of reaching a profitable state:
//!
//!   committor = (depth_ratio / (1 + depth_ratio)) * timing_factor * (1 - cost_penalty * 0.5)
//!
//! This estimates the probability that the vote is valid and uncontested —
//! a "rare event" prediction for ballot quality.

use serde::{Deserialize, Serialize};

/// Ballot energy evaluation result — mirrors RouteEnergyResult from FMD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BallotEnergyResult {
    /// Total energy score (higher = better quality proof)
    pub energy: f64,
    /// Depth ratio (anonymity strength relative to tree depth)
    pub depth_ratio: f64,
    /// Timing factor (recency decay, 0..1)
    pub timing_factor: f64,
    /// Latency decay (proof gen + verify speed, 0..1)
    pub latency_decay: f64,
    /// Cost penalty (on-chain verification cost, 0..1)
    pub cost_penalty: f64,
    /// Committor probability (likelihood vote is valid & uncontested)
    pub committor: f64,
    /// Negentropy extracted (information created by the proof, in bits)
    pub negentropy_bits: f64,
    /// Anonymity set size (2^tree_depth)
    pub anonymity_set: u64,
}

/// Configuration for ballot energy evaluation.
#[derive(Debug, Clone)]
pub struct BallotPotential {
    /// On-chain verification cost per proof (USD) — e.g., Solidity verifier gas
    pub verify_cost_usd: f64,
    /// Proof generation latency in milliseconds
    pub proof_latency_ms: u64,
    /// Verification latency in milliseconds
    pub verify_latency_ms: u64,
    /// Vote age in seconds (time since proof was generated)
    pub vote_age_secs: f64,
    /// Circuit constraint count (more constraints = more negentropy)
    pub constraint_count: u64,
    /// Merkle tree depth (determines anonymity set size: 2^depth)
    pub tree_depth: usize,
}

impl Default for BallotPotential {
    fn default() -> Self {
        Self {
            verify_cost_usd: 0.05, // ~$0.05 on-chain verify on Horizen L3
            proof_latency_ms: 1000,
            verify_latency_ms: 27,
            vote_age_secs: 0.0,
            constraint_count: 20, // zk-ballot: ~20 constraints (hash + merkle + bool)
            tree_depth: 4,        // VOTE_TREE_DEPTH = 4 → 16 voters
        }
    }
}

impl BallotPotential {
    /// Evaluate ballot energy — adapts the FMD route energy formula.
    ///
    /// FMD route energy (orkid `fmd-physics/src/route_energy.rs`):
    ///   energy = net_bps * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - gas_penalty)
    ///
    /// Ballot energy:
    ///   energy = confidence * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - cost_penalty)
    pub fn energy(&self, registry_trust: f64) -> BallotEnergyResult {
        // Confidence: registry trust score (0..1) scaled to a base depth
        // Analogous to pool TVL in the FMD engine — higher trust = more confidence
        let confidence = 100.0 * registry_trust.clamp(0.0, 1.0);

        // Depth ratio: tree depth as anonymity strength
        // Deeper tree = larger anonymity set = more negentropy extracted
        // Using tree_depth directly (log2 of anonymity set size)
        // This is analogous to FMD depth_ratio = reserve_ratio / trade_size
        let depth_ratio = confidence * self.tree_depth as f64 / 10.0;

        // Timing factor: exponential decay based on vote age
        // Half-life of 1 hour (3600s) — stale votes lose energy
        // Analogous to FMD timing_factor but here we use recency because
        // votes are point-in-time assertions in a voting window
        let half_life = 3600.0;
        let timing_factor = (-self.vote_age_secs / half_life).exp();

        // Latency decay: total proof generation + verification latency
        // Analogous to FMD: (1 - 0.001 * hops * stage_latency_ms).max(0)
        // Here we use a softer decay: 1 / (1 + latency * rate)
        let total_latency = self.proof_latency_ms + self.verify_latency_ms;
        let latency_decay = 1.0 / (1.0 + total_latency as f64 * 0.0001);

        // Cost penalty: on-chain verification cost, normalized
        // Analogous to FMD gas_penalty = gas_units * gas_cost * 0.005
        let cost_penalty = (self.verify_cost_usd * 0.1).min(0.5);

        // Energy: the core formula, adapted from FMD route_energy.rs
        let energy = confidence
            * (depth_ratio * timing_factor).sqrt()
            * latency_decay
            * (1.0 - cost_penalty).max(0.0);

        // Committor: probability vote is valid & uncontested
        // Adapted from TPS committor function — uses depth, timing, and cost
        // as features for a simplified probability estimate
        let committor = (depth_ratio / (1.0 + depth_ratio))
            * timing_factor
            * (1.0 - cost_penalty * 0.5)
            .clamp(0.0, 1.0);

        // Negentropy: information extracted by the proof (in bits)
        // Each constraint contributes ~1 bit of negentropy (order from chaos)
        // The tree depth determines the anonymity set: 2^depth possible voters
        // N = constraint_count * tree_depth
        // This captures the idea that deeper trees = more anonymity = more
        // negentropy per constraint (each constraint rules out more possibilities)
        let negentropy_bits = self.constraint_count as f64 * self.tree_depth as f64;

        // Anonymity set size: 2^tree_depth
        let anonymity_set = 1u64 << self.tree_depth;

        BallotEnergyResult {
            energy,
            depth_ratio,
            timing_factor,
            latency_decay,
            cost_penalty,
            committor,
            negentropy_bits,
            anonymity_set,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ballot_energy() {
        let pot = BallotPotential::default();
        let result = pot.energy(0.95);

        assert!(result.energy > 0.0, "energy should be positive");
        assert!(result.depth_ratio > 0.0);
        assert!(result.timing_factor > 0.99, "fresh vote should have high timing");
        assert!(result.latency_decay > 0.0);
        assert!(result.committor > 0.0 && result.committor <= 1.0);
        assert!(result.negentropy_bits > 0.0);
        assert_eq!(result.anonymity_set, 16, "2^4 = 16 voters");
    }

    #[test]
    fn test_stale_vote_decays() {
        let mut pot = BallotPotential::default();
        pot.vote_age_secs = 7200.0; // 2 hours = 2 half-lives

        let fresh = BallotPotential::default().energy(0.9);
        let stale = pot.energy(0.9);

        assert!(
            stale.energy < fresh.energy,
            "stale vote should have lower energy"
        );
        assert!(
            stale.timing_factor < fresh.timing_factor * 0.5,
            "2 half-lives should reduce timing by >50%"
        );
    }

    #[test]
    fn test_deeper_tree_more_negentropy() {
        let mut pot = BallotPotential::default();
        pot.tree_depth = 8; // 256 voters

        let shallow = BallotPotential::default().energy(0.9);
        let deep = pot.energy(0.9);

        assert!(
            deep.negentropy_bits > shallow.negentropy_bits,
            "deeper tree should extract more negentropy"
        );
        assert_eq!(deep.anonymity_set, 256, "2^8 = 256 voters");
    }

    #[test]
    fn test_low_trust_reduces_energy() {
        let pot = BallotPotential::default();

        let high_trust = pot.energy(0.95);
        let low_trust = pot.energy(0.3);

        assert!(
            low_trust.energy < high_trust.energy,
            "lower registry trust should reduce energy"
        );
    }

    #[test]
    fn test_negentropy_formula() {
        // 20 constraints, depth 4: N = 20 * 4 = 80 bits
        let pot = BallotPotential::default();
        let result = pot.energy(0.9);
        let expected = 20.0 * 4.0;
        assert!(
            (result.negentropy_bits - expected).abs() < 0.01,
            "negentropy should be 20 * 4 = 80, got {:.1}",
            result.negentropy_bits
        );
    }
}
