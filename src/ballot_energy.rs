//! Ballot Energy — thin domain adapter over the `negentropy` physics
//! engine for ranking anonymous voting proofs.
//!
//! The core thermodynamic formula (route energy, committor, negentropy
//! extraction) lives in the [`negentropy`] crate. This module maps ballot
//! domain quantities onto that engine:
//!
//! - **confidence** ← registry trust score (0..1) scaled to 100
//! - **depth_ratio** ← confidence × tree_depth / 10 (anonymity strength)
//! - **timing_factor** ← exp(-vote_age / half_life)
//! - **latency_decay** ← 1 / (1 + total_latency × decay_rate)
//! - **cost_penalty** ← on-chain verification cost, normalized
//!
//! The negentropy extracted is `constraint_count × tree_depth` bits —
//! elegantly expressed as `Negentropy::from_constraints(n, 2^depth)` since
//! `log₂(2^depth) = depth`.
//!
//! See <https://github.com/jjcav84/negentropy> for the physics.

use serde::{Deserialize, Serialize};

use negentropy::{Committor, Negentropy, RouteEnergy};

/// Ballot energy evaluation result.
///
/// Produced by [`BallotPotential::energy`]. The fields mirror the core
/// `negentropy::RouteEnergyResult` plus domain-specific extras (committor,
/// negentropy bits, and anonymity set size).
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

/// Half-life for vote recency decay (1 hour, in seconds).
const HALF_LIFE_SECS: f64 = 3600.0;

impl BallotPotential {
    /// Evaluate ballot energy via the `negentropy` physics engine.
    ///
    /// Delegates:
    /// - energy → `negentropy::RouteEnergy::new`
    /// - committor → `negentropy::Committor::score`
    /// - negentropy_bits → `negentropy::Negentropy::from_constraints(n, 2^depth)`
    ///   (since `log₂(2^depth) = depth`, this gives `n × depth`)
    pub fn energy(&self, registry_trust: f64) -> BallotEnergyResult {
        // Validate inputs
        assert!(
            self.vote_age_secs.is_finite() && self.vote_age_secs >= 0.0,
            "vote_age_secs must be finite and non-negative"
        );
        assert!(
            self.verify_cost_usd.is_finite() && self.verify_cost_usd >= 0.0,
            "verify_cost_usd must be finite and non-negative"
        );

        // Domain mapping: registry trust (0..1) → confidence (0..100)
        let confidence = 100.0 * registry_trust.clamp(0.0, 1.0);

        // Depth ratio: tree depth as anonymity strength
        let depth_ratio = confidence * self.tree_depth as f64 / 10.0;

        // Timing factor: exponential decay based on vote age
        let timing_factor = (-self.vote_age_secs / HALF_LIFE_SECS).exp();

        // Latency decay: total proof generation + verification latency
        let total_latency = self.proof_latency_ms + self.verify_latency_ms;
        let latency_decay = 1.0 / (1.0 + total_latency as f64 * 0.0001);

        // Cost penalty: on-chain verification cost, normalized
        let cost_penalty = (self.verify_cost_usd * 0.1).min(0.5);

        // Core energy from negentropy
        let energy = RouteEnergy::new(
            confidence,
            depth_ratio,
            timing_factor,
            latency_decay,
            cost_penalty,
        )
        .energy;

        // Committor from negentropy (TPS rare-event prediction)
        let committor = Committor::score(depth_ratio, timing_factor, cost_penalty);

        // Negentropy: N = constraint_count × tree_depth
        // Expressed as from_constraints(n, 2^depth) since log₂(2^depth) = depth
        let anonymity_set = if self.tree_depth >= 64 {
            u64::MAX
        } else {
            1u64 << self.tree_depth
        };
        let negentropy_bits =
            Negentropy::from_constraints(self.constraint_count, anonymity_set).bits();

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
#[allow(clippy::field_reassign_with_default)]
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
