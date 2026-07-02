//! CLI demo — runs a full anonymous-voting session end-to-end.
//!
//! ```sh
//! cargo run --release --bin demo
//! ```
//!
//! Steps:
//! 1. Register 5 voters (each gets a random secret + nullifier seed).
//! 2. Build the voter-registry Merkle tree.
//! 3. Each voter casts a secret yes/no vote and generates a Halo2 proof.
//! 4. Verify every proof against the public inputs.
//! 5. Tally the votes.

use std::time::Instant;

use ff::Field;
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::bn256::{Fr, G1Affine};
use rand::rngs::OsRng;

use zk_ballot::{
    circuit::{VoteCircuit, VoteInputs, VOTE_TREE_DEPTH},
    tree::MerkleTree,
    ballot_energy::BallotPotential,
};

fn main() {
    println!("=== zk-ballot: Anonymous Voting with Halo2 ===\n");
    println!(
        "Tree depth: {} (up to {} voters)\n",
        VOTE_TREE_DEPTH,
        1 << VOTE_TREE_DEPTH
    );

    // ---- 1. Register voters ----
    let mut rng = OsRng;
    let num_voters = 5;
    let voters: Vec<(Fr, Fr)> = (0..num_voters)
        .map(|_| (Fr::random(&mut rng), Fr::random(&mut rng)))
        .collect();

    let leaves: Vec<Fr> = voters
        .iter()
        .map(|(secret, seed)| MerkleTree::leaf(*secret, *seed))
        .collect();

    let tree = MerkleTree::new(&leaves);
    println!("Voter registry Merkle root: 0x{}", to_hex(tree.root));
    println!("Registered {} voters\n", num_voters);

    // ---- 2. Each voter casts a secret vote ----
    let votes = [Fr::one(), Fr::zero(), Fr::one(), Fr::one(), Fr::zero()];

    // ---- 3. MockProver sanity check (fast, no SRS) ----
    println!("--- MockProver sanity check ---");
    for (i, ((secret, seed), vote)) in voters.iter().zip(votes.iter()).enumerate() {
        let inputs = VoteInputs {
            secret: *secret,
            nullifier_seed: *seed,
            vote: *vote,
            merkle_path: tree.path(i),
            position: i,
        };
        let circuit = VoteCircuit { inputs };

        let public = vec![
            tree.root,
            MerkleTree::nullifier(*seed),
            MerkleTree::vote_commitment(*vote, *secret),
        ];

        let prover = MockProver::run(VOTE_TREE_DEPTH as u32 + 8, &circuit, vec![public])
            .expect("mock prover setup");
        prover.assert_satisfied();
        println!("  voter {} mock proof verified ✓", i);
    }
    println!();

    // ---- 4. Real Halo2 proof (PLONK + IPA commitment) ----
    println!("--- Real Halo2 proof generation ---");
    let k = (VOTE_TREE_DEPTH as u32) + 8;
    println!("Circuit parameter k = {} (2^{} rows)", k, k);

    let start = Instant::now();
    let params: Params<G1Affine> = Params::new(k);
    println!("Setup SRS: {:?}", start.elapsed());

    let start = Instant::now();
    let vk = keygen_vk(&params, &VoteCircuit::empty()).expect("vk");
    let pk = keygen_pk(&params, vk.clone(), &VoteCircuit::empty()).expect("pk");
    println!("Keygen (vk + pk): {:?}", start.elapsed());

    let mut tally_yes = 0u64;
    let mut tally_no = 0u64;
    let mut total_energy = 0.0f64;
    let mut total_negentropy = 0.0f64;

    for (i, ((secret, seed), vote)) in voters.iter().zip(votes.iter()).enumerate() {
        let inputs = VoteInputs {
            secret: *secret,
            nullifier_seed: *seed,
            vote: *vote,
            merkle_path: tree.path(i),
            position: i,
        };
        let circuit = VoteCircuit { inputs };

        let public = vec![
            tree.root,
            MerkleTree::nullifier(*seed),
            MerkleTree::vote_commitment(*vote, *secret),
        ];

        // Prove
        let start = Instant::now();
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[public.as_slice()]],
            OsRng,
            &mut transcript,
        )
        .expect("prove");
        let proof_bytes = transcript.finalize();
        let prove_ms = start.elapsed().as_millis() as u64;
        println!(
            "  voter {} proof generated in {:?} ({} bytes)",
            i,
            start.elapsed(),
            proof_bytes.len()
        );

        // Verify
        let start = Instant::now();
        let mut verifier_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_bytes[..]);
        let strategy = SingleVerifier::new(&params);
        verify_proof(
            &params,
            &vk,
            strategy,
            &[&[public.as_slice()]],
            &mut verifier_transcript,
        )
        .expect("verify");
        let verify_ms = start.elapsed().as_millis() as u64;
        println!("  voter {} proof verified in {:?}", i, start.elapsed());

        // Compute FMD physics energy score
        let potential = BallotPotential {
            proof_latency_ms: prove_ms,
            verify_latency_ms: verify_ms,
            ..Default::default()
        };
        let energy = potential.energy(0.95); // high trust in the registry
        println!(
            "    energy={:.2}  negentropy={:.1} bits  committor={:.1}%  anonymity_set={}",
            energy.energy,
            energy.negentropy_bits,
            energy.committor * 100.0,
            energy.anonymity_set,
        );
        total_energy += energy.energy;
        total_negentropy += energy.negentropy_bits;

        if *vote == Fr::one() {
            tally_yes += 1;
        } else {
            tally_no += 1;
        }
    }

    println!("\n=== Tally ===");
    println!("YES: {}", tally_yes);
    println!("NO:  {}", tally_no);
    println!(
        "\nAll {} proofs generated and verified. Voter privacy preserved.\n",
        num_voters
    );
    println!("Each proof proves:");
    println!("  1. Voter is registered (Merkle membership in the public registry)");
    println!("  2. Voter hasn't voted before (nullifier is unique)");
    println!("  3. Vote is valid (boolean 0 or 1)");
    println!("  4. Vote is bound to this proof (commitment)");
    println!("\nNo one — not the tally authority, not other voters, not the chain —");
    println!("can link a proof back to the voter who produced it.");

    println!("\n=== FMD Physics Energy Summary ===");
    println!("Model: FMD Route Energy (adapted from orkid fmd-physics/src/route_energy.rs)");
    println!("Formula: energy = confidence * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - cost_penalty)");
    println!("Negentropy: N = constraint_count * tree_depth = {} * {} = {:.0} bits/proof",
        BallotPotential::default().constraint_count,
        VOTE_TREE_DEPTH,
        BallotPotential::default().constraint_count as f64 * VOTE_TREE_DEPTH as f64,
    );
    println!("Total energy: {:.2}", total_energy);
    println!("Total negentropy extracted: {:.1} bits", total_negentropy);
    println!("Average energy per proof: {:.2}", total_energy / num_voters as f64);
    println!("Average negentropy per proof: {:.1} bits", total_negentropy / num_voters as f64);
    println!("\nReferences:");
    println!("  orkid/fmd-physics/src/route_energy.rs — route energy formula");
    println!("  orkid/fmd-physics/src/tps.rs — committor function");
    println!("  Blog: Blockchain Thermodynamics (Landauer, Shannon, negentropy)");
    println!("  Blog: Negentropy = Information (D_KL, Brillouin)");
    println!("  Blog: Formal Negentropy Model (MEV closure equation)");
}

fn to_hex(f: Fr) -> String {
    hex::encode(f.to_bytes())
}
