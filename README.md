# zk-ballot

**Anonymous on-chain voting with Halo2 zero-knowledge proofs, scored by FMD physics energy.**

Built for the [Thrive](https://thrive.xyz) / [Horizen](https://horizen.io) Genesis Pool grant program — Anonymous Infrastructure category. Energy model adapted from the [orkid](https://github.com/jjcav84/orkid) FMD (Financial Molecular Dynamics) MEV detection engine.

---

## What it does

`zk-ballot` lets a group of registered voters cast secret ballots on-chain. Each voter produces a Halo2 zero-knowledge proof that proves:

1. **They are registered** — their commitment is a leaf in a publicly-known Merkle tree (the voter registry)
2. **They haven't voted before** — a nullifier hash is published that uniquely identifies them without revealing which leaf is theirs
3. **Their vote is valid** — the vote is constrained to be boolean (0 or 1)
4. **The vote is bound to the proof** — a vote commitment hash ties the ballot to this specific proof

No one — not the tally authority, not other voters, not the chain — can link a proof back to the voter who produced it.

Each proof is scored by its **thermodynamic energy** — the negentropy extracted from private data, adapted from the orkid FMD physics engine.

## The thermodynamic framing

zk-ballot applies the **Financial Molecular Dynamics (FMD)** physics framework from the orkid MEV detection engine to score anonymous voting proofs. This is not metaphor — the mathematics of statistical mechanics, information theory, and zero-knowledge proofs are fundamentally connected.

### Negentropy = Information = Order

From Brillouin's negentropy principle (1953) and the orkid blog post ["Negentropy = Information: A Generalized Mathematical Framework"](https://github.com/jjcav84/orkid/blob/main/blog/2025-11-06-negentropy-information-generalized-framework.md):

> **Negentropy = H_max − H_actual = D_KL(p_informed || p_uninformed)**

A vote is a **high-entropy state** — without proof, anyone could claim eligibility and cast arbitrary ballots. A ZK vote proof is a **negentropy extraction**: it converts private, chaotic data (voter identity + ballot) into structured, verifiable order (proof of eligible membership + valid vote) without revealing either.

### Extracted vs. preserved entropy

The genius of ZK voting is that it **extracts negentropy** (verifiable order) while **preserving entropy** (privacy):

| | Before proof | After proof |
|---|---|---|
| **Voter identity** | High entropy (anyone could claim) | Negentropy extracted: eligibility proven. Entropy preserved: identity hidden in anonymity set of 2^depth |
| **Vote value** | High entropy (could be anything) | Negentropy extracted: vote is boolean. Entropy preserved: actual vote hidden |
| **Double-voting** | Uncertain | Negentropy extracted: nullifier proves uniqueness |

For the zk-ballot circuit (~20 constraints, depth-4 tree):

```
N = constraint_count × tree_depth = 20 × 4 = 80 bits
```

This is the Shannon entropy reduction — the amount of uncertainty about voter eligibility eliminated by the proof. The tree depth determines the anonymity set size (2^depth = 16 voters), and each constraint contributes ~1 bit of negentropy per tree level.

### Landauer's principle

From Landauer (1961) and the orkid blog post ["Blockchain Thermodynamics: How Negentropy Explains MEV"](https://github.com/jjcav84/orkid/blob/main/blog/2025-10-18-blockchain-thermodynamics-negentropy-mev.md):

> **E ≥ k_B × T × ln(2) per bit erased**

Proof generation pays the thermodynamic cost of extracting negentropy. The compute energy spent generating the Halo2 proof is the Landauer cost of creating 80 bits of order from private chaos. The verifier receives this order without paying the cost.

### The MEV closure analogy

From the orkid blog post ["A Formal Mathematical Model of Blockchain Negentropy and MEV Dynamics"](https://github.com/jjcav84/orkid/blob/main/blog/2025-10-18-formal-negentropy-model-mev-dynamics.md):

> **dM/dt = a·δ + b·H_M − c·χ(I)·M**

In MEV: information closes arbitrage opportunities. In zk-ballot: the ZK proof "closes" the uncertainty about voter eligibility. The proof is the information injection that collapses the entropy of the unverifiable ballot into a deterministic set of public assertions (registered, not double-voted, valid vote).

## The energy model

The ballot energy model is adapted from the **route energy formula** in the orkid FMD physics engine (`fmd-physics/src/route_energy.rs`):

### FMD route energy (orkid)

```
energy = net_bps × √(depth_ratio × timing_factor) × latency_decay × (1 − gas_penalty)
```

This scores arbitrage paths by net output, liquidity depth, timing, and gas cost. Higher energy = more profitable route.

### Ballot energy (zk-ballot)

```
energy = confidence × √(depth_ratio × timing_factor) × latency_decay × (1 − cost_penalty)
```

This scores ZK vote proofs by registry confidence, anonymity strength, recency, proof speed, and verification cost. Higher energy = higher quality proof.

| Factor | FMD (MEV) | zk-ballot (voting) |
|--------|-----------|---------------------|
| **Confidence** | Pool TVL (liquidity depth) | Registry trust score (credential strength) |
| **Depth ratio** | Reserve ratio / trade size | Confidence × tree_depth / 10 |
| **Timing factor** | 1/√(hops) | exp(−age / half_life) |
| **Latency decay** | (1 − 0.001 × hops × latency) | 1 / (1 + total_latency × 0.0001) |
| **Cost penalty** | Gas units × gas cost | On-chain verification cost |

### Committor function

Adapted from the TPS (Transition Path Sampling) committor in the FMD engine, which predicts the probability of reaching a profitable state:

```
committor = (depth_ratio / (1 + depth_ratio)) × timing_factor × (1 − cost_penalty × 0.5)
```

This estimates the probability that the vote is valid and uncontested — a "rare event" prediction for ballot quality. A fresh proof from a trusted registry with a deep tree yields a committor near 1.0.

### Example

For a 5-voter election (depth-4 tree, 16-voter anonymity set), registry trust=0.95, proof gen ~1s:

| Metric | Value |
|--------|-------|
| Energy per proof | ~526 |
| Negentropy per proof | 80 bits |
| Committor | 97.2% |
| Anonymity set | 16 voters |
| Total negentropy (5 proofs) | 400 bits |
| Proof size | 4032 bytes |

## Public inputs

| Index | Name | Purpose |
|-------|------|---------|
| 0 | `merkle_root` | Anchors the proof to a specific voter registry |
| 1 | `nullifier` | Prevents double-voting (unique per voter) |
| 2 | `vote_commitment` | Binds the vote to this proof (for tally / reveal) |

### Private witnesses

| Witness | Purpose |
|---------|---------|
| `secret` | Voter's private key (never revealed) |
| `nullifier_seed` | Derives the nullifier (never revealed) |
| `vote` | The actual ballot (0 = no, 1 = yes) |
| `merkle_path[]` | Authentication path from leaf to root |
| `position` | Leaf index in the tree |

## Circuit architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              VoteCircuit                     │
                    │                                              │
  secret ──────┐   │  ┌──────────┐   ┌─────────────────────┐      │
  nullifier ───┼──▶│  │ HashChip │──▶│  leaf = H(s, n)     │      │
  seed ────────┘   │  └──────────┘   └────────┬────────────┘      │
                    │                          │                   │
                    │                ┌─────────▼──────────┐        │
                    │                │  MerkleChip         │        │
  merkle_path ─────▶│                │  (depth-4 tree)     │        │
  position ────────▶│                │  conditional swap   │        │
                    │                │  + hash per level   │        │
                    │                └─────────┬──────────┘        │
                    │                          │                   │
                    │          root ───────────▶ instance[0]       │
                    │                                              │
                    │  ┌──────────┐   ┌─────────────────────┐      │
                    │  │ HashChip │──▶│ nullifier = H(n, 0) │──▶instance[1]
                    │  └──────────┘   └─────────────────────┘      │
                    │                                              │
                    │  vote*(1-vote) = 0  ◀── boolean constraint   │
                    │                                              │
                    │  ┌──────────┐   ┌─────────────────────┐      │
                    │  │ HashChip │──▶│ commit = H(v, s)    │──▶instance[2]
                    │  └──────────┘   └─────────────────────┘      │
                    └─────────────────────────────────────────────┘
```

### Chips

- **`HashChip`** — constrains `out = a² + b² + a·b` via a single PLONK gate. This is a demo hash (not cryptographically secure). A production deployment would swap in a [Poseidon](https://github.com/privacy-scaling-explorations/halo2/tree/main/halo2_gadgets/src/poseidon) chip without changing the circuit's public/private interface.

- **`MerkleChip`** — conditional-swap gate per tree level: enforces `pos_bit` booleanity, computes `left`/`right` via mux, then hashes the pair. This is the standard pattern used by [Tornado Cash](https://github.com/tornadocash/tornado-core), [Semaphore](https://github.com/semaphore-protocol/semaphore), and [vocdoni](https://github.com/vocdoni/halo2-franchise-proof).

## Quick start

```sh
# Build
cargo build --release

# Run the end-to-end demo (5 voters, real Halo2 proofs + FMD energy scores)
cargo run --release --bin demo
```

### Expected output

```
=== zk-ballot: Anonymous Voting with Halo2 ===

Tree depth: 4 (up to 16 voters)

Voter registry Merkle root: 0x...
Registered 5 voters

--- MockProver sanity check ---
  voter 0 mock proof verified ✓
  ...

--- Real Halo2 proof generation ---
Circuit parameter k = 10 (2^10 rows)
Setup SRS: 1.1s
Keygen (vk + pk): 280ms

  voter 0 proof generated in 1.00s (4032 bytes)
  voter 0 proof verified in 28ms
    energy=528.37  negentropy=80.0 bits  committor=97.2%  anonymity_set=16
  ...

=== Tally ===
YES: 3
NO:  2

=== FMD Physics Energy Summary ===
Model: FMD Route Energy (adapted from orkid fmd-physics/src/route_energy.rs)
Formula: energy = confidence * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - cost_penalty)
Negentropy: N = constraint_count * tree_depth = 20 * 4 = 80 bits/proof
Total energy: 2628.18
Total negentropy extracted: 400.0 bits
Average energy per proof: 525.64
Average negentropy per proof: 80.0 bits
```

## Run tests

```sh
cargo test
```

## Performance

Measured on Apple Silicon (M-series), `k=10` (1024 rows):

| Operation | Time |
|-----------|------|
| SRS setup | ~1.1s |
| Keygen (vk + pk) | ~280ms |
| Prove (per voter) | ~1.0s |
| Verify (per proof) | ~28ms |
| Proof size | 4032 bytes |
| Energy per proof | ~526 |
| Negentropy per proof | 80 bits |

## Tech stack

- **[Halo2](https://github.com/privacy-scaling-explorations/halo2)** (PSE fork, `halo2_proofs 0.3`) — PLONK-based ZK proving system with no trusted setup
- **[halo2curves](https://github.com/privacy-scaling-explorations/halo2curves)** — BN254 curve arithmetic (EVM-compatible)
- **FMD physics energy model** (adapted from [orkid](https://github.com/jjcav84/orkid)) — thermodynamic proof quality scoring
- **Rust** — no external dependencies beyond the crypto stack

## Why Halo2?

Halo2 uses the [Inner Product Argument (IPA)](https://eprint.iacr.org/2019/1021) commitment scheme, which requires **no trusted setup ceremony** — a critical advantage for decentralized governance. The BN254 curve is natively supported by the EVM, so proofs can be verified on-chain via a Solidity verifier contract.

## Project structure

```
zk-ballot/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Library exports
│   ├── circuit.rs          # VoteCircuit — ties together all constraints
│   ├── hash.rs             # HashChip — algebraic hash gate
│   ├── merkle.rs           # MerkleChip — conditional-swap membership proof
│   ├── tree.rs             # Off-circuit Merkle tree + helpers
│   ├── ballot_energy.rs    # FMD physics energy model (adapted from orkid)
│   └── bin/
│       └── demo.rs         # CLI demo — full voting session + energy scores
└── README.md
```

## Thrive / Horizen alignment

This project targets the **Horizen Genesis Pool** — net-new privacy-first applications built for [Horizen](https://horizen.io), an EVM-compatible Base L3 appchain.

| Thrive category | How zk-ballot fits |
|----------------|-------------------|
| Anonymous Infrastructure | Private voting systems — exactly this |
| Confidential DeFi | On-chain governance for private DeFi protocols |
| Privacy-Preserving AI | Verifiable, anonymous model governance |

### Roadmap to Horizen mainnet

1. **[Done]** Core Halo2 circuit + off-circuit Merkle tree + demo
2. **[Done]** FMD physics energy model for proof quality scoring
3. **[Next]** Solidity verifier contract (on-chain proof verification)
4. **[Next]** Voter registry contract (manages Merkle root on-chain)
5. **[Next]** Tally contract (accumulates vote commitments, reveals tally)
6. **[Next]** Poseidon hash chip (production-grade, replaces demo hash)
7. **[Next]** Deploy to Horizen L3 testnet

### Why this matters for Horizen

Horizen's [Vela](https://blog.horizen.io/introducing-vela-the-confidential-compute-layer-on-horizen) confidential compute layer provides TEE-based privacy. ZK-proof-based voting complements this — Vela protects computation, ZK proofs protect voter identity. Together they enable governance systems where both the execution and the voter's identity are private, with cryptographic auditability.

## References

The FMD physics energy model is adapted from the orkid workspace:

- **Route energy formula**: [`orkid/fmd-physics/src/route_energy.rs`](https://github.com/jjcav84/orkid/blob/main/fmd-physics/src/route_energy.rs)
- **TPS committor function**: [`orkid/fmd-physics/src/tps.rs`](https://github.com/jjcav84/orkid/blob/main/fmd-physics/src/tps.rs)
- **Profit potential energy**: [`orkid/fmd-physics/src/profit_potential.rs`](https://github.com/jjcav84/orkid/blob/main/fmd-physics/src/profit_potential.rs)

Blog posts establishing the thermodynamic framework:

- ["Blockchain Thermodynamics: How Negentropy Explains MEV"](https://github.com/jjcav84/orkid/blob/main/blog/2025-10-18-blockchain-thermodynamics-negentropy-mev.md) — Landauer's principle, Shannon entropy, negentropy extraction
- ["Negentropy = Information: A Generalized Mathematical Framework"](https://github.com/jjcav84/orkid/blob/main/blog/2025-11-06-negentropy-information-generalized-framework.md) — D_KL, Brillouin's negentropy principle
- ["A Formal Mathematical Model of Blockchain Negentropy and MEV Dynamics"](https://github.com/jjcav84/orkid/blob/main/blog/2025-10-18-formal-negentropy-model-mev-dynamics.md) — MEV closure equation, graph diffusion
- ["Complex Microstructure and Route Scoring in DeFi"](https://github.com/jjcav84/orkid/blob/main/blog/2025-10-18-complex-microstructure-route-scoring.md) — Complex microstructure factor, phase conjugation, time-normalized scoring

## License

MIT
