# zk-ballot

**Anonymous on-chain voting with Halo2 zero-knowledge proofs.**

Built for the [Thrive](https://thrive.xyz) / [Horizen](https://horizen.io) Genesis Pool grant program — Anonymous Infrastructure category.

---

## What it does

`zk-ballot` lets a group of registered voters cast secret ballots on-chain. Each voter produces a Halo2 zero-knowledge proof that proves:

1. **They are registered** — their commitment is a leaf in a publicly-known Merkle tree (the voter registry)
2. **They haven't voted before** — a nullifier hash is published that uniquely identifies them without revealing which leaf is theirs
3. **Their vote is valid** — the vote is constrained to be boolean (0 or 1)
4. **The vote is bound to the proof** — a vote commitment hash ties the ballot to this specific proof

No one — not the tally authority, not other voters, not the chain — can link a proof back to the voter who produced it.

### Public inputs

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

# Run the end-to-end demo (5 voters, real Halo2 proofs)
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
  voter 0 proof generated in 1.08s (4032 bytes)
  voter 0 proof verified in 26.7ms
  ...

=== Tally ===
YES: 3
NO:  2

All 5 proofs generated and verified. Voter privacy preserved.
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
| Verify (per proof) | ~27ms |
| Proof size | 4032 bytes |

## Tech stack

- **[Halo2](https://github.com/privacy-scaling-explorations/halo2)** (PSE fork, `halo2_proofs 0.3`) — PLONK-based ZK proving system with no trusted setup
- **[halo2curves](https://github.com/privacy-scaling-explorations/halo2curves)** — BN254 curve arithmetic (EVM-compatible)
- **Rust** — no external dependencies beyond the crypto stack

## Why Halo2?

Halo2 uses the [Inner Product Argument (IPA)](https://eprint.iacr.org/2019/1021) commitment scheme, which requires **no trusted setup ceremony** — a critical advantage for decentralized governance. The BN254 curve is natively supported by the EVM, so proofs can be verified on-chain via a Solidity verifier contract.

## Thrive / Horizen alignment

This project targets the **Horizen Genesis Pool** — net-new privacy-first applications built for [Horizen](https://horizen.io), an EVM-compatible Base L3 appchain.

| Thrive category | How zk-ballot fits |
|----------------|-------------------|
| Anonymous Infrastructure | Private voting systems — exactly this |
| Confidential DeFi | On-chain governance for private DeFi protocols |
| Privacy-Preserving AI | Verifiable, anonymous model governance |

### Roadmap to Horizen mainnet

1. **[Done]** Core Halo2 circuit + off-circuit Merkle tree + demo
2. **[Next]** Solidity verifier contract (on-chain proof verification)
3. **[Next]** Voter registry contract (manages Merkle root on-chain)
4. **[Next]** Tally contract (accumulates vote commitments, reveals tally)
5. **[Next]** Poseidon hash chip (production-grade, replaces demo hash)
6. **[Next]** Deploy to Horizen L3 testnet

### Why this matters for Horizen

Horizen's [Vela](https://blog.horizen.io/introducing-vela-the-confidential-compute-layer-on-horizen) confidential compute layer provides TEE-based privacy. ZK-proof-based voting complements this — Vela protects computation, ZK proofs protect voter identity. Together they enable governance systems where both the execution and the voter's identity are private, with cryptographic auditability.

## License

MIT
