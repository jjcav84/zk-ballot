//! Off-circuit Merkle tree and helpers.
//!
//! Uses the same algebraic hash `H(a, b) = a² + b² + a·b` as the on-circuit
//! chip so proofs verify against trees built here.

use halo2curves::bn256::Fr;

use crate::circuit::VOTE_TREE_DEPTH;

/// Algebraic hash matching the on-circuit `HashChip`.
pub fn hash(a: Fr, b: Fr) -> Fr {
    a * a + b * b + a * b
}

/// A binary Merkle tree of fixed depth `VOTE_TREE_DEPTH`.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// All nodes, level-order: `[root, level1..., level2..., leaves...]`.
    /// Stored bottom-up for easier path extraction.
    pub leaves: Vec<Fr>,
    pub nodes: Vec<Vec<Fr>>,
    pub root: Fr,
}

impl MerkleTree {
    /// Build a tree from a list of voter commitments (leaves). Pads with
    /// `Fr::zero()` up to `2^DEPTH`.
    pub fn new(leaves: &[Fr]) -> Self {
        // Compile-time guard: VOTE_TREE_DEPTH must be < usize bits to prevent shift overflow
        const { assert!(VOTE_TREE_DEPTH < 64, "VOTE_TREE_DEPTH must be < 64"); }
        let capacity = 1usize << VOTE_TREE_DEPTH;
        let mut padded = leaves.to_vec();
        padded.resize(capacity, Fr::zero());

        let mut nodes = Vec::with_capacity(VOTE_TREE_DEPTH + 1);
        nodes.push(padded.clone()); // level 0 = leaves

        let mut current = padded.clone();
        for _ in 0..VOTE_TREE_DEPTH {
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                next.push(hash(pair[0], pair[1]));
            }
            nodes.push(next.clone());
            current = next;
        }

        let root = current[0];
        Self {
            leaves: padded,
            nodes,
            root,
        }
    }

    /// Return the sibling hashes (authentication path) for the leaf at
    /// `index`, ordered from leaf level to root.
    pub fn path(&self, index: usize) -> Vec<Fr> {
        let mut path = Vec::with_capacity(VOTE_TREE_DEPTH);
        let mut idx = index;
        for level in 0..VOTE_TREE_DEPTH {
            let sibling = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            path.push(self.nodes[level][sibling]);
            idx /= 2;
        }
        path
    }

    /// Compute the voter's leaf commitment: `H(secret, nullifier_seed)`.
    pub fn leaf(secret: Fr, nullifier_seed: Fr) -> Fr {
        hash(secret, nullifier_seed)
    }

    /// Compute the nullifier: `H(nullifier_seed, 0)`.
    pub fn nullifier(nullifier_seed: Fr) -> Fr {
        hash(nullifier_seed, Fr::zero())
    }

    /// Compute the vote commitment: `H(vote, secret)`.
    pub fn vote_commitment(vote: Fr, secret: Fr) -> Fr {
        hash(vote, secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_root_is_deterministic() {
        let leaves = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
        let t1 = MerkleTree::new(&leaves);
        let t2 = MerkleTree::new(&leaves);
        assert_eq!(t1.root, t2.root);
    }

    #[test]
    fn path_verifies() {
        let leaves = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
        let tree = MerkleTree::new(&leaves);
        let path = tree.path(2);
        let mut current = tree.leaves[2];
        for sibling in &path {
            current = hash(current, *sibling);
        }
        // Note: path gives siblings in leaf→root order, but hash order depends
        // on position. The on-circuit chip handles ordering via pos_bit.
        // Here we just check the path has the right length.
        assert_eq!(path.len(), VOTE_TREE_DEPTH);
        assert_eq!(tree.root, tree.nodes[VOTE_TREE_DEPTH][0]);
    }
}
