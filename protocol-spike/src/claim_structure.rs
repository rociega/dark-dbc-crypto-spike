//! Fixed-capacity claim data structures for host-side invariant tests.
//!
//! This module only constructs and checks ordinary Merkle paths and models
//! eight nullifier slots. It does not choose the production hash, create or
//! verify a zero-knowledge proof, authenticate a claimant, or transfer assets.

use crate::MAX_BIDS;

pub const CLAIM_TREE_DEPTH: usize = 3;
pub const CLAIM_TREE_CAPACITY: usize = 1 << CLAIM_TREE_DEPTH;
pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimStructureError {
    EmptyTree,
    TooManyLeaves,
    InvalidLeafIndex,
    DuplicateNullifier,
    NullifierRegistryFull,
    NullifierNotRegistered,
    NullifierAlreadySpent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleWitness {
    /// The leaf position. A production claim proof must keep this private.
    pub index: usize,
    /// The public registered-leaf count used to reject padded empty leaves.
    pub leaf_count: usize,
    /// Siblings from the leaf level up to the root.
    pub siblings: [Digest; CLAIM_TREE_DEPTH],
}

/// A depth-three Merkle tree over already-hashed note commitments.
///
/// The caller supplies the leaf hash, empty-leaf value, and pair hash. This
/// keeps the host structure independent of the eventual circuit-compatible
/// hash choice. The root alone does not bind `leaf_count`; callers must retain
/// and validate the count alongside the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedDepthMerkleTree {
    leaf_count: usize,
    levels: Vec<Vec<Digest>>,
}

impl FixedDepthMerkleTree {
    pub fn new(
        leaves: &[Digest],
        empty_leaf: Digest,
        mut hash_pair: impl FnMut(&Digest, &Digest) -> Digest,
    ) -> Result<Self, ClaimStructureError> {
        if leaves.is_empty() {
            return Err(ClaimStructureError::EmptyTree);
        }
        if leaves.len() > CLAIM_TREE_CAPACITY || leaves.len() > MAX_BIDS {
            return Err(ClaimStructureError::TooManyLeaves);
        }

        let mut leaf_level = vec![empty_leaf; CLAIM_TREE_CAPACITY];
        leaf_level[..leaves.len()].copy_from_slice(leaves);
        let mut levels = vec![leaf_level];

        for _ in 0..CLAIM_TREE_DEPTH {
            let previous = levels.last().expect("leaf level is always present");
            let next = previous
                .chunks_exact(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }

        Ok(Self {
            leaf_count: leaves.len(),
            levels,
        })
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn root(&self) -> &Digest {
        &self.levels[CLAIM_TREE_DEPTH][0]
    }

    pub fn witness(&self, index: usize) -> Result<MerkleWitness, ClaimStructureError> {
        if index >= self.leaf_count {
            return Err(ClaimStructureError::InvalidLeafIndex);
        }

        let mut siblings = [[0; 32]; CLAIM_TREE_DEPTH];
        let mut position = index;
        for (level, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.levels[level][position ^ 1];
            position >>= 1;
        }

        Ok(MerkleWitness {
            index,
            leaf_count: self.leaf_count,
            siblings,
        })
    }
}

/// Checks a transparent host-side path. This is not a zero-knowledge proof:
/// callers of a production claim instruction must prove membership without
/// publishing `witness.index` or its sibling path.
pub fn verify_merkle_witness(
    leaf: &Digest,
    witness: &MerkleWitness,
    registered_leaf_count: usize,
    expected_root: &Digest,
    mut hash_pair: impl FnMut(&Digest, &Digest) -> Digest,
) -> bool {
    if registered_leaf_count == 0
        || registered_leaf_count > CLAIM_TREE_CAPACITY
        || registered_leaf_count > MAX_BIDS
        || witness.leaf_count != registered_leaf_count
        || witness.index >= registered_leaf_count
    {
        return false;
    }

    let mut current = *leaf;
    let mut position = witness.index;
    for sibling in witness.siblings {
        current = if position & 1 == 0 {
            hash_pair(&current, &sibling)
        } else {
            hash_pair(&sibling, &current)
        };
        position >>= 1;
    }

    &current == expected_root
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullifierStatus {
    Registered,
    Spent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NullifierEntry {
    value: Digest,
    status: NullifierStatus,
}

/// Host-side model of the fixed eight-slot registration/spend state.
///
/// It validates uniqueness and one-time state transitions only. It does not
/// derive a nullifier from a secret or prove that the caller owns its note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierRegistry {
    entries: [Option<NullifierEntry>; MAX_BIDS],
    len: usize,
}

impl Default for NullifierRegistry {
    fn default() -> Self {
        Self {
            entries: [None; MAX_BIDS],
            len: 0,
        }
    }
}

impl NullifierRegistry {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn status(&self, nullifier: &Digest) -> Option<NullifierStatus> {
        self.entries[..self.len]
            .iter()
            .flatten()
            .find(|entry| &entry.value == nullifier)
            .map(|entry| entry.status)
    }

    pub fn register(&mut self, nullifier: Digest) -> Result<(), ClaimStructureError> {
        if self.status(&nullifier).is_some() {
            return Err(ClaimStructureError::DuplicateNullifier);
        }
        if self.len == MAX_BIDS {
            return Err(ClaimStructureError::NullifierRegistryFull);
        }

        self.entries[self.len] = Some(NullifierEntry {
            value: nullifier,
            status: NullifierStatus::Registered,
        });
        self.len += 1;
        Ok(())
    }

    pub fn mark_spent(&mut self, nullifier: &Digest) -> Result<(), ClaimStructureError> {
        let Some(entry) = self.entries[..self.len]
            .iter_mut()
            .flatten()
            .find(|entry| &entry.value == nullifier)
        else {
            return Err(ClaimStructureError::NullifierNotRegistered);
        };

        if entry.status == NullifierStatus::Spent {
            return Err(ClaimStructureError::NullifierAlreadySpent);
        }
        entry.status = NullifierStatus::Spent;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn test_leaf(value: u8) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"dark-dbc-test-leaf-v1");
        hasher.update([value]);
        hasher.finalize().into()
    }

    fn test_hash_pair(left: &Digest, right: &Digest) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"dark-dbc-test-node-v1");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    #[test]
    fn all_eight_leaves_have_three_level_membership_witnesses() {
        let leaves: Vec<_> = (0..CLAIM_TREE_CAPACITY as u8).map(test_leaf).collect();
        let tree = FixedDepthMerkleTree::new(&leaves, [0xff; 32], test_hash_pair).unwrap();
        let root = *tree.root();

        assert_eq!(tree.leaf_count(), MAX_BIDS);
        for (index, leaf) in leaves.iter().enumerate() {
            let witness = tree.witness(index).unwrap();
            assert_eq!(witness.siblings.len(), CLAIM_TREE_DEPTH);
            assert!(verify_merkle_witness(
                leaf,
                &witness,
                tree.leaf_count(),
                &root,
                test_hash_pair
            ));

            let mut altered_leaf = *leaf;
            altered_leaf[0] ^= 1;
            assert!(!verify_merkle_witness(
                &altered_leaf,
                &witness,
                tree.leaf_count(),
                &root,
                test_hash_pair
            ));
        }
    }

    #[test]
    fn partial_tree_rejects_padded_leaf_and_mutated_path() {
        let leaves = [test_leaf(1), test_leaf(2), test_leaf(3)];
        let tree = FixedDepthMerkleTree::new(&leaves, [0xff; 32], test_hash_pair).unwrap();
        let root = *tree.root();
        let witness = tree.witness(2).unwrap();

        assert!(verify_merkle_witness(
            &leaves[2],
            &witness,
            tree.leaf_count(),
            &root,
            test_hash_pair
        ));
        assert_eq!(tree.witness(3), Err(ClaimStructureError::InvalidLeafIndex));

        let mut wrong_index = witness.clone();
        wrong_index.index = 1;
        assert!(!verify_merkle_witness(
            &leaves[2],
            &wrong_index,
            tree.leaf_count(),
            &root,
            test_hash_pair
        ));

        let mut wrong_sibling = witness;
        wrong_sibling.siblings[0][0] ^= 1;
        assert!(!verify_merkle_witness(
            &leaves[2],
            &wrong_sibling,
            tree.leaf_count(),
            &root,
            test_hash_pair
        ));
    }

    #[test]
    fn membership_rejects_leaf_count_that_differs_from_registered_state() {
        let leaves = [test_leaf(1), test_leaf(2), test_leaf(3)];
        let tree = FixedDepthMerkleTree::new(&leaves, [0xff; 32], test_hash_pair).unwrap();
        let root = *tree.root();
        let mut witness = tree.witness(2).unwrap();
        witness.leaf_count = CLAIM_TREE_CAPACITY;

        assert!(!verify_merkle_witness(
            &leaves[2],
            &witness,
            tree.leaf_count(),
            &root,
            test_hash_pair
        ));
    }

    #[test]
    fn tree_enforces_the_nonempty_eight_leaf_capacity() {
        assert_eq!(
            FixedDepthMerkleTree::new(&[], [0; 32], test_hash_pair),
            Err(ClaimStructureError::EmptyTree)
        );
        assert_eq!(
            FixedDepthMerkleTree::new(&[[1; 32]; CLAIM_TREE_CAPACITY + 1], [0; 32], test_hash_pair),
            Err(ClaimStructureError::TooManyLeaves)
        );
    }

    #[test]
    fn nullifier_registry_enforces_unique_registration_and_single_spend() {
        let mut registry = NullifierRegistry::default();
        let registered = [1; 32];
        let unknown = [2; 32];

        assert!(registry.is_empty());
        registry.register(registered).unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.status(&registered),
            Some(NullifierStatus::Registered)
        );
        assert_eq!(
            registry.register(registered),
            Err(ClaimStructureError::DuplicateNullifier)
        );
        assert_eq!(
            registry.mark_spent(&unknown),
            Err(ClaimStructureError::NullifierNotRegistered)
        );

        registry.mark_spent(&registered).unwrap();
        assert_eq!(registry.status(&registered), Some(NullifierStatus::Spent));
        assert_eq!(
            registry.mark_spent(&registered),
            Err(ClaimStructureError::NullifierAlreadySpent)
        );
    }

    #[test]
    fn nullifier_registry_caps_unique_entries_at_eight() {
        let mut registry = NullifierRegistry::default();
        for value in 0..MAX_BIDS as u8 {
            registry.register(test_leaf(value)).unwrap();
        }

        assert_eq!(registry.len(), MAX_BIDS);
        assert_eq!(
            registry.register(test_leaf(MAX_BIDS as u8)),
            Err(ClaimStructureError::NullifierRegistryFull)
        );
        assert_eq!(registry.len(), MAX_BIDS);
    }
}
