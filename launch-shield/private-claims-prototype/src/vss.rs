//! Test-only Feldman share-consistency model.
//!
//! This models polynomial commitments and share verification in one process.
//! It has no authenticated transport, complaint protocol, transcript binding,
//! or malicious-secure distributed inversion, so it is not a DKG.

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::Identity,
};
use solana_zk_sdk::encryption::pedersen::G;

struct DealerPolynomial {
    constant: Scalar,
    slope: Scalar,
}

impl DealerPolynomial {
    fn new(constant: Scalar, slope: Scalar) -> Self {
        Self { constant, slope }
    }

    fn share_at(&self, recipient_id: u64) -> Scalar {
        self.constant + self.slope * Scalar::from(recipient_id)
    }

    fn commitment(&self) -> PolynomialCommitment {
        PolynomialCommitment {
            constant: *G * self.constant,
            slope: *G * self.slope,
        }
    }
}

struct PolynomialCommitment {
    constant: RistrettoPoint,
    slope: RistrettoPoint,
}

impl PolynomialCommitment {
    fn sum(commitments: &[Self]) -> Option<Self> {
        if commitments.is_empty() {
            return None;
        }

        let mut constant = RistrettoPoint::identity();
        let mut slope = RistrettoPoint::identity();
        for commitment in commitments {
            constant += commitment.constant;
            slope += commitment.slope;
        }

        Some(Self { constant, slope })
    }
}

fn verify_share(
    commitment: &PolynomialCommitment,
    recipient_id: u64,
    share: Scalar,
) -> bool {
    recipient_id != 0
        && *G * share
            == commitment.constant + commitment.slope * Scalar::from(recipient_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dealers() -> [DealerPolynomial; 3] {
        [
            DealerPolynomial::new(Scalar::from(11u64), Scalar::from(5u64)),
            DealerPolynomial::new(Scalar::from(22u64), Scalar::from(7u64)),
            DealerPolynomial::new(Scalar::from(33u64), Scalar::from(9u64)),
        ]
    }

    #[test]
    fn combined_shares_match_the_joint_feldman_commitment() {
        let dealers = sample_dealers();
        let commitments = dealers
            .iter()
            .map(DealerPolynomial::commitment)
            .collect::<Vec<_>>();
        let joint_commitment =
            PolynomialCommitment::sum(&commitments).expect("three dealer commitments");
        let expected_secret =
            Scalar::from(11u64) + Scalar::from(22u64) + Scalar::from(33u64);

        assert_eq!(joint_commitment.constant, *G * expected_secret);
        assert_ne!(joint_commitment.constant, RistrettoPoint::identity());

        for recipient_id in 1..=3 {
            let combined_share = dealers
                .iter()
                .map(|dealer| dealer.share_at(recipient_id))
                .sum::<Scalar>();
            assert!(verify_share(
                &joint_commitment,
                recipient_id,
                combined_share
            ));
        }
    }

    #[test]
    fn invalid_or_zero_index_shares_are_rejected() {
        let dealer = DealerPolynomial::new(Scalar::from(19u64), Scalar::from(23u64));
        let commitment = dealer.commitment();
        let valid_share = dealer.share_at(2);

        assert!(verify_share(&commitment, 2, valid_share));
        assert!(!verify_share(
            &commitment,
            2,
            valid_share + Scalar::ONE
        ));
        assert!(!verify_share(&commitment, 0, dealer.share_at(0)));
    }

    #[test]
    fn altered_public_commitment_is_detected_by_share_verification() {
        let dealer = DealerPolynomial::new(Scalar::from(19u64), Scalar::from(23u64));
        let mut commitment = dealer.commitment();
        commitment.constant += *G;

        assert!(!verify_share(&commitment, 2, dealer.share_at(2)));
    }

    #[test]
    fn zero_joint_secret_is_visible_as_the_identity_commitment() {
        let dealers = [
            DealerPolynomial::new(Scalar::from(11u64), Scalar::from(5u64)),
            DealerPolynomial::new(Scalar::from(22u64), Scalar::from(7u64)),
            DealerPolynomial::new(-Scalar::from(33u64), Scalar::from(9u64)),
        ];
        let commitments = dealers
            .iter()
            .map(DealerPolynomial::commitment)
            .collect::<Vec<_>>();
        let joint_commitment =
            PolynomialCommitment::sum(&commitments).expect("three dealer commitments");

        assert_eq!(joint_commitment.constant, RistrettoPoint::identity());
    }
}