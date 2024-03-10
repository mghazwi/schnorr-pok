
// To prove knowledge of 2 discrete logs, i.e. given public `y1`, `y2`, `a1`, `a2`, `b1` and `b2`, prove knowledge of `x1` and `x2` such that `a1 * x1 + a2 * x2 = y1` and b1 * x1 + b2 * x2 = y2.
// 1. Prover chooses 2 random `r1` and `r2` and computes `t1 = a1 * r1 + a2 * r2`, `t2 = b1 * r1 + b2 * r2`
// 2. Hashes `t1` and `t2` towards getting a challenge `c`.
// 3. Computes 2 responses `s1 = r1 + c*x1` and `s2 = r2 + c*x2` and sends them to the verifier.
// 4. Verifier checks if `a1 * s1 + a2 * s2 = t1 + y*c` AND `b1 * s1 + b2 * s2 = t2 + y*c`

use crate::error::SchnorrError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, vec::Vec};
use crate::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Protocol for proving knowledge of 2 discrete logs
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct PokProtocol<G: AffineRepr> {
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub t1: G,
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub t2: G,
    #[serde_as(as = "ArkObjectBytes")]
    blinding1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    witness1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    blinding2: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    witness2: G::ScalarField,
}

// Proof of knowledge of 2 discrete logs
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PokProof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t1: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub t2: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub response1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub response2: G::ScalarField,
}

impl<G: AffineRepr> PokProtocol<G> {
    pub fn init(
        witness1: G::ScalarField,
        blinding1: G::ScalarField,
        a1: &G,
        a2: &G,
        witness2: G::ScalarField,
        blinding2: G::ScalarField,
        b1: &G,
        b2: &G,
    ) -> Self {
        let t1 = (a1.mul_bigint(blinding1.into_bigint())
            + a2.mul_bigint(blinding2.into_bigint()))
            .into_affine();
        let t2 = (b1.mul_bigint(blinding1.into_bigint())
            + b2.mul_bigint(blinding2.into_bigint()))
            .into_affine();
        Self {
            t1,
            t2,
            blinding1,
            witness1,
            blinding2,
            witness2,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        a1: &G,
        a2: &G,
        b1: &G,
        b2: &G,
        y1: &G,
        y2: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        Self::compute_challenge_contribution(a1, a2, b1, b2, y1, y2, &self.t1, &self.t2, writer)
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> PokProof<G> {
        let response1 = self.blinding1 + (self.witness1 * *challenge);
        let response2 = self.blinding2 + (self.witness2 * *challenge);
        PokProof {
            t1: self.t1,
            t2: self.t2,
            response1,
            response2,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        a1: &G,
        a2: &G,
        b1: &G,
        b2: &G,
        y1: &G,
        y2: &G,
        t1: &G,
        t2: &G,
        mut writer: W,
    ) -> Result<(), SchnorrError> {
        a1.serialize_compressed(&mut writer)?;
        a2.serialize_compressed(&mut writer)?;
        b1.serialize_compressed(&mut writer)?;
        b2.serialize_compressed(&mut writer)?;
        y1.serialize_compressed(&mut writer)?;
        y2.serialize_compressed(&mut writer)?;
        t1.serialize_compressed(&mut writer)?;
        t2.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<G: AffineRepr> PokProof<G> {
    pub fn challenge_contribution<W: Write>(
        &self,
        a1: &G,
        a2: &G,
        b1: &G,
        b2: &G,
        y1: &G,
        y2: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokProtocol::compute_challenge_contribution(a1, a2, b1, b2, y1, y2, &self.t1, &self.t2, writer)
    }

    // `base1*response1 + base2*response2 - y*challenge == t`
    pub fn verify(
        &self, 
        y1: &G,
        y2: &G, 
        a1: &G, 
        a2: &G, 
        b1: &G, 
        b2: &G, 
        challenge: &G::ScalarField
    ) -> bool {
        let mut expected = a1.mul_bigint(self.response1.into_bigint());
        expected += a2.mul_bigint(self.response2.into_bigint());
        expected -= y1.mul_bigint(challenge.into_bigint());
        let result1 = expected.into_affine() == self.t1;
        // print!("result 1: {}", result1);
        
        let mut expected2 = b1.mul_bigint(self.response1.into_bigint());
        expected2 += b2.mul_bigint(self.response2.into_bigint());
        expected2 -= y2.mul_bigint(challenge.into_bigint());
        let result2 = expected2.into_affine() == self.t2;
        // print!("result 2: {}", result2);
        result1 && result2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{schnorr::compute_random_oracle_challenge, test_serialization};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn pok2equality() {
        let mut rng = StdRng::seed_from_u64(0u64);

        macro_rules! check {
            ($group_affine:ident, $group_projective:ident) => {
                // private values 
                let witness1 = Fr::rand(&mut rng);
                let witness2 = Fr::rand(&mut rng);
                let blinding1 = Fr::rand(&mut rng);
                let blinding2 = Fr::rand(&mut rng);
                // public values 
                let a1 = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
                let a2 = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
                let b1 = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
                let b2 = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
                let y1 = (a1 * witness1 + a2 * witness2).into_affine();
                let y2 = (b1 * witness1 + b2 * witness2).into_affine();

                // PROVER part
                let protocol =
                    PokProtocol::<<Bls12_381 as Pairing>::$group_affine>::init(
                        witness1, blinding1, &a1, &a2, witness2, blinding2, &b1, &b2
                    );
                let mut chal_contrib_prover = vec![];
                protocol
                    .challenge_contribution(&a1, &a2, &b1, &b2, &y1, &y2, &mut chal_contrib_prover)
                    .unwrap();
                let challenge_prover =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);
                let proof = protocol.clone().gen_proof(&challenge_prover);

                // VERIFIER part
                let mut chal_contrib_verifier = vec![];
                proof
                    .challenge_contribution(&a1, &a2, &b1, &b2, &y1, &y2, &mut chal_contrib_verifier)
                    .unwrap();

                let challenge_verifier =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);

                assert!(proof.verify(&y1, &y2, &a1, &a2, &b1, &b2, &challenge_verifier));

                // sanity check
                assert_eq!(chal_contrib_prover, chal_contrib_verifier);
                assert_eq!(challenge_prover, challenge_verifier);
            };
        }

        check!(G1Affine, G1);
        check!(G2Affine, G2);
    }
}