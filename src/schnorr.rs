use crate::ecmult::ECMultContext;
use crate::field::Field;
use crate::group::{Affine, Jacobian};
use crate::{util, Error, Message, PublicKey, Scalar, ECMULT_CONTEXT};
use digest::{Digest, Input};
use sha2::Sha256;

/// A Schnorr signature.
pub struct SchnorrSignature {
    pub r: Scalar,
    pub s: Scalar,
}

impl SchnorrSignature {
    pub fn parse(p: &[u8; util::SIGNATURE_SIZE]) -> SchnorrSignature {
        let mut r = Scalar::default();
        let mut s = Scalar::default();

        // TODO: Okay for signature to overflow?
        let _ = r.set_b32(array_ref!(p, 0, 32));
        let _ = s.set_b32(array_ref!(p, 32, 32));

        SchnorrSignature { r, s }
    }

    pub fn parse_slice(p: &[u8]) -> Result<SchnorrSignature, Error> {
        if p.len() != util::SIGNATURE_SIZE {
            return Err(Error::InvalidInputLength);
        }

        let mut a = [0; util::SIGNATURE_SIZE];
        a.copy_from_slice(p);
        Ok(Self::parse(&a))
    }
}

impl ECMultContext {
    pub fn verify_raw_schnorr(&self,
                              sigr: &Scalar,
                              sigs: &Scalar,
                              pubkey: &Affine,
                              e: &Scalar) 
                              -> bool {
        let mut rx = Field::default();
        // TODO: check sigr < p, sigs < n?
        let _ = rx.set_b32(&sigr.b32());

        let nege = e.neg();
        let mut pubkeyj: Jacobian = Jacobian::default();
        pubkeyj.set_ge(pubkey);
        let mut rj: Jacobian = Jacobian::default();
        self.ecmult(&mut rj, &pubkeyj, &nege, &sigs);
        // TODO: does it check jacobi(y(R)) == 1 where jacobi is the Jacobi symbol of x / p?
        if rj.has_quad_y_var() // checks rj.is_infinity()
        && rj.eq_x_var(&rx) {
            return true;
        }
        return false;
    }
}

/// Check signature is a valid message signed by public key.
pub fn schnorr_verify(message: &Message, signature: &SchnorrSignature, pubkey: &PublicKey) -> bool {
    let pk = pubkey.serialize_compressed();
    let mut sha = Sha256::default();
    sha.process(&signature.r.b32());
    sha.process(&pk);
    sha.process(&message.0.b32());
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&sha.result()[..]);
    let mut e = Scalar::default();
    let _ = e.set_b32(&buf);
    ECMULT_CONTEXT.verify_raw_schnorr(&signature.r, &signature.s, &pubkey.0, &e)
}
