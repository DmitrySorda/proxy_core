//! Simple Password-Hardened Encryption Services (PHE) on P-256.
//!
//! This module follows the lecture flow:
//! - Server creates enrollment material from `sNonce` and private key `y`
//! - Backend mixes password + `cNonce` with client private key `x`
//! - Stored record is `T0 = C0 + HC0`, `T1 = C1 + HC1 + MC`
//! - Login reconstructs `C0 = T0 - HC0`, server validates, returns `C1`
//! - Backend recovers `MC = T1 - C1 - HC1` and derives encryption key
//! - Rotation updates DB using `sNonce` only (no password required)

use hkdf::Hkdf;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{NistP256, ProjectivePoint, Scalar};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const H2C_SERVER_DST: &[u8] = b"PHE-V1-server-h2c";
const H2C_CLIENT_DST: &[u8] = b"PHE-V1-client-h2c";
const H2S_DST: &[u8] = b"PHE-V1-proof-h2s";
const PROOF_DST: &[u8] = b"PHE-V1-schnorr-proof";
const ENC_KEY_INFO: &[u8] = b"PHE-V1-encryption-key";
const AES_KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum PheError {
    HashToCurve(String),
    InvalidProof,
    WrongPassword,
    InvalidPoint(String),
    InvalidScalar(String),
    KeyDerivation(String),
}

impl std::fmt::Display for PheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashToCurve(e) => write!(f, "hash-to-curve failed: {e}"),
            Self::InvalidProof => write!(f, "Schnorr proof verification failed"),
            Self::WrongPassword => write!(f, "password verification failed"),
            Self::InvalidPoint(e) => write!(f, "invalid point: {e}"),
            Self::InvalidScalar(e) => write!(f, "invalid scalar: {e}"),
            Self::KeyDerivation(e) => write!(f, "key derivation failed: {e}"),
        }
    }
}

impl std::error::Error for PheError {}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey([u8; AES_KEY_LEN]);

impl EncryptionKey {
    pub fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptionKey(***)")
    }
}

impl PartialEq for EncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for EncryptionKey {}

#[derive(Debug, Clone)]
pub struct PheRecord {
    pub t0: ProjectivePoint,
    pub t1: ProjectivePoint,
    pub server_salt: [u8; 32],
    pub client_salt: [u8; 32],
}

impl PheRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(130);
        out.extend_from_slice(self.t0.to_affine().to_encoded_point(true).as_bytes());
        out.extend_from_slice(self.t1.to_affine().to_encoded_point(true).as_bytes());
        out.extend_from_slice(&self.server_salt);
        out.extend_from_slice(&self.client_salt);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PheError> {
        if data.len() != 130 {
            return Err(PheError::InvalidPoint(format!(
                "record must be 130 bytes, got {}",
                data.len()
            )));
        }

        let t0 = decode_point(&data[0..33])?;
        let t1 = decode_point(&data[33..66])?;

        let mut server_salt = [0u8; 32];
        server_salt.copy_from_slice(&data[66..98]);

        let mut client_salt = [0u8; 32];
        client_salt.copy_from_slice(&data[98..130]);

        Ok(Self {
            t0,
            t1,
            server_salt,
            client_salt,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SchnorrProof {
    pub commitment: ProjectivePoint,
    pub challenge: Scalar,
    pub response: Scalar,
}

#[derive(Debug, Clone)]
pub struct EnrollmentResponse {
    pub server_salt: [u8; 32],
    pub c0: ProjectivePoint,
    pub c1: ProjectivePoint,
    pub proof_c0: SchnorrProof,
    pub proof_c1: SchnorrProof,
}

#[derive(Debug, Clone)]
pub struct VerifyResponse {
    pub success: bool,
    pub c1: Option<ProjectivePoint>,
    pub proof_c1: Option<SchnorrProof>,
}

#[derive(Debug, Clone)]
pub struct UpdateToken {
    pub delta: Scalar,
}

pub struct PheServer {
    private_key: Scalar,
    public_key: ProjectivePoint,
}

impl PheServer {
    pub fn new() -> Self {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = ProjectivePoint::GENERATOR * private_key;
        Self {
            private_key,
            public_key,
        }
    }

    pub fn from_scalar(private_key: Scalar) -> Self {
        let public_key = ProjectivePoint::GENERATOR * private_key;
        Self {
            private_key,
            public_key,
        }
    }

    pub fn from_bytes(key_bytes: &[u8; 32]) -> Result<Self, PheError> {
        let scalar = decode_scalar(key_bytes)?;
        Ok(Self::from_scalar(scalar))
    }

    pub fn public_key(&self) -> ProjectivePoint {
        self.public_key
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        let repr = self.private_key.to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(repr.as_slice());
        out
    }

    pub fn enrollment_material(&self) -> Result<EnrollmentResponse, PheError> {
        let server_salt = random_salt();
        let s0 = server_base_point(&server_salt, 0)?;
        let s1 = server_base_point(&server_salt, 1)?;

        let c0 = s0 * self.private_key;
        let c1 = s1 * self.private_key;

        let proof_c0 = self.prove_dlog_eq(s0, c0);
        let proof_c1 = self.prove_dlog_eq(s1, c1);

        Ok(EnrollmentResponse {
            server_salt,
            c0,
            c1,
            proof_c0,
            proof_c1,
        })
    }

    pub fn verify_c0(
        &self,
        server_salt: &[u8; 32],
        candidate_c0: ProjectivePoint,
    ) -> Result<VerifyResponse, PheError> {
        let s0 = server_base_point(server_salt, 0)?;
        let s1 = server_base_point(server_salt, 1)?;

        let expected_c0 = s0 * self.private_key;
        let expected_c1 = s1 * self.private_key;

        let is_match: bool = point_bytes(expected_c0)
            .ct_eq(&point_bytes(candidate_c0))
            .into();

        if is_match {
            let proof_c1 = self.prove_dlog_eq(s1, expected_c1);
            Ok(VerifyResponse {
                success: true,
                c1: Some(expected_c1),
                proof_c1: Some(proof_c1),
            })
        } else {
            Ok(VerifyResponse {
                success: false,
                c1: None,
                proof_c1: None,
            })
        }
    }

    pub fn rotate(&self, new_key: &Scalar) -> UpdateToken {
        UpdateToken {
            delta: *new_key - self.private_key,
        }
    }

    fn prove_dlog_eq(&self, base: ProjectivePoint, result: ProjectivePoint) -> SchnorrProof {
        let k = Scalar::random(&mut OsRng);
        let r1 = ProjectivePoint::GENERATOR * k;
        let r2 = base * k;

        let challenge = schnorr_challenge(
            r1,
            r2,
            ProjectivePoint::GENERATOR,
            self.public_key,
            base,
            result,
        );

        let response = k + challenge * self.private_key;

        SchnorrProof {
            commitment: r1,
            challenge,
            response,
        }
    }
}

impl Drop for PheServer {
    fn drop(&mut self) {
        self.private_key = Scalar::ZERO;
    }
}

pub struct PheClient {
    client_key: Scalar,
    server_public_key: ProjectivePoint,
}

impl PheClient {
    pub fn new(server_public_key: ProjectivePoint) -> Self {
        let client_key = Scalar::random(&mut OsRng);
        Self {
            client_key,
            server_public_key,
        }
    }

    pub fn from_scalar(client_key: Scalar, server_public_key: ProjectivePoint) -> Self {
        Self {
            client_key,
            server_public_key,
        }
    }

    pub fn client_key_bytes(&self) -> [u8; 32] {
        let repr = self.client_key.to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(repr.as_slice());
        out
    }

    pub fn enroll(
        &self,
        password: &[u8],
        server_response: &EnrollmentResponse,
    ) -> Result<(PheRecord, EncryptionKey), PheError> {
        let s0 = server_base_point(&server_response.server_salt, 0)?;
        let s1 = server_base_point(&server_response.server_salt, 1)?;

        verify_schnorr_proof(
            &server_response.proof_c0,
            ProjectivePoint::GENERATOR,
            self.server_public_key,
            s0,
            server_response.c0,
        )?;

        verify_schnorr_proof(
            &server_response.proof_c1,
            ProjectivePoint::GENERATOR,
            self.server_public_key,
            s1,
            server_response.c1,
        )?;

        let client_salt = random_salt();
        let hc0 = self.password_hardened_component(password, &client_salt, 0)?;
        let hc1 = self.password_hardened_component(password, &client_salt, 1)?;

        // M: random 32-byte scalar, MC = (G*M) * x
        let m = Scalar::random(&mut OsRng);
        let m_point = ProjectivePoint::GENERATOR * m;
        let mc = m_point * self.client_key;

        let t0 = server_response.c0 + hc0;
        let t1 = server_response.c1 + hc1 + mc;

        let record = PheRecord {
            t0,
            t1,
            server_salt: server_response.server_salt,
            client_salt,
        };

        let key = derive_encryption_key(mc)?;
        Ok((record, key))
    }

    pub fn verify(
        &self,
        password: &[u8],
        record: &PheRecord,
        server_response: &VerifyResponse,
    ) -> Result<EncryptionKey, PheError> {
        if !server_response.success {
            return Err(PheError::WrongPassword);
        }

        let c1 = server_response
            .c1
            .ok_or_else(|| PheError::InvalidPoint("missing C1 in successful verify".into()))?;
        let proof_c1 = server_response
            .proof_c1
            .as_ref()
            .ok_or(PheError::InvalidProof)?;

        let s1 = server_base_point(&record.server_salt, 1)?;
        verify_schnorr_proof(
            proof_c1,
            ProjectivePoint::GENERATOR,
            self.server_public_key,
            s1,
            c1,
        )?;

        let hc1 = self.password_hardened_component(password, &record.client_salt, 1)?;

        // MC = T1 - C1 - HC1
        let mc = record.t1 - c1 - hc1;
        derive_encryption_key(mc)
    }

    pub fn recover_c0(
        &self,
        password: &[u8],
        record: &PheRecord,
    ) -> Result<ProjectivePoint, PheError> {
        let hc0 = self.password_hardened_component(password, &record.client_salt, 0)?;
        Ok(record.t0 - hc0)
    }

    pub fn update_record(
        &self,
        record: &PheRecord,
        token: &UpdateToken,
    ) -> Result<PheRecord, PheError> {
        let s0 = server_base_point(&record.server_salt, 0)?;
        let s1 = server_base_point(&record.server_salt, 1)?;

        // Update server contribution only; does not require password.
        let t0_new = record.t0 + s0 * token.delta;
        let t1_new = record.t1 + s1 * token.delta;

        Ok(PheRecord {
            t0: t0_new,
            t1: t1_new,
            server_salt: record.server_salt,
            client_salt: record.client_salt,
        })
    }

    fn password_hardened_component(
        &self,
        password: &[u8],
        client_salt: &[u8; 32],
        slot: u8,
    ) -> Result<ProjectivePoint, PheError> {
        let p = client_password_base_point(password, client_salt, slot)?;
        Ok(p * self.client_key)
    }
}

impl Drop for PheClient {
    fn drop(&mut self) {
        self.client_key = Scalar::ZERO;
    }
}

use p256::elliptic_curve::rand_core::{OsRng, RngCore};

fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn server_base_point(server_salt: &[u8; 32], slot: u8) -> Result<ProjectivePoint, PheError> {
    let mut msg = Vec::with_capacity(33);
    msg.extend_from_slice(server_salt);
    msg.push(slot);
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&msg], &[H2C_SERVER_DST])
        .map_err(|e| PheError::HashToCurve(format!("server base: {e}")) )
}

fn client_password_base_point(
    password: &[u8],
    client_salt: &[u8; 32],
    slot: u8,
) -> Result<ProjectivePoint, PheError> {
    let mut msg = Vec::with_capacity(client_salt.len() + password.len() + 1);
    msg.extend_from_slice(client_salt);
    msg.extend_from_slice(password);
    msg.push(slot);
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&msg], &[H2C_CLIENT_DST])
        .map_err(|e| PheError::HashToCurve(format!("client base: {e}")))
}

fn derive_encryption_key(point: ProjectivePoint) -> Result<EncryptionKey, PheError> {
    let encoded = point.to_affine().to_encoded_point(true);
    let hk = Hkdf::<Sha256>::new(None, encoded.as_bytes());

    let mut key = [0u8; AES_KEY_LEN];
    hk.expand(ENC_KEY_INFO, &mut key)
        .map_err(|e| PheError::KeyDerivation(format!("HKDF expand: {e}")))?;

    Ok(EncryptionKey(key))
}

fn schnorr_challenge(
    r1: ProjectivePoint,
    r2: ProjectivePoint,
    g: ProjectivePoint,
    public_key: ProjectivePoint,
    base: ProjectivePoint,
    result: ProjectivePoint,
) -> Scalar {
    let mut transcript = Vec::with_capacity(6 * 33 + PROOF_DST.len());
    transcript.extend_from_slice(point_bytes(r1).as_slice());
    transcript.extend_from_slice(point_bytes(r2).as_slice());
    transcript.extend_from_slice(point_bytes(g).as_slice());
    transcript.extend_from_slice(point_bytes(public_key).as_slice());
    transcript.extend_from_slice(point_bytes(base).as_slice());
    transcript.extend_from_slice(point_bytes(result).as_slice());
    transcript.extend_from_slice(PROOF_DST);
    hash_to_scalar(&transcript)
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hk = Hkdf::<Sha256>::new(Some(H2S_DST), data);
    let mut repr = [0u8; 32];
    hk.expand(b"scalar", &mut repr)
        .expect("HKDF scalar derivation must succeed");

    let opt: Option<Scalar> = Scalar::from_repr(p256::FieldBytes::from(repr)).into();
    opt.unwrap_or_else(|| {
        let hk2 = Hkdf::<Sha256>::new(Some(H2S_DST), &repr);
        let mut repr2 = [0u8; 32];
        hk2.expand(b"scalar-retry", &mut repr2)
            .expect("HKDF scalar retry must succeed");
        repr2[0] &= 0x7F;
        Scalar::from_repr(p256::FieldBytes::from(repr2))
            .into_option()
            .expect("masked scalar must be valid")
    })
}

fn verify_schnorr_proof(
    proof: &SchnorrProof,
    generator: ProjectivePoint,
    public_key: ProjectivePoint,
    base: ProjectivePoint,
    result: ProjectivePoint,
) -> Result<(), PheError> {
    let r1_check = generator * proof.response - public_key * proof.challenge;
    let r2_check = base * proof.response - result * proof.challenge;

    let e_check = schnorr_challenge(
        r1_check,
        r2_check,
        generator,
        public_key,
        base,
        result,
    );

    if proof
        .challenge
        .to_repr()
        .ct_eq(&e_check.to_repr())
        .into()
    {
        Ok(())
    } else {
        Err(PheError::InvalidProof)
    }
}

fn decode_point(data: &[u8]) -> Result<ProjectivePoint, PheError> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    let encoded = p256::EncodedPoint::from_bytes(data)
        .map_err(|e| PheError::InvalidPoint(format!("bad SEC1 encoding: {e}")))?;
    let affine: Option<p256::AffinePoint> = p256::AffinePoint::from_encoded_point(&encoded).into();
    affine
        .map(ProjectivePoint::from)
        .ok_or_else(|| PheError::InvalidPoint("point not on curve".into()))
}

fn decode_scalar(data: &[u8; 32]) -> Result<Scalar, PheError> {
    let opt: Option<Scalar> = Scalar::from_repr(p256::FieldBytes::from(*data)).into();
    opt.ok_or_else(|| PheError::InvalidScalar("not a valid P-256 scalar".into()))
}

fn point_bytes(point: ProjectivePoint) -> Vec<u8> {
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

pub struct PheContext {
    server: PheServer,
    client: PheClient,
}

impl PheContext {
    pub fn new() -> Self {
        let server = PheServer::new();
        let client = PheClient::new(server.public_key());
        Self { server, client }
    }

    pub fn from_keys(server_key: &[u8; 32], client_key: &[u8; 32]) -> Result<Self, PheError> {
        let server = PheServer::from_bytes(server_key)?;
        let client_scalar = decode_scalar(client_key)?;
        let client = PheClient::from_scalar(client_scalar, server.public_key());
        Ok(Self { server, client })
    }

    pub fn enroll(&self, password: &[u8]) -> Result<(PheRecord, EncryptionKey), PheError> {
        let enrollment = self.server.enrollment_material()?;
        self.client.enroll(password, &enrollment)
    }

    pub fn verify(&self, password: &[u8], record: &PheRecord) -> Result<EncryptionKey, PheError> {
        let c0 = self.client.recover_c0(password, record)?;
        let verify_resp = self.server.verify_c0(&record.server_salt, c0)?;
        self.client.verify(password, record, &verify_resp)
    }

    pub fn rotate(&mut self) -> UpdateToken {
        let new_key = Scalar::random(&mut OsRng);
        let token = self.server.rotate(&new_key);
        self.server = PheServer::from_scalar(new_key);
        self.client = PheClient::from_scalar(self.client.client_key, self.server.public_key());
        token
    }

    pub fn update_record(
        &self,
        record: &PheRecord,
        token: &UpdateToken,
    ) -> Result<PheRecord, PheError> {
        self.client.update_record(record, token)
    }

    pub fn server(&self) -> &PheServer {
        &self.server
    }

    pub fn client(&self) -> &PheClient {
        &self.client
    }
}

impl Default for PheContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrip_is_130_bytes() {
        let ctx = PheContext::new();
        let (record, _) = ctx.enroll(b"password").unwrap();
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 130);

        let restored = PheRecord::from_bytes(&bytes).unwrap();
        assert_eq!(point_bytes(restored.t0), point_bytes(record.t0));
        assert_eq!(point_bytes(restored.t1), point_bytes(record.t1));
        assert_eq!(restored.server_salt, record.server_salt);
        assert_eq!(restored.client_salt, record.client_salt);
    }

    #[test]
    fn enrollment_and_verify_same_key() {
        let ctx = PheContext::new();
        let password = b"correct horse battery staple";

        let (record, enroll_key) = ctx.enroll(password).unwrap();
        let verify_key = ctx.verify(password, &record).unwrap();
        assert_eq!(enroll_key, verify_key);
    }

    #[test]
    fn wrong_password_fails() {
        let ctx = PheContext::new();
        let (record, _) = ctx.enroll(b"right").unwrap();

        let err = ctx.verify(b"wrong", &record).unwrap_err();
        assert!(matches!(err, PheError::WrongPassword));
    }

    #[test]
    fn lecture_equation_t0_uses_c0_plus_hc0() {
        let server = PheServer::new();
        let client = PheClient::new(server.public_key());

        let enrollment = server.enrollment_material().unwrap();
        let password = b"pw";
        let (record, _) = client.enroll(password, &enrollment).unwrap();

        let hc0 = client
            .password_hardened_component(password, &record.client_salt, 0)
            .unwrap();

        // C0 recovered on login must match server C0 from enrollment material.
        let recovered_c0 = record.t0 - hc0;
        assert_eq!(point_bytes(recovered_c0), point_bytes(enrollment.c0));
    }

    #[test]
    fn lecture_equation_mc_recovered_from_t1() {
        let server = PheServer::new();
        let client = PheClient::new(server.public_key());

        let enrollment = server.enrollment_material().unwrap();
        let password = b"pw";
        let (record, enroll_key) = client.enroll(password, &enrollment).unwrap();

        let c0 = client.recover_c0(password, &record).unwrap();
        let verify_resp = server.verify_c0(&record.server_salt, c0).unwrap();
        assert!(verify_resp.success);

        let c1 = verify_resp.c1.unwrap();
        let hc1 = client
            .password_hardened_component(password, &record.client_salt, 1)
            .unwrap();

        let mc = record.t1 - c1 - hc1;
        let recovered_key = derive_encryption_key(mc).unwrap();
        assert_eq!(enroll_key, recovered_key);
    }

    #[test]
    fn rotation_and_update_without_password_keeps_key() {
        let mut ctx = PheContext::new();
        let password = b"rotation-password";

        let (record, key_before) = ctx.enroll(password).unwrap();
        let token = ctx.rotate();

        // Update does not need password.
        let updated = ctx.update_record(&record, &token).unwrap();

        let key_after = ctx.verify(password, &updated).unwrap();
        assert_eq!(key_before, key_after);
    }

    #[test]
    fn from_keys_produces_equivalent_context() {
        let ctx = PheContext::new();
        let server_bytes = ctx.server().private_key_bytes();
        let client_bytes = ctx.client().client_key_bytes();

        let restored = PheContext::from_keys(&server_bytes, &client_bytes).unwrap();

        let (record, key1) = ctx.enroll(b"abc").unwrap();
        let key2 = restored.verify(b"abc", &record).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn verify_requires_valid_proof_when_success() {
        let server = PheServer::new();
        let client = PheClient::new(server.public_key());

        let enrollment = server.enrollment_material().unwrap();
        let password = b"pw";
        let (record, _) = client.enroll(password, &enrollment).unwrap();

        let c0 = client.recover_c0(password, &record).unwrap();
        let mut verify_resp = server.verify_c0(&record.server_salt, c0).unwrap();

        verify_resp.proof_c1 = Some(SchnorrProof {
            commitment: ProjectivePoint::GENERATOR,
            challenge: Scalar::ONE,
            response: Scalar::ONE,
        });

        let err = client.verify(password, &record, &verify_resp).unwrap_err();
        assert!(matches!(err, PheError::InvalidProof));
    }
}
