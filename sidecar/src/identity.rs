use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context as AnyhowContext, ensure};
use rustls::client::ResolvesClientCert;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};
use rustls_pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use sha2::{Digest as ShaDigest, Sha256};
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::{
    Digest, HashScheme, HashcheckTicket, Public, Signature, SignatureScheme as TpmSignatureScheme,
    SymmetricDefinition,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::{Context, tss2_esys};
use x509_parser::prelude::*;

const PERSISTENT_HANDLE_START: u32 = 0x8100_0000;
const PERSISTENT_HANDLE_END: u32 = 0x81ff_ffff;
const P256_COORDINATE_LEN: usize = 32;

// ASN.1 DER tags used to construct RFC 5280 SubjectPublicKeyInfo and
// RFC 3279 ECDSA signatures. Keep the structure named instead of embedding
// opaque byte prefixes.
// Sources:
// - SubjectPublicKeyInfo: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
// - EC SPKI OIDs and uncompressed point form: https://www.rfc-editor.org/rfc/rfc5480#section-2
// - ECDSA signature shape: https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3
const ASN1_SEQUENCE_TAG: u8 = 0x30;
const ASN1_INTEGER_TAG: u8 = 0x02;
const ASN1_OBJECT_IDENTIFIER_TAG: u8 = 0x06;
const ASN1_BIT_STRING_TAG: u8 = 0x03;
const ASN1_BIT_STRING_ZERO_UNUSED_BITS: u8 = 0x00;
const SEC1_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

// RFC 5480: id-ecPublicKey and secp256r1/prime256v1.
const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];

pub fn parse_tpm_key_handle(value: &str) -> anyhow::Result<u32> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let handle = u32::from_str_radix(hex, 16)
        .with_context(|| format!("invalid TPM key handle {value:?}; expected hex"))?;
    ensure!(
        (PERSISTENT_HANDLE_START..=PERSISTENT_HANDLE_END).contains(&handle),
        "TPM key handle {value:?} is not in the persistent handle range 0x81000000..=0x81ffffff"
    );
    Ok(handle)
}

pub struct TpmClientIdentity {
    cert_chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<TpmSigningKey>,
}

impl TpmClientIdentity {
    pub fn load(tcti: &str, key_handle: u32, cert_path: &Path) -> anyhow::Result<Self> {
        let cert_chain = load_certs(cert_path)?;
        let leaf_spki = certificate_spki(
            cert_chain
                .first()
                .context("client certificate chain must contain a leaf certificate")?,
        )?;

        let signing_key = Arc::new(TpmSigningKey::load(tcti, key_handle)?);
        ensure!(
            signing_key.spki_der == leaf_spki,
            "client certificate public key does not match TPM key handle 0x{key_handle:08x}"
        );

        Ok(Self {
            cert_chain,
            signing_key,
        })
    }

    pub fn resolver(self) -> Arc<dyn ResolvesClientCert> {
        Arc::new(StaticTpmClientCert {
            certified_key: Arc::new(CertifiedKey::new(self.cert_chain, self.signing_key)),
        })
    }
}

#[derive(Debug)]
struct StaticTpmClientCert {
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesClientCert for StaticTpmClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.certified_key
            .key
            .choose_scheme(sigschemes)
            .map(|_| self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct TpmSigningKey {
    tcti: String,
    key_handle: u32,
    spki_der: Vec<u8>,
}

impl fmt::Debug for TpmSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmSigningKey")
            .field("tcti", &self.tcti)
            .field("key_handle", &format_args!("0x{:08x}", self.key_handle))
            .finish_non_exhaustive()
    }
}

impl TpmSigningKey {
    fn load(tcti: &str, key_handle: u32) -> anyhow::Result<Self> {
        let public = read_persistent_public(tcti, key_handle)?;
        let spki_der = p256_spki_from_tpm_public(&public)?;
        Ok(Self {
            tcti: tcti.to_owned(),
            key_handle,
            spki_der,
        })
    }
}

impl SigningKey for TpmSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Box::new(TpmP256Signer {
                tcti: self.tcti.clone(),
                key_handle: self.key_handle,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki_der.as_slice()))
    }
}

#[derive(Debug)]
struct TpmP256Signer {
    tcti: String,
    key_handle: u32,
}

impl Signer for TpmP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        sign_p256_sha256(&self.tcti, self.key_handle, message)
            .map_err(|e| RustlsError::General(format!("TPM signing failed: {e:#}")))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

fn sign_p256_sha256(tcti: &str, key_handle: u32, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut hash = Sha256::new();
    hash.update(message);
    let digest = Digest::try_from(hash.finalize().as_slice()).context("building TPM digest")?;

    let mut ctx = new_context(tcti)?;
    let key_handle = load_persistent_key(&mut ctx, key_handle)?;
    let validation = HashcheckTicket::try_from(tss2_esys::TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    })
    .context("building TPM validation ticket")?;

    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("starting TPM auth session")?
        .context("TPM did not return an auth session")?;
    ctx.set_sessions((Some(session), None, None));

    let signature = ctx.sign(
        key_handle,
        digest,
        TpmSignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        },
        validation,
    );

    let session_handle: SessionHandle = session.into();
    ctx.flush_context(session_handle.into())
        .context("flushing TPM auth session")?;

    let signature = signature.context("signing with TPM key")?;
    p256_signature_der(&signature)
}

fn read_persistent_public(tcti: &str, key_handle: u32) -> anyhow::Result<Public> {
    let mut ctx = new_context(tcti)?;
    let key_handle = load_persistent_key(&mut ctx, key_handle)?;
    let (public, _, _) = ctx
        .read_public(key_handle)
        .context("reading TPM public key")?;
    Ok(public)
}

fn new_context(tcti: &str) -> anyhow::Result<Context> {
    let tcti = TctiNameConf::from_str(tcti)
        .with_context(|| format!("parsing TPM TCTI configuration {tcti:?}"))?;
    Context::new(tcti).context("creating TPM context")
}

fn load_persistent_key(ctx: &mut Context, handle: u32) -> anyhow::Result<KeyHandle> {
    let persistent = PersistentTpmHandle::new(handle)
        .with_context(|| format!("building persistent TPM handle 0x{handle:08x}"))?;
    let loaded = ctx
        .tr_from_tpm_public(persistent.into())
        .with_context(|| format!("loading persistent TPM handle 0x{handle:08x}"))?;
    KeyHandle::try_from(loaded).context("converting TPM handle to key handle")
}

fn certificate_spki(cert: &CertificateDer<'_>) -> anyhow::Result<Vec<u8>> {
    let (_, cert) =
        X509Certificate::from_der(cert.as_ref()).context("parsing client certificate")?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

fn p256_spki_from_tpm_public(public: &Public) -> anyhow::Result<Vec<u8>> {
    let Public::Ecc {
        parameters, unique, ..
    } = public
    else {
        anyhow::bail!("TPM key is not an ECC key");
    };
    ensure!(
        parameters.ecc_curve() == EccCurve::NistP256,
        "TPM key must be NIST P-256"
    );

    let x = left_pad_coordinate(unique.x().value())?;
    let y = left_pad_coordinate(unique.y().value())?;

    Ok(p256_spki_der_from_coordinates(&x, &y))
}

fn p256_signature_der(signature: &Signature) -> anyhow::Result<Vec<u8>> {
    let Signature::EcDsa(sig) = signature else {
        anyhow::bail!("TPM returned a non-ECDSA signature");
    };
    let r = left_pad_coordinate(sig.signature_r().value())?;
    let s = left_pad_coordinate(sig.signature_s().value())?;
    Ok(ecdsa_p1363_to_der(&r, &s))
}

fn left_pad_coordinate(value: &[u8]) -> anyhow::Result<[u8; P256_COORDINATE_LEN]> {
    ensure!(
        value.len() <= P256_COORDINATE_LEN,
        "P-256 coordinate is too large: {} bytes",
        value.len()
    );
    let mut out = [0u8; P256_COORDINATE_LEN];
    out[P256_COORDINATE_LEN - value.len()..].copy_from_slice(value);
    Ok(out)
}

fn ecdsa_p1363_to_der(r: &[u8; P256_COORDINATE_LEN], s: &[u8; P256_COORDINATE_LEN]) -> Vec<u8> {
    let r_der = der_encode_int(r);
    let s_der = der_encode_int(s);
    let seq_len = r_der.len() + s_der.len();

    let mut out = Vec::with_capacity(2 + seq_len);
    out.push(ASN1_SEQUENCE_TAG);
    out.extend(der_len(seq_len));
    out.extend(r_der);
    out.extend(s_der);
    out
}

fn der_encode_int(raw: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < raw.len() && raw[start] == 0 {
        start += 1;
    }
    let mut value = raw[start..].to_vec();
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }

    let mut out = Vec::with_capacity(2 + value.len());
    out.push(ASN1_INTEGER_TAG);
    out.extend(der_len(value.len()));
    out.extend(value);
    out
}

fn p256_spki_der_from_coordinates(
    x: &[u8; P256_COORDINATE_LEN],
    y: &[u8; P256_COORDINATE_LEN],
) -> Vec<u8> {
    let algorithm_identifier = der_sequence(&[
        der_object_identifier(OID_EC_PUBLIC_KEY),
        der_object_identifier(OID_PRIME256V1),
    ]);

    let mut public_key = Vec::with_capacity(1 + P256_COORDINATE_LEN * 2);
    public_key.push(SEC1_UNCOMPRESSED_POINT_TAG);
    public_key.extend_from_slice(x);
    public_key.extend_from_slice(y);

    der_sequence(&[algorithm_identifier, der_bit_string(&public_key)])
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let len: usize = parts.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(1 + der_len(len).len() + len);
    out.push(ASN1_SEQUENCE_TAG);
    out.extend(der_len(len));
    for part in parts {
        out.extend(part);
    }
    out
}

fn der_object_identifier(arcs: &[u32]) -> Vec<u8> {
    assert!(
        arcs.len() >= 2 && arcs[0] <= 2 && (arcs[0] == 2 || arcs[1] < 40),
        "invalid object identifier arcs"
    );

    let mut body = Vec::new();
    body.push((arcs[0] * 40 + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        der_base128_encode(arc, &mut body);
    }

    let mut out = Vec::with_capacity(1 + der_len(body.len()).len() + body.len());
    out.push(ASN1_OBJECT_IDENTIFIER_TAG);
    out.extend(der_len(body.len()));
    out.extend(body);
    out
}

fn der_base128_encode(mut value: u32, out: &mut Vec<u8>) {
    let mut encoded = [0u8; 5];
    let mut idx = encoded.len();
    loop {
        idx -= 1;
        encoded[idx] = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    let last = encoded.len() - 1;
    for byte in &mut encoded[idx..last] {
        *byte |= 0x80;
    }
    out.extend_from_slice(&encoded[idx..]);
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + bytes.len());
    body.push(ASN1_BIT_STRING_ZERO_UNUSED_BITS);
    body.extend_from_slice(bytes);

    let mut out = Vec::with_capacity(1 + der_len(body.len()).len() + body.len());
    out.push(ASN1_BIT_STRING_TAG);
    out.extend(der_len(body.len()));
    out.extend(body);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut remaining = len;
        while remaining > 0 {
            bytes.push((remaining & 0xff) as u8);
            remaining >>= 8;
        }
        bytes.reverse();
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
        out
    }
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "no certificates in {}", path.display());
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn encodes_p256_spki() {
        let x = [1u8; P256_COORDINATE_LEN];
        let y = [2u8; P256_COORDINATE_LEN];
        let spki = p256_spki_der_from_coordinates(&x, &y);

        assert_eq!(spki.len(), 91);
        assert!(spki.ends_with(&y));
        assert_eq!(
            x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki)
                .unwrap()
                .0,
            &[] as &[u8]
        );
    }

    #[test]
    fn ecdsa_der_encoding_handles_high_bit() {
        let mut r = [0u8; P256_COORDINATE_LEN];
        let mut s = [0u8; P256_COORDINATE_LEN];
        r[31] = 1;
        s[0] = 0x80;

        let der = ecdsa_p1363_to_der(&r, &s);
        assert_eq!(der[0], ASN1_SEQUENCE_TAG);
        assert!(der.windows(3).any(|w| w == [ASN1_INTEGER_TAG, 0x21, 0x00]));
    }

    #[test]
    fn coordinate_padding_rejects_oversized_values() {
        assert!(left_pad_coordinate(&[0u8; P256_COORDINATE_LEN + 1]).is_err());
    }

    #[test]
    fn simulated_tpm_signer_signs_tls_message() {
        let (port, ctrl_port) = allocate_port_pair();
        let tcti = format!("swtpm:host=127.0.0.1,port={port}");
        let temp_dir = unique_temp_dir();
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut swtpm = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", temp_dir.display()),
                "--server",
                &format!("type=tcp,bindaddr=127.0.0.1,port={port}"),
                "--ctrl",
                &format!("type=tcp,bindaddr=127.0.0.1,port={ctrl_port}"),
                "--flags",
                "startup-clear",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start swtpm");
        let _guard = SwtpmGuard {
            child: &mut swtpm,
            temp_dir: temp_dir.clone(),
        };
        wait_for_port(port);

        let handle = 0x8101_0004;
        let key_ctx = temp_dir.join("signing.ctx");
        run_tpm2(
            &tcti,
            "tpm2_createprimary",
            &[
                "-Q",
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "ecc256:ecdsa",
                "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                "-c",
                key_ctx.to_str().unwrap(),
            ],
        );
        run_tpm2(
            &tcti,
            "tpm2_evictcontrol",
            &[
                "-Q",
                "-C",
                "o",
                "-c",
                key_ctx.to_str().unwrap(),
                "0x81010004",
            ],
        );

        let key = TpmSigningKey::load(&tcti, handle).unwrap();
        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("choose TPM ECDSA signer");
        let signature = signer.sign(b"rustls CertificateVerify message").unwrap();
        assert_eq!(signature[0], 0x30, "ECDSA signature should be DER");
    }

    struct SwtpmGuard<'a> {
        child: &'a mut Child,
        temp_dir: std::path::PathBuf,
    }

    impl Drop for SwtpmGuard<'_> {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }

    fn allocate_port_pair() -> (u16, u16) {
        for _ in 0..100 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            if port == u16::MAX {
                continue;
            }
            if let Ok(ctrl_listener) = TcpListener::bind(("127.0.0.1", port + 1)) {
                drop(ctrl_listener);
                drop(listener);
                return (port, port + 1);
            }
        }
        panic!("failed to allocate adjacent swtpm ports");
    }

    fn wait_for_port(port: u16) {
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("swtpm did not listen on port {port}");
    }

    fn unique_temp_dir() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("agent-gateway-swtpm-{nanos}"))
    }

    fn run_tpm2(tcti: &str, cmd: &str, args: &[&str]) {
        let output = Command::new(cmd)
            .args(args)
            .env("TPM2TOOLS_TCTI", tcti)
            .output()
            .unwrap_or_else(|e| panic!("run {cmd}: {e}"));
        assert!(
            output.status.success(),
            "{cmd} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
