//! Throwaway PKIs made at test time with rcgen: a CA, leaves it signs, and
//! CRLs. Nothing here is a real key, and nothing is written to the repository.

#![allow(dead_code)]

use iec104_tls::{
    CertificateDer, CertificateRevocationListDer, Identity, PrivateKeyDer, TlsConfig,
    TlsConfigBuilder,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SerialNumber, date_time_ymd,
};

/// A certificate authority.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pub cert: CertificateDer<'static>,
    pub pem: String,
}

/// A leaf certificate and its key, usable for both TLS roles.
pub struct Leaf {
    pub cert: CertificateDer<'static>,
    pub cert_pem: String,
    pub key_pem: String,
    key_der: Vec<u8>,
}

impl Ca {
    /// A CA with a fresh ECDSA P-256 key.
    pub fn new(name: &str) -> Self {
        Self::with_key(name, KeyPair::generate().unwrap())
    }

    /// A CA signing with `key` (rcgen with *ring* cannot generate RSA keys,
    /// but signs with one it is given).
    pub fn with_key(name: &str, key: KeyPair) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self {
            pem: cert.pem(),
            cert: cert.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    /// A leaf for `names` (DNS names or IP addresses, as subjectAltNames)
    /// with serial number `serial`.
    pub fn leaf(&self, names: &[&str], serial: u64) -> Leaf {
        self.leaf_with_key(names, serial, &KeyPair::generate().unwrap())
    }

    /// [`Ca::leaf`] for the given key.
    pub fn leaf_with_key(&self, names: &[&str], serial: u64, key: &KeyPair) -> Leaf {
        let names: Vec<String> = names.iter().map(std::string::ToString::to_string).collect();
        let mut params = CertificateParams::new(names).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("station {serial}"));
        params.serial_number = Some(SerialNumber::from(serial));
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(key, &self.issuer).unwrap();
        Leaf {
            cert: cert.der().clone(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            key_der: key.serialize_der(),
        }
    }

    /// A CRL from this CA revoking `serials`.
    pub fn crl(&self, serials: &[u64]) -> CertificateRevocationListDer<'static> {
        self.signed_crl(serials).der().clone()
    }

    /// [`Ca::crl`] in PEM.
    pub fn crl_pem(&self, serials: &[u64]) -> String {
        self.signed_crl(serials).pem().unwrap()
    }

    fn signed_crl(&self, serials: &[u64]) -> rcgen::CertificateRevocationList {
        let params = CertificateRevocationListParams {
            this_update: date_time_ymd(2025, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|&s| RevokedCertParams {
                    serial_number: SerialNumber::from(s),
                    revocation_time: date_time_ymd(2025, 1, 1),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        params.signed_by(&self.issuer).unwrap()
    }
}

impl Leaf {
    pub fn identity(&self) -> Identity {
        Identity::new(vec![self.cert.clone()], self.key())
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der.clone()).unwrap()
    }
}

/// A station: its leaf from `ca`, for `127.0.0.1` and `localhost`, trusting
/// `trusts`.
pub fn station(ca: &Ca, serial: u64, trusts: &Ca) -> TlsConfigBuilder {
    let leaf = ca.leaf(&["127.0.0.1", "localhost"], serial);
    TlsConfig::builder(leaf.identity(), vec![trusts.cert.clone()])
}

impl Ca {
    pub fn sign_crl(
        &self,
        params: &CertificateRevocationListParams,
    ) -> CertificateRevocationListDer<'static> {
        params.signed_by(&self.issuer).unwrap().der().clone()
    }

    /// A leaf that stops being valid `secs` seconds from now.
    pub fn leaf_expiring(&self, names: &[&str], serial: u64, secs: u64) -> Leaf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let key = KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(std::string::ToString::to_string).collect();
        let mut params = CertificateParams::new(names).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("station {serial}"));
        params.serial_number = Some(SerialNumber::from(serial));
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(1970, 1, 1) + (now + std::time::Duration::from_secs(secs));
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Leaf {
            cert: cert.der().clone(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            key_der: key.serialize_der(),
        }
    }
}
