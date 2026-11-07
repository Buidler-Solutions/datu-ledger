//! Keychain wallet: multi-identity key management (minus the money) and
//! field-level encryption for selective disclosure.
//!
//! Three roles:
//! - **Keystore**: named identities (Ed25519 + ML-DSA-65 + X25519 sealing
//!   key), encrypted at rest with a passphrase. This is what a browser
//!   extension or mobile app would embed; the CLI is the reference signer.
//! - **Signing**: a dApp supplies an entry body (namespace, seq, prev, refs,
//!   payload); the wallet stamps authorship and hybrid-signs it. The wallet
//!   never needs network access - entries are self-verifying.
//! - **Sealing**: selected JSON fields are encrypted to one or more readers'
//!   X25519 sealing keys (XChaCha20-Poly1305, per-field commitment), so the
//!   entry travels publicly while only authorized readers decrypt those
//!   fields.
//!
//! Keystores are version 2: the passphrase is stretched with Argon2id
//! (memory-hard) before key encryption. Version 1 files (BLAKE3-derived key,
//! not memory-hard) remain readable.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake3;
use borsh::BorshDeserialize;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use datu_core::parties::SignedDocument;
use datu_core::pq::PqPrivateKey;
use datu_core::{Entry, EntryBody};
use ed25519_dalek::SigningKey;
use fips204::traits::Signer as PqSigner;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
pub type WResult<T> = Result<T, String>;

pub const SEALED_MARK: &str = "dag-sealed-v1";
pub const SEALED_V2_MARK: &str = "datu-sealed-v2";
/// Pre-rebrand v2 seal mark: still readable, never written.
pub const SEALED_V2_MARK_LEGACY: &str = "dag-sealed-v2";
pub const KEYS_DIR: &str = "wallet/identities";
pub const INDEX_FILE: &str = "wallet/index.json";

/// Argon2id parameters used for new keystores (64 MiB, 3 passes).
pub const KDF_ARGON2ID: &str = "argon2id";
pub const ARGON2_M_KIB: u32 = 65536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 1;

/// Public view of a wallet identity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IdentityPublic {
    pub name: String,
    /// Ed25519 verifying key (hex) - the entry author id.
    pub ed_public: String,
    /// ML-DSA-65 public key (hex).
    pub pq_public: String,
    /// X25519 public key (hex) - the sealing/decryption key id.
    pub seal_public: String,
    pub created_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KeystoreFile {
    version: u8,
    /// Key-derivation function: "argon2id" (v2) or "blake3" (v1 legacy).
    #[serde(default)]
    kdf: String,
    /// Argon2id parameters, present when kdf = "argon2id".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_params: Option<KdfParams>,
    salt_b64: String,
    nonce_b64: String,
    ct_b64: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// Portable identity backup: the identity's secrets re-encrypted under a
/// *backup passphrase* (which may differ from the identity's usual one), plus
/// the public metadata needed to verify the restored keys. Move it to another
/// device (`wallet import`) or keep it as an offline backup.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IdentityBackup {
    /// Always "datu-identity-backup".
    pub format: String,
    pub version: u8,
    pub name: String,
    pub ed_public: String,
    pub pq_public: String,
    pub seal_public: String,
    pub created_at_ms: u64,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ct_b64: String,
}

pub const BACKUP_FORMAT: &str = "datu-identity-backup";
pub const BACKUP_VERSION: u8 = 1;

#[derive(borsh::BorshDeserialize, borsh::BorshSerialize)]
struct SecretBundle {
    ed: [u8; 32],
    pq_hex: String,
    seal: [u8; 32],
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn derive_key(context: &str, material: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in material {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> WResult<[u8; 32]> {
    let mut out = [0u8; 32];
    let a2params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| format!("argon2id params invalid: {e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, a2params)
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| format!("argon2id failed: {e}"))?;
    Ok(out)
}

fn seal_symmetric(key: &[u8; 32], plaintext: &[u8]) -> WResult<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 24];
    use rand::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encryption failed: {e}"))?;
    Ok((nonce_bytes.to_vec(), ct))
}

fn open_symmetric(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> WResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| "decryption failed (wrong key, wrong passphrase, or tampered data)".to_string())
}

pub struct Wallet {
    root: PathBuf,
}

impl Wallet {
    pub fn open(root: &Path) -> Wallet {
        Wallet {
            root: root.to_path_buf(),
        }
    }

    fn keys_dir(&self) -> PathBuf {
        self.root.join(KEYS_DIR)
    }

    fn key_file(&self, name: &str) -> WResult<PathBuf> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("identity name must be [a-zA-Z0-9-_]".into());
        }
        Ok(self.keys_dir().join(format!("{name}.wallet.json")))
    }

    pub fn list(&self) -> WResult<Vec<IdentityPublic>> {
        let path = self.root.join(INDEX_FILE);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| format!("corrupt wallet index: {e}"))
    }

    fn write_index(&self, identities: &[IdentityPublic]) -> WResult<()> {
        let path = self.root.join(INDEX_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        let text = serde_json::to_string_pretty(identities).map_err(|e| e.to_string())?;
        std::fs::write(&path, text).map_err(|e| e.to_string())
    }

    /// Create a new identity, encrypted under `passphrase`.
    pub fn create(&self, name: &str, passphrase: &str) -> WResult<IdentityPublic> {
        let file = self.key_file(name)?;
        if file.exists() {
            return Err(format!("identity '{name}' already exists"));
        }
        let ed = SigningKey::generate(&mut OsRng);
        let (pq_public, pq_secret) =
            datu_core::pq::keypair().map_err(|e| format!("keygen failed: {e}"))?;
        let seal = StaticSecret::random_from_rng(&mut OsRng);

        let public = IdentityPublic {
            name: name.to_string(),
            ed_public: hex::encode(ed.verifying_key().as_bytes()),
            pq_public: datu_core::pq::pk_to_hex(&pq_public),
            seal_public: hex::encode(XPublicKey::from(&seal).as_bytes()),
            created_at_ms: now_ms(),
        };
        let bundle = SecretBundle {
            ed: ed.to_bytes(),
            pq_hex: datu_core::pq::sk_to_hex(&pq_secret),
            seal: seal.to_bytes(),
        };
        let plaintext =
            borsh::to_vec(&bundle).map_err(|e| format!("encode failed: {e}"))?;
        let mut salt = [0u8; 16];
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);
        let kdf_params = KdfParams {
            m_kib: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
        };
        let kek = derive_key_argon2id(passphrase.as_bytes(), &salt, &kdf_params)?;
        let (nonce, ct) = seal_symmetric(&kek, &plaintext)?;

        std::fs::create_dir_all(self.keys_dir()).map_err(|e| e.to_string())?;
        let keystore = KeystoreFile {
            version: 2,
            kdf: KDF_ARGON2ID.to_string(),
            kdf_params: Some(kdf_params),
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(&nonce),
            ct_b64: B64.encode(&ct),
        };
        let text = serde_json::to_string_pretty(&keystore).map_err(|e| e.to_string())?;
        std::fs::write(&file, text).map_err(|e| e.to_string())?;

        let mut identities = self.list()?;
        identities.push(public.clone());
        self.write_index(&identities)?;
        Ok(public)
    }

    /// Unlock an identity with its passphrase.
    pub fn load(&self, name: &str, passphrase: &str) -> WResult<LoadedIdentity> {
        let file = self.key_file(name)?;
        if !file.exists() {
            return Err(format!("identity '{name}' not found"));
        }
        let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
        let keystore: KeystoreFile =
            serde_json::from_str(&text).map_err(|e| format!("corrupt keystore: {e}"))?;
        let salt = B64
            .decode(&keystore.salt_b64)
            .map_err(|_| "corrupt keystore (salt)".to_string())?;
        let nonce = B64
            .decode(&keystore.nonce_b64)
            .map_err(|_| "corrupt keystore (nonce)".to_string())?;
        let ct = B64
            .decode(&keystore.ct_b64)
            .map_err(|_| "corrupt keystore (ciphertext)".to_string())?;
        let kek = if keystore.kdf == KDF_ARGON2ID || keystore.version >= 2 {
            let params = keystore
                .kdf_params
                .as_ref()
                .ok_or("corrupt keystore (missing argon2id params)")?;
            derive_key_argon2id(passphrase.as_bytes(), &salt, params)?
        } else {
            // v1 keystores: BLAKE3-derived key (not memory-hard; readable for
            // backward compatibility, never written anymore).
            derive_key(
                "datu-wallet-keystore-v1",
                &[passphrase.as_bytes(), &salt],
            )
        };
        let plaintext = open_symmetric(&kek, &nonce, &ct)?;
        let bundle = SecretBundle::try_from_slice(&plaintext)
            .map_err(|e| format!("corrupt keystore: {e}"))?;
        let ed = SigningKey::from_bytes(&bundle.ed);
        let pq_secret = datu_core::pq::sk_from_hex(&bundle.pq_hex)
            .map_err(|e| e.to_string())?;
        let seal = StaticSecret::from(bundle.seal);
        let public = self
            .list()?
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| format!("identity '{name}' missing from index"))?;
        Ok(LoadedIdentity {
            public,
            ed,
            pq: pq_secret,
            seal,
        })
    }

    /// Export `name` as a portable backup encrypted under `backup_passphrase`.
    /// Unlocking the identity still needs its own passphrase first, so a
    /// stolen wallet file alone is not enough to produce a backup.
    pub fn export_identity(
        &self,
        name: &str,
        passphrase: &str,
        backup_passphrase: &str,
    ) -> WResult<IdentityBackup> {
        if backup_passphrase.chars().count() < 8 {
            return Err("backup passphrase must be at least 8 characters".into());
        }
        let loaded = self.load(name, passphrase)?;
        let bundle = SecretBundle {
            ed: loaded.ed.to_bytes(),
            pq_hex: datu_core::pq::sk_to_hex(&loaded.pq),
            seal: loaded.seal.to_bytes(),
        };
        let plaintext =
            borsh::to_vec(&bundle).map_err(|e| format!("encode failed: {e}"))?;
        let kdf_params = KdfParams {
            m_kib: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
        };
        let mut salt = [0u8; 16];
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);
        let kek = derive_key_argon2id(backup_passphrase.as_bytes(), &salt, &kdf_params)?;
        let (nonce, ct) = seal_symmetric(&kek, &plaintext)?;
        Ok(IdentityBackup {
            format: BACKUP_FORMAT.to_string(),
            version: BACKUP_VERSION,
            name: loaded.public.name.clone(),
            ed_public: loaded.public.ed_public.clone(),
            pq_public: loaded.public.pq_public.clone(),
            seal_public: loaded.public.seal_public.clone(),
            created_at_ms: loaded.public.created_at_ms,
            kdf: KDF_ARGON2ID.to_string(),
            kdf_params,
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(&nonce),
            ct_b64: B64.encode(&ct),
        })
    }

    /// Import a backup into this wallet. The restored identity's passphrase
    /// becomes `backup_passphrase`; `rename` lets it coexist with a same-named
    /// identity already here.
    pub fn import_identity(
        &self,
        backup: &IdentityBackup,
        backup_passphrase: &str,
        rename: Option<&str>,
    ) -> WResult<IdentityPublic> {
        if backup.format != BACKUP_FORMAT || backup.version != BACKUP_VERSION {
            return Err("not a datu-identity-backup v1 file".into());
        }
        let name = rename.unwrap_or(&backup.name).to_string();
        let file = self.key_file(&name)?;
        if file.exists() {
            return Err(format!(
                "identity '{name}' already exists - import under another name"
            ));
        }
        let salt = B64
            .decode(&backup.salt_b64)
            .map_err(|_| "corrupt backup (salt)".to_string())?;
        let nonce = B64
            .decode(&backup.nonce_b64)
            .map_err(|_| "corrupt backup (nonce)".to_string())?;
        let ct = B64
            .decode(&backup.ct_b64)
            .map_err(|_| "corrupt backup (ciphertext)".to_string())?;
        let kek =
            derive_key_argon2id(backup_passphrase.as_bytes(), &salt, &backup.kdf_params)?;
        let plaintext = open_symmetric(&kek, &nonce, &ct)?;
        let bundle = SecretBundle::try_from_slice(&plaintext)
            .map_err(|e| format!("corrupt backup: {e}"))?;

        // The restored keys must match the public metadata in the file.
        let ed = SigningKey::from_bytes(&bundle.ed);
        let pq_secret =
            datu_core::pq::sk_from_hex(&bundle.pq_hex).map_err(|e| e.to_string())?;
        let seal = StaticSecret::from(bundle.seal);
        if hex::encode(ed.verifying_key().as_bytes()) != backup.ed_public
            || datu_core::pq::pk_to_hex(&pq_secret.get_public_key()) != backup.pq_public
            || hex::encode(XPublicKey::from(&seal).as_bytes()) != backup.seal_public
        {
            return Err("backup metadata does not match its keys (tampered file?)".into());
        }

        // Re-encrypt under a fresh salt with the backup passphrase, so the
        // imported identity unlocks with the same phrase the backup used.
        let kdf_params = KdfParams {
            m_kib: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
        };
        let mut fresh_salt = [0u8; 16];
        use rand::RngCore;
        OsRng.fill_bytes(&mut fresh_salt);
        let fresh_kek =
            derive_key_argon2id(backup_passphrase.as_bytes(), &fresh_salt, &kdf_params)?;
        let (fresh_nonce, fresh_ct) = seal_symmetric(&fresh_kek, &plaintext)?;
        let keystore = KeystoreFile {
            version: 2,
            kdf: KDF_ARGON2ID.to_string(),
            kdf_params: Some(kdf_params),
            salt_b64: B64.encode(fresh_salt),
            nonce_b64: B64.encode(&fresh_nonce),
            ct_b64: B64.encode(&fresh_ct),
        };
        std::fs::create_dir_all(self.keys_dir()).map_err(|e| e.to_string())?;
        let text = serde_json::to_string_pretty(&keystore).map_err(|e| e.to_string())?;
        std::fs::write(&file, text).map_err(|e| e.to_string())?;

        let public = IdentityPublic {
            name,
            ed_public: backup.ed_public.clone(),
            pq_public: backup.pq_public.clone(),
            seal_public: backup.seal_public.clone(),
            created_at_ms: backup.created_at_ms,
        };
        let mut identities = self.list()?;
        identities.push(public.clone());
        self.write_index(&identities)?;
        Ok(public)
    }
}

/// An unlocked identity: the signer a dApp talks to.
pub struct LoadedIdentity {
    pub public: IdentityPublic,
    pub ed: SigningKey,
    pub pq: PqPrivateKey,
    pub seal: StaticSecret,
}

impl LoadedIdentity {
    /// Sign an entry body as this identity (stamps author, author_pq, pq_alg).
    pub fn sign_entry(&self, body: EntryBody) -> WResult<Entry> {
        Entry::sign(body, &self.ed, &self.pq).map_err(|e| format!("signing failed: {e}"))
    }

    /// Add this identity's party signature (consent) to a document under
    /// `role`, e.g. the holder of a land title. Hybrid-signed: Ed25519 is
    /// mandatory, ML-DSA-65 rides along so the consent is quantum-resistant.
    pub fn sign_document(&self, document: &mut SignedDocument, role: &str) -> WResult<()> {
        document
            .sign(role, &self.ed, Some(&self.pq))
            .map_err(|e| format!("party signing failed: {e}"))
    }

    /// Replace selected top-level fields of a JSON document with sealed
    /// objects, encrypted to every key in `readers_seal_public_hex` (one
    /// recipient entry per reader; readers can be added at seal time only).
    /// Returns how many fields were sealed. Unencrypted fields stay public.
    pub fn seal_fields(
        &self,
        document: &mut serde_json::Value,
        field_names: &[String],
        readers_seal_public_hex: &[String],
    ) -> WResult<usize> {
        if readers_seal_public_hex.is_empty() {
            return Err("sealing needs at least one reader seal key".into());
        }
        let mut readers = Vec::with_capacity(readers_seal_public_hex.len());
        for hex_key in readers_seal_public_hex {
            let bytes = hex::decode(hex_key.trim())
                .map_err(|_| "reader seal keys must be hex".to_string())?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "reader seal key must be 32 bytes".to_string())?;
            readers.push(XPublicKey::from(key));
        }

        let map = document
            .as_object_mut()
            .ok_or("document must be a JSON object")?;
        let mut sealed_count = 0;
        for name in field_names {
            let value = match map.get(name) {
                Some(v) => v.clone(),
                None => continue,
            };
            let plaintext = serde_json::to_vec(&value)
                .map_err(|e| format!("cannot serialize field '{name}': {e}"))?;
            let sealed = seal_field_multi(&plaintext, &readers)?;
            map.insert(name.clone(), sealed);
            sealed_count += 1;
        }
        Ok(sealed_count)
    }

    /// Decrypt every sealed field addressed to this identity's sealing key
    /// (v1 single-reader and v2 multi-reader formats). Returns
    /// (opened, skipped_for_other_readers).
    pub fn open_fields(
        &self,
        document: &mut serde_json::Value,
    ) -> WResult<(usize, usize)> {
        let map = document
            .as_object_mut()
            .ok_or("document must be a JSON object")?;
        let mut opened = 0;
        let mut skipped = 0;
        for (_name, value) in map.iter_mut() {
            let obj = match value.as_object() {
                Some(o) => o,
                None => continue,
            };
            match obj.get("sealed").and_then(|m| m.as_str()) {
                Some(SEALED_V2_MARK) | Some(SEALED_V2_MARK_LEGACY) => {
                    let sealed: SealedFieldV2 =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    match sealed
                        .recipients
                        .iter()
                        .find(|r| r.to == self.public.seal_public)
                    {
                        Some(recipient) => {
                            let plaintext = open_recipient(recipient, &sealed.commitment, &self.seal)?;
                            *value = serde_json::from_slice(&plaintext)
                                .map_err(|e| format!("decrypted field is not valid JSON: {e}"))?;
                            opened += 1;
                        }
                        None => skipped += 1,
                    }
                }
                Some(SEALED_MARK) => {
                    let sealed: SealedField =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    if sealed.to != self.public.seal_public {
                        skipped += 1;
                        continue;
                    }
                    let plaintext = open_field(&sealed, &self.seal)?;
                    *value = serde_json::from_slice(&plaintext)
                        .map_err(|e| format!("decrypted field is not valid JSON: {e}"))?;
                    opened += 1;
                }
                _ => continue,
            }
        }
        Ok((opened, skipped))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SealedField {
    pub sealed: String,
    /// Reader's X25519 public key (hex).
    pub to: String,
    /// Ephemeral X25519 public key (hex).
    pub eph: String,
    /// XChaCha20-Poly1305 nonce (base64, 24 bytes).
    pub nonce: String,
    /// Ciphertext (base64).
    pub ct: String,
    /// BLAKE3 of the plaintext (hex): anyone can verify against a later reveal.
    pub commitment: String,
}

/// Multi-reader sealed field (v2): one commitment over the plaintext, one
/// recipient entry per authorized reader.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SealedFieldV2 {
    pub sealed: String,
    pub recipients: Vec<Recipient>,
    /// BLAKE3 of the plaintext (hex), shared by all recipients.
    pub commitment: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Recipient {
    /// This reader's X25519 public key (hex).
    pub to: String,
    /// Ephemeral X25519 public key for this recipient (hex).
    pub eph: String,
    /// XChaCha20-Poly1305 nonce (base64, 24 bytes).
    pub nonce: String,
    /// Ciphertext for this recipient (base64).
    pub ct: String,
}

fn seal_to_recipient(plaintext: &[u8], reader: &XPublicKey) -> WResult<Recipient> {
    let eph_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let eph_public = XPublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(reader);
    let key = derive_key(
        "datu-seal-v1",
        &[shared.as_bytes(), eph_public.as_bytes(), reader.as_bytes()],
    );
    let (nonce, ct) = seal_symmetric(&key, plaintext)?;
    Ok(Recipient {
        to: hex::encode(reader.as_bytes()),
        eph: hex::encode(eph_public.as_bytes()),
        nonce: B64.encode(&nonce),
        ct: B64.encode(&ct),
    })
}

fn seal_field_multi(plaintext: &[u8], readers: &[XPublicKey]) -> WResult<serde_json::Value> {
    let mut recipients = Vec::with_capacity(readers.len());
    for reader in readers {
        recipients.push(seal_to_recipient(plaintext, reader)?);
    }
    let sealed = SealedFieldV2 {
        sealed: SEALED_V2_MARK.to_string(),
        recipients,
        commitment: hex::encode(blake3::hash(plaintext).as_bytes()),
    };
    serde_json::to_value(sealed).map_err(|e| e.to_string())
}

fn open_recipient(
    recipient: &Recipient,
    commitment: &str,
    my_seal: &StaticSecret,
) -> WResult<Vec<u8>> {
    let eph_bytes = hex::decode(&recipient.eph).map_err(|_| "bad eph key".to_string())?;
    let eph: [u8; 32] = eph_bytes
        .try_into()
        .map_err(|_| "eph key must be 32 bytes".to_string())?;
    let shared = my_seal.diffie_hellman(&XPublicKey::from(eph));
    let reader_bytes =
        hex::decode(&recipient.to).map_err(|_| "bad reader key".to_string())?;
    let key = derive_key(
        "datu-seal-v1",
        &[shared.as_bytes(), &eph, reader_bytes.as_slice()],
    );
    let nonce = B64
        .decode(&recipient.nonce)
        .map_err(|_| "bad nonce".to_string())?;
    let ct = B64.decode(&recipient.ct).map_err(|_| "bad ct".to_string())?;
    let plaintext = open_symmetric(&key, &nonce, &ct)?;
    let computed = hex::encode(blake3::hash(&plaintext).as_bytes());
    if computed != commitment {
        return Err("commitment mismatch: field was tampered with".into());
    }
    Ok(plaintext)
}

fn open_field(sealed: &SealedField, my_seal: &StaticSecret) -> WResult<Vec<u8>> {
    let eph_bytes = hex::decode(&sealed.eph).map_err(|_| "bad eph key".to_string())?;
    let eph: [u8; 32] = eph_bytes
        .try_into()
        .map_err(|_| "eph key must be 32 bytes".to_string())?;
    let shared = my_seal.diffie_hellman(&XPublicKey::from(eph));
    let reader_bytes =
        hex::decode(&sealed.to).map_err(|_| "bad reader key".to_string())?;
    let key = derive_key(
        "datu-seal-v1",
        &[shared.as_bytes(), &eph, reader_bytes.as_slice()],
    );
    let nonce = B64
        .decode(&sealed.nonce)
        .map_err(|_| "bad nonce".to_string())?;
    let ct = B64.decode(&sealed.ct).map_err(|_| "bad ct".to_string())?;
    let plaintext = open_symmetric(&key, &nonce, &ct)?;
    let commitment = hex::encode(blake3::hash(&plaintext).as_bytes());
    if commitment != sealed.commitment {
        return Err("commitment mismatch: field was tampered with".into());
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_keystore_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::open(dir.path());
        let created = wallet.create("v2user", "pass").unwrap();
        assert_eq!(created.name, "v2user");

        // Hand-craft a version-1 (blake3 KDF) keystore for "legacy" and make
        // sure load() still opens it.
        let ed = SigningKey::generate(&mut OsRng);
        let (_pq_public, pq_secret) = datu_core::pq::keypair().unwrap();
        let seal = StaticSecret::random_from_rng(&mut OsRng);
        let bundle = SecretBundle {
            ed: ed.to_bytes(),
            pq_hex: datu_core::pq::sk_to_hex(&pq_secret),
            seal: seal.to_bytes(),
        };
        let plaintext = borsh::to_vec(&bundle).unwrap();
        let mut salt = [0u8; 16];
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);
        let kek = derive_key("datu-wallet-keystore-v1", &[b"old pass".as_slice(), &salt]);
        let (nonce, ct) = seal_symmetric(&kek, &plaintext).unwrap();
        let legacy = KeystoreFile {
            version: 1,
            kdf: String::new(),
            kdf_params: None,
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(&nonce),
            ct_b64: B64.encode(&ct),
        };
        std::fs::create_dir_all(wallet.keys_dir()).unwrap();
        std::fs::write(
            wallet.key_file("legacy").unwrap(),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();
        let mut identities = wallet.list().unwrap();
        identities.push(IdentityPublic {
            name: "legacy".into(),
            ed_public: hex::encode(ed.verifying_key().as_bytes()),
            pq_public: String::new(),
            seal_public: hex::encode(XPublicKey::from(&seal).as_bytes()),
            created_at_ms: 1,
        });
        wallet.write_index(&identities).unwrap();

        let loaded = wallet.load("legacy", "old pass").unwrap();
        assert_eq!(
            loaded.public.ed_public,
            hex::encode(ed.verifying_key().as_bytes())
        );
        assert!(wallet.load("legacy", "wrong").is_err());
    }

    #[test]
    fn v1_sealed_field_still_opens() {
        let reader = StaticSecret::random_from_rng(&mut OsRng);
        let reader_public = XPublicKey::from(&reader);
        let reader_hex = hex::encode(reader_public.as_bytes());
        let identity = LoadedIdentity {
            public: IdentityPublic {
                name: "reader".into(),
                ed_public: String::new(),
                pq_public: String::new(),
                seal_public: reader_hex.clone(),
                created_at_ms: 1,
            },
            ed: SigningKey::generate(&mut OsRng),
            pq: datu_core::pq::keypair().unwrap().1,
            seal: reader,
        };

        // Build a v1-format sealed field with the same key derivation.
        let plaintext = br#"{"secret":42}"#;
        let eph_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let eph_public = XPublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&reader_public);
        let key = derive_key(
            "datu-seal-v1",
            &[shared.as_bytes(), eph_public.as_bytes(), reader_public.as_bytes()],
        );
        let (nonce, ct) = seal_symmetric(&key, plaintext).unwrap();
        let v1_field = SealedField {
            sealed: SEALED_MARK.to_string(),
            to: reader_hex,
            eph: hex::encode(eph_public.as_bytes()),
            nonce: B64.encode(&nonce),
            ct: B64.encode(&ct),
            commitment: hex::encode(blake3::hash(plaintext).as_bytes()),
        };
        let mut doc = serde_json::json!({ "old": serde_json::to_value(&v1_field).unwrap(), "plain": 1 });
        let (opened, skipped) = identity.open_fields(&mut doc).unwrap();
        assert_eq!((opened, skipped), (1, 0));
        assert_eq!(doc["old"]["secret"], 42);
    }
}
