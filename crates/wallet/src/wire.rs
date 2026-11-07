//! Wire format shared by every wallet front end: the CLI (`wallet sign`), the
//! desktop bridge (`wallet serve`), and the mobile FFI core. Sign requests in,
//! fully-signed entry JSON out - one grammar, so a phone and a desktop
//! produce byte-identical envelopes that any node accepts unchanged.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use datu_core::{Entry, EntryBody};
use serde_json::Value;

use crate::LoadedIdentity;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn parse_id(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad entry id '{hex_str}': {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("entry id must be 32 bytes: '{hex_str}'"))
}

/// A dApp's ask: "sign this payload as me" (namespace, seq, prev, refs,
/// payload). The wallet stamps authorship and hybrid-signs it.
#[derive(serde::Deserialize)]
pub struct SignRequest {
    pub namespace: String,
    pub seq: u64,
    #[serde(default)]
    pub prev: Option<String>,
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    #[serde(default)]
    pub payload_base64: Option<String>,
    #[serde(default)]
    pub payload_json: Option<Value>,
}

/// Build and hybrid-sign an entry from a dApp sign request.
pub fn entry_from_sign_request(
    identity: &LoadedIdentity,
    request: &SignRequest,
) -> Result<Entry, String> {
    if request.payload_base64.is_none() && request.payload_json.is_none() {
        return Err("sign request needs payload_base64 or payload_json".into());
    }
    let payload = if let Some(b64) = &request.payload_base64 {
        B64
            .decode(b64)
            .map_err(|_| "bad payload_base64".to_string())?
    } else {
        let value = request.payload_json.as_ref().expect("checked above");
        serde_json::to_vec(value).map_err(|e| e.to_string())?
    };
    let prev = match &request.prev {
        Some(p) => Some(parse_id(p)?),
        None => None,
    };
    let mut refs = Vec::with_capacity(request.refs.len());
    for r in &request.refs {
        refs.push(parse_id(r)?);
    }
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: identity.public.ed_public.clone(),
        author_pq: identity.public.pq_public.clone(),
        pq_alg: "mldsa65".to_string(),
        namespace: request.namespace.clone(),
        seq: request.seq,
        prev,
        refs,
        timestamp_ms: request.timestamp_ms.unwrap_or_else(now_ms),
        payload,
    };
    identity.sign_entry(body)
}

/// Full signed-entry JSON: exactly what `POST /v1/entries` accepts on any
/// node, and what a wallet hands back to the dApp.
pub fn entry_full_json(entry: &Entry) -> Result<Value, String> {
    Ok(serde_json::json!({
        "author": entry.body.author,
        "author_pq": entry.body.author_pq,
        "pq_alg": entry.body.pq_alg,
        "namespace": entry.body.namespace,
        "seq": entry.body.seq,
        "prev": entry.body.prev.map(hex::encode),
        "refs": entry.body.refs.iter().map(hex::encode).collect::<Vec<_>>(),
        "timestamp_ms": entry.body.timestamp_ms,
        "payload_base64": B64.encode(&entry.body.payload),
        "signature": hex::encode(entry.signature),
        "pq_signature": B64.encode(&entry.pq_signature),
        "id": hex::encode(entry.id().map_err(|e| e.to_string())?),
    }))
}

/// The dApp submission format - exactly what a wallet signer returns.
#[derive(serde::Deserialize)]
struct EntrySubmission {
    author: String,
    author_pq: String,
    pq_alg: String,
    namespace: String,
    seq: u64,
    #[serde(default)]
    prev: Option<String>,
    #[serde(default)]
    refs: Vec<String>,
    timestamp_ms: u64,
    payload_base64: String,
    signature: String,
    pq_signature: String,
}

/// Reconstruct a fully-signed entry from its submission JSON (node ingestion
/// and wallet-side verification of a fetched record).
pub fn entry_from_submission(value: &Value) -> Result<Entry, String> {
    let sub: EntrySubmission =
        serde_json::from_value(value.clone()).map_err(|e| format!("bad entry JSON: {e}"))?;
    let prev = match &sub.prev {
        Some(p) => Some(
            hex::decode(p)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("bad prev id")?,
        ),
        None => None,
    };
    let mut refs = Vec::with_capacity(sub.refs.len());
    for r in &sub.refs {
        refs.push(
            hex::decode(r)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("bad ref id")?,
        );
    }
    let payload = B64.decode(&sub.payload_base64).map_err(|_| "bad payload_base64")?;
    let signature_arr: [u8; 64] = hex::decode(&sub.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or("bad signature")?;
    let pq_signature = B64.decode(&sub.pq_signature).map_err(|_| "bad pq_signature")?;
    Ok(Entry {
        body: EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: sub.author,
            author_pq: sub.author_pq,
            pq_alg: sub.pq_alg,
            namespace: sub.namespace,
            seq: sub.seq,
            prev,
            refs,
            timestamp_ms: sub.timestamp_ms,
            payload,
        },
        signature: signature_arr,
        pq_signature,
    })
}
