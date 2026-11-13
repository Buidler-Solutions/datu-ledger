mod node;
mod serve;
mod walletd;

use base64::Engine;
use borsh::BorshDeserialize;
use clap::{Parser, Subcommand};
use datu_core::attest::{self, AttestationDoc, CosignDoc};
use datu_core::checkpoint::CoverageProof;
use datu_core::contract::{self, ContractSpec};
use datu_core::fork::{self, ForkEvidence};
use datu_core::merkle::merkle_root;
use datu_core::parties::SignedDocument;
use datu_core::{BloomFilter, Checkpoint, CheckpointBody, Entry, EntryBody};
use datu_p2p::{sign_hello, NetworkPolicy, NodeHello, NETWORK_POLICY_VERSION};
use datu_store::{decode_witness_stream, Store, WritePolicy};
use datu_wallet::wire::{entry_from_sign_request, SignRequest};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fmt::Display;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

#[derive(Parser)]
#[command(
    name = "datu",
    version,
    about = "DATU (Decentralized Accountable Trust Union) - tokenless, offline-capable, DAG-type accountability ledger (not a blockchain): signed entries, append-only, run a node anywhere"
)]
struct Cli {
    /// Node directory (database + identity key)
    #[arg(long, global = true, default_value = ".datu")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a node directory with a fresh identity key
    Init,
    /// Show this node's identity
    Keys,
    /// Publish a signed entry to your feed
    Publish {
        /// Namespace, e.g. gov.records, audit.claims
        #[arg(long, default_value = "general")]
        ns: String,
        /// Payload as inline text (typically JSON)
        #[arg(long, conflicts_with = "file")]
        payload: Option<String>,
        /// Payload read from a file
        #[arg(long, conflicts_with = "payload")]
        file: Option<PathBuf>,
        /// Causal reference to another entry id (repeatable)
        #[arg(long = "ref")]
        refs: Vec<String>,
    },
    /// List recent entries
    Log {
        #[arg(long)]
        ns: Option<String>,
        #[arg(long)]
        author: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Show one entry in full
    Get {
        #[arg(long)]
        id: String,
    },
    /// Verify every signature, feed chain, and checkpoint in the store
    Verify,
    /// Sign a checkpoint over everything this node has seen
    Checkpoint,
    /// Witness tooling: sign, list, and exchange checkpoint streams
    Witness {
        #[command(subcommand)]
        cmd: WitnessCmd,
    },
    /// Run the node HTTP API + ledger explorer (mirror node)
    Serve {
        #[arg(long, default_value = "127.0.0.1:7474")]
        addr: String,
        /// Accept no new entries at all (pure view/witness mirror)
        #[arg(long)]
        read_only: bool,
        /// Max POST /v1/entries per peer IP per minute (0 = unlimited)
        #[arg(long = "submit-per-min", default_value_t = 60)]
        submit_per_min: u32,
        /// Max POST /v1/sync/haves per peer IP per minute (0 = unlimited)
        #[arg(long = "haves-per-min", default_value_t = 120)]
        haves_per_min: u32,
    },
    /// Signet Personal Vault: identities, signing, field-level encryption
    #[command(alias = "wallet")]
    Signet {
        #[command(subcommand)]
        cmd: WalletCmd,
    },
    /// Identity attestations: bind keys to names/roles, cosign for weight
    Attest {
        #[command(subcommand)]
        cmd: AttestCmd,
    },
    /// Writer policy: gate validators' namespaces; observers stay free
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Network mode: who may join and sync (permissioned vs permissionless)
    Network {
        #[command(subcommand)]
        cmd: NetworkCmd,
    },
    /// Governance manifests: the on-ledger policy chain for official meshes
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
    /// Recorded feed disputes + any resolution records referencing them
    Disputes,
    /// Show and verify this code's genesis record - the founder-signed
    /// statement every ledger seeded from this code begins with
    Genesis,
    /// Party signatures: the people a record is about must sign it
    Parties {
        #[command(subcommand)]
        cmd: PartiesCmd,
    },
    /// Document contracts: predicate rules governed documents must satisfy
    Contract {
        #[command(subcommand)]
        cmd: ContractCmd,
    },
    /// Pull missing entries from peer node(s) - bloom-filter reconciliation
    Sync {
        /// Peer: bare host:port (native p2p protocol) or http://host:port
        #[arg(long = "peer", required = true)]
        peers: Vec<String>,
        /// Max entries per page request
        #[arg(long, default_value_t = 500)]
        page: usize,
    },
    /// Run the always-on node: native p2p sync listener + auto-sync loop
    Node {
        /// Listen address for the native p2p sync protocol (any node can dial this)
        #[arg(long, default_value = "0.0.0.0:7476")]
        addr: String,
        /// Peers to pull from every cycle (repeatable: host:port or http://…)
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Seconds between sync cycles (0 = serve only, no auto-sync)
        #[arg(long, default_value_t = 300)]
        every: u64,
        /// Discover LAN peers via mDNS every cycle and pull from them too
        #[arg(long)]
        discover: bool,
        /// Sign a witness checkpoint whenever new entries arrive
        #[arg(long)]
        witness: bool,
        /// Also run the HTTP explorer/API on this address (for dApps/humans)
        #[arg(long)]
        http: Option<String>,
        /// Accept no new entries: pure view/witness mirror (--read-only)
        #[arg(long)]
        read_only: bool,
    },
    /// Find datu nodes on the local network (mDNS) and print sync addresses
    Discover {
        #[arg(long, default_value_t = 3)]
        seconds: u64,
    },
    /// Offline reconciliation files: request/answer/merge over any channel
    Delta {
        #[command(subcommand)]
        cmd: DeltaCmd,
    },
    /// Compare checkpoint streams / a bundle and prove contradictory histories
    ProveFork {
        /// First witness stream file
        #[arg(long, requires = "b", conflicts_with_all = ["against"])]
        a: Option<PathBuf>,
        /// Second witness stream file
        #[arg(long, requires = "a", conflicts_with_all = ["against"])]
        b: Option<PathBuf>,
        /// Full data bundle to check against this node's stored history
        #[arg(long, conflicts_with_all = ["a", "b"])]
        against: Option<PathBuf>,
        /// Write the evidence package (JSON) to this file
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show store summary
    Status,
    /// Export/import a sync bundle (USB, LAN copy, any file channel)
    Bundle {
        #[command(subcommand)]
        cmd: BundleCmd,
    },
}

#[derive(Subcommand)]
enum ContractCmd {
    /// Show a contract entry's spec (the rule itself)
    Show {
        /// Contract entry id (hex)
        #[arg(long)]
        id: String,
        /// Write the contract's wasm body to this file (audit what will run)
        #[arg(long = "wasm-out")]
        wasm_out: Option<PathBuf>,
    },
    /// Build a contract spec JSON: the rule shape before it is party-signed
    /// into a gov.contract document and published
    New {
        /// Document kind the contract admits, e.g. land.title.grant
        #[arg(long)]
        admits: String,
        /// wasm32 module implementing the predicate (base64-encoded into the
        /// spec); omit for a JSON-DSL skeleton to fill in by hand
        #[arg(long = "wasm-file", conflicts_with = "wasm_b64")]
        wasm_file: Option<PathBuf>,
        /// Already-compiled module bytes as base64 (rare; prefer --wasm-file)
        #[arg(long = "wasm-b64", conflicts_with = "wasm_file")]
        wasm_b64: Option<String>,
        /// Write the spec here instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Evaluate the contract an entry's document declares, condition by condition
    Check {
        /// Entry id (hex) of the governed document
        #[arg(long)]
        id: String,
    },
    /// Pending view of the contract an anchor entry declares: which
    /// citation-side conditions are already met by the evidence on this
    /// node (the walker behind "conditions outstanding" surfaces)
    Status {
        /// Anchor entry id (hex), e.g. the escrow agreement
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
enum BundleCmd {
    /// Write this node's full content to a file
    Export {
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify-then-merge a bundle into this node
    Import {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum WitnessCmd {
    /// Sign a checkpoint over everything this node has seen
    Sign,
    /// Show every signer's latest checkpoint (root of what they witnessed)
    List,
    /// Write a checkpoint-only stream (small - publishable anywhere)
    Export {
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify-then-merge a checkpoint stream
    Import {
        #[arg(long)]
        input: PathBuf,
    },
    /// Prove a checkpoint covered an entry: an offline-verifiable time
    /// attestation ("this witness's ledger had seen this entry by now")
    Prove {
        /// Entry id (hex) whose presence the checkpoint attests
        #[arg(long)]
        entry: String,
        /// Checkpoint id (hex) on this node; default: sign a fresh one now
        #[arg(long)]
        checkpoint: Option<String>,
        /// Write the proof artifact (JSON) here instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a coverage proof offline: checkpoint signatures plus the
    /// Merkle path to the covered entry, zero other context
    VerifyProof {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum DeltaCmd {
    /// Write a "what I have" request file (carry it to any peer by any channel)
    Make {
        #[arg(long)]
        out: PathBuf,
    },
    /// Answer a request file with the entries the requester lacks
    Answer {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify-then-merge a response file into this node
    Merge {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum AttestCmd {
    /// Publish an attestation binding claims to a subject key (you are the attestor)
    Create {
        /// Subject: Ed25519 public key (hex) - from `datu keys` or `wallet show`
        #[arg(long)]
        subject: String,
        /// Free-form claims as JSON, e.g. '{"legal_name":"Acme Ltd","role":"bidder"}'
        #[arg(long)]
        claims: String,
        /// Optional human-readable subject label, e.g. "Acme Ltd"
        #[arg(long)]
        label: Option<String>,
    },
    /// Cosign an existing attestation (adds your node's weight to it)
    Cosign {
        /// Attestation entry id (hex)
        #[arg(long)]
        id: String,
    },
    /// Revoke an attestation, or a subject key directly (the ejection path
    /// for explicit members/writers): a new `identity.revoke` statement,
    /// never an edit
    Revoke {
        /// Attestation entry id (hex) to revoke
        #[arg(long, group = "target")]
        id: Option<String>,
        /// Subject key (hex) to revoke without an attestation to name
        #[arg(long, group = "target")]
        key: Option<String>,
        /// Optional reason, kept on the ledger for the audit trail
        #[arg(long)]
        reason: Option<String>,
    },
    /// Show attestations for a subject key, or one attestation with cosigners
    Status {
        #[arg(long, conflicts_with = "id")]
        subject: Option<String>,
        #[arg(long, conflicts_with = "subject")]
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Write this node's writer policy (gated namespaces, trust roots)
    Init {
        /// Trust root key: its attestations admit writers (repeatable)
        #[arg(long = "attestor", value_delimiter = ',')]
        attestors: Vec<String>,
        /// Explicitly admitted writer key (repeatable)
        #[arg(long = "writer", value_delimiter = ',')]
        writers: Vec<String>,
        /// Gated namespace pattern, e.g. 'gov.*' (repeatable; default gov.* + identity.attest + identity.revoke)
        #[arg(long = "ns", value_delimiter = ',')]
        gated: Vec<String>,
        /// Cosigners required on an attestation for admission (0 = attestor alone suffices)
        #[arg(long, default_value_t = 0)]
        min_cosigners: usize,
        /// Party role gated documents must carry a verified signature for (repeatable, any key)
        #[arg(long = "require-role", value_delimiter = ',')]
        require_roles: Vec<String>,
        /// Per-namespace party rule: NS:ROLE[@FIELD][=KEY] (repeatable).
        /// `gov.titles.*:holder@holder_key` binds the holder role to the key
        /// named in the document's holder_key field.
        #[arg(long = "rule")]
        rules: Vec<String>,
        /// Field that must be ENCRYPTED in that namespace: NS:FIELD
        /// (repeatable). Personal data is never published in plaintext.
        #[arg(long = "seal-field")]
        seal_fields: Vec<String>,
        /// Cap entries per author in a namespace: NS:N (repeatable). N=1
        /// means one-per-author - one ballot per voter in an election
        /// namespace; duplicates are denied at admission.
        #[arg(long = "max-per-author")]
        max_per_author: Vec<String>,
        /// Accept no new entries at all (pure view/witness mirror)
        #[arg(long)]
        readonly: bool,
    },
    /// Show the current policy (or say you are a free observer)
    Show,
    /// Delete the policy - this node becomes a free, open observer
    Clear,
}

#[derive(Subcommand)]
enum NetworkCmd {
    /// Write this node's network policy (the join gate; writes stay policy.json)
    Init {
        /// 'permissioned' (join = members + attestations) or 'permissionless'
        #[arg(long)]
        mode: String,
        /// Mesh id: nodes only sync with peers carrying the same id
        /// (empty = the open network)
        #[arg(long, default_value = "")]
        network_id: String,
        /// Admitted member key, hex ed25519 (repeatable)
        #[arg(long = "member", value_delimiter = ',')]
        members: Vec<String>,
        /// Attestation root key: any node it attests on-ledger is admitted (repeatable)
        #[arg(long = "root", value_delimiter = ',')]
        roots: Vec<String>,
        /// Pin the governance manifest root key (hex): this node compiles
        /// its writer policy from the on-ledger chain
        /// gov.mesh.<network-id>.policy (fail-closed without a valid chain)
        #[arg(long = "manifest-root")]
        manifest_root: Option<String>,
    },
    /// Show the current network policy (or say you are the open network)
    Show,
    /// Delete the network policy - this node becomes the open network
    Clear,
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Write a manifest template to start a chain from (this node = first root)
    Init {
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Publish the next manifest entry, authored by this node's key -
    /// must be a root of the current manifest (or the founder of the first)
    Publish {
        #[arg(long)]
        file: PathBuf,
        /// Publish despite stale governance evidence (roots changed while this
        /// node could not establish that its manifest is the newest one)
        #[arg(long)]
        accept_stale: bool,
    },
    /// Show the compiled policy + chain provenance this node enforces
    Show,
    /// Verify the chain this node holds (signatures, lineage, authorship,
    /// policy versions) without needing any publishing authority
    Verify {
        /// Also verify a manifest file: would publishing it extend the chain,
        /// and is this node's key allowed to sign it?
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Print the verified manifest chain, oldest first
    History,
    /// Print whether this node's governance is current, stale, unverified or
    /// conflicted - and why
    Status,
    /// Show competing manifest claims (a split), if any
    Conflicts,
}

#[derive(Subcommand)]
enum PartiesCmd {
    /// Sign a document as a party (consent) using this node's identity
    Sign {
        /// Party role: registrar, holder, witness…
        #[arg(long)]
        role: String,
        /// Transaction kind when the input is a bare document (e.g. land.title.application)
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify every party signature on a published entry
    Show {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Create a new identity (encrypted keychain entry)
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// List identities
    List,
    /// Show an identity's public keys
    Show {
        #[arg(long)]
        name: String,
    },
    /// Sign a dApp entry request → returns the signed entry (submit to any node)
    Sign {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Encrypt selected fields of a JSON document to reader seal key(s)
    Seal {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        /// Reader X25519 seal public key(s) (hex, comma-separated for multiple)
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// Read seal key(s) from top-level document field(s): a hex string or
        /// an array of hex strings (e.g. holder_seal)
        #[arg(long = "to-field", value_delimiter = ',')]
        to_fields: Vec<String>,
        #[arg(long)]
        input: PathBuf,
        /// Comma-separated top-level field names to encrypt
        #[arg(long)]
        fields: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Seal selected fields for deferred delivery: ciphertext lands now,
    /// the key half only at release (fields stay unopenable until then)
    SealDeferred {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        /// Holder X25519 seal public key (hex) the release will address
        #[arg(long, conflicts_with = "to_field")]
        to: Option<String>,
        /// Read the holder's seal key from this top-level document field
        #[arg(long = "to-field", conflicts_with = "to")]
        to_field: Option<String>,
        #[arg(long)]
        input: PathBuf,
        /// Comma-separated top-level field names to defer
        #[arg(long)]
        fields: String,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Where to write the release secrets (default: <input>.release.json)
        #[arg(long = "release-out")]
        release_out: Option<PathBuf>,
    },
    /// Attach a deferred field's release half: emits the object a release
    /// entry carries (sealed to the nominated holder)
    ReleaseDeferred {
        #[arg(long)]
        input: PathBuf,
        /// Field name of the deferred object inside the input document
        #[arg(long)]
        field: String,
        /// Release secrets written by seal-deferred
        #[arg(long, required_unless_present = "recover")]
        release: Option<PathBuf>,
        /// Recover the release secret from the issuer's own custody copy
        /// sealed in the field (safety net when the secrets file is lost)
        #[arg(long, requires_all = ["name", "passphrase"])]
        recover: bool,
        /// Issuer identity that sealed the field (with --recover)
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Open a deferred field with its published release object
    OpenDeferred {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        field: String,
        /// Release object (or any document containing one)
        #[arg(long)]
        release: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Decrypt sealed fields addressed to one of your identities
    Open {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export an identity as an encrypted backup (offline copy / move devices)
    Export {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        /// Passphrase protecting the backup file (may differ; min 8 chars)
        #[arg(long)]
        backup_passphrase: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Import an identity backup into this wallet
    Import {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        backup_passphrase: Option<String>,
        /// Import under a different name if it already exists here
        #[arg(long)]
        rename: Option<String>,
    },
    /// Run the local Signet service: a browser Signet extension / dApp talks
    /// to this process instead of holding keys in JS (paired with a token, loopback only)
    Serve {
        #[arg(long, default_value = "127.0.0.1:7482")]
        addr: String,
        /// Extra browser origin allowed to call the bridge (repeatable);
        /// extension pages and http://127.0.0.1:5173 are always allowed
        #[arg(long = "allow-origin")]
        allow_origins: Vec<String>,
    },
    /// Sign a document's party role from the wallet - citizen consent (e.g. as holder)
    CosignDoc {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        /// Party role, e.g. holder
        #[arg(long)]
        role: String,
        /// Transaction kind when the input is a bare document (e.g. land.title.application)
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Sign a login challenge with a wallet identity (SignetAuth): the
    /// assertion a relying party verifies to log you in - never a ledger entry
    AuthAssert {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
        /// Relying party identifier, e.g. app.example.com
        #[arg(long)]
        rp_id: String,
        /// Origin the login request came from, e.g. https://app.example.com
        #[arg(long)]
        origin: String,
        /// Single-use nonce issued by the relying party (32 hex chars)
        #[arg(long)]
        nonce: String,
        /// Challenge expiry: milliseconds since Unix epoch
        #[arg(long)]
        expires_at_ms: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

struct Node {
    store: Store,
    key: SigningKey,
    pq_key: datu_core::pq::PqPrivateKey,
    identity: String,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn s<T, E: Display>(r: Result<T, E>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}

fn parse_id(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad entry id '{hex_str}': {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("entry id must be 32 bytes: '{hex_str}'"))
}

fn short(h: &str) -> &str {
    &h[..8.min(h.len())]
}

fn get_passphrase(flag: Option<String>) -> Result<String, String> {
    flag.or_else(|| std::env::var("DATU_WALLET_PASS").ok())
        .ok_or_else(|| "pass --passphrase or set DATU_WALLET_PASS".to_string())
}

fn get_backup_passphrase(flag: Option<String>) -> Result<String, String> {
    flag.or_else(|| std::env::var("DAG_BACKUP_PASS").ok())
        .ok_or_else(|| "pass --backup-passphrase or set DAG_BACKUP_PASS".to_string())
}

fn cmd_wallet_export(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    backup_passphrase: &str,
    out: &Path,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let backup = wallet.export_identity(name, passphrase, backup_passphrase)?;
    let json = serde_json::to_string_pretty(&backup).map_err(|e| e.to_string())?;
    std::fs::write(out, &json).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600));
    }
    println!("backup written: {}", out.display());
    println!(
        "  identity '{}' · ed {}",
        backup.name,
        short(&backup.ed_public)
    );
    println!("  encrypted with the backup passphrase - keep the two apart");
    Ok(())
}

fn cmd_wallet_import(
    data_dir: &Path,
    input: &Path,
    backup_passphrase: &str,
    rename: Option<String>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let backup: datu_wallet::IdentityBackup =
        serde_json::from_str(&text).map_err(|e| format!("not a datu identity backup: {e}"))?;
    let public = wallet.import_identity(&backup, backup_passphrase, rename.as_deref())?;
    println!("identity imported: {}", public.name);
    println!("  author (ed25519): {}", public.ed_public);
    println!("  seal   (x25519):  {}", public.seal_public);
    println!("  it unlocks with the backup passphrase you just used");
    Ok(())
}

fn write_output(out: &Option<PathBuf>, text: &str) -> Result<(), String> {
    match out {
        Some(path) => {
            std::fs::write(path, text)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            println!("written: {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}

pub(crate) fn policy_path(data_dir: &Path) -> PathBuf {
    data_dir.join("policy.json")
}

/// Load this node's writer policy, if any. `None` = free, open observer.
pub(crate) fn read_policy(data_dir: &Path) -> Result<Option<WritePolicy>, String> {
    let path = policy_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    WritePolicy::from_json(&text).map(Some)
}

/// The policy a long-running service enforces. Precedence: a pinned
/// governance manifest (network.json → manifest_root) **replaces**
/// policy.json - the manifest is the auditable, on-ledger source of official
/// admission; policy.json stays for ungoverned local gating. `--read-only`
/// freezes the node regardless of source. Fail-closed: a pinned root without
/// a verifiable chain is an error, never a silent fallback - unless
/// `allow_bootstrap`, which the founding node needs in order to publish
/// manifest entry #0 at all.
pub(crate) fn effective_policy(
    data_dir: &Path,
    read_only: bool,
    allow_bootstrap: bool,
) -> Result<Option<WritePolicy>, String> {
    let network = read_network(data_dir)?;
    if let Some(net) = &network {
        if let Some(root) = &net.manifest_root {
            let store = Store::open(&data_dir.join("node.db")).map_err(|e| e.to_string())?;
            let compiled =
                datu_store::manifest::compile(&store, &net.network_id, std::slice::from_ref(root))
                    .map_err(|e| format!("governance manifest: {e}"))?;
            if let Some(compiled) = compiled {
                return Ok(match read_only {
                    true => Some(WritePolicy::readonly()),
                    false => Some(compiled.policy),
                });
            }
            if !allow_bootstrap {
                return Err(format!(
                    "network.json pins manifest root {} but no verifiable manifest exists in {} - sync one, publish one (`datu manifest publish`), or clear the pin (fail-closed)",
                    short(root),
                    datu_store::manifest::manifest_namespace(&net.network_id)
                ));
            }
            // Bootstrap: this node may ingest the chain and nothing else, so
            // it can pull governance from a peer (or a USB bundle) without
            // admitting a single data entry. Everything else waits.
            return Ok(Some(WritePolicy::bootstrap(
                &datu_store::manifest::manifest_namespace(&net.network_id),
            )));
        }
    }
    if read_only {
        return Ok(Some(WritePolicy::readonly()));
    }
    read_policy(data_dir)
}

// ---- network modes (who may JOIN; policy.json decides who may WRITE) ----

pub(crate) fn network_path(data_dir: &Path) -> PathBuf {
    data_dir.join("network.json")
}

/// Load this node's network policy, if any. `None` = permissionless, the
/// open network: anyone may sync (today's behavior).
pub(crate) fn read_network(data_dir: &Path) -> Result<Option<NetworkPolicy>, String> {
    let path = network_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    NetworkPolicy::from_json(&text).map(Some)
}

/// This node's mesh id ("" = the open network).
pub(crate) fn our_network_id(data_dir: &Path) -> Result<String, String> {
    Ok(read_network(data_dir)?
        .map(|net| net.network_id)
        .unwrap_or_default())
}

/// This node's introduction for walled syncs: sent when we are permissioned
/// or carry a mesh id; omitted on the open network so old peers keep working.
pub(crate) fn network_hello(
    data_dir: &Path,
    key: &SigningKey,
) -> Result<Option<NodeHello>, String> {
    match read_network(data_dir)? {
        Some(net) if net.is_permissioned() || !net.network_id.is_empty() => {
            Ok(Some(sign_hello(key, &net.network_id)))
        }
        _ => Ok(None),
    }
}

/// Parse a JSON document into a party-signed one: an already-signed
/// document is used as-is, a bare object is wrapped under `--kind`.
fn load_or_wrap_document(input: &Path, kind: Option<&str>) -> Result<SignedDocument, String> {
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    if let Ok(document) = serde_json::from_str::<SignedDocument>(&text) {
        return Ok(document);
    }
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("input must be JSON: {e}"))?;
    if !value.is_object() {
        return Err("document must be a JSON object".into());
    }
    let kind =
        kind.ok_or("pass --kind (e.g. land.title.application) or an already-signed document")?;
    Ok(SignedDocument::new(kind, value))
}

fn print_policy(policy: &WritePolicy) {
    if policy.readonly {
        println!("  mode: read-only - no new entries accepted (view + witness only)");
    } else {
        println!("  mode: validator gate");
        println!(
            "  gated namespaces: {}",
            if policy.gated.is_empty() {
                "(none)".to_string()
            } else {
                policy.gated.join(", ")
            }
        );
    }
    println!(
        "  trust roots:      {}",
        if policy.attestors.is_empty() {
            "(none)".to_string()
        } else {
            policy.attestors.join(", ")
        }
    );
    println!(
        "  explicit writers: {}",
        if policy.writers.is_empty() {
            "(none)".to_string()
        } else {
            policy.writers.join(", ")
        }
    );
    if !policy.allow.is_empty() {
        println!(
            "  admitted anyway:  {} (governance bootstrap - everything else waits for a verified chain)",
            policy.allow.join(", ")
        );
    }
    if policy.min_cosigners > 0 {
        println!("  min cosigners:    {}", policy.min_cosigners);
    }
    if !policy.required_roles.is_empty() {
        println!(
            "  required roles:   {} (party signature required, any key)",
            policy.required_roles.join(", ")
        );
    }
    for rule in &policy.rules {
        let parts: Vec<String> = rule
            .require
            .iter()
            .map(|r| {
                let mut part = r.role.clone();
                if let Some(field) = &r.bind_field {
                    part.push_str(&format!(" (key must equal doc field '{field}')"));
                }
                if let Some(key) = &r.key {
                    part.push_str(&format!(" (key {})", short(key)));
                }
                part
            })
            .collect();
        let mut line = format!("  rule {}: {}", rule.ns, parts.join(", "));
        if !rule.require_sealed.is_empty() {
            line.push_str(&format!(
                "   [encrypted fields: {}]",
                rule.require_sealed.join(", ")
            ));
        }
        if let Some(cap) = rule.max_entries_per_author {
            line.push_str(&format!("   [max {cap} entries per author]"));
        }
        println!("{line}");
    }
    if !policy.readonly {
        println!(
            "  observers:        unencumbered - a node with no policy.json accepts everything"
        );
    }
}

fn print_network(net: &NetworkPolicy) {
    if net.is_permissioned() {
        println!("  mode: permissioned - join = member key or an attestation from a root");
    } else if !net.network_id.is_empty() {
        println!(
            "  mode: permissionless on mesh '{}' - a free mirror of one walled mesh",
            net.network_id
        );
    } else {
        println!("  mode: permissionless - the open network, anyone may sync");
    }
    if !net.network_id.is_empty() {
        println!(
            "  mesh:              {} (peers presenting any other id are refused)",
            net.network_id
        );
    }
    if let Some(root) = &net.manifest_root {
        println!(
            "  governance:        manifest chain {} pinned to root {} (replaces policy.json; fail-closed)",
            datu_store::manifest_namespace(&net.network_id),
            short(root)
        );
    }
    println!(
        "  members:           {}",
        if net.members.is_empty() {
            "(none)".to_string()
        } else {
            net.members
                .iter()
                .map(|k| short(k).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "  attestation roots: {}",
        if net.roots.is_empty() {
            "(none)".to_string()
        } else {
            net.roots
                .iter()
                .map(|k| short(k).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!("  wall:              bundles, deltas and witness streams carry this mesh id; foreign ones are refused");
}

/// Parse `NS:ROLE[@FIELD][=KEY]` into a namespace party rule.
fn parse_rule(spec: &str) -> Result<datu_store::NamespaceRule, String> {
    let (ns, rest) = spec
        .split_once(':')
        .ok_or("rule must look like 'gov.titles.*:holder@holder_key'")?;
    let (rest, key) = match rest.split_once('=') {
        Some((r, k)) => (r, Some(k.to_string())),
        None => (rest, None),
    };
    let (role, bind_field) = match rest.split_once('@') {
        Some((r, f)) => (r, Some(f.to_string())),
        None => (rest, None),
    };
    if ns.trim().is_empty() || role.trim().is_empty() {
        return Err(format!(
            "bad rule '{spec}': namespace and role must be non-empty"
        ));
    }
    if let Some(key) = &key {
        parse_id(key)
            .map_err(|_| format!("rule key '{key}' is not a 32-byte Ed25519 key (hex)"))?;
    }
    Ok(datu_store::NamespaceRule {
        ns: ns.trim().to_string(),
        require: vec![datu_store::RoleRule {
            role: role.trim().to_string(),
            key,
            bind_field,
        }],
        require_sealed: vec![],
        max_entries_per_author: None,
    })
}

/// Parse `NS:N` into (namespace, max entries per author) for per-author caps.
fn parse_max_per_author(spec: &str) -> Result<(String, u32), String> {
    let (ns, n) = spec
        .split_once(':')
        .ok_or_else(|| format!("bad --max-per-author '{spec}': expected NS:N"))?;
    if ns.trim().is_empty() {
        return Err(format!(
            "bad --max-per-author '{spec}': namespace must be non-empty"
        ));
    }
    let cap: u32 = n
        .trim()
        .parse()
        .map_err(|_| format!("bad --max-per-author '{spec}': N must be a number"))?;
    if cap == 0 {
        return Err(format!(
            "bad --max-per-author '{spec}': N must be at least 1 (0 would reject everyone)"
        ));
    }
    Ok((ns.trim().to_string(), cap))
}

/// Parse `NS:FIELD` into (namespace, field) for required encryption.
fn parse_seal_field(spec: &str) -> Result<(String, String), String> {
    match spec.split_once(':') {
        Some((ns, field)) if !ns.trim().is_empty() && !field.trim().is_empty() => {
            Ok((ns.trim().to_string(), field.trim().to_string()))
        }
        _ => Err(format!("bad --seal-field '{spec}': expected NS:FIELD")),
    }
}

fn cmd_wallet_create(data_dir: &Path, name: &str, passphrase: &str) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let public = wallet.create(name, passphrase)?;
    println!("identity created: {}", public.name);
    println!("  author  (ed25519):  {}", public.ed_public);
    println!(
        "  pq      (mldsa65):  {}…",
        &public.pq_public[..16.min(public.pq_public.len())]
    );
    println!("  seal    (x25519):   {}", public.seal_public);
    println!("keystore encrypted with your passphrase - keys never leave this wallet unencrypted");
    Ok(())
}

fn cmd_wallet_list(data_dir: &Path) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identities = wallet.list()?;
    if identities.is_empty() {
        println!("no identities - run `datu wallet create --name NAME`");
        return Ok(());
    }
    println!(
        "{:<12}  {:<16}  {:<8}  seal key (x25519)",
        "name", "author(ed)", "created"
    );
    for id in identities {
        println!(
            "{:<12}  {:<16}  {:<8}  {}",
            id.name,
            short(&id.ed_public),
            "",
            id.seal_public
        );
    }
    Ok(())
}

fn cmd_wallet_show(data_dir: &Path, name: &str) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet
        .list()?
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| format!("identity '{name}' not found"))?;
    println!("name:            {}", identity.name);
    println!("author (ed25519): {}", identity.ed_public);
    println!(
        "pq (mldsa65):     {}…",
        &identity.pq_public[..16.min(identity.pq_public.len())]
    );
    println!("seal (x25519):    {}", identity.seal_public);
    println!("publish this seal key so others can encrypt fields to you");
    Ok(())
}

fn cmd_wallet_sign(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    request_path: &Path,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet.load(name, passphrase)?;
    let text = std::fs::read_to_string(request_path)
        .map_err(|e| format!("cannot read {}: {e}", request_path.display()))?;
    let request: SignRequest =
        serde_json::from_str(&text).map_err(|e| format!("bad sign request: {e}"))?;
    let entry = entry_from_sign_request(&identity, &request)?;
    let id = s(entry.id())?;
    let json = serde_json::to_string_pretty(&s(serve::entry_full_json(&entry))?)
        .map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!(
        "signed as {} seq {} → entry {}",
        short(&identity.public.ed_public),
        entry.body.seq,
        hex::encode(id)
    );
    println!("submit: POST /v1/entries to any node");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_wallet_seal(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    to: &[String],
    to_fields: &[String],
    input: &Path,
    fields: &str,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet.load(name, passphrase)?;
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let mut document: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("input must be a JSON object: {e}"))?;
    // Readers = explicit --to keys plus seal keys published inside the
    // document itself (e.g. holder_seal): the enclosure is written to the
    // registry office AND to each party whose data it is.
    let mut readers: Vec<String> = to.to_vec();
    for field in to_fields {
        match document.get(field) {
            Some(serde_json::Value::String(key)) => readers.push(key.clone()),
            Some(serde_json::Value::Array(items)) => {
                for item in items {
                    if let Some(key) = item.as_str() {
                        readers.push(key.to_string());
                    }
                }
            }
            _ => {
                return Err(format!(
                    "document has no seal key in field '{field}' (expected a hex string or array)"
                ))
            }
        }
    }
    readers.sort();
    readers.dedup();
    if readers.is_empty() {
        return Err("pass at least one reader seal key: --to KEY or --to-field FIELD".into());
    }
    let field_names: Vec<String> = fields
        .split(',')
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .collect();
    let sealed = identity.seal_fields(&mut document, &field_names, &readers)?;
    let json = serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!(
        "{sealed} field(s) sealed to {} reader(s); everything else stays public",
        readers.len()
    );
    Ok(())
}

fn cmd_wallet_open(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    input: &Path,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet.load(name, passphrase)?;
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let mut document: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("input must be a JSON object: {e}"))?;
    let mut opened = identity.open_fields(&mut document)?;
    // Party-signed documents carry their payload under `doc`: open sealed
    // fields there too, so holders can read what they signed.
    let signed_document = document.get("doc").map(|d| d.is_object()).unwrap_or(false)
        && document.get("parties").is_some();
    if signed_document {
        if let Some(inner) = document.get_mut("doc") {
            let (inner_opened, inner_skipped) = identity.open_fields(inner)?;
            opened.0 += inner_opened;
            opened.1 += inner_skipped;
        }
    }
    let (opened, skipped) = opened;
    let json = serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!(
        "{opened} field(s) decrypted for {}, {skipped} sealed for other readers",
        identity.public.name
    );
    Ok(())
}

/// Seal selected fields for deferred delivery. The document carries
/// unopenable ciphertext from day one; the release secrets come back as a
/// side file the issuer keeps until the release entry publishes them.
#[allow(clippy::too_many_arguments)]
fn cmd_wallet_seal_deferred(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    to: &Option<String>,
    to_field: &Option<String>,
    input: &Path,
    fields: &str,
    out: &Option<PathBuf>,
    release_out: &Option<PathBuf>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet.load(name, passphrase)?;
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let mut document: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("input must be a JSON object: {e}"))?;
    let holder_key = match (to, to_field) {
        (Some(key), None) => key.clone(),
        (None, Some(field)) => document
            .get(field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("document has no seal key string in field '{field}'"))?
            .to_string(),
        _ => return Err("pass exactly one holder key: --to KEY or --to-field FIELD".into()),
    };
    let field_names: Vec<String> = fields
        .split(',')
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .collect();
    let releases = identity.seal_deferred_fields(&mut document, &field_names, &holder_key)?;
    if releases.is_empty() {
        return Err("none of the named fields are present in the document".into());
    }
    let json = serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    let map: serde_json::Map<String, serde_json::Value> = releases
        .iter()
        .map(|(field, secret)| (field.clone(), serde_json::json!(hex::encode(secret))))
        .collect();
    let release_doc = serde_json::json!({"version": 1, "fields": map});
    let release_path = release_out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.release.json", input.display())));
    std::fs::write(
        &release_path,
        serde_json::to_string_pretty(&release_doc).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("cannot write {}: {e}", release_path.display()))?;
    println!(
        "{} field(s) sealed for deferred delivery to {}",
        releases.len(),
        short(&holder_key)
    );
    println!(
        "  release secrets written to {} - keep them off the ledger until the release",
        release_path.display()
    );
    println!("  after release, the holder opens with: datu wallet open-deferred");
    Ok(())
}

/// Attach a deferred field's release half: usually needs public keys only,
/// because releasing is an act of the ledger, not of the seal key. With
/// `--recover` the issuer's identity opens the sealed custody copy instead
/// of reading a secrets file.
#[allow(clippy::too_many_arguments)]
fn cmd_wallet_release_deferred(
    data_dir: &Path,
    input: &Path,
    field: &str,
    release: Option<&PathBuf>,
    recover: bool,
    name: Option<&str>,
    passphrase: Option<&str>,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let document: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("input must be a JSON object: {e}"))?;
    let field_value = document
        .get(field)
        .cloned()
        .ok_or_else(|| format!("input has no field '{field}'"))?;
    let deferred: datu_wallet::DeferredField = serde_json::from_value(field_value)
        .map_err(|e| format!("'{field}' is not a deferred-delivery field: {e}"))?;
    let secret: [u8; 32] = if recover {
        let name = name.ok_or("--recover needs --name")?;
        let passphrase = passphrase.ok_or("--recover needs --passphrase")?;
        let identity = datu_wallet::Wallet::open(data_dir).load(name, passphrase)?;
        let secret = datu_wallet::recover_release_secret(
            &deferred,
            &identity.public.seal_public,
            &identity.seal,
        )?;
        println!("release secret recovered from the issuer's sealed custody copy");
        secret
    } else {
        let release = release.ok_or("pass --release secrets.json or --recover")?;
        let release_text = std::fs::read_to_string(release)
            .map_err(|e| format!("cannot read {}: {e}", release.display()))?;
        let release_doc: serde_json::Value = serde_json::from_str(&release_text)
            .map_err(|e| format!("release secrets must be JSON: {e}"))?;
        let secret_hex = release_doc["fields"][field]
            .as_str()
            .ok_or_else(|| format!("release secrets have no entry for '{field}'"))?;
        hex::decode(secret_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or("release secret is not a 32-byte hex value")?
    };
    let share = datu_wallet::attach_release(&deferred, &secret)?;
    let json = serde_json::to_string_pretty(&share).map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!(
        "release half for '{field}' sealed to {} - put this object in the release entry",
        short(&deferred.release_to)
    );
    Ok(())
}

/// Open a deferred field with its published release object: the holder
/// identity recomposes the content key and checks the commitment.
fn cmd_wallet_open_deferred(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    input: &Path,
    field: &str,
    release: &Path,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet.load(name, passphrase)?;
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let document: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("input must be a JSON object: {e}"))?;
    let field_value = document
        .get(field)
        .cloned()
        .ok_or_else(|| format!("input has no field '{field}'"))?;
    let deferred: datu_wallet::DeferredField = serde_json::from_value(field_value)
        .map_err(|e| format!("'{field}' is not a deferred-delivery field: {e}"))?;
    let release_text = std::fs::read_to_string(release)
        .map_err(|e| format!("cannot read {}: {e}", release.display()))?;
    let release_doc: serde_json::Value =
        serde_json::from_str(&release_text).map_err(|e| format!("release must be JSON: {e}"))?;
    let share = datu_wallet::SealedShare::find(&release_doc)
        .ok_or("release file carries no share object (expected a 'datu-share-v2' object)")?;
    let plaintext = datu_wallet::open_deferred(
        &deferred,
        &share,
        &identity.public.seal_public,
        &identity.seal,
    )?;
    let value: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("decrypted field is not valid JSON: {e}"))?;
    let json = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!("field '{field}' opened for {}", identity.public.name);
    Ok(())
}

fn payload_preview(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(60).collect()
}

/// Open this node with the policy a *writer* must respect: a pinned
/// governance manifest wins, and a pin with no verifiable chain fails closed.
fn load_node(dir: &Path) -> Result<Node, String> {
    open_node(dir, effective_policy(dir, false, false)?)
}

/// Open this node for the one bootstrap case - founding or publishing a
/// manifest - where a pinned chain may not exist yet. Falls back to
/// policy.json only in that case, so entry #0 can be published at all.
fn load_node_bootstrap(dir: &Path) -> Result<Node, String> {
    open_node(dir, effective_policy(dir, false, true)?)
}

/// Open this node for commands that only read. No admission policy: a
/// governance break must never stop anyone inspecting the evidence.
fn load_node_reader(dir: &Path) -> Result<Node, String> {
    open_node(dir, None)
}

fn open_node(dir: &Path, policy: Option<WritePolicy>) -> Result<Node, String> {
    let secret_path = dir.join("secret.key");
    if !secret_path.exists() {
        return Err(format!(
            "no node at {} - run `datu init` first",
            dir.display()
        ));
    }
    let hex_secret = std::fs::read_to_string(&secret_path).map_err(|e| e.to_string())?;
    let bytes = hex::decode(hex_secret.trim()).map_err(|_| "corrupt secret.key".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "corrupt secret.key".to_string())?;
    let key = SigningKey::from_bytes(&arr);
    let pq_secret_path = dir.join("secret.mldsa65");
    if !pq_secret_path.exists() {
        return Err(format!(
            "node at {} is missing its post-quantum key - re-run `datu init`",
            dir.display()
        ));
    }
    let pq_hex = std::fs::read_to_string(&pq_secret_path).map_err(|e| e.to_string())?;
    let pq_key = s(datu_core::pq::sk_from_hex(pq_hex.trim()))?;
    let identity = hex::encode(key.verifying_key().as_bytes());
    let store = s(Store::open_with_policy(&dir.join("node.db"), policy))?;
    Ok(Node {
        store,
        key,
        pq_key,
        identity,
    })
}

fn cmd_init(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let secret_path = dir.join("secret.key");
    if secret_path.exists() {
        return Err(format!("node already exists at {}", dir.display()));
    }
    let key = SigningKey::generate(&mut OsRng);
    let pq_secret_path = dir.join("secret.mldsa65");
    let (_pq_pk, pq_key) = s(datu_core::pq::keypair())?;
    std::fs::write(&secret_path, hex::encode(key.to_bytes())).map_err(|e| e.to_string())?;
    std::fs::write(&pq_secret_path, datu_core::pq::sk_to_hex(&pq_key))
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&secret_path, mode.clone());
        let _ = std::fs::set_permissions(&pq_secret_path, mode);
    }
    let identity = hex::encode(key.verifying_key().as_bytes());
    let _store = s(Store::open(&dir.join("node.db")))?;
    println!("node created: {}", dir.display());
    println!("identity:     {identity}");
    println!(
        "genesis:      {} - every ledger from this code begins with it (`datu genesis`)",
        short(datu_core::genesis::GENESIS_ID_HEX)
    );
    println!("signatures:   hybrid Ed25519 + ML-DSA-65 (quantum-resistant)");
    println!("records are append-only and content-addressed; nothing can be edited or deleted.");
    Ok(())
}

/// Show and verify the code-carried genesis record: the founder's signed
/// statement, the lineage mark of this codebase and every fork that keeps
/// it. Any tampering with the embedded constant fails verification here.
fn cmd_genesis(data_dir: &Path) -> Result<(), String> {
    let genesis = datu_core::genesis::genesis_entry().map_err(|e| e.to_string())?;
    let id = s(genesis.id().map_err(|e| e.to_string()))?;
    println!(
        "genesis record: {} (signature verified: Ed25519 + ML-DSA-65)",
        hex::encode(id)
    );
    println!("founder:        {}", datu_core::genesis::GENESIS_FOUNDER);
    println!("author key:     {}", genesis.body.author);
    println!(
        "namespace:      {} (seq 0, the first entry of every ledger)",
        genesis.body.namespace
    );
    let payload: serde_json::Value =
        s(serde_json::from_slice(&genesis.body.payload).map_err(|e| e.to_string()))?;
    if let Some(statement) = payload["statement"].as_str() {
        println!();
        for line in statement.lines() {
            println!("  | {line}");
        }
        println!();
    }
    let db = data_dir.join("node.db");
    if db.exists() {
        let store = s(Store::open(&db))?;
        if store.has_entry(&id).map_err(|e| e.to_string())? {
            println!("local ledger:   carries this genesis - lineage intact");
        } else {
            println!("local ledger:   MISSING this genesis - rebuilt from foreign code?");
        }
    } else {
        println!("local ledger:   none here yet (`datu init` starts one from this record)");
    }
    Ok(())
}

fn cmd_publish(
    node: &Node,
    ns: String,
    payload: Option<String>,
    file: Option<PathBuf>,
    refs: Vec<String>,
) -> Result<(), String> {
    let payload: Vec<u8> = if let Some(path) = file {
        std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?
    } else {
        payload
            .ok_or_else(|| "provide --payload TEXT or --file PATH".to_string())?
            .into_bytes()
    };
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "payload is {} bytes; limit is {MAX_PAYLOAD_BYTES}",
            payload.len()
        ));
    }
    let refs: Vec<[u8; 32]> = refs.iter().map(|r| parse_id(r)).collect::<Result<_, _>>()?;

    let latest = s(node.store.latest(&node.identity))?;
    let (seq, prev) = match &latest {
        Some(e) => (e.body.seq + 1, Some(s(e.id())?)),
        None => (0, None),
    };
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: node.identity.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: ns,
        seq,
        prev,
        refs,
        timestamp_ms: now_ms(),
        payload,
    };
    let entry = s(Entry::sign(body, &node.key, &node.pq_key))?;
    let id = s(entry.id())?;
    if !s(node.store.insert_entry(&entry))? {
        return Err("entry unexpectedly already present".into());
    }
    println!("published {} (seq {seq})", hex::encode(id));
    Ok(())
}

fn cmd_log(
    node: &Node,
    ns: Option<String>,
    author: Option<String>,
    limit: usize,
) -> Result<(), String> {
    let entries = s(node.store.list(ns.as_deref(), author.as_deref(), limit))?;
    if entries.is_empty() {
        println!("no entries");
        return Ok(());
    }
    for e in entries {
        let id = hex::encode(s(e.id())?);
        println!(
            "{}  {}  ns={} seq={}  {}",
            short(&id),
            short(&e.body.author),
            e.body.namespace,
            e.body.seq,
            payload_preview(&e.body.payload)
        );
    }
    Ok(())
}

fn cmd_get(node: &Node, id_hex: String) -> Result<(), String> {
    let id = parse_id(&id_hex)?;
    let e = s(node.store.get_entry(&id))?.ok_or_else(|| format!("entry {id_hex} not found"))?;
    let json = serde_json::json!({
        "id": hex::encode(s(e.id())?),
        "author": e.body.author,
        "author_pq": format!("{}…", &e.body.author_pq[..16.min(e.body.author_pq.len())]),
        "pq_alg": e.body.pq_alg,
        "namespace": e.body.namespace,
        "seq": e.body.seq,
        "prev": e.body.prev.map(hex::encode),
        "refs": e.body.refs.iter().map(hex::encode).collect::<Vec<_>>(),
        "timestamp_ms": e.body.timestamp_ms,
        "payload": String::from_utf8_lossy(&e.body.payload),
        "signature": hex::encode(e.signature),
        "pq_signature": format!("{}…", hex::encode(&e.pq_signature)[..32].to_string()),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn cmd_verify(node: &Node) -> Result<(), String> {
    let report = s(node.store.verify_all())?;
    println!(
        "OK: {} entries, {} feeds, {} checkpoints, {} pending links (unseen references, not errors), {} contract failures",
        report.entries,
        report.feeds,
        report.checkpoints,
        report.pending_links,
        report.contracts_failed
    );
    if report.contracts_failed > 0 {
        println!(
            "contracts: {} governed entries do not (or cannot) satisfy the contract they declare - evidence-grade here; `datu contract check --id` shows why",
            report.contracts_failed
        );
    }
    println!(
        "lineage: {}",
        if report.lineage {
            "intact - the code's genesis record is the first entry of this ledger"
        } else {
            "FOREIGN - the code's genesis record is missing: this ledger was built by genesis-stripped code"
        }
    );
    Ok(())
}

/// Show the rule itself: a contract entry's spec.
fn cmd_contract_show(node: &Node, id: String, wasm_out: Option<PathBuf>) -> Result<(), String> {
    let entry_id = parse_id(&id)?;
    let entry = s(node.store.get_entry(&entry_id))?
        .ok_or_else(|| format!("entry {id} is not on this node"))?;
    if !contract::is_contracts_namespace(&entry.body.namespace) {
        return Err(format!(
            "entry {id} is in namespace '{}', not a contract (contracts live in {} or its sub-namespaces)",
            entry.body.namespace,
            contract::CONTRACTS_NAMESPACE
        ));
    }
    let spec = ContractSpec::from_payload(&entry.body.payload).ok_or_else(|| {
        format!(
            "entry {id} is in the contracts namespace but carries no contract spec (expected a '{}' document holding the rule)",
            contract::CONTRACT_KIND
        )
    })?;
    println!(
        "contract {}  v{}  ns={}  author {} seq {}",
        short(&id),
        spec.version,
        entry.body.namespace,
        short(&entry.body.author),
        entry.body.seq
    );
    if let Some(path) = wasm_out {
        let body = spec
            .wasm
            .as_deref()
            .ok_or("this contract carries no wasm body (a JSON-DSL rule)")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| "the contract's wasm body is not valid base64".to_string())?;
        std::fs::write(&path, &bytes)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        println!(
            "wasm body written to {} ({} bytes, BLAKE3 {})",
            path.display(),
            bytes.len(),
            hex::encode(blake3::hash(&bytes).as_bytes())
        );
        match contract::wasm::check_module(&bytes) {
            Ok(exports) => println!(
                "module parses; exports: {}",
                if exports.is_empty() {
                    "(none)".to_string()
                } else {
                    exports.join(", ")
                }
            ),
            Err(e) => println!("warning: {e} - evaluation denies every document"),
        }
    }
    let mut json = serde_json::to_value(&spec).map_err(|e| e.to_string())?;
    // Elide the wasm body: it can be hundreds of KB of base64. `check`
    // executes the rule; `show` describes it.
    if let (Some(size), Some(serde_json::Value::String(wasm))) =
        (spec.wasm.as_ref().map(|b| b.len()), json.get_mut("wasm"))
    {
        *wasm = format!("<{size} bytes of base64 (elided; 'datu contract check' executes it)>");
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// Build a contract spec JSON. The wasm body is base64-encoded here so the
/// authoring flow never hand-rolls it; the spec still needs party signatures
/// (datu wallet cosign-doc --kind gov.contract) before `datu publish
/// --ns gov.contracts` can land it.
fn cmd_contract_new(
    admits: String,
    wasm_file: Option<PathBuf>,
    wasm_b64: Option<String>,
    out: Option<PathBuf>,
) -> Result<(), String> {
    let wasm = match (wasm_file, wasm_b64) {
        (Some(path), None) => {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let exports = contract::wasm::check_module(&bytes)?;
            let missing: Vec<&str> = ["memory", "alloc", "evaluate"]
                .into_iter()
                .filter(|required| !exports.iter().any(|name| name == required))
                .collect();
            if missing.is_empty() {
                println!("module parses; exports memory/alloc/evaluate");
            } else {
                println!(
                    "warning: module exports no {} - evaluation will fail closed until it does",
                    missing.join(", ")
                );
            }
            Some(base64::engine::general_purpose::STANDARD.encode(&bytes))
        }
        (None, Some(b64)) => Some(b64),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces the conflict"),
    };
    let mut spec = serde_json::json!({
        "version": contract::CONTRACT_VERSION,
        "admits": admits,
    });
    if let Some(body) = &wasm {
        spec["wasm"] = serde_json::json!(body);
    }
    let json = serde_json::to_string_pretty(&spec).map_err(|e| e.to_string())?;
    match &out {
        Some(path) => {
            std::fs::write(path, &json)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            println!("contract spec written to {}", path.display());
        }
        None => println!("{json}"),
    }
    match wasm {
        Some(body) => println!(
            "wasm body: {} bytes of base64 (the module runs sandboxed, fuel-metered, no host calls)",
            body.len()
        ),
        None => println!(
            "JSON-DSL skeleton: add requires_refs / requires_parties / deadlines, or pass --wasm-file"
        ),
    }
    println!(
        "next: sign it into a gov.contract document and publish, e.g.
  datu wallet cosign-doc --name <you> --role issuer --kind gov.contract --input <spec> --out contract.json
  datu publish --ns gov.contracts --file contract.json"
    );
    Ok(())
}

/// Re-run the contract an entry declares, condition by condition. The same
/// pure predicate admission uses, so open observers can evaluate what
/// validators enforce.
fn cmd_contract_check(node: &Node, id: String) -> Result<(), String> {
    let entry_id = parse_id(&id)?;
    let entry = s(node.store.get_entry(&entry_id))?
        .ok_or_else(|| format!("entry {id} is not on this node"))?;
    match s(node.store.check_contract(&entry))? {
        None => println!(
            "entry {} declares no contract (nothing to evaluate)",
            short(&id)
        ),
        Some(check) => {
            println!("entry       {}", short(&id));
            println!("document    kind '{}'", check.kind);
            println!(
                "contract    {} v{}",
                short(&hex::encode(check.contract_id)),
                check.version
            );
            println!(
                "verdict     {}",
                if check.admitted { "ADMITTED" } else { "DENIED" }
            );
            if !check.conditions.is_empty() {
                println!("conditions:");
                for condition in &check.conditions {
                    println!(
                        "  [{}] {} (required: {}, found: {})",
                        if condition.met { "met    " } else { "NOT MET" },
                        condition.requirement,
                        condition.required,
                        condition.found
                    );
                }
            }
            if !check.reasons.is_empty() {
                println!("reasons:");
                for reason in &check.reasons {
                    println!("  - {reason}");
                }
            }
        }
    }
    Ok(())
}

/// Pending view: judge the contract an anchor document declares over the
/// evidence that exists so far (every stored entry citing the anchor).
/// Party signatures, kind, window, and seals belong to the future satisfying
/// document; only citation-side conditions are judged here.
fn cmd_contract_status(node: &Node, id: String) -> Result<(), String> {
    let anchor_id = parse_id(&id)?;
    match s(node.store.contract_outlook(&anchor_id))? {
        None => println!(
            "entry {} declares no contract (nothing pending)",
            short(&id)
        ),
        Some(outlook) => {
            println!("anchor      {}", short(&id));
            println!("document    kind '{}'", outlook.kind);
            println!(
                "contract    {} v{}",
                short(&hex::encode(outlook.contract_id)),
                outlook.version
            );
            if !outlook.admits.is_empty() {
                println!(
                    "awaits      a '{}' document citing this anchor",
                    outlook.admits
                );
            }
            println!(
                "evidence    {} citing entries on this node",
                outlook.citing.len()
            );
            println!(
                "verdict     {}",
                if outlook.ready {
                    "READY - citation-side conditions are met; the satisfying document may land"
                } else {
                    "OUTSTANDING - citation-side conditions unmet"
                }
            );
            if !outlook.conditions.is_empty() {
                println!("conditions:");
                for condition in &outlook.conditions {
                    println!(
                        "  [{}] {} (required: {}, found: {})",
                        if condition.met { "met    " } else { "NOT MET" },
                        condition.requirement,
                        condition.required,
                        condition.found
                    );
                }
            }
            if !outlook.reasons.is_empty() {
                println!("reasons:");
                for reason in &outlook.reasons {
                    println!("  - {reason}");
                }
            }
            if !outlook.citing.is_empty() {
                println!("citing entries (the evidence so far):");
                for cited in &outlook.citing {
                    println!(
                        "  {}  kind {}  author {}  ts {}",
                        short(&hex::encode(cited.id)),
                        cited.kind.as_deref().unwrap_or("-"),
                        short(&cited.author),
                        cited.timestamp_ms
                    );
                }
            }
        }
    }
    Ok(())
}

fn cmd_checkpoint(node: &Node) -> Result<(), String> {
    let ids = s(node.store.entry_ids())?;
    let (id, height) = sign_checkpoint_into(&node.store, &node.key, &node.pq_key, &node.identity)?;
    let root = merkle_root(&ids);
    println!(
        "checkpoint {} (height {height}) over {} entries, root {}",
        hex::encode(id),
        ids.len(),
        hex::encode(root)
    );
    Ok(())
}

/// Sign and append a checkpoint over everything in the store. Shared by the
/// `checkpoint` command, witness flows, and the always-on node daemon.
pub(crate) fn sign_checkpoint_into(
    store: &Store,
    key: &SigningKey,
    pq_key: &datu_core::pq::PqPrivateKey,
    identity: &str,
) -> Result<([u8; 32], u64), String> {
    let ids = s(store.entry_ids())?;
    let root = merkle_root(&ids);
    let last = s(store.last_checkpoint(identity))?;
    let (height, prev) = match &last {
        Some(c) => (c.body.height + 1, Some(s(c.id())?)),
        None => (0, None),
    };
    let body = CheckpointBody {
        version: datu_core::CHECKPOINT_VERSION,
        signer: identity.to_string(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height,
        prev,
        timestamp_ms: now_ms(),
        entries_count: ids.len() as u64,
        entry_ids_root: root,
    };
    let checkpoint = s(Checkpoint::sign(body, key, pq_key))?;
    let id = s(checkpoint.id())?;
    if !s(store.append_checkpoint(&checkpoint))? {
        return Err("checkpoint unexpectedly already present".into());
    }
    Ok((id, height))
}

fn cmd_status(node: &Node) -> Result<(), String> {
    let entries = s(node.store.entry_count())?;
    let checkpoints = s(node.store.checkpoint_count())?;
    println!("identity:    {}", node.identity);
    println!("database:    {}", node.store.path().unwrap_or("<memory>"));
    println!("entries:     {entries}");
    println!("checkpoints: {checkpoints}");
    if let Some(c) = s(node.store.last_checkpoint(&node.identity))? {
        println!(
            "my last checkpoint: height {} covering {} entries, root {}",
            c.body.height,
            c.body.entries_count,
            hex::encode(c.body.entry_ids_root)
        );
    } else {
        println!("my last checkpoint: none (run `datu checkpoint`)");
    }
    Ok(())
}

fn cmd_bundle_export(node: &Node, mesh: &str, out: &Path) -> Result<(), String> {
    let bytes = s(node.store.export_bundle(mesh))?;
    std::fs::write(out, &bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "exported {} entries + checkpoints to {} ({} bytes)",
        s(node.store.entry_count())?,
        out.display(),
        bytes.len()
    );
    Ok(())
}

fn cmd_bundle_import(node: &Node, mesh: &str, input: &Path) -> Result<(), String> {
    let bytes =
        std::fs::read(input).map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let summary = s(node.store.import_bundle(&bytes, mesh))?;
    println!(
        "imported: {} new entries ({} already present{}), {} new checkpoints ({} already present)",
        summary.entries_new,
        summary.entries_existing,
        if summary.entries_denied > 0 {
            format!(", {} skipped by this node's policy", summary.entries_denied)
        } else {
            String::new()
        },
        summary.checkpoints_new,
        summary.checkpoints_existing
    );
    Ok(())
}

fn cmd_witness_list(node: &Node) -> Result<(), String> {
    let checkpoints = s(node.store.all_checkpoints())?;
    if checkpoints.is_empty() {
        println!("no checkpoints stored (run `datu witness sign`)");
        return Ok(());
    }
    let mut latest: std::collections::BTreeMap<String, &Checkpoint> =
        std::collections::BTreeMap::new();
    for cp in &checkpoints {
        let update = match latest.get(&cp.body.signer) {
            Some(prev) => prev.body.height < cp.body.height,
            None => true,
        };
        if update {
            latest.insert(cp.body.signer.clone(), cp);
        }
    }
    println!(
        "{:<16}  {:>6}  {:>8}  merkle root",
        "signer", "height", "entries"
    );
    for (signer, cp) in &latest {
        println!(
            "{}  {:>6}  {:>8}  {}",
            short(signer),
            cp.body.height,
            cp.body.entries_count,
            hex::encode(cp.body.entry_ids_root)
        );
    }
    Ok(())
}

fn cmd_witness_export(node: &Node, mesh: &str, out: &Path) -> Result<(), String> {
    let bytes = s(node.store.export_witness_stream(mesh))?;
    std::fs::write(out, &bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "exported witness stream: {} checkpoints to {} ({} bytes) - publish it anywhere",
        s(node.store.checkpoint_count())?,
        out.display(),
        bytes.len()
    );
    Ok(())
}

fn cmd_witness_import(node: &Node, mesh: &str, input: &Path) -> Result<(), String> {
    let bytes =
        std::fs::read(input).map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let summary = s(node.store.import_witness_stream(&bytes, mesh))?;
    println!(
        "imported checkpoints: {} new, {} already present",
        summary.checkpoints_new, summary.checkpoints_existing
    );
    Ok(())
}

/// Prove that a checkpoint covered an entry id: sign (or reuse) a
/// checkpoint over everything this node has seen, then emit the Merkle path
/// from the entry to the checkpoint's root. The artifact is self-contained
/// evidence - anyone can verify it offline with `witness verify-proof`.
fn cmd_witness_prove(
    node: &Node,
    entry_hex: String,
    checkpoint_hex: Option<String>,
    out: Option<PathBuf>,
) -> Result<(), String> {
    let entry_id = parse_id(&entry_hex)?;
    if s(node.store.get_entry(&entry_id))?.is_none() {
        return Err(format!(
            "entry {entry_hex} is not on this node - sync it first (a witness can only attest what it has seen)"
        ));
    }
    let checkpoint = match checkpoint_hex {
        Some(hex) => {
            let id = parse_id(&hex)?;
            s(node.store.all_checkpoints())?
                .into_iter()
                .find(|cp| s(cp.id()).map(|x| x == id).unwrap_or(false))
                .ok_or_else(|| {
                    format!("checkpoint {hex} is not on this node - sync or sign it first")
                })?
        }
        None => {
            // Fresh attestation: "as of now, this entry and everything else
            // I hold". The claimed time is this node's clock, accountable
            // like any witness statement.
            let (id, height) =
                sign_checkpoint_into(&node.store, &node.key, &node.pq_key, &node.identity)?;
            s(node.store.all_checkpoints())?
                .into_iter()
                .find(|cp| s(cp.id()).map(|x| x == id).unwrap_or(false))
                .ok_or_else(|| format!("signed checkpoint {} vanished", hex::encode(id)))
                .inspect(|cp| {
                    println!(
                        "signed checkpoint {} (height {height}) over {} entries",
                        hex::encode(id),
                        cp.body.entries_count
                    );
                })?
        }
    };
    let proof = s(node.store.coverage_proof(&entry_id, &checkpoint))?;
    let checkpoint_b64 =
        base64::engine::general_purpose::STANDARD.encode(s(borsh::to_vec(&checkpoint))?);
    let artifact = serde_json::json!({
        "version": 1,
        "checkpoint_b64": checkpoint_b64,
        "proof": proof,
    });
    let rendered = serde_json::to_string_pretty(&artifact).map_err(|e| e.to_string())?;
    match &out {
        Some(path) => {
            std::fs::write(path, &rendered)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            println!("coverage proof written to {}", path.display());
        }
        None => println!("{rendered}"),
    }
    println!(
        "entry {} is covered by witness {} at checkpoint height {} (claimed ts {})",
        short(&entry_hex),
        short(&checkpoint.body.signer),
        checkpoint.body.height,
        checkpoint.body.timestamp_ms
    );
    Ok(())
}

/// Verify a coverage-proof artifact with zero other context: decode the
/// checkpoint, verify both signatures, then walk the Merkle path to the
/// signed root.
fn cmd_witness_verify_proof(input: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let artifact: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("not a coverage-proof artifact: {e}"))?;
    let checkpoint_b64 = artifact["checkpoint_b64"]
        .as_str()
        .ok_or("artifact has no checkpoint_b64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(checkpoint_b64)
        .map_err(|_| "checkpoint_b64 is not valid base64".to_string())?;
    let checkpoint = Checkpoint::try_from_slice(&bytes)
        .map_err(|e| format!("checkpoint_b64 does not decode as a checkpoint: {e}"))?;
    s(checkpoint.verify())?;
    let proof: CoverageProof = serde_json::from_value(artifact["proof"].clone())
        .map_err(|e| format!("artifact proof does not parse: {e}"))?;
    s(proof.verify(&checkpoint))?;
    println!(
        "OK  entry {} was covered by witness {} at checkpoint {} (height {}, claimed ts {})",
        short(&proof.entry_id),
        short(&checkpoint.body.signer),
        short(&hex::encode(s(checkpoint.id())?)),
        checkpoint.body.height,
        checkpoint.body.timestamp_ms
    );
    Ok(())
}

fn read_witness_stream(path: &Path) -> Result<Vec<Checkpoint>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let stream = s(decode_witness_stream(&bytes))?;
    Ok(stream.checkpoints)
}

fn checkpoint_json(cp: &Checkpoint) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "id": hex::encode(s(cp.id())?),
        "signer": cp.body.signer,
        "height": cp.body.height,
        "prev": cp.body.prev.map(hex::encode),
        "timestamp_ms": cp.body.timestamp_ms,
        "entries_count": cp.body.entries_count,
        "entry_ids_root": hex::encode(cp.body.entry_ids_root),
        "signature": hex::encode(cp.signature),
        "pq_signature": hex::encode(&cp.pq_signature),
    }))
}

fn evidence_json(ev: &ForkEvidence) -> Result<serde_json::Value, String> {
    let checkpoints = ev
        .checkpoints
        .iter()
        .map(checkpoint_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(serde_json::json!({
        "kind": ev.kind,
        "signer": ev.signer,
        "height": ev.height,
        "description": ev.description,
        "checkpoints": checkpoints,
    }))
}

fn cmd_prove_fork(
    data_dir: &Path,
    a: Option<PathBuf>,
    b: Option<PathBuf>,
    against: Option<PathBuf>,
    out: Option<PathBuf>,
) -> Result<(), String> {
    let mut evidence: Vec<ForkEvidence> = if let (Some(fa), Some(fb)) = (&a, &b) {
        let stream_a = read_witness_stream(fa)?;
        let stream_b = read_witness_stream(fb)?;
        s(fork::analyze(&stream_a, &stream_b))?
    } else if let Some(bundle_path) = &against {
        let node = load_node_reader(data_dir)?;
        let bytes = std::fs::read(bundle_path)
            .map_err(|e| format!("cannot read {}: {e}", bundle_path.display()))?;
        let bundle: datu_store::Bundle = s(datu_store::Bundle::try_from_slice(&bytes)
            .map_err(|e| format!("not a data bundle: {e}")))?;
        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(bundle.entries.len());
        for entry in &bundle.entries {
            s(entry.verify())?;
            ids.push(s(entry.id())?);
        }
        let root = merkle_root(&ids);
        let count = ids.len() as u64;
        let mut found: Vec<ForkEvidence> = Vec::new();
        for cp in s(node.store.all_checkpoints())? {
            if cp.body.entries_count == count && cp.body.entry_ids_root != root {
                found.push(ForkEvidence {
                    kind: "history-mismatch",
                    signer: cp.body.signer.clone(),
                    height: cp.body.height,
                    description: format!(
                        "a stored checkpoint by {} covers {} entries with root {}, but this bundle's {} entries hash to root {} - if that witness mirrors this history, one of the two is fabricated",
                        short(&cp.body.signer),
                        cp.body.entries_count,
                        hex::encode(cp.body.entry_ids_root),
                        count,
                        hex::encode(root)
                    ),
                    checkpoints: vec![cp.clone()],
                });
            }
        }
        let stored = s(node.store.all_checkpoints())?;
        let mut cross = s(fork::analyze(&stored, &bundle.checkpoints))?;
        found.append(&mut cross);
        found
    } else {
        return Err("provide --a and --b, or --against".into());
    };
    evidence.sort_by_key(|entry| std::cmp::Reverse(entry.height));

    let verdict = if evidence.is_empty() {
        "NO_CONTRADICTIONS"
    } else {
        "FORK_PROVEN"
    };
    println!("verdict: {verdict}");
    for ev in &evidence {
        println!("  [{}] {}", ev.kind, ev.description);
    }

    let doc = serde_json::json!({
        "verdict": verdict,
        "generated_at_ms": now_ms(),
        "evidence": evidence
            .iter()
            .map(evidence_json)
            .collect::<Result<Vec<_>, _>>()?,
    });
    let json = s(serde_json::to_string_pretty(&doc))?;
    match &out {
        Some(path) => {
            std::fs::write(path, &json)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            println!("evidence package written: {}", path.display());
        }
        None => {
            if !evidence.is_empty() {
                println!("pass --out FILE to save the full evidence package");
            }
        }
    }
    if !evidence.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

// ---- identity attestations ----

fn cmd_attest_create(
    node: &Node,
    subject: String,
    claims: String,
    label: Option<String>,
) -> Result<(), String> {
    parse_id(&subject)
        .map_err(|_| "subject must be a 32-byte Ed25519 public key (hex)".to_string())?;
    let claims: serde_json::Value = serde_json::from_str(&claims)
        .map_err(|e| format!("--claims must be a JSON object: {e}"))?;
    if !claims.is_object() {
        return Err("--claims must be a JSON object".into());
    }
    let doc = AttestationDoc {
        subject: subject.clone(),
        label: label.clone(),
        claims,
    };
    let payload = doc.payload_bytes()?;
    let latest = s(node.store.latest(&node.identity))?;
    let (seq, prev) = match &latest {
        Some(e) => (e.body.seq + 1, Some(s(e.id())?)),
        None => (0, None),
    };
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: node.identity.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: attest::NS_ATTEST.to_string(),
        seq,
        prev,
        refs: vec![],
        timestamp_ms: now_ms(),
        payload,
    };
    let entry = s(Entry::sign(body, &node.key, &node.pq_key))?;
    let id = s(entry.id())?;
    if !s(node.store.insert_entry(&entry))? {
        return Err("attestation unexpectedly already present".into());
    }
    println!("attestation {} published", hex::encode(id));
    println!(
        "  attestor: {}  subject: {}{}",
        node.identity,
        short(&subject),
        label
            .as_deref()
            .map(|l| format!(" ({l})"))
            .unwrap_or_default()
    );
    println!(
        "  others can add weight: datu attest cosign --id {}",
        hex::encode(id)
    );
    Ok(())
}

fn cmd_attest_cosign(node: &Node, id_hex: String) -> Result<(), String> {
    let id = parse_id(&id_hex)?;
    let target = s(node.store.get_entry(&id))?
        .ok_or_else(|| format!("entry {id_hex} not found on this node - sync first"))?;
    if attest::parse_attestation(&target).is_none() {
        return Err(format!("{id_hex} is not an identity.attest entry"));
    }
    let doc = CosignDoc {
        attestation: id_hex.clone(),
    };
    let payload = s(serde_json::to_vec(&doc))?;
    let latest = s(node.store.latest(&node.identity))?;
    let (seq, prev) = match &latest {
        Some(e) => (e.body.seq + 1, Some(s(e.id())?)),
        None => (0, None),
    };
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: node.identity.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: attest::NS_COSIGN.to_string(),
        seq,
        prev,
        refs: vec![id],
        timestamp_ms: now_ms(),
        payload,
    };
    let entry = s(Entry::sign(body, &node.key, &node.pq_key))?;
    let cosign_id = s(entry.id())?;
    if !s(node.store.insert_entry(&entry))? {
        return Err("cosign unexpectedly already present".into());
    }
    println!(
        "cosigned {id_hex} as {} ({})",
        short(&node.identity),
        hex::encode(cosign_id)
    );
    Ok(())
}

/// Revoke an attestation (by id) or a subject key (directly): publish an
/// `identity.revoke` statement. Append-only means revocation is a new entry,
/// never an edit - the attestation and its revocations remain forever, and
/// verifiers apply the statement only where the author is a configured trust
/// root. A key-level revoke is the ejection path for explicit members/writers
/// entries, which have no attestation to name.
fn cmd_attest_revoke(
    node: &Node,
    id_hex: Option<String>,
    subject_hex: Option<String>,
    reason: Option<String>,
) -> Result<(), String> {
    let (doc, refs, target_short) = match (id_hex, subject_hex) {
        (Some(id_hex), None) => {
            let id = parse_id(&id_hex)?;
            // Typo protection when the target is local: only revoke real
            // attestations. When it is not local yet, the statement stands -
            // it takes effect wherever the attestation lands.
            match s(node.store.get_entry(&id))? {
                Some(target) if attest::parse_attestation(&target).is_none() => {
                    return Err(format!("{id_hex} is not an identity.attest entry"));
                }
                Some(_) => {}
                None => println!(
                    "  note: the attestation is not on this node yet; the statement stands"
                ),
            }
            (
                attest::RevokeDoc {
                    attestation: Some(id_hex.clone()),
                    subject: None,
                    reason,
                },
                vec![id],
                format!("attestation {}", short(&id_hex)),
            )
        }
        (None, Some(subject_hex)) => {
            let subject = parse_id(&subject_hex)?;
            (
                attest::RevokeDoc {
                    attestation: None,
                    subject: Some(subject_hex.clone()),
                    reason,
                },
                vec![],
                format!("key {}", hex::encode(subject)),
            )
        }
        _ => return Err("pass exactly one of --id or --key".into()),
    };
    let payload = doc.payload_bytes()?;
    let latest = s(node.store.latest(&node.identity))?;
    let (seq, prev) = match &latest {
        Some(e) => (e.body.seq + 1, Some(s(e.id())?)),
        None => (0, None),
    };
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: node.identity.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: attest::NS_REVOKE.to_string(),
        seq,
        prev,
        refs,
        timestamp_ms: now_ms(),
        payload,
    };
    let entry = s(Entry::sign(body, &node.key, &node.pq_key))?;
    let revoke_id = s(entry.id())?;
    if !s(node.store.insert_entry(&entry))? {
        return Err("revocation unexpectedly already present".into());
    }
    println!("revocation {} published", hex::encode(revoke_id));
    println!(
        "  {target_short} is revoked where {} is a configured trust root",
        short(&node.identity)
    );
    if let Some(reason) = doc.reason {
        println!("  reason: {reason}");
    }
    Ok(())
}

fn cmd_attest_status(
    node: &Node,
    subject: Option<String>,
    id: Option<String>,
) -> Result<(), String> {
    let entries = s(node.store.all_entries())?;
    if let Some(id_hex) = id {
        let id = parse_id(&id_hex)?;
        let entry = entries
            .iter()
            .find(|e| s(e.id()).map(|x| x == id).unwrap_or(false))
            .ok_or_else(|| format!("entry {id_hex} not found on this node"))?;
        let doc = attest::parse_attestation(entry)
            .ok_or_else(|| format!("{id_hex} is not an identity.attest entry"))?;
        println!("attestation {}", id_hex);
        println!("  attestor: {}", entry.body.author);
        println!(
            "  subject:  {}{}",
            doc.subject,
            doc.label
                .as_deref()
                .map(|l| format!(" ({l})"))
                .unwrap_or_default()
        );
        println!("  claims:   {}", doc.claims);
        let cosigners = attest::cosigners_for(entries.iter(), &id);
        println!("  cosigners ({} distinct):", cosigners.len());
        for (c, _) in &cosigners {
            println!("    {}  seq {}", c.body.author, c.body.seq);
        }
        let revocations = attest::revocations_for(entries.iter(), &id);
        if revocations.is_empty() {
            println!("  revoked:  no");
        } else {
            println!("  revoked:  yes ({} statement(s))", revocations.len());
            for (r, doc) in &revocations {
                println!(
                    "    by {}  seq {}{}",
                    r.body.author,
                    r.body.seq,
                    doc.reason
                        .as_deref()
                        .map(|x| format!("  ({x})"))
                        .unwrap_or_default()
                );
            }
        }
        return Ok(());
    }
    let subject = subject.ok_or_else(|| "pass --subject KEY or --id ID".to_string())?;
    let found = attest::attestations_for(entries.iter(), &subject);
    if found.is_empty() {
        println!("no attestations for {subject} on this node");
        println!("  (an institution binds its key with: datu attest create --subject KEY --claims '{{\"legal_name\":\"...\"}}')");
        return Ok(());
    }
    println!("subject: {subject}");
    let has_feed = s(node.store.latest(&subject))?.is_some();
    println!(
        "  published on this node: {}",
        if has_feed { "yes" } else { "no entries seen" }
    );
    for (entry, doc) in found {
        let id = s(entry.id())?;
        let cosigners = attest::cosigners_for(entries.iter(), &id);
        let revoked = attest::revocations_for(entries.iter(), &id);
        println!(
            "  attestation {} by {} ({} cosigners){}",
            short(&hex::encode(id)),
            short(&entry.body.author),
            cosigners.len(),
            if revoked.is_empty() {
                ""
            } else {
                "  [REVOKED]"
            }
        );
        if let Some(label) = &doc.label {
            println!("    label: {label}");
        }
        println!("    claims: {}", doc.claims);
        for (c, _) in &cosigners {
            println!("    + cosigned by {}", short(&c.body.author));
        }
    }
    Ok(())
}

// ---- bloom-filter sync ----

/// Minimal std-only HTTP POST of a JSON body; returns the parsed JSON
/// response. Good enough for localhost/LAN peer sync.
fn http_post_json(
    peer: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let host = peer
        .strip_prefix("http://")
        .unwrap_or(peer)
        .trim_end_matches('/');
    let payload = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let mut stream = TcpStream::connect(host).map_err(|e| {
        format!("cannot connect to {host}: {e} (is the peer running `datu serve`?)")
    })?;
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(&payload))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("send to {host} failed: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("bad response: {e}"))?;
    if !status_line.contains("200") && !status_line.contains("201") {
        return Err(format!("peer replied {status_line}"));
    }
    let mut content_length: Option<usize> = None;
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .map_err(|e| format!("bad response: {e}"))?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().ok();
            }
        }
    }
    let mut response = Vec::new();
    match content_length {
        Some(len) => {
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| format!("truncated response: {e}"))?;
            response = buf;
        }
        None => {
            reader
                .read_to_end(&mut response)
                .map_err(|e| format!("bad response: {e}"))?;
        }
    }
    serde_json::from_slice(&response).map_err(|e| format!("peer sent invalid JSON: {e}"))
}

fn cmd_sync(
    node: &Node,
    peers: &[String],
    page: usize,
    hello: Option<&NodeHello>,
    our_network_id: &str,
) -> Result<(), String> {
    for peer in peers {
        let stats = pull_peer(&node.store, peer, page, hello, our_network_id)?;
        println!(
            "{peer}: {} new entries ({} already had{}), {} new checkpoints",
            stats.new_entries,
            stats.known,
            if stats.denied > 0 {
                format!(", {} skipped by this node's policy", stats.denied)
            } else {
                String::new()
            },
            stats.new_checkpoints
        );
    }
    println!("sync complete; sync is pull-only - run `datu sync --peer <addr>` on the peer (or `datu node` there) for bidirectional flow");
    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SyncStats {
    pub new_entries: usize,
    pub known: usize,
    pub denied: usize,
    pub new_checkpoints: usize,
}

/// Pull everything a peer has that this store lacks, over whichever
/// transport the peer address implies: bare `host:port` speaks the native
/// p2p protocol (no HTTP anywhere); `http://…` uses the HTTP API. The mesh
/// wall applies on both: p2p via the hello handshake, HTTP via the peer's
/// advertised network id.
pub(crate) fn pull_peer(
    store: &Store,
    peer: &str,
    page: usize,
    hello: Option<&NodeHello>,
    our_network_id: &str,
) -> Result<SyncStats, String> {
    let peer = peer.trim().trim_end_matches('/');
    if peer.starts_with("https://") {
        return Err("https is not supported for sync - use a bare host:port (native p2p) or an http:// endpoint".into());
    }
    if peer.starts_with("http://") {
        check_peer_mesh_http(peer, our_network_id)?;
        pull_peer_http(store, peer, page)
    } else {
        let addr = peer
            .strip_prefix("datu://")
            .or_else(|| peer.strip_prefix("dag://"))
            .unwrap_or(peer);
        let stats = datu_p2p::pull_and_merge(addr, store, page.clamp(1, 2000) as u16, hello)
            .map_err(|e| e.to_string())?;
        Ok(SyncStats {
            new_entries: stats.entries_new,
            known: stats.entries_existing,
            denied: stats.entries_denied,
            new_checkpoints: stats.checkpoints_new,
        })
    }
}

/// The mesh wall for HTTP sync: read the peer's advertised network id and
/// refuse a cross-mesh pull before any data moves. A peer with no network
/// block (older datu) counts as the open network.
fn check_peer_mesh_http(peer: &str, our_network_id: &str) -> Result<(), String> {
    let status =
        http_get_json(peer, "/v1/status").map_err(|e| format!("cannot read peer status: {e}"))?;
    let theirs = status["network"]["network_id"].as_str().unwrap_or("");
    if theirs != our_network_id {
        return Err(format!(
            "network mismatch: peer is on {}, this node is on {} - the wall refuses (see `datu network`)",
            datu_p2p::mesh_name(theirs),
            datu_p2p::mesh_name(our_network_id)
        ));
    }
    Ok(())
}

/// Minimal std-only HTTP GET returning parsed JSON (peer status checks).
fn http_get_json(peer: &str, path: &str) -> Result<serde_json::Value, String> {
    let host = peer
        .strip_prefix("http://")
        .unwrap_or(peer)
        .trim_end_matches('/');
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let mut stream =
        TcpStream::connect(host).map_err(|e| format!("cannot connect to {host}: {e}"))?;
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| format!("send to {host} failed: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("bad response: {e}"))?;
    if !status_line.contains("200") {
        return Err(format!("peer replied {status_line}"));
    }
    let mut content_length: Option<usize> = None;
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .map_err(|e| format!("bad response: {e}"))?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().ok();
            }
        }
    }
    let mut response = Vec::new();
    match content_length {
        Some(len) => {
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| format!("truncated response: {e}"))?;
            response = buf;
        }
        None => {
            reader
                .read_to_end(&mut response)
                .map_err(|e| format!("bad response: {e}"))?;
        }
    }
    serde_json::from_slice(&response).map_err(|e| format!("peer sent invalid JSON: {e}"))
}

fn pull_peer_http(store: &Store, peer: &str, page: usize) -> Result<SyncStats, String> {
    let ids = s(store.entry_ids())?;
    let mut have = BloomFilter::new_for(ids.len().max(16), 0.001);
    for id in &ids {
        have.insert(id);
    }
    let mut stats = SyncStats::default();
    let mut cursor: Option<i64> = None;
    loop {
        let request = serde_json::json!({
            "m": have.bit_count(),
            "k": have.hash_count(),
            "bits_b64": base64::engine::general_purpose::STANDARD.encode(have.bit_bytes()),
            "cursor": cursor,
            "limit": page,
        });
        let response = http_post_json(peer, "/v1/sync/haves", &request)?;
        for item in response["entries"]
            .as_array()
            .ok_or("peer response missing entries")?
        {
            let entry = serve::entry_from_submission(item)?;
            match store.insert_entry(&entry) {
                Ok(true) => stats.new_entries += 1,
                Ok(false) => stats.known += 1,
                Err(datu_store::StoreError::Denied(_)) => stats.denied += 1,
                Err(datu_store::StoreError::Conflict { .. }) => {
                    return Err(format!(
                        "peer serves history contradicting ours at author {} seq {}: {} - this is fork evidence, not a sync error; collect the peer's witness stream and run `datu prove-fork`",
                        short(&entry.body.author),
                        entry.body.seq,
                        entry.id().map(hex::encode).unwrap_or_default()
                    ));
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        for item in response["checkpoints"].as_array().unwrap_or(&Vec::new()) {
            let checkpoint = serve::checkpoint_from_json(item)?;
            match store.append_checkpoint(&checkpoint) {
                Ok(true) => stats.new_checkpoints += 1,
                Ok(false) => {}
                Err(datu_store::StoreError::Fork { .. }) => {
                    return Err(format!(
                        "peer checkpoint contradicts a stored checkpoint: {} - fork evidence, see `datu prove-fork`",
                        item["id"].as_str().unwrap_or("?")
                    ));
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        cursor = response["cursor"].as_i64();
        let more = response["more"].as_bool().unwrap_or(false);
        if !more || cursor.is_none() {
            return Ok(stats);
        }
    }
}

fn cmd_delta_make(node: &Node, mesh: &str, out: &Path) -> Result<(), String> {
    let bytes = s(node.store.export_haves_request(0.001, mesh))?;
    std::fs::write(out, &bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "request written: {} ({} bytes) - carry it to any peer by any channel",
        out.display(),
        bytes.len()
    );
    Ok(())
}

fn cmd_delta_answer(node: &Node, mesh: &str, input: &Path, out: &Path) -> Result<(), String> {
    let request =
        std::fs::read(input).map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let (bytes, suppressed) = s(node.store.answer_delta(&request, mesh))?;
    std::fs::write(out, &bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "answer written: {} ({} entries they lack, {suppressed} suppressed as known)",
        out.display(),
        s(datu_store::decode_delta_response(&bytes))?.entries.len()
    );
    Ok(())
}

fn cmd_delta_merge(node: &Node, mesh: &str, input: &Path) -> Result<(), String> {
    let bytes =
        std::fs::read(input).map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let summary = s(node.store.merge_delta(&bytes, mesh))?;
    println!(
        "merged: {} new entries ({} already present{}), {} new checkpoints ({} already present) - every record verified",
        summary.entries_new,
        summary.entries_existing,
        if summary.entries_denied > 0 {
            format!(", {} skipped by this node's policy", summary.entries_denied)
        } else {
            String::new()
        },
        summary.checkpoints_new,
        summary.checkpoints_existing
    );
    Ok(())
}

// ---- writer policy (validators gated, observers free) ----

#[allow(clippy::too_many_arguments)]
fn cmd_policy_init(
    data_dir: &Path,
    attestors: Vec<String>,
    writers: Vec<String>,
    gated: Vec<String>,
    min_cosigners: usize,
    require_roles: Vec<String>,
    rule_specs: Vec<String>,
    seal_field_specs: Vec<String>,
    max_per_author_specs: Vec<String>,
    readonly: bool,
) -> Result<(), String> {
    for key in attestors.iter().chain(writers.iter()) {
        parse_id(key).map_err(|_| format!("'{key}' is not a 32-byte Ed25519 key (hex)"))?;
    }
    let mut rules: Vec<datu_store::NamespaceRule> = Vec::new();
    for spec in &rule_specs {
        let rule = parse_rule(spec)?;
        match rules.iter_mut().find(|existing| existing.ns == rule.ns) {
            Some(existing) => existing.require.extend(rule.require),
            None => rules.push(rule),
        }
    }
    for spec in &seal_field_specs {
        let (ns, field) = parse_seal_field(spec)?;
        match rules.iter_mut().find(|existing| existing.ns == ns) {
            Some(existing) => existing.require_sealed.push(field),
            None => rules.push(datu_store::NamespaceRule {
                ns,
                require: vec![],
                require_sealed: vec![field],
                max_entries_per_author: None,
            }),
        }
    }
    for spec in &max_per_author_specs {
        let (ns, cap) = parse_max_per_author(spec)?;
        match rules.iter_mut().find(|existing| existing.ns == ns) {
            Some(existing) => existing.max_entries_per_author = Some(cap),
            None => rules.push(datu_store::NamespaceRule {
                ns,
                require: vec![],
                require_sealed: vec![],
                max_entries_per_author: Some(cap),
            }),
        }
    }
    let gated = if gated.is_empty() && !readonly {
        vec![
            "gov.*".to_string(),
            "identity.attest".to_string(),
            "identity.revoke".to_string(),
        ]
    } else {
        gated
    };
    let policy = WritePolicy {
        version: datu_store::POLICY_VERSION,
        readonly,
        gated,
        writers,
        attestors,
        min_cosigners,
        required_roles: require_roles,
        rules,
        allow: vec![],
    };
    let path = policy_path(data_dir);
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    std::fs::write(&path, policy.to_json()?)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("policy written: {}", path.display());
    print_policy(&policy);
    Ok(())
}

fn cmd_policy_show(data_dir: &Path) -> Result<(), String> {
    match read_policy(data_dir)? {
        Some(policy) => {
            println!("policy: {}", policy_path(data_dir).display());
            print_policy(&policy);
            println!("{}", policy.to_json()?);
        }
        None => {
            println!("no policy file - this is a free, open observer node:");
            println!("  it accepts every validly-signed entry, syncs, reads and witnesses.");
            println!("  gate this node with: datu policy init --attestor KEY --ns 'gov.*'");
        }
    }
    if let Some(net) = read_network(data_dir)? {
        if let Some(root) = &net.manifest_root {
            println!(
                "note: network.json pins manifest root {} - when a chain verifies in {},",
                short(root),
                datu_store::manifest_namespace(&net.network_id)
            );
            println!("      the manifest REPLACES this policy file; see `datu manifest show`");
        }
    }
    Ok(())
}

fn cmd_policy_clear(data_dir: &Path) -> Result<(), String> {
    let path = policy_path(data_dir);
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        println!("policy removed: this node is now a free, open observer (accepts everything)");
    } else {
        println!("no policy file - already a free, open observer");
    }
    Ok(())
}

// ---- network modes (permissioned vs permissionless joining) ----

fn cmd_network_init(
    data_dir: &Path,
    mode: String,
    network_id: String,
    members: Vec<String>,
    roots: Vec<String>,
    manifest_root: Option<String>,
) -> Result<(), String> {
    for key in members.iter().chain(roots.iter()) {
        parse_id(key).map_err(|_| format!("'{key}' is not a 32-byte Ed25519 key (hex)"))?;
    }
    if let Some(root) = &manifest_root {
        parse_id(root).map_err(|_| format!("'{root}' is not a 32-byte Ed25519 key (hex)"))?;
        if network_id.is_empty() {
            return Err(
                "a manifest root needs a --network-id: the chain lives at gov.mesh.<id>.policy"
                    .into(),
            );
        }
    }
    if mode != "permissioned" && mode != "permissionless" {
        return Err(format!(
            "mode must be 'permissioned' or 'permissionless', not '{mode}'"
        ));
    }
    if mode == "permissioned" && members.is_empty() && roots.is_empty() {
        return Err(
            "a permissioned network needs at least one --member or --root (who may join?)".into(),
        );
    }
    let net = NetworkPolicy {
        version: NETWORK_POLICY_VERSION,
        mode,
        network_id,
        members,
        roots,
        manifest_root,
    };
    let path = network_path(data_dir);
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    std::fs::write(&path, net.to_json()?)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("network policy written: {}", path.display());
    print_network(&net);
    if net.is_permissioned() {
        let node = load_node_bootstrap(data_dir)?;
        if !net.self_admitted(&node.identity) {
            println!(
                "  warning: this node's key {} is NOT a member or root - `datu node` will refuse to start (fail-closed)",
                short(&node.identity)
            );
        }
    }
    Ok(())
}

// ---- governance manifests (design §D: who may write, as an on-ledger chain) ----

fn cmd_manifest_init(data_dir: &Path, network_id: String, out: PathBuf) -> Result<(), String> {
    let node = load_node_bootstrap(data_dir)?;
    if network_id.is_empty()
        || !network_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(
            "--network-id must be 1+ chars of [a-z0-9-] (the chain lives at gov.mesh.<id>.policy)"
                .into(),
        );
    }
    let policy = WritePolicy {
        version: datu_store::POLICY_VERSION,
        gated: vec!["gov.*".into()],
        attestors: vec![node.identity.clone()],
        ..WritePolicy::default()
    };
    let mut doc = datu_store::ManifestDoc::new(&network_id, vec![node.identity.clone()], policy);
    doc.note = Some(
        "founding manifest - edit the policy, keep the roots, then `datu manifest publish`".into(),
    );
    let json = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(&out, &json).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!("manifest template: {}", out.display());
    println!(
        "  network:  {} (chain namespace: {})",
        network_id,
        datu_store::manifest_namespace(&network_id)
    );
    println!(
        "  founder:  {} (this node - signs the first entry)",
        short(&node.identity)
    );
    println!(
        "next: edit the template, `datu manifest publish --file {}`, then pin the root",
        out.display()
    );
    println!("      on every member: `datu network init --mode permissioned --network-id {network_id} --manifest-root {}`", node.identity);
    Ok(())
}

fn cmd_manifest_publish(data_dir: &Path, file: PathBuf, accept_stale: bool) -> Result<(), String> {
    let node = load_node_bootstrap(data_dir)?;
    let text = std::fs::read_to_string(&file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let mut doc: datu_store::ManifestDoc =
        serde_json::from_str(&text).map_err(|e| format!("bad manifest JSON: {e}"))?;
    if doc.version != 1 {
        return Err(format!(
            "unsupported manifest version {} (expected 1)",
            doc.version
        ));
    }
    if doc.network_id.is_empty()
        || !doc
            .network_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("manifest network_id must be 1+ chars of [a-z0-9-]".into());
    }
    if doc.roots.is_empty() {
        return Err("a manifest must name at least one root - who signs the next one?".into());
    }
    for key in &doc.roots {
        parse_id(key).map_err(|_| format!("root '{key}' is not a 32-byte Ed25519 key (hex)"))?;
    }
    if doc.policy.readonly {
        return Err(
            "a manifest cannot be read-only - read-only is an operational flag of a node, not a governance act"
                .into(),
        );
    }

    let ns = datu_store::manifest_namespace(&doc.network_id);
    let supersedes = match datu_store::manifest::head(&node.store, &doc.network_id)? {
        None => {
            if !doc.roots.contains(&node.identity) {
                println!(
                    "  warning: founding a chain whose roots do not include this key - you cannot publish the next manifest from here"
                );
            }
            None
        }
        Some((head_id, roots)) => {
            if !roots.contains(&node.identity) {
                return Err(format!(
                    "this node's key {} is not a root of the current manifest - the current authority authorizes the next",
                    short(&node.identity)
                ));
            }
            // Changing who may speak for the mesh is the one governance act
            // where staleness can do real damage: from a view this node cannot
            // show is current, a rotation may resurrect a retired root or bury
            // one it never learned about. Everything else proceeds under stale
            // policy by design (offline recording is the point).
            let mut current = roots.clone();
            let mut next = doc.roots.clone();
            current.sort();
            next.sort();
            if current != next && !accept_stale {
                let st = datu_store::manifest::status_unpinned(
                    &node.store,
                    &doc.network_id,
                    Some(&node.identity),
                )?;
                if st.freshness != datu_store::Freshness::Current {
                    return Err(format!(
                        "refusing a root change on {} governance evidence: {}.
  Every observer would carry the same doubt, and a rotation taken from a stale view can resurrect a retired root.
  Re-run with --accept-stale only to deliberately repair a partition; the result stays reported as {} until independent checkpoints exist.",
                        st.freshness.as_str(),
                        st.reason,
                        st.freshness.as_str()
                    ));
                }
            }
            Some(head_id)
        }
    };
    doc.supersedes = supersedes.clone();

    let payload = serde_json::to_vec(&doc).map_err(|e| e.to_string())?;
    let latest = s(node.store.latest(&node.identity))?;
    let (seq, prev) = match &latest {
        Some(e) => (e.body.seq + 1, Some(s(e.id())?)),
        None => (0, None),
    };
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: node.identity.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: ns.clone(),
        seq,
        prev,
        refs: supersedes
            .as_ref()
            .map(|p| parse_id(p))
            .transpose()?
            .into_iter()
            .collect(),
        timestamp_ms: now_ms(),
        payload,
    };
    let entry = s(Entry::sign(body, &node.key, &node.pq_key))?;
    let id = s(entry.id())?;
    if !s(node.store.insert_entry(&entry))? {
        return Err("manifest unexpectedly already present".into());
    }
    println!("manifest published {} ({} seq {seq})", hex::encode(id), ns);
    println!(
        "  roots:       {}",
        doc.roots
            .iter()
            .map(|k| short(k).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    match &doc.supersedes {
        Some(prev_id) => println!("  supersedes:  {prev_id}"),
        None => println!("  founding manifest - pin its root in every member's network.json:"),
    }
    if doc.supersedes.is_none() {
        println!("                datu network init --mode permissioned --network-id {} --manifest-root {}", doc.network_id, doc.roots[0]);
    }
    Ok(())
}

fn cmd_manifest_show(data_dir: &Path) -> Result<(), String> {
    let net = read_network(data_dir)?;
    let pinned = net.as_ref().and_then(|n| n.manifest_root.clone());
    match (net, pinned) {
        (Some(net), Some(root)) => {
            let store = Store::open(&data_dir.join("node.db")).map_err(|e| e.to_string())?;
            match datu_store::manifest::compile(&store, &net.network_id, std::slice::from_ref(&root))? {
                Some(compiled) => {
                    println!(
                        "governance: {} (pinned root {})",
                        datu_store::manifest_namespace(&net.network_id),
                        short(&root)
                    );
                    for (i, (id, author, note)) in compiled.chain.iter().enumerate() {
                        println!(
                            "  #{} {} by {}{}",
                            i,
                            short(id),
                            short(author),
                            note.as_ref().map(|n| format!(" - {n}")).unwrap_or_default()
                        );
                    }
                    println!(
                        "  current roots: {} (they may sign the next manifest)",
                        compiled.doc.roots.iter().map(|k| short(k).to_string()).collect::<Vec<_>>().join(", ")
                    );
                    println!("compiled writer policy (what this node's gate enforces):");
                    print_policy(&compiled.policy);
                    if policy_path(data_dir).exists() {
                        println!("  note: policy.json exists but is SHADOWED by the manifest while the pin holds");
                    }
                }
                None => println!(
                    "pinned root {} but no verifiable manifest in {} - nodes fail closed until one syncs or is published",
                    short(&root),
                    datu_store::manifest_namespace(&net.network_id)
                ),
            }
        }
        _ => println!(
            "no manifest pinned - writer policy comes from policy.json; pin one with `datu network init --manifest-root KEY`"
        ),
    }
    Ok(())
}

/// (network id, pinned root) if this node pins a governance manifest.
fn manifest_pin(data_dir: &Path) -> Result<Option<(String, String)>, String> {
    match read_network(data_dir)? {
        None => Ok(None),
        Some(net) => match net.manifest_root {
            Some(root) => Ok(Some((net.network_id, root))),
            None => Ok(None),
        },
    }
}

fn print_manifest_status(st: &datu_store::ManifestStatus, network_id: &str, root: &str) {
    println!(
        "governance: {} (pinned root {})",
        datu_store::manifest_namespace(network_id),
        short(root)
    );
    println!("  freshness:  {}", st.freshness.as_str());
    println!("  reason:     {}", st.reason);
    match (&st.manifest_id, &st.author) {
        (Some(id), Some(author)) => println!(
            "  manifest:   {} by {}{}",
            short(id),
            short(author),
            st.published_ms
                .map(|t| format!(" (published {t})"))
                .unwrap_or_default()
        ),
        _ => println!("  manifest:   none verified"),
    }
    if !st.roots.is_empty() {
        println!(
            "  roots:      {} (they may sign the next manifest)",
            st.roots
                .iter()
                .map(|k| short(k).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !st.chain_ids.is_empty() {
        println!("  chain:      {} verified manifest(s)", st.chain_ids.len());
    }
    match &st.corroborated_by {
        Some(signer) => println!("  evidence:   independent checkpoint by {}", short(signer)),
        None => {
            println!("  evidence:   none - no independent checkpoint at or after this manifest")
        }
    }
    for id in &st.missing_predecessors {
        println!(
            "  missing:    {id} - a manifest this node holds supersedes it (this view is behind)"
        );
    }
    for (id, author) in &st.conflicts {
        println!("  claim:      {} by {}", short(id), short(author));
    }
}

fn no_pin_hint() -> Result<(), String> {
    println!("no governance manifest pinned on this node");
    println!("  the writer policy comes from policy.json; pin one with:");
    println!("    datu network init --manifest-root <root-key-hex> --network-id <mesh-id>");
    Ok(())
}

/// Read-only: what this node can establish about its own governance.
fn cmd_manifest_status(data_dir: &Path) -> Result<(), String> {
    let node = load_node_reader(data_dir)?;
    let Some((network_id, root)) = manifest_pin(data_dir)? else {
        return no_pin_hint();
    };
    let st = datu_store::manifest::status(
        &node.store,
        &network_id,
        std::slice::from_ref(&root),
        Some(&node.identity),
    )?;
    print_manifest_status(&st, &network_id, &root);
    Ok(())
}

/// Read-only: the verified chain, oldest first.
fn cmd_manifest_history(data_dir: &Path) -> Result<(), String> {
    let node = load_node_reader(data_dir)?;
    let Some((network_id, root)) = manifest_pin(data_dir)? else {
        return no_pin_hint();
    };
    let Some(compiled) =
        datu_store::manifest::compile(&node.store, &network_id, std::slice::from_ref(&root))?
    else {
        return Err(format!(
            "no verified manifest chain for {network_id} - `datu manifest status` says why"
        ));
    };
    println!(
        "manifest history: {} ({} entr{}, oldest first)",
        datu_store::manifest_namespace(&network_id),
        compiled.chain.len(),
        if compiled.chain.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    for (i, (id, author, note)) in compiled.chain.iter().enumerate() {
        let published = parse_id(id)
            .ok()
            .and_then(|arr| node.store.get_entry(&arr).ok().flatten())
            .map(|e| e.body.timestamp_ms);
        println!(
            "  #{i} {} by {}{}{}",
            short(id),
            short(author),
            published.map(|t| format!(" at {t}")).unwrap_or_default(),
            note.as_ref().map(|n| format!(" - {n}")).unwrap_or_default()
        );
    }
    println!(
        "  head roots: {}",
        compiled
            .doc
            .roots
            .iter()
            .map(|k| short(k).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

/// Read-only: competing claims, if any. Exits 0 either way - this is a query.
fn cmd_manifest_conflicts(data_dir: &Path) -> Result<(), String> {
    let node = load_node_reader(data_dir)?;
    let Some((network_id, root)) = manifest_pin(data_dir)? else {
        return no_pin_hint();
    };
    let st = datu_store::manifest::status(
        &node.store,
        &network_id,
        std::slice::from_ref(&root),
        Some(&node.identity),
    )?;
    if st.conflicts.is_empty() && st.missing_predecessors.is_empty() {
        println!(
            "no competing manifest claims on this node ({})",
            st.freshness.as_str()
        );
        return Ok(());
    }
    println!(
        "governance {}: {} - {}",
        datu_store::manifest_namespace(&network_id),
        st.freshness.as_str(),
        st.reason
    );
    for (id, author) in &st.conflicts {
        println!(
            "  competing claim: {} by {} ({})",
            id,
            author,
            short(author)
        );
    }
    for id in &st.missing_predecessors {
        println!("  unlinked: a held manifest supersedes {id}, which this node does not have");
    }
    if !st.conflicts.is_empty() {
        println!("  no side is chosen here: replay the chain, hold both, and let each institution decide");
    }
    Ok(())
}

/// Read-only verification (design §I): signatures, lineage, authorship and
/// policy versions, with no publishing authority required - an observer with
/// a browsed bundle can run exactly this.
fn cmd_manifest_verify(data_dir: &Path, file: Option<PathBuf>) -> Result<(), String> {
    let node = load_node_reader(data_dir)?;
    match file {
        None => {
            let Some((network_id, root)) = manifest_pin(data_dir)? else {
                return no_pin_hint();
            };
            let st = datu_store::manifest::status(
                &node.store,
                &network_id,
                std::slice::from_ref(&root),
                Some(&node.identity),
            )?;
            print_manifest_status(&st, &network_id, &root);
            if matches!(
                st.freshness,
                datu_store::Freshness::Unverified | datu_store::Freshness::Conflicted
            ) {
                return Err(format!("governance does not verify: {}", st.reason));
            }
            println!("chain verification (offline, no authority needed):");
            for (i, id) in st.chain_ids.iter().enumerate() {
                let arr = parse_id(id)?;
                let entry = node
                    .store
                    .get_entry(&arr)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("manifest entry {id} is missing from this store"))?;
                s(entry.verify())?;
                if hex::encode(s(entry.id())?) != *id {
                    return Err(format!(
                        "manifest entry {id} does not match its content address"
                    ));
                }
                println!(
                    "  #{i} {} ok - signatures valid, content-addressed, by {}",
                    short(id),
                    short(&entry.body.author)
                );
            }
            println!(
                "  result: chain verifies; freshness is {}",
                st.freshness.as_str()
            );
            Ok(())
        }
        Some(path) => cmd_manifest_verify_file(&node, data_dir, &path),
    }
}

fn cmd_manifest_verify_file(node: &Node, data_dir: &Path, path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let doc: datu_store::ManifestDoc =
        serde_json::from_str(&text).map_err(|e| format!("bad manifest JSON: {e}"))?;
    println!("manifest file: {}", path.display());
    if doc.version != 1 {
        return Err(format!(
            "unsupported manifest version {} (expected 1)",
            doc.version
        ));
    }
    if doc.network_id.is_empty()
        || !doc
            .network_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("manifest network_id must be 1+ chars of [a-z0-9-]".into());
    }
    if doc.roots.is_empty() {
        return Err("a manifest must name at least one root".into());
    }
    for key in &doc.roots {
        parse_id(key).map_err(|_| format!("root '{key}' is not a 32-byte Ed25519 key (hex)"))?;
    }
    if doc.policy.readonly {
        return Err("a manifest cannot be read-only".into());
    }
    if doc.policy.version > datu_store::POLICY_VERSION {
        println!(
            "  warning:     policy version {} is newer than this build ({}) - publishing it would make it unreadable here",
            doc.policy.version,
            datu_store::POLICY_VERSION
        );
    }
    println!("  network:     {}", doc.network_id);
    println!(
        "  roots:       {}",
        doc.roots
            .iter()
            .map(|k| short(k).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some((pinned_net, _)) = manifest_pin(data_dir)? {
        if pinned_net != doc.network_id {
            return Err(format!(
                "this node is pinned to mesh '{pinned_net}', not '{}'",
                doc.network_id
            ));
        }
    }

    let head = datu_store::manifest::head(&node.store, &doc.network_id)?;
    let authorized = match &head {
        None => {
            println!("  position:    founding manifest (would be entry #0 - pinning is the separate trust act)");
            true
        }
        Some((head_id, head_roots)) => {
            match &doc.supersedes {
                None => println!(
                    "  position:    a SECOND founding manifest for this mesh - publishing it would claim a competing genesis"
                ),
                Some(prev) if prev == head_id => println!(
                    "  position:    extends the current head {}",
                    short(head_id)
                ),
                Some(prev) => println!(
                    "  position:    supersedes {} but the head is {} - the chain rule would not link it",
                    short(prev),
                    short(head_id)
                ),
            }
            let allowed = head_roots.contains(&node.identity);
            println!(
                "  authorizes:  this node's key {} - {} of the current head's roots",
                short(&node.identity),
                if allowed { "one" } else { "NOT one" }
            );
            allowed && doc.supersedes.as_deref() == Some(head_id.as_str())
        }
    };
    if !authorized {
        return Err("this node cannot publish this manifest as it stands".into());
    }
    println!(
        "  result:      publishable from here (`datu manifest publish --file {}`)",
        path.display()
    );
    Ok(())
}

// ---- disputes (design §A/C: preserved evidence + resolution records) ----

fn cmd_disputes(data_dir: &Path) -> Result<(), String> {
    let node = load_node_reader(data_dir)?;
    let conflicts = s(node.store.list_conflicts(200))?;
    if conflicts.is_empty() {
        println!("no recorded feed disputes on this node");
        return Ok(());
    }
    let resolutions: Vec<datu_core::Entry> = s(node.store.all_entries())?
        .into_iter()
        .filter(|e| e.body.namespace.starts_with("gov.dispute."))
        .collect();
    for c in &conflicts {
        println!(
            "dispute: {} seq {} by {}",
            c.namespace,
            c.seq,
            short(&c.author)
        );
        println!("  stored:      {}", hex::encode(c.stored_id));
        println!("  conflicting: {}", hex::encode(c.id));
        let sides = [c.id, c.stored_id];
        let linked: Vec<&datu_core::Entry> = resolutions
            .iter()
            .filter(|e| e.body.refs.iter().any(|r| sides.contains(r)))
            .collect();
        if linked.is_empty() {
            println!("  resolution:  none recorded - evidence preserved, dispute open");
        }
        for e in linked {
            println!(
                "  resolution:  {} in {} by {}: {}",
                hex::encode(s(e.id())?),
                e.body.namespace,
                short(&e.body.author),
                String::from_utf8_lossy(&e.body.payload)
                    .chars()
                    .take(80)
                    .collect::<String>()
            );
        }
    }
    Ok(())
}

fn cmd_network_show(data_dir: &Path) -> Result<(), String> {
    match read_network(data_dir)? {
        Some(net) => {
            println!("network: {}", network_path(data_dir).display());
            print_network(&net);
            println!("{}", net.to_json()?);
        }
        None => {
            println!("no network policy - this node is the open network:");
            println!("  permissionless: anyone may sync, read, and witness.");
            println!("  wall or gate joining with: datu network init --mode permissioned --network-id gov-mesh --member KEY");
        }
    }
    Ok(())
}

fn cmd_network_clear(data_dir: &Path) -> Result<(), String> {
    let path = network_path(data_dir);
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        println!(
            "network policy removed: this node is the open network (permissionless, no walls)"
        );
    } else {
        println!("no network policy - already the open network");
    }
    Ok(())
}

// ---- party signatures (the citizens a record is about consent to it) ----

fn cmd_parties_sign(
    node: &Node,
    role: String,
    kind: Option<String>,
    input: &Path,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let mut document = load_or_wrap_document(input, kind.as_deref())?;
    s(document.sign(&role, &node.key, Some(&node.pq_key)))?;
    let json = serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!(
        "signed as party '{role}' with {} (Ed25519 + ML-DSA-65) - kind {}",
        node.identity, document.kind
    );
    Ok(())
}

fn cmd_parties_show(node: &Node, id_hex: String) -> Result<(), String> {
    let id = parse_id(&id_hex)?;
    let entry = s(node.store.get_entry(&id))?.ok_or_else(|| format!("entry {id_hex} not found"))?;
    let document = SignedDocument::from_payload(&entry.body.payload)
        .ok_or_else(|| format!("{id_hex} payload is not a party-signed document"))?;
    println!("entry:  {id_hex}");
    println!("author: {}", entry.body.author);
    println!("kind:   {}", document.kind);
    println!(
        "doc:    {}",
        serde_json::to_string(&document.doc).map_err(|e| e.to_string())?
    );
    let parties = s(document.verify())?;
    println!("parties ({}):", parties.len());
    for (role, key) in parties {
        println!("  [{role:<10}] {key}  verified");
    }
    Ok(())
}

fn cmd_wallet_cosign_doc(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    role: &str,
    kind: Option<String>,
    input: &Path,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet.load(name, passphrase)?;
    let mut document = load_or_wrap_document(input, kind.as_deref())?;
    identity.sign_document(&mut document, role)?;
    let json = serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!(
        "signed as party '{role}' with wallet identity {} (Ed25519 + ML-DSA-65) - kind {}",
        identity.public.name, document.kind
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_wallet_auth_assert(
    data_dir: &Path,
    name: &str,
    passphrase: &str,
    rp_id: &str,
    origin: &str,
    nonce_hex: &str,
    expires_at_ms: u64,
    out: &Option<PathBuf>,
) -> Result<(), String> {
    let wallet = datu_wallet::Wallet::open(data_dir);
    let identity = wallet.load(name, passphrase)?;
    if rp_id.is_empty() || rp_id.len() > 255 {
        return Err("rp_id must be 1-255 chars".into());
    }
    let nonce: [u8; datu_core::auth::NONCE_BYTES] = hex::decode(nonce_hex)
        .map_err(|e| format!("bad nonce hex: {e}"))?
        .try_into()
        .map_err(|_| {
            format!(
                "nonce must be {} hex chars",
                datu_core::auth::NONCE_BYTES * 2
            )
        })?;
    let challenge = datu_core::auth::AuthChallenge {
        rp_id: rp_id.to_string(),
        origin: origin.to_string(),
        nonce,
        expires_at_ms,
    };
    let signature = datu_core::auth::sign_assertion(&identity.ed, &challenge);
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "domain": datu_core::auth::AUTH_DOMAIN,
        "rp_id": challenge.rp_id,
        "origin": challenge.origin,
        "nonce": nonce_hex,
        "expires_at_ms": challenge.expires_at_ms,
        "pubkey": identity.public.ed_public,
        "signature": hex::encode(signature),
    }))
    .map_err(|e| e.to_string())?;
    write_output(out, &json)?;
    println!(
        "signed login assertion for '{}' as {} (datu-auth-v1; nonce single-use tracking is the relying party's job)",
        challenge.rp_id, identity.public.name
    );
    Ok(())
}

fn run(cli: Cli) -> Result<(), String> {
    match &cli.command {
        Commands::Init => cmd_init(&cli.data_dir),
        Commands::Keys => {
            let node = load_node_reader(&cli.data_dir)?;
            println!("identity (ed25519): {}", node.identity);
            println!("pq key:              ml-dsa-65 (hybrid signatures)");
            Ok(())
        }
        Commands::Publish {
            ns,
            payload,
            file,
            refs,
        } => {
            let node = load_node(&cli.data_dir)?;
            cmd_publish(
                &node,
                ns.clone(),
                payload.clone(),
                file.clone(),
                refs.clone(),
            )
        }
        Commands::Log { ns, author, limit } => {
            let node = load_node_reader(&cli.data_dir)?;
            cmd_log(&node, ns.clone(), author.clone(), *limit)
        }
        Commands::Get { id } => {
            let node = load_node_reader(&cli.data_dir)?;
            cmd_get(&node, id.clone())
        }
        Commands::Verify => {
            let node = load_node_reader(&cli.data_dir)?;
            cmd_verify(&node)
        }
        Commands::Checkpoint => {
            let node = load_node_reader(&cli.data_dir)?;
            cmd_checkpoint(&node)
        }
        Commands::Witness { cmd } => {
            match cmd {
                WitnessCmd::Sign => {
                    let node = load_node_reader(&cli.data_dir)?;
                    cmd_checkpoint(&node)
                }
                WitnessCmd::List => {
                    let node = load_node_reader(&cli.data_dir)?;
                    cmd_witness_list(&node)
                }
                WitnessCmd::Export { out } => {
                    let node = load_node_reader(&cli.data_dir)?;
                    let mesh = our_network_id(&cli.data_dir)?;
                    cmd_witness_export(&node, &mesh, out)
                }
                WitnessCmd::Import { input } => {
                    let node = load_node_reader(&cli.data_dir)?;
                    let mesh = our_network_id(&cli.data_dir)?;
                    cmd_witness_import(&node, &mesh, input)
                }
                WitnessCmd::Prove {
                    entry,
                    checkpoint,
                    out,
                } => {
                    let node = load_node_reader(&cli.data_dir)?;
                    cmd_witness_prove(&node, entry.clone(), checkpoint.clone(), out.clone())
                }
                // Offline: no node, no store - the artifact carries its own
                // evidence, which is the whole point.
                WitnessCmd::VerifyProof { input } => cmd_witness_verify_proof(input),
            }
        }
        Commands::ProveFork { a, b, against, out } => cmd_prove_fork(
            &cli.data_dir,
            a.clone(),
            b.clone(),
            against.clone(),
            out.clone(),
        ),
        Commands::Serve {
            addr,
            read_only,
            submit_per_min,
            haves_per_min,
        } => serve::serve(
            &cli.data_dir,
            addr,
            effective_policy(&cli.data_dir, *read_only, false)?,
            *submit_per_min as usize,
            *haves_per_min as usize,
        ),
        Commands::Signet { cmd } => match cmd {
            WalletCmd::Create { name, passphrase } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_create(&cli.data_dir, name, &pass)
            }
            WalletCmd::List => cmd_wallet_list(&cli.data_dir),
            WalletCmd::Show { name } => cmd_wallet_show(&cli.data_dir, name),
            WalletCmd::Sign {
                name,
                passphrase,
                request,
                out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_sign(&cli.data_dir, name, &pass, request, out)
            }
            WalletCmd::Seal {
                name,
                passphrase,
                to,
                to_fields,
                input,
                fields,
                out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_seal(
                    &cli.data_dir,
                    name,
                    &pass,
                    to,
                    to_fields,
                    input,
                    fields,
                    out,
                )
            }
            WalletCmd::SealDeferred {
                name,
                passphrase,
                to,
                to_field,
                input,
                fields,
                out,
                release_out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_seal_deferred(
                    &cli.data_dir,
                    name,
                    &pass,
                    to,
                    to_field,
                    input,
                    fields,
                    out,
                    release_out,
                )
            }
            WalletCmd::ReleaseDeferred {
                input,
                field,
                release,
                recover,
                name,
                passphrase,
                out,
            } => {
                let pass = if *recover {
                    Some(get_passphrase(passphrase.clone())?)
                } else {
                    None
                };
                cmd_wallet_release_deferred(
                    &cli.data_dir,
                    input,
                    field,
                    release.as_ref(),
                    *recover,
                    name.as_deref(),
                    pass.as_deref(),
                    out,
                )
            }
            WalletCmd::OpenDeferred {
                name,
                passphrase,
                input,
                field,
                release,
                out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_open_deferred(&cli.data_dir, name, &pass, input, field, release, out)
            }
            WalletCmd::Open {
                name,
                passphrase,
                input,
                out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_open(&cli.data_dir, name, &pass, input, out)
            }
            WalletCmd::Export {
                name,
                passphrase,
                backup_passphrase,
                out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                let backup_pass = get_backup_passphrase(backup_passphrase.clone())?;
                cmd_wallet_export(&cli.data_dir, name, &pass, &backup_pass, out)
            }
            WalletCmd::Import {
                input,
                backup_passphrase,
                rename,
            } => {
                let backup_pass = get_backup_passphrase(backup_passphrase.clone())?;
                cmd_wallet_import(&cli.data_dir, input, &backup_pass, rename.clone())
            }
            WalletCmd::Serve {
                addr,
                allow_origins,
            } => walletd::serve(&cli.data_dir, addr, allow_origins.clone()),
            WalletCmd::CosignDoc {
                name,
                passphrase,
                role,
                kind,
                input,
                out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_cosign_doc(&cli.data_dir, name, &pass, role, kind.clone(), input, out)
            }
            WalletCmd::AuthAssert {
                name,
                passphrase,
                rp_id,
                origin,
                nonce,
                expires_at_ms,
                out,
            } => {
                let pass = get_passphrase(passphrase.clone())?;
                cmd_wallet_auth_assert(
                    &cli.data_dir,
                    name,
                    &pass,
                    rp_id,
                    origin,
                    nonce,
                    *expires_at_ms,
                    out,
                )
            }
        },
        Commands::Attest { cmd } => match cmd {
            // Creating/cosigning writes an entry, so it carries write
            // authority; looking at one never does.
            AttestCmd::Create {
                subject,
                claims,
                label,
            } => cmd_attest_create(
                &load_node(&cli.data_dir)?,
                subject.clone(),
                claims.clone(),
                label.clone(),
            ),
            AttestCmd::Cosign { id } => cmd_attest_cosign(&load_node(&cli.data_dir)?, id.clone()),
            AttestCmd::Revoke { id, key, reason } => cmd_attest_revoke(
                &load_node(&cli.data_dir)?,
                id.clone(),
                key.clone(),
                reason.clone(),
            ),
            AttestCmd::Status { subject, id } => cmd_attest_status(
                &load_node_reader(&cli.data_dir)?,
                subject.clone(),
                id.clone(),
            ),
        },
        Commands::Policy { cmd } => match cmd {
            PolicyCmd::Init {
                attestors,
                writers,
                gated,
                min_cosigners,
                require_roles,
                rules,
                seal_fields,
                max_per_author,
                readonly,
            } => cmd_policy_init(
                &cli.data_dir,
                attestors.clone(),
                writers.clone(),
                gated.clone(),
                *min_cosigners,
                require_roles.clone(),
                rules.clone(),
                seal_fields.clone(),
                max_per_author.clone(),
                *readonly,
            ),
            PolicyCmd::Show => cmd_policy_show(&cli.data_dir),
            PolicyCmd::Clear => cmd_policy_clear(&cli.data_dir),
        },
        Commands::Network { cmd } => match cmd {
            NetworkCmd::Init {
                mode,
                network_id,
                members,
                roots,
                manifest_root,
            } => cmd_network_init(
                &cli.data_dir,
                mode.clone(),
                network_id.clone(),
                members.clone(),
                roots.clone(),
                manifest_root.clone(),
            ),
            NetworkCmd::Show => cmd_network_show(&cli.data_dir),
            NetworkCmd::Clear => cmd_network_clear(&cli.data_dir),
        },
        Commands::Manifest { cmd } => match cmd {
            ManifestCmd::Init { network_id, out } => {
                cmd_manifest_init(&cli.data_dir, network_id.clone(), out.clone())
            }
            ManifestCmd::Publish { file, accept_stale } => {
                cmd_manifest_publish(&cli.data_dir, file.clone(), *accept_stale)
            }
            ManifestCmd::Show => cmd_manifest_show(&cli.data_dir),
            ManifestCmd::Verify { file } => cmd_manifest_verify(&cli.data_dir, file.clone()),
            ManifestCmd::History => cmd_manifest_history(&cli.data_dir),
            ManifestCmd::Status => cmd_manifest_status(&cli.data_dir),
            ManifestCmd::Conflicts => cmd_manifest_conflicts(&cli.data_dir),
        },
        Commands::Disputes => cmd_disputes(&cli.data_dir),
        Commands::Parties { cmd } => {
            let node = load_node_reader(&cli.data_dir)?;
            match cmd {
                PartiesCmd::Sign {
                    role,
                    kind,
                    input,
                    out,
                } => cmd_parties_sign(&node, role.clone(), kind.clone(), input, out),
                PartiesCmd::Show { id } => cmd_parties_show(&node, id.clone()),
            }
        }
        Commands::Contract { cmd } => {
            let node = load_node_reader(&cli.data_dir)?;
            match cmd {
                ContractCmd::Show { id, wasm_out } => {
                    cmd_contract_show(&node, id.clone(), wasm_out.clone())
                }
                ContractCmd::New {
                    admits,
                    wasm_file,
                    wasm_b64,
                    out,
                } => cmd_contract_new(
                    admits.clone(),
                    wasm_file.clone(),
                    wasm_b64.clone(),
                    out.clone(),
                ),
                ContractCmd::Check { id } => cmd_contract_check(&node, id.clone()),
                ContractCmd::Status { id } => cmd_contract_status(&node, id.clone()),
            }
        }
        Commands::Sync { peers, page } => {
            // Sync is evidence acquisition: it must work while governance is
            // unverified (that is how the chain arrives), so it runs the
            // bootstrap policy - chain namespace in, everything else skipped.
            let node = load_node_bootstrap(&cli.data_dir)?;
            let hello = network_hello(&cli.data_dir, &node.key)?;
            let mesh = our_network_id(&cli.data_dir)?;
            cmd_sync(&node, peers, *page, hello.as_ref(), &mesh)
        }
        Commands::Node {
            addr,
            peers,
            every,
            discover,
            witness,
            http,
            read_only,
        } => node::run(
            &cli.data_dir,
            addr,
            peers.clone(),
            *every,
            *discover,
            *witness,
            http.clone(),
            *read_only,
        ),
        Commands::Discover { seconds } => node::discover(*seconds),
        Commands::Delta { cmd } => {
            let mesh = our_network_id(&cli.data_dir)?;
            match cmd {
                DeltaCmd::Make { out } => {
                    cmd_delta_make(&load_node_reader(&cli.data_dir)?, &mesh, out)
                }
                DeltaCmd::Answer { input, out } => {
                    cmd_delta_answer(&load_node_reader(&cli.data_dir)?, &mesh, input, out)
                }
                DeltaCmd::Merge { input } => {
                    cmd_delta_merge(&load_node_bootstrap(&cli.data_dir)?, &mesh, input)
                }
            }
        }
        Commands::Genesis => cmd_genesis(&cli.data_dir),
        Commands::Status => {
            let node = load_node_reader(&cli.data_dir)?;
            cmd_status(&node)
        }
        Commands::Bundle { cmd } => {
            let mesh = our_network_id(&cli.data_dir)?;
            match cmd {
                BundleCmd::Export { out } => {
                    cmd_bundle_export(&load_node_reader(&cli.data_dir)?, &mesh, out)
                }
                BundleCmd::Import { input } => {
                    cmd_bundle_import(&load_node_bootstrap(&cli.data_dir)?, &mesh, input)
                }
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(data_dir: &Path, command: Commands) -> Cli {
        Cli {
            data_dir: data_dir.to_path_buf(),
            command,
        }
    }

    fn publish(data_dir: &Path, ns: &str) -> Result<(), String> {
        run(cli(
            data_dir,
            Commands::Publish {
                ns: ns.into(),
                payload: Some("{\"statement\":\"x\"}".into()),
                file: None,
                refs: vec![],
            },
        ))
    }

    /// A pinned manifest governs every CLI write path, not only `datu serve`:
    /// a pin with no chain fails closed, and a verified chain supplies the
    /// gate. Read-only commands keep working either way - evidence must stay
    /// inspectable precisely when governance is broken.
    #[test]
    fn pinned_manifest_governs_cli_writes_but_never_reads() {
        // `run` holds one frame per subcommand arm; the default 2 MiB test
        // stack is not enough for the whole dispatch tree.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(pinned_manifest_body)
            .unwrap()
            .join()
            .unwrap();
    }

    fn pinned_manifest_body() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        run(cli(d, Commands::Init)).unwrap();
        let root = load_node(d).unwrap().identity.clone();

        run(cli(
            d,
            Commands::Network {
                cmd: NetworkCmd::Init {
                    mode: "permissionless".into(),
                    network_id: "gov-mesh".into(),
                    members: vec![],
                    roots: vec![],
                    manifest_root: Some(root.clone()),
                },
            },
        ))
        .unwrap();

        let err = publish(d, "gov.records").unwrap_err();
        assert!(
            err.contains("fail-closed") && err.contains("manifest"),
            "a pin without a verifiable chain must refuse CLI writes: {err}"
        );

        // …while every read-only path keeps working without publishing
        // authority: a chainless pinned observer must still be able to look.
        for read_only in [
            Commands::Log {
                ns: None,
                author: None,
                limit: 5,
            },
            Commands::Manifest {
                cmd: ManifestCmd::Status,
            },
            Commands::Manifest {
                cmd: ManifestCmd::Conflicts,
            },
            Commands::Attest {
                cmd: AttestCmd::Status {
                    subject: Some(root.clone()),
                    id: None,
                },
            },
            Commands::Disputes,
            Commands::Status,
        ] {
            run(cli(d, read_only)).unwrap_or_else(|e| panic!("read-only command failed: {e}"));
        }
        // `history` and `verify` have nothing to report yet; they explain why
        // rather than demanding authority they do not need.
        let err = run(cli(
            d,
            Commands::Manifest {
                cmd: ManifestCmd::History,
            },
        ))
        .unwrap_err();
        assert!(err.contains("no verified manifest chain"), "{err}");
        let err = run(cli(
            d,
            Commands::Manifest {
                cmd: ManifestCmd::Verify { file: None },
            },
        ))
        .unwrap_err();
        assert!(err.contains("does not verify"), "{err}");

        let template = d.join("mesh.json");
        run(cli(
            d,
            Commands::Manifest {
                cmd: ManifestCmd::Init {
                    network_id: "gov-mesh".into(),
                    out: template.clone(),
                },
            },
        ))
        .unwrap();
        run(cli(
            d,
            Commands::Manifest {
                cmd: ManifestCmd::Publish {
                    file: template.clone(),
                    accept_stale: false,
                },
            },
        ))
        .unwrap();

        publish(d, "gov.records").expect("the manifest admits its own root");

        // Verification is read-only and needs no publishing rights, and it
        // reports the honest truth: nothing independent has corroborated this
        // manifest yet, so the governance is stale even though it verifies.
        run(cli(
            d,
            Commands::Manifest {
                cmd: ManifestCmd::Verify { file: None },
            },
        ))
        .expect("a verified chain must verify");
        let store = Store::open(&d.join("node.db")).unwrap();
        let st =
            datu_store::manifest::status(&store, "gov-mesh", std::slice::from_ref(&root), None)
                .unwrap();
        assert_eq!(
            st.freshness,
            datu_store::Freshness::Stale,
            "one node cannot corroborate itself: {}",
            st.reason
        );

        // A root change taken from that stale view is refused unless the
        // operator says so explicitly.
        let mut rotated: datu_store::ManifestDoc =
            serde_json::from_str(&std::fs::read_to_string(&template).unwrap()).unwrap();
        rotated.roots = vec!["11".repeat(32)];
        std::fs::write(&template, serde_json::to_string_pretty(&rotated).unwrap()).unwrap();
        let err = run(cli(
            d,
            Commands::Manifest {
                cmd: ManifestCmd::Publish {
                    file: template.clone(),
                    accept_stale: false,
                },
            },
        ))
        .unwrap_err();
        assert!(
            err.contains("refusing a root change") && err.contains("--accept-stale"),
            "{err}"
        );

        assert!(
            store
                .list(Some("gov.mesh.gov-mesh.policy"), None, 10)
                .unwrap()
                .len()
                == 1,
            "the chain itself is an ordinary entry in the manifest namespace"
        );
    }

    /// Revocation end to end through the CLI: create, revoke, recount.
    /// Runs on a dedicated thread: ML-DSA key generation and signing in
    /// debug builds are stack-hungry, and the whole flow in one frame can
    /// outgrow the 2 MiB default test-thread stack.
    #[test]
    fn attest_revoke_publishes_a_statement() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(attest_revoke_flow)
            .unwrap()
            .join()
            .unwrap();
    }

    fn attest_revoke_flow() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        run(cli(d, Commands::Init)).unwrap();

        let subject = hex::encode([7u8; 32]);
        run(cli(
            d,
            Commands::Attest {
                cmd: AttestCmd::Create {
                    subject: subject.clone(),
                    claims: r#"{"role":"member"}"#.into(),
                    label: None,
                },
            },
        ))
        .unwrap();

        let node = load_node(d).unwrap();
        let attestation = node
            .store
            .all_entries()
            .unwrap()
            .into_iter()
            .find(|e| e.body.namespace == attest::NS_ATTEST)
            .expect("the attestation was stored");
        let attestation_id = attestation.id().unwrap();

        run(cli(
            d,
            Commands::Attest {
                cmd: AttestCmd::Revoke {
                    id: Some(hex::encode(attestation_id)),
                    key: None,
                    reason: Some("rotated".into()),
                },
            },
        ))
        .unwrap();

        let node = load_node(d).unwrap();
        let entries = node.store.all_entries().unwrap();
        let revokes = attest::revocations_for(entries.iter(), &attestation_id);
        assert_eq!(revokes.len(), 1, "one revocation statement on the ledger");
        assert_eq!(revokes[0].1.reason.as_deref(), Some("rotated"));
        let revoked = attest::revoked_by(entries.iter(), std::slice::from_ref(&node.identity));
        assert!(revoked.contains(&attestation_id));

        // Both status views render the revocation without error.
        run(cli(
            d,
            Commands::Attest {
                cmd: AttestCmd::Status {
                    subject: None,
                    id: Some(hex::encode(attestation_id)),
                },
            },
        ))
        .unwrap();
        run(cli(
            d,
            Commands::Attest {
                cmd: AttestCmd::Status {
                    subject: Some(subject),
                    id: None,
                },
            },
        ))
        .unwrap();
    }
    /// Witness time-attestation end to end: prove a checkpoint covered an
    /// entry, verify the artifact offline, and prove tampering is caught.
    #[test]
    fn witness_coverage_proof_roundtrip() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(witness_coverage_flow)
            .unwrap()
            .join()
            .unwrap();
    }

    fn witness_coverage_flow() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        run(cli(d, Commands::Init)).unwrap();
        publish(d, "general").expect("an open-namespace write lands");

        let node = load_node(d).unwrap();
        let target = node
            .store
            .latest(&node.identity)
            .unwrap()
            .expect("the publish is on this node's feed");
        let entry_hex = hex::encode(target.id().unwrap());

        let proof_path = d.join("coverage.json");
        run(cli(
            d,
            Commands::Witness {
                cmd: WitnessCmd::Prove {
                    entry: entry_hex.clone(),
                    checkpoint: None,
                    out: Some(proof_path.clone()),
                },
            },
        ))
        .unwrap();

        run(cli(
            d,
            Commands::Witness {
                cmd: WitnessCmd::VerifyProof {
                    input: proof_path.clone(),
                },
            },
        ))
        .unwrap();

        // Tamper one sibling hash: the path must no longer reach the
        // signed root, and verification must say so.
        let text = std::fs::read_to_string(&proof_path).unwrap();
        let mut artifact: serde_json::Value = serde_json::from_str(&text).unwrap();
        let sibling = artifact["proof"]["siblings"][0]
            .as_str()
            .expect("a two-entry set has one sibling")
            .to_string();
        let mut chars: Vec<char> = sibling.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        artifact["proof"]["siblings"][0] = serde_json::Value::String(chars.into_iter().collect());
        let tampered = d.join("tampered.json");
        std::fs::write(&tampered, serde_json::to_string(&artifact).unwrap()).unwrap();
        let err = run(cli(
            d,
            Commands::Witness {
                cmd: WitnessCmd::VerifyProof { input: tampered },
            },
        ))
        .unwrap_err();
        assert!(err.contains("does not reach"), "tampering is caught: {err}");
    }
    /// Deferred delivery end to end through the CLI: seal now (unopenable),
    /// release the key half, holder opens, non-holder cannot.
    #[test]
    fn deferred_delivery_cli_roundtrip() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(deferred_delivery_flow)
            .unwrap()
            .join()
            .unwrap();
    }

    fn deferred_delivery_flow() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for (name, pass) in [("issuer", "pw1"), ("holder", "pw2")] {
            run(cli(
                d,
                Commands::Signet {
                    cmd: WalletCmd::Create {
                        name: name.into(),
                        passphrase: Some(pass.into()),
                    },
                },
            ))
            .unwrap();
        }
        let holder_seal = datu_wallet::Wallet::open(d)
            .load("holder", "pw2")
            .unwrap()
            .public
            .seal_public;

        let doc = d.join("escrow.json");
        std::fs::write(
            &doc,
            format!(r#"{{"cert_id":"C-7","owner_name":"Amina","holder_seal":"{holder_seal}"}}"#),
        )
        .unwrap();

        let sealed_path = d.join("sealed.json");
        let secrets_path = d.join("secrets.json");
        run(cli(
            d,
            Commands::Signet {
                cmd: WalletCmd::SealDeferred {
                    name: "issuer".into(),
                    passphrase: Some("pw1".into()),
                    to: None,
                    to_field: Some("holder_seal".into()),
                    input: doc.clone(),
                    fields: "owner_name".into(),
                    out: Some(sealed_path.clone()),
                    release_out: Some(secrets_path.clone()),
                },
            },
        ))
        .unwrap();

        let sealed_doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sealed_path).unwrap()).unwrap();
        assert_eq!(
            sealed_doc["owner_name"]["sealed"],
            "datu-sealed-deferred-v2"
        );

        // Opening without a release object has nothing to open with.
        let err = run(cli(
            d,
            Commands::Signet {
                cmd: WalletCmd::OpenDeferred {
                    name: "holder".into(),
                    passphrase: Some("pw2".into()),
                    input: sealed_path.clone(),
                    field: "owner_name".into(),
                    release: sealed_path.clone(),
                    out: None,
                },
            },
        ))
        .unwrap_err();
        assert!(
            err.contains("no share object"),
            "locked before release: {err}"
        );

        let share_path = d.join("share.json");
        run(cli(
            d,
            Commands::Signet {
                cmd: WalletCmd::ReleaseDeferred {
                    input: sealed_path.clone(),
                    field: "owner_name".into(),
                    release: Some(secrets_path.clone()),
                    recover: false,
                    name: None,
                    passphrase: None,
                    out: Some(share_path.clone()),
                },
            },
        ))
        .unwrap();

        // The release addresses the nominated holder only.
        let err = run(cli(
            d,
            Commands::Signet {
                cmd: WalletCmd::OpenDeferred {
                    name: "issuer".into(),
                    passphrase: Some("pw1".into()),
                    input: sealed_path.clone(),
                    field: "owner_name".into(),
                    release: share_path.clone(),
                    out: None,
                },
            },
        ))
        .unwrap_err();
        assert!(err.contains("another holder"), "{err}");

        let opened_path = d.join("opened.json");
        run(cli(
            d,
            Commands::Signet {
                cmd: WalletCmd::OpenDeferred {
                    name: "holder".into(),
                    passphrase: Some("pw2".into()),
                    input: sealed_path.clone(),
                    field: "owner_name".into(),
                    release: share_path.clone(),
                    out: Some(opened_path.clone()),
                },
            },
        ))
        .unwrap();
        let opened: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&opened_path).unwrap()).unwrap();
        assert_eq!(opened, serde_json::json!("Amina"));

        // Lost the secrets file? The issuer's sealed custody copy recovers
        // the release half, and the holder opens with it all the same.
        let recovered_share = d.join("share-recovered.json");
        run(cli(
            d,
            Commands::Signet {
                cmd: WalletCmd::ReleaseDeferred {
                    input: sealed_path.clone(),
                    field: "owner_name".into(),
                    release: None,
                    recover: true,
                    name: Some("issuer".into()),
                    passphrase: Some("pw1".into()),
                    out: Some(recovered_share.clone()),
                },
            },
        ))
        .unwrap();
        let recovered_opened = d.join("opened-recovered.json");
        run(cli(
            d,
            Commands::Signet {
                cmd: WalletCmd::OpenDeferred {
                    name: "holder".into(),
                    passphrase: Some("pw2".into()),
                    input: sealed_path.clone(),
                    field: "owner_name".into(),
                    release: recovered_share,
                    out: Some(recovered_opened.clone()),
                },
            },
        ))
        .unwrap();
        let recovered: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&recovered_opened).unwrap()).unwrap();
        assert_eq!(recovered, serde_json::json!("Amina"));
    }
    /// A wasm contract spec can be built without hand-rolling base64.
    #[test]
    fn contract_new_encodes_the_wasm_body() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(contract_new_flow)
            .unwrap()
            .join()
            .unwrap();
    }

    fn contract_new_flow() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        run(cli(d, Commands::Init)).unwrap();
        // The 8-byte header alone is a valid (empty) wasm module.
        let wasm = d.join("rule.wasm");
        std::fs::write(&wasm, b" asm   ").unwrap();
        let spec_path = d.join("spec.json");
        run(cli(
            d,
            Commands::Contract {
                cmd: ContractCmd::New {
                    admits: "land.title.grant".into(),
                    wasm_file: Some(wasm),
                    wasm_b64: None,
                    out: Some(spec_path.clone()),
                },
            },
        ))
        .unwrap();
        let spec: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&spec_path).unwrap()).unwrap();
        assert_eq!(spec["admits"], "land.title.grant");
        assert_eq!(spec["version"], 1);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(spec["wasm"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, b" asm   ");

        // A module that does not parse fails before the signing steps.
        let bad = d.join("bad.wasm");
        std::fs::write(&bad, b"not wasm").unwrap();
        let err = run(cli(
            d,
            Commands::Contract {
                cmd: ContractCmd::New {
                    admits: "x".into(),
                    wasm_file: Some(bad),
                    wasm_b64: None,
                    out: None,
                },
            },
        ))
        .unwrap_err();
        assert!(err.contains("does not parse"), "typo caught early: {err}");
    }
}
