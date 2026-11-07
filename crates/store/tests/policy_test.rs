use datu_core::attest::{AttestationDoc, CosignDoc};
use datu_core::parties::SignedDocument;
use datu_core::pq::PqPrivateKey;
use datu_core::{Entry, EntryBody};
use datu_store::{NamespaceRule, RoleRule, Store, StoreError, WritePolicy, POLICY_VERSION};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

struct Keys {
    ed: SigningKey,
    pq: PqPrivateKey,
}

impl Keys {
    fn new() -> Keys {
        Keys {
            ed: SigningKey::generate(&mut OsRng),
            pq: datu_core::pq::keypair().unwrap().1,
        }
    }

    fn hex(&self) -> String {
        hex::encode(self.ed.verifying_key().as_bytes())
    }

    fn entry(&self, ns: &str, seq: u64, payload: &[u8]) -> Entry {
        self.entry_with_prev(ns, seq, None, payload)
    }

    fn entry_with_prev(&self, ns: &str, seq: u64, prev: Option<[u8; 32]>, payload: &[u8]) -> Entry {
        let body = EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: ns.to_string(),
            seq,
            prev,
            refs: vec![],
            timestamp_ms: 1,
            payload: payload.to_vec(),
        };
        Entry::sign(body, &self.ed, &self.pq).unwrap()
    }

    fn attest(&self, subject: &str) -> Entry {
        let doc = AttestationDoc {
            subject: subject.to_string(),
            label: Some("Acme Ltd".into()),
            claims: serde_json::json!({"role": "bidder"}),
        };
        let seq = 0;
        let body = EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: "identity.attest".to_string(),
            seq,
            prev: None,
            refs: vec![],
            timestamp_ms: 1,
            payload: doc.payload_bytes().unwrap(),
        };
        Entry::sign(body, &self.ed, &self.pq).unwrap()
    }

    fn cosign(&self, attestation_id: [u8; 32]) -> Entry {
        let doc = CosignDoc {
            attestation: hex::encode(attestation_id),
        };
        let body = EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: "identity.cosign".to_string(),
            seq: 0,
            prev: None,
            refs: vec![attestation_id],
            timestamp_ms: 1,
            payload: serde_json::to_vec(&doc).unwrap(),
        };
        Entry::sign(body, &self.ed, &self.pq).unwrap()
    }
}

fn gated_policy(attestors: Vec<String>, gated: &[&str]) -> WritePolicy {
    WritePolicy {
        version: POLICY_VERSION,
        readonly: false,
        gated: gated.iter().map(|s| s.to_string()).collect(),
        writers: vec![],
        attestors,
        min_cosigners: 0,
        required_roles: vec![],
        rules: vec![],
    }
}

fn gated_store(policy: WritePolicy) -> Store {
    Store::open_in_memory_with_policy(Some(policy)).unwrap()
}

#[test]
fn observer_without_policy_accepts_everything() {
    let store = Store::open_in_memory().unwrap();
    let rogue = Keys::new();
    assert!(store
        .insert_entry(&rogue.entry("gov.records", 0, b"anyone can mirror"))
        .unwrap());
}

#[test]
fn gated_namespace_denies_unadmitted_author() {
    let attestor = Keys::new();
    let store = gated_store(gated_policy(vec![attestor.hex()], &["gov.*"]));
    let rogue = Keys::new();

    // Ungated namespaces stay open even on a gated node.
    assert!(store.insert_entry(&rogue.entry("general", 0, b"hi")).unwrap());

    let stranger = Keys::new();
    match store.insert_entry(&stranger.entry("gov.records", 0, b"forged")) {
        Err(StoreError::Denied(m)) => assert!(m.contains("not an admitted writer")),
        other => panic!("expected Denied, got {other:?}"),
    }
    assert_eq!(store.entry_count().unwrap(), 2); // genesis + the open-ns entry
}

#[test]
fn explicit_writer_is_admitted() {
    let writer = Keys::new();
    let mut policy = gated_policy(vec![], &["gov.*"]);
    policy.writers = vec![writer.hex()];
    policy.attestors = vec![Keys::new().hex()];
    let store = gated_store(policy);
    assert!(store.insert_entry(&writer.entry("gov.records", 0, b"official")).unwrap());
}

#[test]
fn attestation_from_trust_root_admits_writer() {
    let registry = Keys::new();
    let bidder = Keys::new();
    let store = gated_store(gated_policy(vec![registry.hex()], &["gov.*"]));

    // Before the attestation syncs, the bidder is not admitted.
    assert!(matches!(
        store.insert_entry(&bidder.entry("gov.bids", 0, b"bid")),
        Err(StoreError::Denied(_))
    ));
    // The registry attests the bidder (identity.attest is ungated here).
    assert!(store.insert_entry(&registry.attest(&bidder.hex())).unwrap());
    // Now the bidder is admitted - admission is rooted in the attestation graph.
    assert!(store.insert_entry(&bidder.entry("gov.bids", 0, b"bid")).unwrap());
}

#[test]
fn attestation_from_unknown_key_does_not_admit() {
    let stranger = Keys::new();
    let bidder = Keys::new();
    let registry = Keys::new();
    let store = gated_store(gated_policy(vec![registry.hex()], &["gov.*"]));
    assert!(store.insert_entry(&stranger.attest(&bidder.hex())).unwrap());
    assert!(matches!(
        store.insert_entry(&bidder.entry("gov.bids", 0, b"bid")),
        Err(StoreError::Denied(_))
    ));
}

#[test]
fn min_cosigners_is_enforced() {
    let registry = Keys::new();
    let bidder = Keys::new();
    let mut policy = gated_policy(vec![registry.hex()], &["gov.*"]);
    policy.min_cosigners = 1;
    let store = gated_store(policy);

    let attestation = registry.attest(&bidder.hex());
    let attestation_id = attestation.id().unwrap();
    assert!(store.insert_entry(&attestation).unwrap());
    // Registry signature alone is not enough when 1 cosigner is required.
    assert!(matches!(
        store.insert_entry(&bidder.entry("gov.bids", 0, b"bid")),
        Err(StoreError::Denied(_))
    ));
    // A cosigner adds weight; now the subject is admitted.
    let cosigner = Keys::new();
    assert!(store.insert_entry(&cosigner.cosign(attestation_id)).unwrap());
    assert!(store.insert_entry(&bidder.entry("gov.bids", 0, b"bid")).unwrap());
}

#[test]
fn read_only_denies_all_writes() {
    let store = gated_store(WritePolicy::readonly());
    let anyone = Keys::new();
    assert!(matches!(
        store.insert_entry(&anyone.entry("general", 0, b"x")),
        Err(StoreError::Denied(_))
    ));
    assert_eq!(store.entry_count().unwrap(), 1); // the seeded genesis
}

#[test]
fn required_party_role_must_sign() {
    let registry = Keys::new();
    let citizen = Keys::new();
    let mut policy = gated_policy(vec![registry.hex()], &["gov.*"]);
    policy.required_roles = vec!["holder".into()];
    let store = gated_store(policy);

    let document = SignedDocument::new(
        "land.title.application",
        serde_json::json!({"parcel": "TIT-1", "holder": citizen.hex()}),
    );

    // No party signature at all: denied even though the registry is admitted.
    let unsigned = serde_json::to_vec(&document).unwrap();
    assert!(matches!(
        store.insert_entry(&registry.entry("gov.titles", 0, &unsigned)),
        Err(StoreError::Denied(_))
    ));

    // Registrar signature only: still missing holder consent.
    let mut registrar_signed = document.clone();
    registrar_signed
        .sign("registrar", &registry.ed, Some(&registry.pq))
        .unwrap();
    let bytes = serde_json::to_vec(&registrar_signed).unwrap();
    assert!(matches!(
        store.insert_entry(&registry.entry("gov.titles", 0, &bytes)),
        Err(StoreError::Denied(_))
    ));

    // The citizen (holder) signs: admitted.
    let mut fully_signed = registrar_signed;
    fully_signed.sign("holder", &citizen.ed, None).unwrap();
    let bytes = serde_json::to_vec(&fully_signed).unwrap();
    assert!(store.insert_entry(&registry.entry("gov.titles", 0, &bytes)).unwrap());
}

#[test]
fn tampered_party_document_is_denied() {
    let registry = Keys::new();
    let citizen = Keys::new();
    let mut policy = gated_policy(vec![registry.hex()], &["gov.*"]);
    policy.required_roles = vec!["holder".into()];
    let store = gated_store(policy);

    let mut document = SignedDocument::new(
        "land.title.application",
        serde_json::json!({"parcel": "TIT-1"}),
    );
    document
        .sign("holder", &citizen.ed, None)
        .unwrap();
    // Mutate after signing: the holder never consented to this.
    document.doc["parcel"] = serde_json::json!("TIT-999");
    let bytes = serde_json::to_vec(&document).unwrap();
    assert!(matches!(
        store.insert_entry(&registry.entry("gov.titles", 0, &bytes)),
        Err(StoreError::Denied(_))
    ));
}

#[test]
fn denied_entries_are_skipped_not_fatal_in_merges() {
    let writer = Keys::new();
    let rogue = Keys::new();

    // Open observer mirror: collects everything.
    let observer = Store::open_in_memory().unwrap();
    assert!(observer.insert_entry(&writer.entry("general", 0, b"open data")).unwrap());
    assert!(observer.insert_entry(&rogue.entry("gov.records", 0, b"forged")).unwrap());
    let bundle = observer.export_bundle("").unwrap();

    // Gated node: imports the rest, skips the rogue entry, does not abort.
    let mut policy = gated_policy(vec![], &["gov.*"]);
    policy.writers = vec![writer.hex()];
    policy.attestors = vec![Keys::new().hex()];
    let gated = gated_store(policy);
    let summary = gated.import_bundle(&bundle, "").unwrap();
    assert_eq!(summary.entries_new, 1);
    assert_eq!(summary.entries_denied, 1);
    assert_eq!(gated.entry_count().unwrap(), 2); // genesis + the admitted entry

    // Delta files behave identically.
    let empty = Store::open_in_memory().unwrap();
    let request = empty.export_haves_request(0.001, "").unwrap();
    let (response, _) = observer.answer_delta(&request, "").unwrap();
    let summary = gated.merge_delta(&response, "").unwrap();
    assert_eq!(summary.entries_denied, 1);
}

#[test]
fn network_wall_refuses_foreign_offline_artifacts() {
    let gov = Store::open_in_memory().unwrap();
    let open = Store::open_in_memory().unwrap();

    // A walled bundle never imports into an open node, nor the other way.
    let bundle = gov.export_bundle("gov-mesh").unwrap();
    assert!(open.import_bundle(&bundle, "").is_err());
    let open_bundle = open.export_bundle("").unwrap();
    assert!(gov.import_bundle(&open_bundle, "gov-mesh").is_err());

    // Same mesh imports fine (and is idempotent).
    let gov2 = Store::open_in_memory().unwrap();
    assert!(gov2.import_bundle(&bundle, "gov-mesh").is_ok());

    // Delta and witness files carry the wall too.
    let request = open.export_haves_request(0.001, "").unwrap();
    assert!(gov.answer_delta(&request, "gov-mesh").is_err());
    let gov_request = gov.export_haves_request(0.001, "gov-mesh").unwrap();
    assert!(open.answer_delta(&gov_request, "").is_err());
    let witness = gov.export_witness_stream("gov-mesh").unwrap();
    assert!(open.import_witness_stream(&witness, "").is_err());
    assert!(gov2.import_witness_stream(&witness, "gov-mesh").is_ok());

    // Pre-network-mode files (no id) count as open-network artifacts.
    use borsh::{BorshDeserialize, BorshSerialize};
    #[derive(BorshSerialize, BorshDeserialize)]
    struct LegacyBundle {
        entries: Vec<Entry>,
        checkpoints: Vec<datu_core::Checkpoint>,
    }
    let legacy = LegacyBundle {
        entries: vec![],
        checkpoints: vec![],
    };
    let legacy_bytes = borsh::to_vec(&legacy).unwrap();
    assert!(open.import_bundle(&legacy_bytes, "").is_ok());
    assert!(gov.import_bundle(&legacy_bytes, "gov-mesh").is_err());
}

#[test]
fn policy_json_roundtrip_and_validation() {
    let policy = WritePolicy {
        version: POLICY_VERSION,
        readonly: false,
        gated: vec!["gov.*".into()],
        writers: vec!["11".repeat(32)],
        attestors: vec!["22".repeat(32)],
        min_cosigners: 2,
        required_roles: vec!["holder".into()],
        rules: vec![NamespaceRule {
            ns: "gov.titles.*".into(),
            require: vec![RoleRule {
                role: "holder".into(),
                key: None,
                bind_field: Some("holder_key".into()),
            }],
            require_sealed: vec!["holder_name".into()],
        }],
    };
    let json = policy.to_json().unwrap();
    assert_eq!(WritePolicy::from_json(&json).unwrap(), policy);
    assert!(WritePolicy::from_json(r#"{"version": 99}"#).is_err());
    // Unknown fields stay tolerant; defaults make hand-written files easy.
    let minimal = WritePolicy::from_json(r#"{"version": 1, "gated": ["gov.*"]}"#).unwrap();
    assert!(!minimal.readonly);
    assert!(minimal.required_roles.is_empty());
    assert!(minimal.rules.is_empty());
    // Older rule shape (no require_sealed) still parses.
    let old_rule = WritePolicy::from_json(
        r#"{"version": 1, "gated": ["gov.*"], "rules": [{"ns": "gov.titles.*", "require": [{"role": "holder"}]}]}"#,
    )
    .unwrap();
    assert!(old_rule.rules[0].require_sealed.is_empty());
}

fn rule(ns: &str, role: &str, key: Option<&str>, bind_field: Option<&str>) -> NamespaceRule {
    NamespaceRule {
        ns: ns.to_string(),
        require: vec![RoleRule {
            role: role.to_string(),
            key: key.map(str::to_string),
            bind_field: bind_field.map(str::to_string),
        }],
        require_sealed: vec![],
    }
}

#[test]
fn per_namespace_rules_are_independent() {
    let registry = Keys::new();
    let bidder = Keys::new();
    let mut policy = gated_policy(vec![registry.hex()], &["gov.*"]);
    policy.rules = vec![
        rule("gov.titles.*", "holder", None, Some("holder_key")),
        rule("gov.bids.*", "bidder", None, None),
    ];
    let store = gated_store(policy);

    // A bid needs a bidder signature, not a holder signature.
    let mut bid = SignedDocument::new("bid", serde_json::json!({"lot": "L7"}));
    bid.sign("bidder", &bidder.ed, None).unwrap();
    let bytes = serde_json::to_vec(&bid).unwrap();
    assert!(store.insert_entry(&registry.entry("gov.bids.lot7", 0, &bytes)).unwrap());

    // A title with only a bidder signature is missing the holder requirement.
    assert!(matches!(
        store.insert_entry(&registry.entry("gov.titles.application", 0, &bytes)),
        Err(StoreError::Denied(_))
    ));
}

#[test]
fn holder_must_be_the_key_named_in_the_document() {
    let registry = Keys::new();
    let citizen = Keys::new();
    let stranger = Keys::new();
    let mut policy = gated_policy(vec![registry.hex()], &["gov.*"]);
    policy.rules = vec![rule("gov.titles.*", "holder", None, Some("holder_key"))];
    let store = gated_store(policy);

    let title_doc = |holder_key: &str| {
        SignedDocument::new(
            "land.title.application",
            serde_json::json!({"parcel": "TIT-1", "holder_key": holder_key}),
        )
    };

    // The citizen named in the doc signs: genuine consent.
    let mut honest = title_doc(&citizen.hex());
    honest.sign("holder", &citizen.ed, None).unwrap();
    assert!(store
        .insert_entry(&registry.entry("gov.titles.application", 0, &serde_json::to_vec(&honest).unwrap()))
        .unwrap());

    // Someone else signs the holder role while the doc names the citizen.
    let mut impersonation = title_doc(&citizen.hex());
    impersonation.sign("holder", &stranger.ed, None).unwrap();
    assert!(matches!(
        store.insert_entry(&registry.entry(
            "gov.titles.application",
            0,
            &serde_json::to_vec(&impersonation).unwrap()
        )),
        Err(StoreError::Denied(_))
    ));

    // The doc names someone else but the citizen signs: not self-bound either.
    let mut swapped = title_doc(&stranger.hex());
    swapped.sign("holder", &citizen.ed, None).unwrap();
    assert!(matches!(
        store.insert_entry(&registry.entry(
            "gov.titles.application",
            0,
            &serde_json::to_vec(&swapped).unwrap()
        )),
        Err(StoreError::Denied(_))
    ));
}

#[test]
fn pinned_role_key_is_enforced() {
    let registry = Keys::new();
    let intruder = Keys::new();
    let mut policy = gated_policy(vec![registry.hex()], &["gov.*"]);
    policy.writers = vec![intruder.hex()];
    policy.rules = vec![rule(
        "gov.degrees.*",
        "registrar",
        Some(&registry.hex()),
        None,
    )];
    let store = gated_store(policy);

    let degree = SignedDocument::new("degree.issued", serde_json::json!({"id": "D-9"}));

    // Only the registry's own key may sign the registrar role.
    let mut genuine = degree.clone();
    genuine.sign("registrar", &registry.ed, None).unwrap();
    assert!(store
        .insert_entry(&registry.entry("gov.degrees.2026", 0, &serde_json::to_vec(&genuine).unwrap()))
        .unwrap());

    // An admitted writer cannot sign the registrar role with their own key.
    let mut forged = degree;
    forged.sign("registrar", &intruder.ed, None).unwrap();
    assert!(matches!(
        store.insert_entry(&intruder.entry(
            "gov.degrees.2026",
            0,
            &serde_json::to_vec(&forged).unwrap()
        )),
        Err(StoreError::Denied(_))
    ));
}

#[test]
fn personal_fields_must_be_encrypted() {
    let registry = Keys::new();
    let second_writer = Keys::new();
    let citizen = Keys::new();
    let mut policy = gated_policy(vec![registry.hex()], &["gov.*"]);
    policy.writers = vec![second_writer.hex()];
    let mut title_rule = rule("gov.titles.*", "holder", None, Some("holder_key"));
    title_rule.require_sealed = vec!["holder_name".into(), "birth_date".into()];
    policy.rules = vec![title_rule];
    let store = gated_store(policy);

    let sealed_blob = || serde_json::json!({
        "sealed": "datu-sealed-v2",
        "recipients": [],
        "commitment": "00"
    });

    let build = |holder_name: serde_json::Value, with_birth: bool| {
        let mut doc = serde_json::json!({
            "parcel": "TIT-1",
            "holder_key": citizen.hex(),
            "holder_name": holder_name,
        });
        if with_birth {
            doc["birth_date"] = sealed_blob();
        }
        let mut signed = SignedDocument::new("land.title.application", doc);
        signed.sign("holder", &citizen.ed, None).unwrap();
        serde_json::to_vec(&signed).unwrap()
    };

    // Plaintext name: personal data must never reach the public ledger.
    match store.insert_entry(&registry.entry(
        "gov.titles.application",
        0,
        &build(serde_json::json!("Amina Yusuf"), false),
    )) {
        Err(StoreError::Denied(m)) => {
            assert!(m.contains("holder_name"), "message names the field: {m}");
            assert!(m.contains("encrypted"), "message explains the rule: {m}");
        }
        other => panic!("plaintext holder name must be denied, got {other:?}"),
    }

    // Sealed name: accepted.
    let sealed_entry = registry.entry(
        "gov.titles.application",
        0,
        &build(sealed_blob(), true),
    );
    assert!(store.insert_entry(&sealed_entry).unwrap());

    // Legacy pre-rebrand seal marks (dag-sealed-*) are still accepted.
    let legacy_blob = serde_json::json!({
        "sealed": "dag-sealed-v2",
        "recipients": [],
        "commitment": "00"
    });
    assert!(store
        .insert_entry(&registry.entry_with_prev(
            "gov.titles.application",
            1,
            Some(sealed_entry.id().unwrap()),
            &build(legacy_blob, true)
        ))
        .unwrap());

    // A document without the personal field at all is fine (nothing to leak).
    let mut bare = SignedDocument::new(
        "land.title.application",
        serde_json::json!({"parcel": "TIT-2", "holder_key": citizen.hex()}),
    );
    bare.sign("holder", &citizen.ed, None).unwrap();
    assert!(store
        .insert_entry(&second_writer.entry(
            "gov.titles.application",
            0,
            &serde_json::to_vec(&bare).unwrap()
        ))
        .unwrap());
}
