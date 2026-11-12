//! Document contracts: admission, evaluation, and reporting.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use datu_core::contract::{
    ConditionKind, ContractSpec, PartyRequirement, RefRequirement, CONTRACT_KIND, CONTRACT_VERSION,
};
use datu_core::parties::SignedDocument;
use datu_core::{Entry, EntryBody};
use datu_store::{Store, StoreError, StoreResult, WritePolicy};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

struct Keys {
    ed: SigningKey,
    pq: datu_core::pq::PqPrivateKey,
    author: String,
}

fn keys() -> Keys {
    let ed = SigningKey::generate(&mut OsRng);
    let author = hex::encode(ed.verifying_key().as_bytes());
    Keys {
        ed,
        pq: datu_core::pq::keypair().unwrap().1,
        author,
    }
}

fn signed_doc(kind: &str, doc: serde_json::Value, roles: &[(&str, &SigningKey)]) -> Vec<u8> {
    let mut document = SignedDocument::new(kind, doc);
    for (role, key) in roles {
        document.sign(role, key, None).unwrap();
    }
    serde_json::to_vec(&document).unwrap()
}

fn make_entry(
    k: &Keys,
    ns: &str,
    payload: Vec<u8>,
    seq: u64,
    prev: Option<[u8; 32]>,
    refs: Vec<[u8; 32]>,
    ts: u64,
) -> Entry {
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: k.author.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: ns.into(),
        seq,
        prev,
        refs,
        timestamp_ms: ts,
        payload,
    };
    Entry::sign(body, &k.ed, &k.pq).unwrap()
}

fn publish(
    store: &Store,
    k: &Keys,
    ns: &str,
    payload: Vec<u8>,
    seq: u64,
    prev: Option<[u8; 32]>,
    refs: Vec<[u8; 32]>,
    ts: u64,
) -> Entry {
    let entry = make_entry(k, ns, payload, seq, prev, refs, ts);
    assert!(store.insert_entry(&entry).unwrap());
    entry
}

fn default_spec() -> ContractSpec {
    ContractSpec {
        version: CONTRACT_VERSION,
        admits: "land.title.grant".into(),
        requires_refs: vec![RefRequirement {
            kind: "land.title.inspection".into(),
            count: 1,
            party: Some("inspector".into()),
            min_cosigners: None,
            author: None,
        }],
        requires_parties: vec![PartyRequirement {
            role: "holder".into(),
            key: None,
            bind_field: Some("holder_key".into()),
        }],
        deadline_from_field: Some("deadline_ms".into()),
        not_before_field: None,
        not_after_field: None,
        requires_sealed: vec![],
        wasm: None,
    }
}

/// A wasm32 needle scanner (the same shape the core tests use): admits
/// when the input JSON contains "PH-1" (i32 LE 0x312D4850), otherwise
/// returns the denial reason from its data segment. The trailing
/// `(unreachable)` is dead code required by wasmi 0.31's validator after
/// a br-terminated loop in a result-bearing function.
const SCAN_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (global $heap (mut i32) (i32.const 4096))
      (data (i32.const 1088) "the parcel PH-1 is not mentioned in the document")
      (func (export "alloc") (param $size i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get $size)))
        (local.get $ptr))
      (func (export "evaluate") (param $in_ptr i32) (param $in_len i32) (param $out_ptr i32) (param $out_cap i32) (result i32)
        (local $i i32)
        (loop $scan
          (if (i32.gt_u (i32.add (local.get $i) (i32.const 4)) (local.get $in_len))
            (then
              (memory.copy (local.get $out_ptr) (i32.const 1088) (i32.const 48))
              (return (i32.const 48))))
          (if (i32.eq (i32.load (i32.add (local.get $in_ptr) (local.get $i))) (i32.const 0x312D4850))
            (then (return (i32.const 0))))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $scan))
        (unreachable)))
"#;

/// A gated validator store plus the keys of the drama: the registrar
/// (admitted writer), the inspector, and the holder. `fixture` also
/// publishes the contract entry itself.
struct Fixture {
    store: Store,
    registrar: Keys,
    inspector: Keys,
    holder: Keys,
    contract_id: [u8; 32],
    registrar_seq: u64,
    registrar_prev: Option<[u8; 32]>,
    inspector_seq: u64,
    inspector_prev: Option<[u8; 32]>,
}

fn fixture_with(spec: &ContractSpec, contract_ns: &str) -> Fixture {
    let registrar = keys();
    let inspector = keys();
    let holder = keys();
    let mut policy = WritePolicy::default();
    policy.gated = vec!["gov.titles.*".into(), "gov.contracts".into()];
    policy.writers = vec![registrar.author.clone()];
    let store = Store::open_in_memory_with_policy(Some(policy)).unwrap();

    let issuer = SigningKey::generate(&mut OsRng);
    let payload = signed_doc(
        CONTRACT_KIND,
        serde_json::to_value(spec).unwrap(),
        &[("issuer", &issuer)],
    );
    let contract = publish(
        &store,
        &registrar,
        contract_ns,
        payload,
        0,
        None,
        vec![],
        1,
    );
    Fixture {
        store,
        registrar,
        inspector,
        holder,
        contract_id: contract.id().unwrap(),
        registrar_seq: 1,
        registrar_prev: Some(contract.id().unwrap()),
        inspector_seq: 0,
        inspector_prev: None,
    }
}

fn fixture() -> Fixture {
    fixture_with(&default_spec(), "gov.contracts")
}

/// A wasm-body contract end to end on a gated validator store: the
/// module replaces the DSL requirements wholesale, admission runs it,
/// and denials carry the guest's own words.
#[test]
fn wasm_contract_body_admits_and_denies() {
    let mut spec = default_spec();
    spec.wasm = Some(B64.encode(wat::parse_str(SCAN_WAT).unwrap()));
    let mut fx = fixture_with(&spec, "gov.contracts");

    let grant_with_parcel = |fx: &mut Fixture, parcel: &str| {
        let payload = signed_doc(
            "land.title.grant",
            serde_json::json!({
                "parcel": parcel,
                "contract": fx.contract_ref(),
            }),
            &[("holder", &fx.holder.ed)],
        );
        let seq = fx.registrar_seq;
        let prev = fx.registrar_prev;
        let entry = make_entry(
            &fx.registrar,
            "gov.titles.grant",
            payload,
            seq,
            prev,
            vec![],
            2000,
        );
        fx.registrar_seq += 1;
        fx.registrar_prev = Some(entry.id().unwrap());
        entry
    };

    // No DSL condition is judged: the guest alone decides.
    let admitted_entry = grant_with_parcel(&mut fx, "PH-1");
    assert!(fx.store.insert_entry(&admitted_entry).is_ok());

    let denied_entry = grant_with_parcel(&mut fx, "PH-2");
    let check = fx.store.check_contract(&denied_entry).unwrap().unwrap();
    assert!(!check.admitted);
    assert!(check.reasons.iter().any(|r| r.contains("not mentioned")));
    let wasm_condition = check
        .conditions
        .iter()
        .find(|c| c.kind == ConditionKind::Wasm)
        .unwrap();
    assert!(!wasm_condition.met);
    assert_eq!(wasm_condition.found, "denied");

    let message = denied_message(fx.store.insert_entry(&denied_entry));
    assert!(
        message.contains("not mentioned"),
        "admission denial carries the guest's reason: {message}"
    );
}

/// A wasm rule cannot be decomposed into pending citation-side
/// conditions: the outlook says so instead of guessing.
#[test]
fn wasm_contract_outlook_requires_the_document() {
    let mut spec = default_spec();
    spec.admits = "datu.cert.release".into();
    spec.requires_refs = vec![];
    spec.requires_parties = vec![];
    spec.deadline_from_field = None;
    spec.wasm = Some(B64.encode(wat::parse_str(SCAN_WAT).unwrap()));
    let mut fx = fixture_with(&spec, "gov.contracts");

    let anchor = publish(
        &fx.store,
        &fx.registrar,
        "records.escrow",
        signed_doc(
            "datu.cert.escrow",
            serde_json::json!({"cert_id": "C-3", "contract": fx.contract_ref()}),
            &[],
        ),
        fx.registrar_seq,
        fx.registrar_prev,
        vec![],
        1000,
    );
    fx.registrar_seq += 1;
    fx.registrar_prev = Some(anchor.id().unwrap());

    let outlook = fx
        .store
        .contract_outlook(&anchor.id().unwrap())
        .unwrap()
        .unwrap();
    assert!(!outlook.ready);
    assert!(outlook.conditions.is_empty());
    assert!(
        outlook.reasons.iter().any(|r| r.contains("wasm predicate")),
        "outlook explains why it cannot predict: {:?}",
        outlook.reasons
    );
}

/// An open mirror accepts everything; the verify_all recount flags wasm
/// denials the same way it flags DSL denials.
#[test]
fn verify_all_counts_wasm_contract_failures() {
    let store = Store::open_in_memory().unwrap();
    let registrar = keys();
    let issuer = SigningKey::generate(&mut OsRng);

    let mut spec = default_spec();
    spec.wasm = Some(B64.encode(wat::parse_str(SCAN_WAT).unwrap()));
    let payload = signed_doc(
        CONTRACT_KIND,
        serde_json::to_value(&spec).unwrap(),
        &[("issuer", &issuer)],
    );
    let contract = publish(&store, &registrar, "gov.contracts", payload, 0, None, vec![], 1);
    let contract_ref = serde_json::json!({
        "id": hex::encode(contract.id().unwrap()),
        "version": CONTRACT_VERSION
    });

    let mut seq = 1u64;
    let mut prev = Some(contract.id().unwrap());
    let grant_doc = |parcel: &str| {
        signed_doc(
            "land.title.grant",
            serde_json::json!({"parcel": parcel, "contract": contract_ref}),
            &[],
        )
    };

    let ok = publish(
        &store,
        &registrar,
        "gov.titles.grant",
        grant_doc("PH-1"),
        seq,
        prev,
        vec![],
        2000,
    );
    assert_eq!(store.verify_all().unwrap().contracts_failed, 0);

    seq += 1;
    prev = Some(ok.id().unwrap());
    publish(
        &store,
        &registrar,
        "gov.titles.grant",
        grant_doc("PH-9"),
        seq,
        prev,
        vec![],
        2000,
    );
    assert_eq!(
        store.verify_all().unwrap().contracts_failed,
        1,
        "evidence-grade recount flags the wasm denial"
    );
}

impl Fixture {
    fn contract_ref(&self) -> serde_json::Value {
        serde_json::json!({
            "id": hex::encode(self.contract_id),
            "version": CONTRACT_VERSION
        })
    }

    /// An inspection record by the inspector (open namespace, any timestamp).
    fn compliance(&mut self, ts: u64, extra_signer: Option<&SigningKey>) -> Entry {
        let mut roles = vec![("inspector", &self.inspector.ed)];
        if let Some(second) = extra_signer {
            roles.push(("second", second));
        }
        let payload = signed_doc(
            "land.title.inspection",
            serde_json::json!({"parcel": "PH-1"}),
            &roles,
        );
        let seq = self.inspector_seq;
        let prev = self.inspector_prev;
        let entry = make_entry(
            &self.inspector,
            "land.records",
            payload,
            seq,
            prev,
            vec![],
            ts,
        );
        self.inspector_seq += 1;
        self.inspector_prev = Some(entry.id().unwrap());
        assert!(self.store.insert_entry(&entry).unwrap());
        entry
    }

    /// The governed entry, built but not inserted (so failed admissions can
    /// also be inspected via `check_contract`).
    fn grant_entry(
        &mut self,
        refs: Vec<[u8; 32]>,
        holder_key_in_doc: Option<String>,
        deadline: Option<u64>,
        contract: Option<serde_json::Value>,
    ) -> Entry {
        let holder_key = hex::encode(self.holder.ed.verifying_key().as_bytes());
        let mut doc = serde_json::json!({
            "parcel": "PH-1",
            "holder_key": holder_key_in_doc.unwrap_or(holder_key),
        });
        if let Some(deadline) = deadline {
            doc["deadline_ms"] = serde_json::json!(deadline);
        }
        if let Some(contract) = contract {
            doc["contract"] = contract;
        }
        let payload =
            signed_doc("land.title.grant", doc, &[("holder", &self.holder.ed)]);
        let seq = self.registrar_seq;
        let prev = self.registrar_prev;
        self.registrar_seq += 1;
        let entry = make_entry(
            &self.registrar,
            "gov.titles.grant",
            payload,
            seq,
            prev,
            refs,
            2000,
        );
        self.registrar_prev = Some(entry.id().unwrap());
        entry
    }

    fn grant(
        &mut self,
        refs: Vec<[u8; 32]>,
        holder_key_in_doc: Option<String>,
        deadline: Option<u64>,
        contract: Option<serde_json::Value>,
    ) -> StoreResult<bool> {
        let entry = self.grant_entry(refs, holder_key_in_doc, deadline, contract);
        self.store.insert_entry(&entry)
    }
}

fn denied_message(result: StoreResult<bool>) -> String {
    match result {
        Err(StoreError::Denied(message)) => message,
        other => panic!("expected a policy denial, got {other:?}"),
    }
}

#[test]
fn compliant_document_is_admitted() {
    let mut fx = fixture();
    let compliance = fx.compliance(1000, None);
    assert!(fx
        .grant(
            vec![compliance.id().unwrap()],
            None,
            Some(1000),
            Some(fx.contract_ref())
        )
        .is_ok());
}

#[test]
fn missing_citation_is_denied_and_names_the_kind() {
    let mut fx = fixture();
    fx.compliance(1000, None);
    let message = denied_message(fx.grant(vec![], None, Some(1000), Some(fx.contract_ref())));
    assert!(
        message.contains("land.title.inspection"),
        "denial names the required kind: {message}"
    );
    assert!(message.contains("contract"), "denial says it is the contract: {message}");
}

#[test]
fn party_bind_field_mismatch_is_denied() {
    let mut fx = fixture();
    let compliance = fx.compliance(1000, None);
    let stranger_key = format!("{}00", "a".repeat(62));
    let message = denied_message(fx.grant(
        vec![compliance.id().unwrap()],
        Some(stranger_key),
        Some(1000),
        Some(fx.contract_ref()),
    ));
    assert!(
        message.contains("'holder'"),
        "denial names the holder role: {message}"
    );
}

#[test]
fn late_citation_does_not_count() {
    let mut fx = fixture();
    let late = fx.compliance(2000, None);
    let message = denied_message(fx.grant(
        vec![late.id().unwrap()],
        None,
        Some(1000),
        Some(fx.contract_ref()),
    ));
    assert!(
        message.contains("found 0"),
        "the late citation was not counted: {message}"
    );
    // The identical citation, on time, admits.
    let mut fx = fixture();
    let on_time = fx.compliance(1000, None);
    assert!(fx
        .grant(
            vec![on_time.id().unwrap()],
            None,
            Some(1000),
            Some(fx.contract_ref())
        )
        .is_ok());
}

#[test]
fn contract_entry_in_wrong_namespace_is_not_a_rule() {
    // Same spec, but published outside the contracts namespace: resolution
    // must refuse it (fail-closed: only contract-namespace entries rule).
    let mut fx = fixture_with(&default_spec(), "general");
    let compliance = fx.compliance(1000, None);
    let message = denied_message(fx.grant(
        vec![compliance.id().unwrap()],
        None,
        Some(1000),
        Some(fx.contract_ref()),
    ));
    assert!(
        message.contains("gov.contracts"),
        "denial explains where contracts must live: {message}"
    );
}

#[test]
fn version_mismatch_is_denied() {
    let mut fx = fixture();
    let compliance = fx.compliance(1000, None);
    let pinned_v2 = serde_json::json!({
        "id": hex::encode(fx.contract_id),
        "version": 2
    });
    let message = denied_message(fx.grant(
        vec![compliance.id().unwrap()],
        None,
        Some(1000),
        Some(pinned_v2),
    ));
    assert!(
        message.contains("v2"),
        "denial names the pinned version: {message}"
    );
}

#[test]
fn contract_entry_absent_from_node_is_denied() {
    let mut fx = fixture();
    let phantom = serde_json::json!({
        "id": hex::encode([7u8; 32]),
        "version": CONTRACT_VERSION
    });
    let message = denied_message(fx.grant(vec![], None, Some(1000), Some(phantom)));
    assert!(
        message.contains("not present on this node"),
        "resolution is local and fail-closed: {message}"
    );
}

#[test]
fn documents_without_a_contract_are_untouched() {
    let mut fx = fixture();
    // No contract field: the predicate machinery is a no-op.
    assert!(fx.grant(vec![], None, None, None).is_ok());
    // Even plain non-document payloads still pass when no role rules apply.
    let entry = make_entry(
        &fx.registrar,
        "gov.titles.grant",
        b"{\"note\":\"plain\"}".to_vec(),
        fx.registrar_seq,
        fx.registrar_prev,
        vec![],
        2000,
    );
    assert!(fx.store.insert_entry(&entry).unwrap());
}

#[test]
fn check_contract_reports_conditions() {
    let mut fx = fixture();
    let compliance = fx.compliance(1000, None);

    // Failing case: no citation.
    let failing = fx.grant_entry(vec![], None, Some(1000), Some(fx.contract_ref()));
    let check = fx.store.check_contract(&failing).unwrap().unwrap();
    assert!(!check.admitted);
    assert_eq!(check.conditions.len(), 4, "kind, holder party, deadline, refs");
    let refs_condition = check
        .conditions
        .iter()
        .find(|c| c.requirement.contains("land.title.inspection"))
        .unwrap();
    assert!(!refs_condition.met);
    assert_eq!(refs_condition.found, "0");
    assert_eq!(refs_condition.required, "1");

    // Compliant case: every condition met.
    let ok = fx.grant_entry(
        vec![compliance.id().unwrap()],
        None,
        Some(1000),
        Some(fx.contract_ref()),
    );
    let check = fx.store.check_contract(&ok).unwrap().unwrap();
    assert!(check.admitted);
    assert!(check.conditions.iter().all(|c| c.met));
    assert_eq!(check.kind, "land.title.grant");
    assert_eq!(check.version, CONTRACT_VERSION);

    // An entry with no contract at all evaluates to None.
    let plain = make_entry(
        &fx.registrar,
        "gov.titles.grant",
        b"{\"note\":\"plain\"}".to_vec(),
        fx.registrar_seq,
        fx.registrar_prev,
        vec![],
        2000,
    );
    assert!(fx.store.check_contract(&plain).unwrap().is_none());
}

#[test]
fn min_cosigners_requires_distinct_verified_parties() {
    let mut spec = default_spec();
    spec.requires_refs = vec![RefRequirement {
        kind: "land.title.inspection".into(),
        count: 1,
        party: None,
        min_cosigners: Some(2),
        author: None,
    }];
    let mut fx = fixture_with(&spec, "gov.contracts");
    let witness = SigningKey::generate(&mut OsRng);

    // One signature only: does not satisfy.
    let single = fx.compliance(1000, None);
    let message = denied_message(fx.grant(
        vec![single.id().unwrap()],
        None,
        Some(1000),
        Some(fx.contract_ref()),
    ));
    assert!(message.contains("found 0"), "one cosigner is not two: {message}");

    // Two distinct verified parties: satisfies.
    let double = fx.compliance(1000, Some(&witness));
    assert!(fx
        .grant(
            vec![double.id().unwrap()],
            None,
            Some(1000),
            Some(fx.contract_ref())
        )
        .is_ok());
}

#[test]
fn authority_feed_pin_only_counts_that_author() {
    let mut spec = default_spec();
    spec.requires_refs = vec![RefRequirement {
        kind: "land.title.inspection".into(),
        count: 1,
        party: Some("inspector".into()),
        min_cosigners: None,
        author: Some(keys().author), // fresh key: nobody's feed yet
    }];
    let mut fx = fixture_with(&spec, "gov.contracts");
    let compliance = fx.compliance(1000, None);
    let message = denied_message(fx.grant(
        vec![compliance.id().unwrap()],
        None,
        Some(1000),
        Some(fx.contract_ref()),
    ));
    assert!(
        message.contains("found 0"),
        "citation from another author does not count: {message}"
    );
    assert!(
        message.contains("authority feed"),
        "denial names the authority: {message}"
    );
}

#[test]
fn landing_window_denies_late_and_early_documents() {
    let mut spec = default_spec();
    spec.not_before_field = Some("opens_ms".into());
    spec.not_after_field = Some("closes_ms".into());
    let mut fx = fixture_with(&spec, "gov.contracts");
    let compliance = fx.compliance(1000, None);

    // The grant entry lands at ts 2000 (grant_entry hardcodes it); give it
    // a window of 1500..=2500 so it lands inside, then prove the edges.
    let grant_with_window = |fx: &mut Fixture, opens: u64, closes: u64| {
        let holder_key = hex::encode(fx.holder.ed.verifying_key().as_bytes());
        let doc = serde_json::json!({
            "parcel": "PH-1",
            "holder_key": holder_key,
            "deadline_ms": 3000,
            "opens_ms": opens,
            "closes_ms": closes,
            "contract": fx.contract_ref(),
        });
        let payload = signed_doc("land.title.grant", doc, &[("holder", &fx.holder.ed)]);
        let entry = make_entry(
            &fx.registrar,
            "gov.titles.grant",
            payload,
            fx.registrar_seq,
            fx.registrar_prev,
            vec![compliance.id().unwrap()],
            2000,
        );
        fx.registrar_seq += 1;
        fx.registrar_prev = Some(entry.id().unwrap());
        fx.store.insert_entry(&entry)
    };

    assert!(grant_with_window(&mut fx, 1500, 2500).is_ok(), "inside the window");
    let message = denied_message(grant_with_window(&mut fx, 2500, 9000));
    assert!(
        message.contains("before the window opening"),
        "early landing denied: {message}"
    );
    let message = denied_message(grant_with_window(&mut fx, 1, 1500));
    assert!(
        message.contains("after the window closing"),
        "late landing denied: {message}"
    );
}

#[test]
fn sealed_field_demand_denies_plaintext() {
    let mut spec = default_spec();
    spec.requires_sealed = vec!["owner_name".into()];
    let mut fx = fixture_with(&spec, "gov.contracts");
    let compliance = fx.compliance(1000, None);
    let holder_key = hex::encode(fx.holder.ed.verifying_key().as_bytes());
    let plaintext = serde_json::json!({
        "parcel": "PH-1",
        "holder_key": holder_key,
        "deadline_ms": 1000,
        "owner_name": "Amina",
        "contract": fx.contract_ref(),
    });
    let payload = signed_doc("land.title.grant", plaintext, &[("holder", &fx.holder.ed)]);
    let entry = make_entry(
        &fx.registrar,
        "gov.titles.grant",
        payload,
        fx.registrar_seq,
        fx.registrar_prev,
        vec![compliance.id().unwrap()],
        2000,
    );
    let message = denied_message(fx.store.insert_entry(&entry));
    assert!(
        message.contains("owner_name"),
        "plaintext personal field denied: {message}"
    );
    assert!(
        message.contains("ciphertext"),
        "denial explains the seal demand: {message}"
    );
}

#[test]
fn outlook_tracks_conditions_outstanding() {
    // The escrow convention end to end: an anchor agreement declares a
    // contract that governs a future release; compliance entries cite the
    // anchor; the outlook answers what is still outstanding.
    let spec = ContractSpec {
        version: CONTRACT_VERSION,
        admits: "datu.cert.release".into(),
        requires_refs: vec![RefRequirement {
            kind: "datu.compliance.inspection".into(),
            count: 1,
            party: Some("inspector".into()),
            min_cosigners: None,
            author: None,
        }],
        requires_parties: vec![PartyRequirement {
            role: "agent".into(),
            key: None,
            bind_field: Some("agent_key".into()),
        }],
        deadline_from_field: Some("deadline_ms".into()),
        not_before_field: None,
        not_after_field: None,
        requires_sealed: vec![],
        wasm: None,
    };
    let mut fx = fixture_with(&spec, "gov.contracts");
    let agent = SigningKey::generate(&mut OsRng);
    let agent_key = hex::encode(agent.verifying_key().as_bytes());

    // 1. The anchor agreement (open namespace: it is not itself governed,
    //    it declares the rule for what may later satisfy it).
    let anchor_doc = serde_json::json!({
        "cert_id": "C-1",
        "agent_key": agent_key,
        "deadline_ms": 5000,
        "contract": fx.contract_ref(),
    });
    let anchor_payload = signed_doc("datu.cert.escrow", anchor_doc, &[]);
    let anchor = publish(
        &fx.store,
        &fx.registrar,
        "records.escrow",
        anchor_payload,
        fx.registrar_seq,
        fx.registrar_prev,
        vec![],
        1000,
    );
    fx.registrar_seq += 1;
    fx.registrar_prev = Some(anchor.id().unwrap());

    // 2. Pending: no compliance yet.
    let outlook = fx.store.contract_outlook(&anchor.id().unwrap()).unwrap().unwrap();
    assert!(!outlook.ready);
    assert_eq!(outlook.admits, "datu.cert.release");
    assert!(outlook.citing.is_empty());
    let refs_condition = outlook
        .conditions
        .iter()
        .find(|c| c.requirement.contains("datu.compliance.inspection"))
        .unwrap();
    assert!(!refs_condition.met);
    assert_eq!(refs_condition.found, "0");

    // 3. Compliance arrives, citing the anchor.
    let compliance_payload = signed_doc(
        "datu.compliance.inspection",
        serde_json::json!({"cert_id": "C-1"}),
        &[("inspector", &fx.inspector.ed)],
    );
    let compliance = publish(
        &fx.store,
        &fx.inspector,
        "records.compliance",
        compliance_payload,
        fx.inspector_seq,
        fx.inspector_prev,
        vec![anchor.id().unwrap()],
        2000,
    );
    fx.inspector_seq += 1;
    fx.inspector_prev = Some(compliance.id().unwrap());

    let outlook = fx.store.contract_outlook(&anchor.id().unwrap()).unwrap().unwrap();
    assert!(outlook.ready, "citation side is satisfied");
    assert_eq!(outlook.citing.len(), 1);
    assert_eq!(outlook.citing[0].kind.as_deref(), Some("datu.compliance.inspection"));
    assert!(outlook.conditions.iter().all(|c| c.met));

    // 4. The release lands in a gated namespace, citing the compliance
    //    entry, agent-signed per the contract's party demand.
    let release_doc = serde_json::json!({
        "cert_id": "C-1",
        "agent_key": agent_key,
        "deadline_ms": 5000,
        "contract": fx.contract_ref(),
    });
    let release_payload = signed_doc("datu.cert.release", release_doc, &[("agent", &agent)]);
    let release = make_entry(
        &fx.registrar,
        "gov.titles.grant",
        release_payload,
        fx.registrar_seq,
        fx.registrar_prev,
        vec![compliance.id().unwrap()],
        3000,
    );
    assert!(fx.store.insert_entry(&release).is_ok());
    let check = fx.store.check_contract(&release).unwrap().unwrap();
    assert!(check.admitted);
}

#[test]
fn outlook_late_compliance_stays_outstanding() {
    let spec = ContractSpec {
        version: CONTRACT_VERSION,
        admits: "datu.cert.release".into(),
        requires_refs: vec![RefRequirement {
            kind: "datu.compliance.inspection".into(),
            count: 1,
            party: None,
            min_cosigners: None,
            author: None,
        }],
        requires_parties: vec![],
        deadline_from_field: Some("deadline_ms".into()),
        not_before_field: None,
        not_after_field: None,
        requires_sealed: vec![],
        wasm: None,
    };
    let mut fx = fixture_with(&spec, "gov.contracts");
    let anchor_doc = serde_json::json!({
        "cert_id": "C-2",
        "deadline_ms": 1500,
        "contract": fx.contract_ref(),
    });
    let anchor = publish(
        &fx.store,
        &fx.registrar,
        "records.escrow",
        signed_doc("datu.cert.escrow", anchor_doc, &[]),
        fx.registrar_seq,
        fx.registrar_prev,
        vec![],
        1000,
    );
    fx.registrar_seq += 1;
    fx.registrar_prev = Some(anchor.id().unwrap());

    let late_payload = signed_doc(
        "datu.compliance.inspection",
        serde_json::json!({"cert_id": "C-2"}),
        &[("inspector", &fx.inspector.ed)],
    );
    publish(
        &fx.store,
        &fx.inspector,
        "records.compliance",
        late_payload,
        fx.inspector_seq,
        fx.inspector_prev,
        vec![anchor.id().unwrap()],
        2000, // after the anchor's declared deadline
    );
    let outlook = fx.store.contract_outlook(&anchor.id().unwrap()).unwrap().unwrap();
    assert!(!outlook.ready, "late evidence is visible but does not count");
    assert_eq!(outlook.citing.len(), 1, "the late entry is still listed as evidence");
    let refs_condition = outlook
        .conditions
        .iter()
        .find(|c| c.requirement.contains("datu.compliance.inspection"))
        .unwrap();
    assert!(!refs_condition.met);
    assert_eq!(refs_condition.found, "0");
}

#[test]
fn verify_all_counts_contract_failures_as_evidence() {
    // An open mirror accepts everything; verify_all recounts which entries
    // would fail their declared contract (evidence-grade, not fatal).
    let store = Store::open_in_memory().unwrap();
    let registrar = keys();
    let inspector = keys();
    let holder = keys();
    let issuer = SigningKey::generate(&mut OsRng);

    let spec = default_spec();
    let payload = signed_doc(
        CONTRACT_KIND,
        serde_json::to_value(&spec).unwrap(),
        &[("issuer", &issuer)],
    );
    let contract = publish(&store, &registrar, "gov.contracts", payload, 0, None, vec![], 1);
    let contract_ref = serde_json::json!({
        "id": hex::encode(contract.id().unwrap()),
        "version": CONTRACT_VERSION
    });

    let compliance_payload = signed_doc(
        "land.title.inspection",
        serde_json::json!({"parcel": "PH-1"}),
        &[("inspector", &inspector.ed)],
    );
    let compliance = publish(
        &store,
        &inspector,
        "land.records",
        compliance_payload,
        0,
        None,
        vec![],
        1000,
    );

    let holder_key = hex::encode(holder.ed.verifying_key().as_bytes());
    let grant_doc = || {
        signed_doc(
            "land.title.grant",
            serde_json::json!({
                "parcel": "PH-1",
                "holder_key": holder_key,
                "deadline_ms": 1000,
                "contract": contract_ref,
            }),
            &[("holder", &holder.ed)],
        )
    };

    // Compliant first: no failure counted.
    let grant_ok = publish(
        &store,
        &registrar,
        "gov.titles.grant",
        grant_doc(),
        1,
        Some(contract.id().unwrap()),
        vec![compliance.id().unwrap()],
        2000,
    );
    let report = store.verify_all().unwrap();
    assert_eq!(report.contracts_failed, 0);

    // Then a grant citing nothing: the mirror stores it, the recount flags it.
    publish(
        &store,
        &registrar,
        "gov.titles.grant",
        grant_doc(),
        2,
        Some(grant_ok.id().unwrap()),
        vec![],
        2000,
    );
    let report = store.verify_all().unwrap();
    assert_eq!(report.contracts_failed, 1, "evidence-grade recount flags it");
}
