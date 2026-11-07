use datu_core::{Entry, EntryBody};
use datu_store::manifest::{compile, head, manifest_namespace};
use datu_store::{ManifestDoc, Store, WritePolicy};
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

/// Publish `doc` as a manifest entry authored by `k`. Seq/prev chain per
/// author is global, so each publisher tracks its own feed position.
fn publish_manifest(store: &Store, k: &Keys, doc: &ManifestDoc, seq: u64, prev: Option<[u8; 32]>) -> Entry {
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: k.author.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: manifest_namespace(&doc.network_id),
        seq,
        prev,
        refs: vec![],
        timestamp_ms: 1,
        payload: serde_json::to_vec(doc).unwrap(),
    };
    let entry = Entry::sign(body, &k.ed, &k.pq).unwrap();
    assert!(store.insert_entry(&entry).unwrap());
    entry
}

fn writer_entry(k: &Keys, ns: &str, payload: &[u8], seq: u64, prev: Option<[u8; 32]>) -> Entry {
    let body = EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: k.author.clone(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: ns.into(),
        seq,
        prev,
        refs: vec![],
        timestamp_ms: 1,
        payload: payload.to_vec(),
    };
    Entry::sign(body, &k.ed, &k.pq).unwrap()
}

fn policy_admitting(writers: Vec<String>) -> WritePolicy {
    let mut policy = WritePolicy::default();
    policy.gated = vec!["gov.titles.*".into()];
    policy.writers = writers;
    policy
}

#[test]
fn manifest_chain_compiles_and_gates() {
    let store = Store::open_in_memory().unwrap();
    let root = keys();
    let successor = keys();
    let old_writer = keys();
    let new_writer = keys();

    let m1 = ManifestDoc::new(
        "gov-mesh",
        vec![root.author.clone(), successor.author.clone()],
        policy_admitting(vec![old_writer.author.clone()]),
    );
    let e1 = publish_manifest(&store, &root, &m1, 0, None);

    let compiled = compile(&store, "gov-mesh", &[root.author.clone()]).unwrap().unwrap();
    assert_eq!(compiled.manifest_id, hex::encode(e1.id().unwrap()));
    assert_eq!(compiled.chain.len(), 1);

    // The compiled policy gates per the manifest, and the current roots are
    // always admitted (governance can always govern).
    let gated = Store::open_in_memory_with_policy(Some(compiled.policy.clone())).unwrap();
    assert!(gated
        .insert_entry(&writer_entry(&old_writer, "gov.titles.application", b"t1", 0, None))
        .is_ok());
    assert!(gated
        .insert_entry(&writer_entry(&root, "gov.titles.application", b"governance writes fine", 0, None))
        .is_ok());
    assert!(gated
        .insert_entry(&writer_entry(&new_writer, "gov.titles.application", b"stranger denied", 0, None))
        .is_err());

    // Rotation + revocation: the successor (a current root) publishes m2
    // whose policy drops the old writer; the old root is retired by omission.
    let m2 = ManifestDoc {
        supersedes: Some(hex::encode(e1.id().unwrap())),
        roots: vec![successor.author.clone()],
        policy: policy_admitting(vec![new_writer.author.clone()]),
        note: Some("rotate: retire the founder, admit the new writer".into()),
        ..ManifestDoc::new("gov-mesh", vec![], WritePolicy::default())
    };
    let e2 = publish_manifest(&store, &successor, &m2, 0, None);

    let compiled2 = compile(&store, "gov-mesh", &[root.author.clone()]).unwrap().unwrap();
    assert_eq!(compiled2.manifest_id, hex::encode(e2.id().unwrap()));
    assert_eq!(compiled2.chain.len(), 2, "genesis + rotation");

    let gated2 = Store::open_in_memory_with_policy(Some(compiled2.policy.clone())).unwrap();
    assert!(gated2
        .insert_entry(&writer_entry(&new_writer, "gov.titles.application", b"new regime", 0, None))
        .is_ok());
    assert!(
        gated2
            .insert_entry(&writer_entry(&old_writer, "gov.titles.application", b"old writer retired", 0, None))
            .is_err(),
        "the manifest revoked the old writer's admission"
    );
    assert!(
        gated2
            .insert_entry(&writer_entry(&root, "gov.titles.application", b"retired root cannot write", 0, None))
            .is_err(),
        "the retired root lost its auto-admission too"
    );

    // The retired root can no longer continue the chain…
    let m3_by_retired = ManifestDoc {
        supersedes: Some(hex::encode(e2.id().unwrap())),
        ..ManifestDoc::new("gov-mesh", vec![root.author.clone()], WritePolicy::default())
    };
    publish_manifest(&store, &root, &m3_by_retired, 1, Some(e1.id().unwrap()));
    // …so compile still ends at m2: the rogue entry is never linked.
    let compiled3 = compile(&store, "gov-mesh", &[root.author.clone()]).unwrap().unwrap();
    assert_eq!(compiled3.manifest_id, hex::encode(e2.id().unwrap()));

    // And `head` agrees for the next publisher.
    let (head_id, head_roots) = head(&store, "gov-mesh").unwrap().unwrap();
    assert_eq!(head_id, hex::encode(e2.id().unwrap()));
    assert_eq!(head_roots, vec![successor.author.clone()]);
}

#[test]
fn manifest_split_is_fail_visible() {
    let store = Store::open_in_memory().unwrap();
    let founder = keys();
    let a = keys();
    let b = keys();

    let m1 = ManifestDoc::new(
        "gov-mesh",
        vec![a.author.clone(), b.author.clone()],
        WritePolicy::default(),
    );
    let e1 = publish_manifest(&store, &founder, &m1, 0, None);

    // Two different current roots publish two different continuations.
    let m2a = ManifestDoc {
        supersedes: Some(hex::encode(e1.id().unwrap())),
        note: Some("A's line".into()),
        ..ManifestDoc::new("gov-mesh", vec![a.author.clone()], WritePolicy::default())
    };
    publish_manifest(&store, &a, &m2a, 0, None);
    let m2b = ManifestDoc {
        supersedes: Some(hex::encode(e1.id().unwrap())),
        note: Some("B's line".into()),
        ..ManifestDoc::new("gov-mesh", vec![b.author.clone()], WritePolicy::default())
    };
    publish_manifest(&store, &b, &m2b, 0, None);

    let err = compile(&store, "gov-mesh", &[founder.author.clone()]).unwrap_err();
    assert!(err.contains("split"), "a split must be an error, not a pick: {err}");
    assert!(head(&store, "gov-mesh").is_err());
}

#[test]
fn junk_and_foreign_manifests_are_ignored() {
    let store = Store::open_in_memory().unwrap();
    let root = keys();
    let nobody = keys();

    // Junk in the manifest namespace: unparseable payload, wrong network id,
    // and a "founding" manifest by a non-pinned key. None of it is authority.
    let junk = writer_entry(&nobody, &manifest_namespace("gov-mesh"), b"not json", 0, None);
    store.insert_entry(&junk).unwrap();
    let foreign = ManifestDoc::new("other-mesh", vec![nobody.author.clone()], WritePolicy::default());
    let foreign_entry = writer_entry(
        &nobody,
        &manifest_namespace("gov-mesh"),
        &serde_json::to_vec(&foreign).unwrap(),
        1,
        Some(junk.id().unwrap()),
    );
    store.insert_entry(&foreign_entry).unwrap();
    let fake_genesis =
        ManifestDoc::new("gov-mesh", vec![nobody.author.clone()], WritePolicy::default());
    store
        .insert_entry(&writer_entry(
            &nobody,
            &manifest_namespace("gov-mesh"),
            &serde_json::to_vec(&fake_genesis).unwrap(),
            2,
            Some(foreign_entry.id().unwrap()),
        ))
        .unwrap();

    assert!(
        compile(&store, "gov-mesh", &[root.author.clone()]).unwrap().is_none(),
        "no pinned-root genesis exists yet"
    );

    let real = ManifestDoc::new("gov-mesh", vec![root.author.clone()], WritePolicy::default());
    let e = publish_manifest(&store, &root, &real, 0, None);
    let compiled = compile(&store, "gov-mesh", &[root.author.clone()]).unwrap().unwrap();
    assert_eq!(compiled.chain.len(), 1);
    assert_eq!(compiled.manifest_id, hex::encode(e.id().unwrap()));
    assert!(
        compile(&store, "unknown-mesh", &[root.author.clone()]).unwrap().is_none(),
        "empty namespace compiles to None, not an error"
    );
}

#[test]
fn unauthorized_continuation_cannot_manufacture_a_split() {
    let store = Store::open_in_memory().unwrap();
    let founder = keys();
    let successor = keys();
    let stranger = keys();

    let m1 = ManifestDoc::new(
        "gov-mesh",
        vec![successor.author.clone()],
        WritePolicy::default(),
    );
    let e1 = publish_manifest(&store, &founder, &m1, 0, None);

    // A stranger spams a "continuation" of the genesis into the namespace.
    // Anyone may hold anything - it is simply never a candidate, so it can
    // neither capture the chain nor force a split that would block publishing.
    let rogue = ManifestDoc {
        supersedes: Some(hex::encode(e1.id().unwrap())),
        ..ManifestDoc::new("gov-mesh", vec![stranger.author.clone()], WritePolicy::default())
    };
    publish_manifest(&store, &stranger, &rogue, 0, None);

    let compiled = compile(&store, "gov-mesh", &[founder.author.clone()]).unwrap().unwrap();
    assert_eq!(compiled.manifest_id, hex::encode(e1.id().unwrap()));
    assert_eq!(compiled.chain.len(), 1);
    let (head_id, _) = head(&store, "gov-mesh").unwrap().unwrap();
    assert_eq!(head_id, hex::encode(e1.id().unwrap()));

    // The real successor still extends the chain, with the spam still present.
    let m2 = ManifestDoc {
        supersedes: Some(hex::encode(e1.id().unwrap())),
        ..ManifestDoc::new("gov-mesh", vec![successor.author.clone()], WritePolicy::default())
    };
    let e2 = publish_manifest(&store, &successor, &m2, 0, None);
    let compiled2 = compile(&store, "gov-mesh", &[founder.author.clone()]).unwrap().unwrap();
    assert_eq!(compiled2.manifest_id, hex::encode(e2.id().unwrap()));
    assert_eq!(compiled2.chain.len(), 2);
}
