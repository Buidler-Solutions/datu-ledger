use datu_core::merkle::merkle_root;
use datu_core::{Checkpoint, CheckpointBody};
use datu_core::{Entry, EntryBody};
use datu_store::manifest::{compile, head, manifest_namespace, status, Freshness};
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
fn publish_manifest(
    store: &Store,
    k: &Keys,
    doc: &ManifestDoc,
    seq: u64,
    prev: Option<[u8; 32]>,
) -> Entry {
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
    WritePolicy {
        gated: vec!["gov.titles.*".into()],
        writers,
        ..WritePolicy::default()
    }
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

    let compiled = compile(&store, "gov-mesh", std::slice::from_ref(&root.author))
        .unwrap()
        .unwrap();
    assert_eq!(compiled.manifest_id, hex::encode(e1.id().unwrap()));
    assert_eq!(compiled.chain.len(), 1);

    // The compiled policy gates per the manifest, and the current roots are
    // always admitted (governance can always govern).
    let gated = Store::open_in_memory_with_policy(Some(compiled.policy.clone())).unwrap();
    assert!(gated
        .insert_entry(&writer_entry(
            &old_writer,
            "gov.titles.application",
            b"t1",
            0,
            None
        ))
        .is_ok());
    assert!(gated
        .insert_entry(&writer_entry(
            &root,
            "gov.titles.application",
            b"governance writes fine",
            0,
            None
        ))
        .is_ok());
    assert!(gated
        .insert_entry(&writer_entry(
            &new_writer,
            "gov.titles.application",
            b"stranger denied",
            0,
            None
        ))
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

    let compiled2 = compile(&store, "gov-mesh", std::slice::from_ref(&root.author))
        .unwrap()
        .unwrap();
    assert_eq!(compiled2.manifest_id, hex::encode(e2.id().unwrap()));
    assert_eq!(compiled2.chain.len(), 2, "genesis + rotation");

    let gated2 = Store::open_in_memory_with_policy(Some(compiled2.policy.clone())).unwrap();
    assert!(gated2
        .insert_entry(&writer_entry(
            &new_writer,
            "gov.titles.application",
            b"new regime",
            0,
            None
        ))
        .is_ok());
    assert!(
        gated2
            .insert_entry(&writer_entry(
                &old_writer,
                "gov.titles.application",
                b"old writer retired",
                0,
                None
            ))
            .is_err(),
        "the manifest revoked the old writer's admission"
    );
    assert!(
        gated2
            .insert_entry(&writer_entry(
                &root,
                "gov.titles.application",
                b"retired root cannot write",
                0,
                None
            ))
            .is_err(),
        "the retired root lost its auto-admission too"
    );

    // The retired root can no longer continue the chain…
    let m3_by_retired = ManifestDoc {
        supersedes: Some(hex::encode(e2.id().unwrap())),
        ..ManifestDoc::new(
            "gov-mesh",
            vec![root.author.clone()],
            WritePolicy::default(),
        )
    };
    publish_manifest(&store, &root, &m3_by_retired, 1, Some(e1.id().unwrap()));
    // …so compile still ends at m2: the rogue entry is never linked.
    let compiled3 = compile(&store, "gov-mesh", std::slice::from_ref(&root.author))
        .unwrap()
        .unwrap();
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

    let err = compile(&store, "gov-mesh", std::slice::from_ref(&founder.author)).unwrap_err();
    assert!(
        err.contains("split"),
        "a split must be an error, not a pick: {err}"
    );
    assert!(head(&store, "gov-mesh").is_err());
}

#[test]
fn junk_and_foreign_manifests_are_ignored() {
    let store = Store::open_in_memory().unwrap();
    let root = keys();
    let nobody = keys();

    // Junk in the manifest namespace: unparseable payload, wrong network id,
    // and a "founding" manifest by a non-pinned key. None of it is authority.
    let junk = writer_entry(
        &nobody,
        &manifest_namespace("gov-mesh"),
        b"not json",
        0,
        None,
    );
    store.insert_entry(&junk).unwrap();
    let foreign = ManifestDoc::new(
        "other-mesh",
        vec![nobody.author.clone()],
        WritePolicy::default(),
    );
    let foreign_entry = writer_entry(
        &nobody,
        &manifest_namespace("gov-mesh"),
        &serde_json::to_vec(&foreign).unwrap(),
        1,
        Some(junk.id().unwrap()),
    );
    store.insert_entry(&foreign_entry).unwrap();
    let fake_genesis = ManifestDoc::new(
        "gov-mesh",
        vec![nobody.author.clone()],
        WritePolicy::default(),
    );
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
        compile(&store, "gov-mesh", std::slice::from_ref(&root.author))
            .unwrap()
            .is_none(),
        "no pinned-root genesis exists yet"
    );

    let real = ManifestDoc::new(
        "gov-mesh",
        vec![root.author.clone()],
        WritePolicy::default(),
    );
    let e = publish_manifest(&store, &root, &real, 0, None);
    let compiled = compile(&store, "gov-mesh", std::slice::from_ref(&root.author))
        .unwrap()
        .unwrap();
    assert_eq!(compiled.chain.len(), 1);
    assert_eq!(compiled.manifest_id, hex::encode(e.id().unwrap()));
    assert!(
        compile(&store, "unknown-mesh", std::slice::from_ref(&root.author))
            .unwrap()
            .is_none(),
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
        ..ManifestDoc::new(
            "gov-mesh",
            vec![stranger.author.clone()],
            WritePolicy::default(),
        )
    };
    publish_manifest(&store, &stranger, &rogue, 0, None);

    let compiled = compile(&store, "gov-mesh", std::slice::from_ref(&founder.author))
        .unwrap()
        .unwrap();
    assert_eq!(compiled.manifest_id, hex::encode(e1.id().unwrap()));
    assert_eq!(compiled.chain.len(), 1);
    let (head_id, _) = head(&store, "gov-mesh").unwrap().unwrap();
    assert_eq!(head_id, hex::encode(e1.id().unwrap()));

    // The real successor still extends the chain, with the spam still present.
    let m2 = ManifestDoc {
        supersedes: Some(hex::encode(e1.id().unwrap())),
        ..ManifestDoc::new(
            "gov-mesh",
            vec![successor.author.clone()],
            WritePolicy::default(),
        )
    };
    let e2 = publish_manifest(&store, &successor, &m2, 0, None);
    let compiled2 = compile(&store, "gov-mesh", std::slice::from_ref(&founder.author))
        .unwrap()
        .unwrap();
    assert_eq!(compiled2.manifest_id, hex::encode(e2.id().unwrap()));
    assert_eq!(compiled2.chain.len(), 2);
}

/// A checkpoint over everything `store` holds, signed by `k` - the evidence
/// that decides freshness in these tests.
fn checkpoint(store: &Store, k: &Keys) -> Checkpoint {
    let ids = store.entry_ids().unwrap();
    let last = store.last_checkpoint(&k.author).unwrap();
    let (height, prev) = match &last {
        Some(c) => (c.body.height + 1, Some(c.id().unwrap())),
        None => (0, None),
    };
    let body = CheckpointBody {
        version: datu_core::CHECKPOINT_VERSION,
        signer: k.author.clone(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height,
        prev,
        timestamp_ms: 1_000,
        entries_count: ids.len() as u64,
        entry_ids_root: merkle_root(&ids),
    };
    let c = Checkpoint::sign(body, &k.ed, &k.pq).unwrap();
    assert!(store.append_checkpoint(&c).unwrap());
    c
}

#[test]
fn freshness_requires_independent_evidence() {
    let store = Store::open_in_memory().unwrap();
    let founder = keys();
    let witness = keys();

    let m1 = ManifestDoc::new(
        "gov-mesh",
        vec![founder.author.clone()],
        WritePolicy::default(),
    );
    publish_manifest(&store, &founder, &m1, 0, None);

    // A chain that verifies is still not "current": nothing but its own
    // author has ever confirmed the mesh was alive after it.
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        None,
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Stale, "reason: {}", st.reason);
    assert!(st.corroborated_by.is_none());

    // The manifest author checkpointing about itself proves nothing.
    checkpoint(&store, &founder);
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        None,
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Stale);
    assert!(st.reason.contains("independent"), "{}", st.reason);

    // The node asking is not independent of itself either.
    checkpoint(&store, &witness);
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        Some(&witness.author),
    )
    .unwrap();
    assert_eq!(
        st.freshness,
        Freshness::Stale,
        "a node cannot corroborate itself"
    );
    let third = keys();
    checkpoint(&store, &third);
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        Some(&witness.author),
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Current, "reason: {}", st.reason);
    assert_eq!(st.corroborated_by.as_deref(), Some(third.author.as_str()));
    assert_eq!(
        st.manifest_id.as_deref(),
        Some(
            hex::encode(
                store
                    .list(Some(&manifest_namespace("gov-mesh")), None, 10)
                    .unwrap()[0]
                    .id()
                    .unwrap(),
            )
            .as_str()
        )
    );
}

#[test]
fn revoked_writer_under_stale_policy_is_reported_not_hidden() {
    let store = Store::open_in_memory().unwrap();
    let founder = keys();
    let successor = keys();
    let writer = keys();

    let m1 = ManifestDoc::new(
        "gov-mesh",
        vec![successor.author.clone()],
        policy_admitting(vec![writer.author.clone()]),
    );
    let e1 = publish_manifest(&store, &founder, &m1, 0, None);

    // The revocation exists on this node…
    let m2 = ManifestDoc {
        supersedes: Some(hex::encode(e1.id().unwrap())),
        ..ManifestDoc::new(
            "gov-mesh",
            vec![successor.author.clone()],
            policy_admitting(vec![]),
        )
    };
    let e2 = publish_manifest(&store, &successor, &m2, 0, None);

    // …and it applies…
    let compiled = compile(&store, "gov-mesh", std::slice::from_ref(&founder.author))
        .unwrap()
        .unwrap();
    assert_eq!(compiled.manifest_id, hex::encode(e2.id().unwrap()));
    let gated = Store::open_in_memory_with_policy(Some(compiled.policy.clone())).unwrap();
    assert!(gated
        .insert_entry(&writer_entry(
            &writer,
            "gov.titles.application",
            b"x",
            0,
            None
        ))
        .is_err());

    // …but this node cannot claim its authorization is current: nothing
    // independent has confirmed the revocation was seen by anyone else, so a
    // *further* revocation may exist that this node never received.
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        None,
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Stale, "reason: {}", st.reason);
    assert_eq!(
        st.manifest_id.as_deref(),
        Some(hex::encode(e2.id().unwrap()).as_str())
    );
    assert!(
        st.roots.contains(&successor.author),
        "the stale policy is still the newest known one"
    );
}

#[test]
fn rollback_leaves_evidence_and_is_stale() {
    let store = Store::open_in_memory().unwrap();
    let founder = keys();
    let successor = keys();

    let m1 = ManifestDoc::new(
        "gov-mesh",
        vec![successor.author.clone()],
        WritePolicy::default(),
    );
    let e1 = publish_manifest(&store, &founder, &m1, 0, None);

    // This node only holds m1. The world moved on: another replica's manifest
    // (which this node received without its predecessor) names a successor of
    // m1 this node never got.
    let missing = "ab".repeat(32);
    let orphan = ManifestDoc {
        supersedes: Some(missing.clone()),
        ..ManifestDoc::new(
            "gov-mesh",
            vec![successor.author.clone()],
            WritePolicy::default(),
        )
    };
    publish_manifest(&store, &successor, &orphan, 0, None);

    // The chain still verifies up to m1 - old evidence stays usable…
    let compiled = compile(&store, "gov-mesh", std::slice::from_ref(&founder.author))
        .unwrap()
        .unwrap();
    assert_eq!(compiled.manifest_id, hex::encode(e1.id().unwrap()));
    // …and the node says out loud that it is behind.
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        None,
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Stale, "reason: {}", st.reason);
    assert_eq!(st.missing_predecessors, vec![missing]);
}

#[test]
fn conflicting_policy_versions_are_never_applied() {
    let store = Store::open_in_memory().unwrap();
    let founder = keys();

    let mut future = ManifestDoc::new(
        "gov-mesh",
        vec![founder.author.clone()],
        WritePolicy::default(),
    );
    future.policy.version = 99;
    publish_manifest(&store, &founder, &future, 0, None);

    // Not authority: this build cannot evaluate it, so nothing verifies…
    assert!(
        compile(&store, "gov-mesh", std::slice::from_ref(&founder.author))
            .unwrap()
            .is_none()
    );
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        None,
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Unverified);
    assert!(st.reason.contains("99"), "{}", st.reason);
}

#[test]
fn invalid_genesis_claims_stay_unverified() {
    let store = Store::open_in_memory().unwrap();
    let founder = keys();
    let impostor = keys();

    // A stranger founds a chain for the mesh: structurally perfect, but not
    // signed by the key this node pinned.
    let fake = ManifestDoc::new(
        "gov-mesh",
        vec![impostor.author.clone()],
        WritePolicy::default(),
    );
    publish_manifest(&store, &impostor, &fake, 0, None);

    assert!(
        compile(&store, "gov-mesh", std::slice::from_ref(&founder.author))
            .unwrap()
            .is_none()
    );
    assert!(
        head(&store, "gov-mesh").unwrap().is_some(),
        "the impostor can see its own chain"
    );
    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        None,
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Unverified);
    assert!(st.manifest_id.is_none());
}

#[test]
fn status_reports_a_conflict_with_both_sides() {
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

    let mut ids = Vec::new();
    for (k, note) in [(&a, "A's line"), (&b, "B's line")] {
        let m = ManifestDoc {
            supersedes: Some(hex::encode(e1.id().unwrap())),
            note: Some(note.into()),
            ..ManifestDoc::new("gov-mesh", vec![k.author.clone()], WritePolicy::default())
        };
        ids.push(hex::encode(
            publish_manifest(&store, k, &m, 0, None).id().unwrap(),
        ));
    }

    let st = status(
        &store,
        "gov-mesh",
        std::slice::from_ref(&founder.author),
        None,
    )
    .unwrap();
    assert_eq!(st.freshness, Freshness::Conflicted);
    assert_eq!(st.conflicts.len(), 2, "{:?}", st.conflicts);
    let claimed: Vec<String> = st.conflicts.iter().map(|(id, _)| id.clone()).collect();
    for id in ids {
        assert!(claimed.contains(&id), "both continuations must be named");
    }
}
