//! Deterministic WASM contract bodies: the sandbox side of
//! [`ContractSpec::wasm`](super::ContractSpec).
//!
//! A contract's rule can be written in the built-in DSL or as a wasm32
//! module carried in the same entry shape. Both are predicates: pure
//! functions of (the contract's `admits`, the governed document, the
//! governed entry's timestamp, the closure of direct references). The
//! WASM path runs the module under four rules:
//!
//! * **Empty linker.** No host functions are linked, ever: the module
//!   cannot read the clock, the disk, the network, or the node. Its
//!   whole world is the JSON input written into its linear memory.
//! * **Fuel metering, not gas.** The module runs with a fixed budget
//!   ([`WASM_FUEL`]). Exhaustion traps and the verdict is a fail-closed
//!   denial. There is no token to pay and no fee market: metering is a
//!   safety cap, not a price.
//! * **Size caps.** The module is capped at [`MAX_WASM_BYTES`], the
//!   serialized input at [`MAX_INPUT_BYTES`] (a closure too large to
//!   judge is a denial, not an error).
//! * **Fail-closed everywhere.** Bad base64, unparseable wasm, missing
//!   exports, traps, out-of-range returns: every failure path is a
//!   normal denial with a reason. A misbehaving contract can never make
//!   the evaluator panic or admit by accident.
//!
//! Determinism is why this is safe on a DAG without consensus: same
//! module bytes, same input bytes, same verdict, on every node, forever.
//! Any wasm32 toolchain works (Rust, C, AssemblyScript, hand-written
//! WAT); the ABI is plain linear memory plus integer conventions.
//!
//! ## The guest ABI
//!
//! The module must export:
//!
//! * `memory` - its linear memory;
//! * `alloc(size: i32) -> i32` - return a pointer to `size` writable
//!   bytes (a bump allocator is fine; the host only needs fresh space);
//! * `evaluate(in_ptr: i32, in_len: i32, out_ptr: i32, out_cap: i32) -> i32`:
//!   read the JSON input from `memory[in_ptr .. in_ptr+in_len]`, and return
//!   `0` to **admit**; otherwise write a UTF-8 denial reason to `out_ptr`
//!   (at most `out_cap` bytes) and return its length.

use super::{ClosureEntry, ConditionKind, ConditionStatus, ContractReport, ContractSpec};
use crate::parties::SignedDocument;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

/// Cap on the decoded module: 256 KiB. Contracts are predicates, not
/// programs; a rule that big is a red flag, not a feature.
pub const MAX_WASM_BYTES: usize = 256 * 1024;

/// Fuel budget per evaluation. A deterministic predicate over a bounded
/// input needs a bounded number of steps; anything that burns more is
/// stuck or hostile, and traps.
pub const WASM_FUEL: u64 = 1_000_000;

/// Cap on the serialized JSON input handed to the module (governed
/// document plus closure). Oversize closures are a denial: the host
/// refuses to feed what it cannot bound.
pub const MAX_INPUT_BYTES: usize = 512 * 1024;

/// Bytes the guest may write as its denial reason. Keeps verdict text
/// report-sized, not ledger-sized.
const OUT_CAP: i32 = 4096;

/// The guest's whole world, as JSON: exactly what the DSL branch sees,
/// nothing more. No wall clock (the entry timestamp is a claim carried
/// *in*, not observed), no randomness, no node state.
fn input_json(
    spec: &ContractSpec,
    document: &SignedDocument,
    entry_ts: u64,
    closure: &[ClosureEntry],
) -> Value {
    let closure = closure
        .iter()
        .map(|entry| {
            let mut object = json!({
                "id": hex::encode(entry.id),
                "author": entry.author,
                "timestamp_ms": entry.timestamp_ms,
            });
            if let Some(doc) = &entry.document {
                object["document"] = serde_json::to_value(doc).unwrap_or(Value::Null);
            }
            object
        })
        .collect::<Vec<_>>();
    json!({
        "admits": spec.admits,
        "document": serde_json::to_value(document).unwrap_or(Value::Null),
        "entry_ts": entry_ts,
        "closure": closure,
    })
}

/// Parse-check a module and report its export names. Not a verdict -
/// evaluation still type-checks the ABI and runs under fuel - but authoring
/// tools can catch typos before the signing steps, and auditors can confirm
/// what a module advertises before trusting it.
pub fn check_module(bytes: &[u8]) -> Result<Vec<String>, String> {
    let engine = wasmi::Engine::new(&wasmi::Config::default());
    let module = wasmi::Module::new(&engine, bytes)
        .map_err(|e| format!("contract wasm does not parse: {e}"))?;
    Ok(module
        .exports()
        .map(|export| export.name().to_string())
        .collect())
}

/// Run a WASM contract body over the governed document.
///
/// `Ok(None)` means the module admitted the document. `Ok(Some(reason))`
/// is a guest denial (the module's own words). `Err(reason)` is a host
/// fault: sandbox setup or ABI failure, always fail-closed.
fn run(
    spec: &ContractSpec,
    wasm_b64: &str,
    document: &SignedDocument,
    entry_ts: u64,
    closure: &[ClosureEntry],
) -> Result<(Option<String>, u64), String> {
    let bytes = B64
        .decode(wasm_b64)
        .map_err(|_| "contract wasm is not valid base64".to_string())?;
    if bytes.len() > MAX_WASM_BYTES {
        return Err(format!(
            "contract wasm exceeds the size cap ({} > {} bytes)",
            bytes.len(),
            MAX_WASM_BYTES
        ));
    }

    let input = serde_json::to_vec(&input_json(spec, document, entry_ts, closure))
        .map_err(|_| "contract input did not serialize".to_string())?;
    if input.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "contract input exceeds the cap ({} > {} bytes: closure too large)",
            input.len(),
            MAX_INPUT_BYTES
        ));
    }

    let mut config = wasmi::Config::default();
    config.consume_fuel(true);
    let engine = wasmi::Engine::new(&config);
    let module = wasmi::Module::new(&engine, &bytes[..])
        .map_err(|e| format!("contract wasm does not parse: {e}"))?;

    let mut store = wasmi::Store::new(&engine, ());
    store
        .add_fuel(WASM_FUEL)
        .map_err(|_| "contract wasm fuel budget could not be set".to_string())?;

    // Deliberately empty: the sandbox has no doors.
    let linker = wasmi::Linker::<()>::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .and_then(|pre| pre.start(&mut store))
        .map_err(|e| format!("contract wasm failed to instantiate: {e}"))?;

    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| "contract wasm exports no linear 'memory'".to_string())?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "alloc")
        .map_err(|_| "contract wasm exports no 'alloc(size) -> ptr' function".to_string())?;
    let evaluate = instance
        .get_typed_func::<(i32, i32, i32, i32), i32>(&store, "evaluate")
        .map_err(|_| {
            "contract wasm exports no 'evaluate(in_ptr, in_len, out_ptr, out_cap) -> written' function"
                .to_string()
        })?;

    // Input buffer in guest memory, then the output buffer for a
    // possible denial reason.
    let in_len = i32::try_from(input.len())
        .map_err(|_| "contract input too large for the wasm ABI".to_string())?;
    let in_ptr = alloc
        .call(&mut store, in_len)
        .map_err(|e| format!("contract wasm 'alloc' trapped: {e}"))?;
    if in_ptr <= 0 {
        return Err("contract wasm 'alloc' returned a non-positive pointer".to_string());
    }
    memory
        .write(&mut store, in_ptr as usize, &input)
        .map_err(|_| "contract wasm memory write failed".to_string())?;

    let out_ptr = alloc
        .call(&mut store, OUT_CAP)
        .map_err(|e| format!("contract wasm 'alloc' trapped: {e}"))?;
    if out_ptr <= 0 {
        return Err("contract wasm 'alloc' returned a non-positive pointer".to_string());
    }

    let written = evaluate
        .call(&mut store, (in_ptr, in_len, out_ptr, OUT_CAP))
        .map_err(|e| format!("contract wasm trapped (or exhausted its fuel): {e}"))?;

    let fuel_used = store.fuel_consumed().unwrap_or(0);
    if written == 0 {
        return Ok((None, fuel_used));
    }
    if !(0..=OUT_CAP).contains(&written) {
        return Err(format!(
            "contract wasm returned a bad byte count {written} (0 admits; 1..={OUT_CAP} denies with a reason)"
        ));
    }
    let mut out = vec![0u8; written as usize];
    memory
        .read(&store, out_ptr as usize, &mut out)
        .map_err(|_| "contract wasm memory read failed".to_string())?;
    let reason = String::from_utf8_lossy(&out).trim().to_string();
    Ok((
        Some(if reason.is_empty() {
            "the wasm predicate denied this document (no reason given)".to_string()
        } else {
            reason
        }),
        fuel_used,
    ))
}

/// Sandboxed evaluation surface: a single WASM-kind condition plus the
/// verdict. Called from [`ContractSpec::evaluate_report`] after the kind
/// check (which stays outside the sandbox: cheap, fast-fail, and
/// identical between DSL and WASM contracts).
pub fn evaluate(
    spec: &ContractSpec,
    wasm_b64: &str,
    document: &SignedDocument,
    entry_ts: u64,
    closure: &[ClosureEntry],
) -> ContractReport {
    // Fuel is reported, not priced: it tells an author how close a rule runs
    // to the cap (metering replaces gas; there is nothing to pay).
    let (met, reason, fuel) = match run(spec, wasm_b64, document, entry_ts, closure) {
        Ok((None, fuel)) => (true, None, fuel),
        Ok((Some(reason), fuel)) => (false, Some(reason), fuel),
        Err(fault) => (false, Some(fault), 0),
    };
    ContractReport {
        admitted: met,
        reasons: reason.into_iter().collect(),
        conditions: vec![ConditionStatus {
            kind: ConditionKind::Wasm,
            requirement: "the wasm predicate admits this document".into(),
            required: "admitted".into(),
            found: format!(
                "{} (fuel {fuel}/{WASM_FUEL})",
                if met { "admitted" } else { "denied" }
            ),
            met,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::CONTRACT_VERSION;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Scans the whole input JSON for the needle "PH-1" (i32 LE
    /// 0x312D4850). Hit -> admit (0). Miss -> copy the denial reason
    /// from a data segment and return its length. Heap bumps from 4096
    /// so allocations never touch the data segments below. The trailing
    /// `(unreachable)` is dead code: the loop only exits via `return`,
    /// and wasmi 0.31's validator wants an unreachable tail after a
    /// br-terminated loop in a result-bearing function (if it ever ran,
    /// the trap would deny, fail-closed).
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

    /// Same shape, needle "INSP" (i32 LE 0x50534E49): only a closure
    /// citation of kind land.title.inspection carrying "INSPECTED"
    /// satisfies it, proving the guest sees the closure.
    const CLOSURE_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $heap (mut i32) (i32.const 4096))
          (data (i32.const 1088) "no inspection citation found")
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
                  (memory.copy (local.get $out_ptr) (i32.const 1088) (i32.const 29))
                  (return (i32.const 29))))
              (if (i32.eq (i32.load (i32.add (local.get $in_ptr) (local.get $i))) (i32.const 0x50534E49))
                (then (return (i32.const 0))))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br $scan))
            (unreachable)))
    "#;

    fn wasm_spec(wat: &str) -> ContractSpec {
        ContractSpec {
            version: CONTRACT_VERSION,
            admits: "land.title.grant".into(),
            requires_refs: vec![],
            requires_parties: vec![],
            deadline_from_field: None,
            not_before_field: None,
            not_after_field: None,
            requires_sealed: vec![],
            wasm: Some(B64.encode(wat::parse_str(wat).unwrap())),
        }
    }

    fn doc_with_parcel(parcel: &str) -> SignedDocument {
        let mut document =
            SignedDocument::new("land.title.grant", serde_json::json!({"parcel": parcel}));
        document
            .sign("holder", &SigningKey::generate(&mut OsRng), None)
            .unwrap();
        document
    }

    #[test]
    fn wasm_admits_when_needle_found() {
        let report = wasm_spec(SCAN_WAT).evaluate_report(&doc_with_parcel("PH-1"), 2000, &[]);
        assert!(report.admitted, "reasons: {:?}", report.reasons);
        assert_eq!(report.conditions.len(), 2);
        assert!(report
            .conditions
            .iter()
            .any(|c| c.kind == ConditionKind::Wasm && c.met));
    }

    #[test]
    fn wasm_denies_when_needle_missing_with_guest_reason() {
        let report = wasm_spec(SCAN_WAT).evaluate_report(&doc_with_parcel("PH-2"), 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("not mentioned")));
        assert!(report
            .conditions
            .iter()
            .any(|c| c.kind == ConditionKind::Wasm && !c.met));
    }

    #[test]
    fn wasm_guest_sees_the_closure() {
        let spec = wasm_spec(CLOSURE_WAT);
        let doc = doc_with_parcel("PH-2");
        let inspection = SignedDocument::new(
            "land.title.inspection",
            serde_json::json!({"note": "INSPECTED"}),
        );
        let closure = vec![ClosureEntry {
            id: [1u8; 32],
            author: "inspector-author".into(),
            timestamp_ms: 500,
            document: Some(inspection),
        }];
        let report = spec.evaluate_report(&doc, 2000, &closure);
        assert!(report.admitted, "reasons: {:?}", report.reasons);

        let denied = spec.evaluate_report(&doc, 2000, &[]);
        assert!(!denied.admitted);
        assert!(denied
            .reasons
            .iter()
            .any(|r| r.contains("no inspection citation found")));
    }

    #[test]
    fn wasm_infinite_loop_is_a_fail_closed_denial() {
        let spec = wasm_spec(
            r#"(module
                 (memory (export "memory") 1)
                 (func (export "alloc") (param $s i32) (result i32) (i32.const 1024))
                 (func (export "evaluate")
                   (param $a i32) (param $b i32) (param $c i32) (param $d i32) (result i32)
                   (loop $spin (br $spin))
                   (unreachable)))"#,
        );
        let report = spec.evaluate_report(&doc_with_parcel("PH-1"), 2000, &[]);
        assert!(!report.admitted);
        assert!(report
            .reasons
            .iter()
            .any(|r| r.contains("trapped (or exhausted its fuel)")));
    }

    #[test]
    fn wasm_missing_exports_is_a_denial() {
        let spec = wasm_spec(r#"(module (memory (export "memory") 1))"#);
        let report = spec.evaluate_report(&doc_with_parcel("PH-1"), 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("exports no")));
    }

    #[test]
    fn wasm_wrong_kind_fails_fast_before_the_sandbox() {
        let doc = SignedDocument::new("land.title.loan", serde_json::json!({"parcel": "PH-1"}));
        let report = wasm_spec(SCAN_WAT).evaluate_report(&doc, 2000, &[]);
        assert!(!report.admitted);
        assert_eq!(report.conditions.len(), 1);
        assert_eq!(report.conditions[0].kind, ConditionKind::Kind);
    }

    #[test]
    fn check_module_reports_exports_and_rejects_garbage() {
        let empty = wat::parse_str(r#"(module)"#).unwrap();
        assert_eq!(check_module(&empty).unwrap(), Vec::<String>::new());
        let with_abi = wat::parse_str(
            r#"(module
                 (memory (export "memory") 1)
                 (func (export "alloc") (param i32) (result i32) (i32.const 0))
                 (func (export "evaluate")
                   (param i32 i32 i32 i32) (result i32) (i32.const 0)))"#,
        )
        .unwrap();
        let exports = check_module(&with_abi).unwrap();
        for required in ["memory", "alloc", "evaluate"] {
            assert!(exports.iter().any(|name| name == required), "{required}");
        }
        assert!(check_module(b"\x00not wasm").is_err());
    }

    #[test]
    fn wasm_bad_base64_is_a_denial() {
        let mut spec = wasm_spec(SCAN_WAT);
        spec.wasm = Some("!! not base64 !!".into());
        let report = spec.evaluate_report(&doc_with_parcel("PH-1"), 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("base64")));
    }

    #[test]
    fn wasm_oversize_module_is_a_denial() {
        let mut spec = wasm_spec(SCAN_WAT);
        spec.wasm = Some(B64.encode(vec![0u8; MAX_WASM_BYTES + 1]));
        let report = spec.evaluate_report(&doc_with_parcel("PH-1"), 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("size cap")));
    }

    #[test]
    fn wasm_unparseable_module_is_a_denial() {
        let mut spec = wasm_spec(SCAN_WAT);
        spec.wasm = Some(B64.encode(b"\x00garbage-not-wasm"));
        let report = spec.evaluate_report(&doc_with_parcel("PH-1"), 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("does not parse")));
    }
}
