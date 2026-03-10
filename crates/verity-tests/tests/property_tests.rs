use serde_json::json;
use verity_kernel::*;
use verity_outcomes::*;
use verity_integrity::*;

/// Property Test 1: Outcome State Machine — UNKNOWN never equals SUCCESS
/// For any state, UNKNOWN and SUCCESS are always distinct.
#[test]
fn prop_unknown_never_equals_success() {
    for _ in 0..100 {
        let sm = OutcomeStateMachine::new();
        assert_ne!(*sm.current(), OutcomeClassification::Success);
        assert_eq!(*sm.current(), OutcomeClassification::Unknown);

        // After transition to SUCCESS, it's no longer UNKNOWN
        let mut sm2 = OutcomeStateMachine::new();
        sm2.transition(OutcomeClassification::Success, "test".into()).unwrap();
        assert_ne!(*sm2.current(), OutcomeClassification::Unknown);
        assert_eq!(*sm2.current(), OutcomeClassification::Success);
    }

    // All seven states are distinct from each other
    let states = vec![
        OutcomeClassification::Success,
        OutcomeClassification::Fail,
        OutcomeClassification::Unknown,
        OutcomeClassification::Disputed,
        OutcomeClassification::Reversed,
        OutcomeClassification::Timeout,
        OutcomeClassification::Partial,
    ];
    for i in 0..states.len() {
        for j in 0..states.len() {
            if i != j {
                assert_ne!(states[i], states[j]);
            }
        }
    }
}

/// Property Test 2: VRT-001 — Replay Determinism
/// compute_replay_hash called twice with same inputs produces identical results.
#[test]
fn prop_replay_determinism() {
    let test_cases: Vec<(serde_json::Value, serde_json::Value, serde_json::Value)> = vec![
        (json!({"a": 1}), json!({"b": 2}), json!({"c": 3})),
        (json!({}), json!({}), json!({})),
        (json!(null), json!(null), json!(null)),
        (
            json!({"nested": {"deep": {"value": 42}}}),
            json!({"rules": ["a", "b", "c"]}),
            json!({"steps": [1, 2, 3, 4, 5]}),
        ),
        (
            json!({"z": 1, "a": 2, "m": 3}),
            json!({"x": true, "b": false}),
            json!({"arr": [100, 200, 300]}),
        ),
        (
            json!({"amount": 999999999999i64}),
            json!({"version": "0.2.0"}),
            json!({"confidence": 9999}),
        ),
    ];

    for (input, rules, comp) in &test_cases {
        let hash1 = compute_replay_hash(input, rules, comp).unwrap();
        let hash2 = compute_replay_hash(input, rules, comp).unwrap();
        assert_eq!(hash1, hash2, "Replay hash must be deterministic for same inputs");
        assert!(hash1.starts_with("sha256:"));
    }

    // Key order independence
    let hash_a = compute_replay_hash(
        &json!({"z": 1, "a": 2}),
        &json!({"x": true}),
        &json!({"y": false}),
    ).unwrap();
    let hash_b = compute_replay_hash(
        &json!({"a": 2, "z": 1}),
        &json!({"x": true}),
        &json!({"y": false}),
    ).unwrap();
    assert_eq!(hash_a, hash_b, "Key order must not affect replay hash");
}

/// Property Test 3: VRT-006 — Forbidden Transitions After Timeout
/// Once an outcome reaches TIMEOUT, the only valid transition is DISPUTED.
#[test]
fn prop_timeout_only_allows_disputed() {
    let forbidden_after_timeout = vec![
        OutcomeClassification::Success,
        OutcomeClassification::Fail,
        OutcomeClassification::Partial,
        OutcomeClassification::Reversed,
        OutcomeClassification::Timeout,
        OutcomeClassification::Unknown,
    ];

    for target in &forbidden_after_timeout {
        let mut sm = OutcomeStateMachine::new();
        sm.transition(OutcomeClassification::Timeout, "timed out".into()).unwrap();
        let result = sm.transition(target.clone(), "attempt".into());
        assert!(
            result.is_err(),
            "TIMEOUT → {:?} should be forbidden",
            target
        );
    }

    // Only DISPUTED is allowed
    let mut sm = OutcomeStateMachine::new();
    sm.transition(OutcomeClassification::Timeout, "timed out".into()).unwrap();
    assert!(
        sm.transition(OutcomeClassification::Disputed, "appeal".into()).is_ok(),
        "TIMEOUT → DISPUTED must be allowed"
    );
}

/// Property Test 4: Money Arithmetic — No Float Contamination
/// add(a, b) then subtract(b) equals a. Split by bps sums to original.
#[test]
fn prop_money_no_float_contamination() {
    let test_amounts: Vec<(i64, i64)> = vec![
        (1000, 500),
        (1, 1),
        (999999, 1),
        (100000, 99999),
        (50000, 50000),
        (1, 0),
        (0, 0),
        (123456789, 987654321),
    ];

    for (a_val, b_val) in &test_amounts {
        let a = Money::new(*a_val, Currency::USD);
        let b = Money::new(*b_val, Currency::USD);

        let sum = a.add(&b).unwrap();
        let back = sum.subtract(&b).unwrap();
        assert_eq!(
            back.amount_minor_units, a.amount_minor_units,
            "add then subtract must return original: {} + {} - {} = {}",
            a_val, b_val, b_val, back.amount_minor_units
        );
    }

    // Split by basis points: sum of splits always equals original
    let split_cases: Vec<(i64, Vec<u16>)> = vec![
        (10000, vec![5000, 3000, 2000]),
        (1, vec![10000]),
        (999, vec![3333, 3333, 3334]),
        (100000, vec![6000, 2500, 1500]),
        (7, vec![5000, 5000]),
        (1000000, vec![1000, 2000, 3000, 4000]),
    ];

    for (total, shares_raw) in &split_cases {
        let money = Money::new(*total, Currency::USD);
        let shares: Vec<BasisPoints> = shares_raw
            .iter()
            .map(|s| BasisPoints::new(*s).unwrap())
            .collect();
        let splits = money.split_bps(&shares).unwrap();
        let sum: i64 = splits.iter().map(|m| m.amount_minor_units).sum();
        assert_eq!(
            sum, *total,
            "Split sum {} must equal original {} for shares {:?}",
            sum, total, shares_raw
        );
    }
}

/// Property Test 5: Hash Chain — Integrity and Uniqueness
/// Each chain entry produces a unique hash. Changing any content produces different hashes.
/// The chain always verifies when built correctly.
#[test]
fn prop_hash_chain_integrity() {
    let chain_sizes = vec![1, 2, 3, 5, 10];

    for size in chain_sizes {
        let settlement_id = SettlementId::generate();
        let mut chain = VerityChain::new(settlement_id);

        let mut hashes = Vec::new();
        for i in 0..size {
            let vid = VerityId::generate();
            let hash = chain.append(vid, &json!({"step": i, "data": format!("entry_{}", i)})).unwrap();
            hashes.push(hash);
        }

        // Chain should verify
        assert!(chain.verify().unwrap(), "Chain of size {} should verify", size);

        // All chain hashes should be unique
        let unique: std::collections::HashSet<&String> = hashes.iter().collect();
        assert_eq!(unique.len(), hashes.len(), "All chain hashes must be unique");

        // Building a different chain with different content produces different hashes
        let settlement_id2 = SettlementId::generate();
        let mut chain2 = VerityChain::new(settlement_id2);
        for i in 0..size {
            let vid = VerityId::generate();
            chain2.append(vid, &json!({"step": i, "data": format!("TAMPERED_{}", i)})).unwrap();
        }
        // Content hashes differ from original
        for i in 0..size {
            assert_ne!(
                chain.entries()[i].content_hash,
                chain2.entries()[i].content_hash,
                "Different content must produce different content hashes at position {}",
                i
            );
        }
    }

    // Verify linkage: each entry's previous_hash matches prior entry's chain_hash
    let settlement_id = SettlementId::generate();
    let mut chain = VerityChain::new(settlement_id);
    for i in 0..5 {
        let vid = VerityId::generate();
        chain.append(vid, &json!({"step": i})).unwrap();
    }
    assert!(chain.entries()[0].previous_hash.is_none());
    for i in 1..5 {
        assert_eq!(
            chain.entries()[i].previous_hash.as_ref().unwrap(),
            &chain.entries()[i - 1].chain_hash,
            "Entry {} must link to entry {}",
            i, i - 1
        );
    }
}
