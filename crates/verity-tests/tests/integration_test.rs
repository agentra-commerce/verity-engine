use serde::{Serialize, Deserialize};
use serde_json::json;
use verity_kernel::*;
use verity_outcomes::*;
use verity_integrity::*;
use verity_finality::*;
use verity_ledgers::*;

#[derive(Serialize, Deserialize)]
struct VerityReceiptOutput {
    verity_id: String,
    settlement_id: String,
    decision_type: String,
    decision_timestamp: String,
    input_state: serde_json::Value,
    rules_applied: serde_json::Value,
    computation: serde_json::Value,
    outcome: serde_json::Value,
    replay_hash: String,
    confidence_bps: u16,
    chain_position: u32,
    chain_previous_verity_hash: Option<String>,
    xap_version: String,
    verity_engine_version: String,
    verity_signature: String,
}

/// Phase 1.5 Gate: capture a settlement decision, produce a VerityReceipt,
/// and replay it deterministically.
#[test]
fn test_full_settlement_flow() {
    // 1. Create agents
    let payer = AgentId::generate();
    let payee = AgentId::generate();
    let platform = AgentId::generate();

    // 2. Create a settlement
    let settlement_id = SettlementId::generate();
    let contract_id = ContractId::generate();

    // 3. Record escrow in MoneyLedger
    let mut money_ledger = MoneyLedger::new(settlement_id.clone());
    money_ledger.append(MoneyEntry {
        entry_id: String::new(),
        agent_id: payer.clone(),
        direction: MoneyDirection::Debit,
        amount: Money::new(100_000, Currency::USD), // $1000.00
        entry_type: MoneyEntryType::Escrow,
        timestamp: CanonicalTimestamp::now(),
        reference: format!("escrow_{}", contract_id),
    });

    // 4. Submit evidence to EvidenceLedger
    let mut evidence_ledger = EvidenceLedger::new(settlement_id.clone());
    evidence_ledger.append(EvidenceEntry {
        entry_id: String::new(),
        condition_id: "http_200_check".to_string(),
        submitted_by: AgentId::generate(), // engine verifier
        evidence_type: EvidenceType::Deterministic,
        evidence_hash: canonical_hash(&json!({"status": 200, "url": "https://api.example.com/health"})).unwrap(),
        timestamp: CanonicalTimestamp::now(),
        confidence_bps: BasisPoints::new(10000).unwrap(), // 100% confidence
    });
    evidence_ledger.append(EvidenceEntry {
        entry_id: String::new(),
        condition_id: "quality_score".to_string(),
        submitted_by: AgentId::generate(),
        evidence_type: EvidenceType::Probabilistic,
        evidence_hash: canonical_hash(&json!({"score": 92, "threshold": 80})).unwrap(),
        timestamp: CanonicalTimestamp::now(),
        confidence_bps: BasisPoints::new(9200).unwrap(), // 92% confidence
    });

    // 5. Create Verity decision context
    let input_state = json!({
        "settlement_id": settlement_id.as_str(),
        "contract_id": contract_id.as_str(),
        "escrow_amount_minor_units": 100_000,
        "currency": "USD",
        "conditions": [
            {"id": "http_200_check", "type": "deterministic", "result": true},
            {"id": "quality_score", "type": "probabilistic", "score_bps": 9200, "threshold_bps": 8000}
        ]
    });

    let rules_applied = json!({
        "rule_set": "standard_v1",
        "version_hash": "sha256:rules_v1_hash_placeholder",
        "rules": [
            "all_deterministic_conditions_must_pass",
            "probabilistic_above_threshold_is_pass",
            "platform_fee_200bps"
        ]
    });

    let computation = json!({
        "steps": [
            {"step": 1, "action": "evaluate_http_200_check", "result": "PASS", "confidence_bps": 10000},
            {"step": 2, "action": "evaluate_quality_score", "result": "PASS", "confidence_bps": 9200},
            {"step": 3, "action": "aggregate_conditions", "result": "ALL_PASS", "overall_confidence_bps": 9600},
            {"step": 4, "action": "calculate_split", "payer_debit": 100000, "payee_credit": 98000, "platform_fee": 2000}
        ],
        "final_outcome": "SUCCESS"
    });

    // 6. Compute replay_hash
    let replay_hash = compute_replay_hash(&input_state, &rules_applied, &computation).unwrap();

    // 7. Run outcome state machine: UNKNOWN → SUCCESS
    let mut outcome_sm = OutcomeStateMachine::new();
    assert_eq!(*outcome_sm.current(), OutcomeClassification::Unknown);
    outcome_sm.transition(OutcomeClassification::Success, "all conditions met".into()).unwrap();
    assert_eq!(*outcome_sm.current(), OutcomeClassification::Success);

    // 8. Append to VerityChain
    let verity_id = VerityId::generate();
    let mut chain = VerityChain::new(settlement_id.clone());

    let decision_content = json!({
        "verity_id": verity_id.as_str(),
        "decision_type": "ConditionVerification",
        "input_state": input_state,
        "rules_applied": rules_applied,
        "computation": computation,
        "outcome": format!("{}", outcome_sm.current()),
        "replay_hash": replay_hash,
    });

    let chain_hash = chain.append(verity_id.clone(), &decision_content).unwrap();
    assert!(chain.verify().unwrap());

    // 9. Sign with VeritySigner
    let signer = VeritySigner::generate();
    let signature = signer.sign(&decision_content).unwrap();
    assert!(verify_signature(&signer.public_key(), &decision_content, &signature).unwrap());

    // 10. Record settlement payouts in MoneyLedger
    money_ledger.append(MoneyEntry {
        entry_id: String::new(),
        agent_id: payee.clone(),
        direction: MoneyDirection::Credit,
        amount: Money::new(98_000, Currency::USD), // $980.00
        entry_type: MoneyEntryType::Settlement,
        timestamp: CanonicalTimestamp::now(),
        reference: format!("payout_{}", verity_id),
    });
    money_ledger.append(MoneyEntry {
        entry_id: String::new(),
        agent_id: platform.clone(),
        direction: MoneyDirection::Credit,
        amount: Money::new(2_000, Currency::USD), // $20.00 platform fee
        entry_type: MoneyEntryType::PlatformFee,
        timestamp: CanonicalTimestamp::now(),
        reference: format!("fee_{}", verity_id),
    });

    // 11. Verify MoneyLedger balances
    assert!(money_ledger.verify_balance().unwrap());
    assert_eq!(money_ledger.len(), 3);

    let payer_net = money_ledger.net_balance(&payer).unwrap();
    assert_eq!(payer_net.amount_minor_units, -100_000);

    let payee_net = money_ledger.net_balance(&payee).unwrap();
    assert_eq!(payee_net.amount_minor_units, 98_000);

    let platform_net = money_ledger.net_balance(&platform).unwrap();
    assert_eq!(platform_net.amount_minor_units, 2_000);

    // 12. Set finality class (TestAdapter → Final)
    let settled_at = CanonicalTimestamp::now();
    let finality = AdapterType::Test.default_finality(&settled_at);
    assert_eq!(finality, FinalityClass::Final);

    // REPLAY TEST
    // 13-16. Recompute replay_hash from stored components and verify deterministic replay
    let replay_hash_2 = compute_replay_hash(
        &input_state,
        &rules_applied,
        &computation,
    ).unwrap();
    assert_eq!(replay_hash, replay_hash_2, "Replay hash must be deterministic");

    assert!(
        verify_replay_hash(&replay_hash, &input_state, &rules_applied, &computation).unwrap(),
        "Replay hash verification must succeed"
    );

    // Build the VerityReceiptOutput
    let chain_entry = &chain.entries()[0];
    let receipt = VerityReceiptOutput {
        verity_id: verity_id.to_string(),
        settlement_id: settlement_id.to_string(),
        decision_type: "ConditionVerification".to_string(),
        decision_timestamp: CanonicalTimestamp::now().to_rfc3339(),
        input_state: input_state.clone(),
        rules_applied: rules_applied.clone(),
        computation: computation.clone(),
        outcome: json!({
            "outcome_classification": format!("{}", outcome_sm.current()),
            "confidence_bps": 9600,
        }),
        replay_hash: replay_hash.clone(),
        confidence_bps: 9600,
        chain_position: chain_entry.position,
        chain_previous_verity_hash: chain_entry.previous_hash.clone(),
        xap_version: "0.2.0".to_string(),
        verity_engine_version: "0.2.0".to_string(),
        verity_signature: signature.clone(),
    };

    // Serialize and print
    let receipt_json = serde_json::to_string_pretty(&receipt).unwrap();
    println!("\n=== VerityReceipt Output ===\n{}\n", receipt_json);

    // Final assertions
    assert!(receipt.replay_hash.starts_with("sha256:"));
    assert!(receipt.verity_signature.starts_with("ed25519:"));
    assert_eq!(receipt.chain_position, 1);
    assert!(receipt.chain_previous_verity_hash.is_none());
    assert_eq!(receipt.xap_version, "0.2.0");

    // Verify chain integrity
    assert!(chain.verify().unwrap());
    assert_eq!(chain.latest_hash().unwrap(), chain_hash);

    // Verify evidence was recorded
    assert_eq!(evidence_ledger.len(), 2);
    assert_eq!(evidence_ledger.entries_for_condition("http_200_check").len(), 1);
    assert_eq!(evidence_ledger.entries_for_condition("quality_score").len(), 1);
}

/// Test multi-decision chain: settlement with dispute resolution
#[test]
fn test_multi_decision_chain() {
    let settlement_id = SettlementId::generate();
    let mut chain = VerityChain::new(settlement_id);

    // First decision: condition verification → DISPUTED
    let v1 = VerityId::generate();
    let content1 = json!({"decision": "condition_verification", "outcome": "DISPUTED"});
    chain.append(v1, &content1).unwrap();

    // Second decision: dispute resolution → SUCCESS
    let v2 = VerityId::generate();
    let content2 = json!({"decision": "dispute_resolution", "outcome": "SUCCESS"});
    chain.append(v2, &content2).unwrap();

    assert_eq!(chain.len(), 2);
    assert!(chain.verify().unwrap());

    // Second entry should link to first
    assert!(chain.entries()[1].previous_hash.is_some());
    assert_eq!(
        chain.entries()[1].previous_hash.as_ref().unwrap(),
        &chain.entries()[0].chain_hash
    );
}
