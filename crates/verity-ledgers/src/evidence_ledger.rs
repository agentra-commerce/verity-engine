use serde::{Serialize, Deserialize};
use verity_kernel::{AgentId, SettlementId, BasisPoints, CanonicalTimestamp};

/// Tracks all evidence submitted for a settlement's condition verification.
/// Append-only. Evidence cannot be modified after submission.
#[derive(Debug, Clone)]
pub struct EvidenceLedger {
    settlement_id: SettlementId,
    entries: Vec<EvidenceEntry>,
    next_entry_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub entry_id: String,
    pub condition_id: String,
    pub submitted_by: AgentId,
    pub evidence_type: EvidenceType,
    pub evidence_hash: String,
    pub timestamp: CanonicalTimestamp,
    pub confidence_bps: BasisPoints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    Deterministic,
    Probabilistic,
    HumanApproval,
    EngineVerified,
    ExternalOracle,
}

impl EvidenceLedger {
    pub fn new(settlement_id: SettlementId) -> Self {
        Self {
            settlement_id,
            entries: Vec::new(),
            next_entry_id: 1,
        }
    }

    pub fn append(&mut self, mut entry: EvidenceEntry) {
        entry.entry_id = format!("eve_{}", self.next_entry_id);
        self.next_entry_id += 1;
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    pub fn entries_for_condition(&self, condition_id: &str) -> Vec<&EvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.condition_id == condition_id)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn settlement_id(&self) -> &SettlementId {
        &self.settlement_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evidence(
        condition_id: &str,
        agent: &AgentId,
        evidence_type: EvidenceType,
        confidence: u16,
    ) -> EvidenceEntry {
        EvidenceEntry {
            entry_id: String::new(),
            condition_id: condition_id.to_string(),
            submitted_by: agent.clone(),
            evidence_type,
            evidence_hash: "sha256:abcdef1234567890".to_string(),
            timestamp: CanonicalTimestamp::now(),
            confidence_bps: BasisPoints::new(confidence).unwrap(),
        }
    }

    #[test]
    fn test_append_and_len() {
        let mut ledger = EvidenceLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_evidence("cond_1", &agent, EvidenceType::Deterministic, 10000));
        ledger.append(make_evidence("cond_2", &agent, EvidenceType::Probabilistic, 8500));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn test_entry_ids_sequential() {
        let mut ledger = EvidenceLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_evidence("cond_1", &agent, EvidenceType::Deterministic, 10000));
        ledger.append(make_evidence("cond_2", &agent, EvidenceType::Probabilistic, 8500));
        assert_eq!(ledger.entries()[0].entry_id, "eve_1");
        assert_eq!(ledger.entries()[1].entry_id, "eve_2");
    }

    #[test]
    fn test_filter_by_condition() {
        let mut ledger = EvidenceLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_evidence("cond_1", &agent, EvidenceType::Deterministic, 10000));
        ledger.append(make_evidence("cond_2", &agent, EvidenceType::Probabilistic, 8500));
        ledger.append(make_evidence("cond_1", &agent, EvidenceType::EngineVerified, 9500));

        assert_eq!(ledger.entries_for_condition("cond_1").len(), 2);
        assert_eq!(ledger.entries_for_condition("cond_2").len(), 1);
        assert_eq!(ledger.entries_for_condition("cond_3").len(), 0);
    }

    #[test]
    fn test_entries_immutable_via_api() {
        let mut ledger = EvidenceLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_evidence("cond_1", &agent, EvidenceType::Deterministic, 10000));

        let entries = ledger.entries();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_empty_ledger() {
        let ledger = EvidenceLedger::new(SettlementId::generate());
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
    }
}
