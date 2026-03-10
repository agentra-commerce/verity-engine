use serde::{Serialize, Deserialize};
use verity_kernel::{AgentId, SettlementId, Money, Currency, VerityError, CanonicalTimestamp};

/// Tracks all monetary movements for a settlement.
/// Every credit has a corresponding debit. The ledger must always balance.
#[derive(Debug, Clone)]
pub struct MoneyLedger {
    settlement_id: SettlementId,
    entries: Vec<MoneyEntry>,
    next_entry_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoneyEntry {
    pub entry_id: String,
    pub agent_id: AgentId,
    pub direction: MoneyDirection,
    pub amount: Money,
    pub entry_type: MoneyEntryType,
    pub timestamp: CanonicalTimestamp,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoneyDirection {
    Credit,
    Debit,
    Hold,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoneyEntryType {
    Escrow,
    Settlement,
    Refund,
    PlatformFee,
    Reversal,
}

impl MoneyLedger {
    pub fn new(settlement_id: SettlementId) -> Self {
        Self {
            settlement_id,
            entries: Vec::new(),
            next_entry_id: 1,
        }
    }

    /// Append an entry. Append-only — cannot modify or delete.
    pub fn append(&mut self, mut entry: MoneyEntry) {
        entry.entry_id = format!("mle_{}", self.next_entry_id);
        self.next_entry_id += 1;
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[MoneyEntry] {
        &self.entries
    }

    pub fn entries_for_agent(&self, agent_id: &AgentId) -> Vec<&MoneyEntry> {
        self.entries.iter().filter(|e| e.agent_id == *agent_id).collect()
    }

    /// Compute net balance for an agent (credits + releases - debits - holds)
    pub fn net_balance(&self, agent_id: &AgentId) -> Result<Money, VerityError> {
        let agent_entries = self.entries_for_agent(agent_id);
        if agent_entries.is_empty() {
            return Err(VerityError::LedgerError(
                "no entries for agent".to_string(),
            ));
        }

        let currency = agent_entries[0].amount.currency.clone();
        let mut net: i64 = 0;

        for entry in &agent_entries {
            if entry.amount.currency != currency {
                return Err(VerityError::CurrencyMismatch(
                    currency,
                    entry.amount.currency.clone(),
                ));
            }
            match entry.direction {
                MoneyDirection::Credit | MoneyDirection::Release => {
                    net = net.checked_add(entry.amount.amount_minor_units)
                        .ok_or(VerityError::ArithmeticOverflow)?;
                }
                MoneyDirection::Debit | MoneyDirection::Hold => {
                    net = net.checked_sub(entry.amount.amount_minor_units)
                        .ok_or(VerityError::ArithmeticOverflow)?;
                }
            }
        }

        Ok(Money::new(net, currency))
    }

    /// Verify the ledger balances: total credits + releases == total debits + holds (per currency)
    pub fn verify_balance(&self) -> Result<bool, VerityError> {
        let mut usd_net: i64 = 0;
        let mut eur_net: i64 = 0;
        let mut gbp_net: i64 = 0;

        for entry in &self.entries {
            let amount = entry.amount.amount_minor_units;
            let delta = match entry.direction {
                MoneyDirection::Credit | MoneyDirection::Release => amount,
                MoneyDirection::Debit | MoneyDirection::Hold => -amount,
            };
            match entry.amount.currency {
                Currency::USD => usd_net += delta,
                Currency::EUR => eur_net += delta,
                Currency::GBP => gbp_net += delta,
            }
        }

        Ok(usd_net == 0 && eur_net == 0 && gbp_net == 0)
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

    fn make_entry(
        agent: &AgentId,
        direction: MoneyDirection,
        amount: i64,
        entry_type: MoneyEntryType,
        reference: &str,
    ) -> MoneyEntry {
        MoneyEntry {
            entry_id: String::new(),
            agent_id: agent.clone(),
            direction,
            amount: Money::new(amount, Currency::USD),
            entry_type,
            timestamp: CanonicalTimestamp::now(),
            reference: reference.to_string(),
        }
    }

    #[test]
    fn test_append_and_len() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_entry(&agent, MoneyDirection::Debit, 1000, MoneyEntryType::Escrow, "escrow"));
        ledger.append(make_entry(&agent, MoneyDirection::Credit, 1000, MoneyEntryType::Settlement, "payout"));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn test_entry_ids_are_sequential() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_entry(&agent, MoneyDirection::Debit, 100, MoneyEntryType::Escrow, "e1"));
        ledger.append(make_entry(&agent, MoneyDirection::Credit, 100, MoneyEntryType::Settlement, "e2"));
        assert_eq!(ledger.entries()[0].entry_id, "mle_1");
        assert_eq!(ledger.entries()[1].entry_id, "mle_2");
    }

    #[test]
    fn test_balanced_ledger() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let payer = AgentId::generate();
        let payee = AgentId::generate();

        // Payer debits 1000, payee credits 1000
        ledger.append(make_entry(&payer, MoneyDirection::Debit, 1000, MoneyEntryType::Escrow, "escrow"));
        ledger.append(make_entry(&payee, MoneyDirection::Credit, 1000, MoneyEntryType::Settlement, "payout"));

        assert!(ledger.verify_balance().unwrap());
    }

    #[test]
    fn test_unbalanced_ledger() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_entry(&agent, MoneyDirection::Credit, 1000, MoneyEntryType::Settlement, "payout"));

        assert!(!ledger.verify_balance().unwrap());
    }

    #[test]
    fn test_net_balance_for_agent() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let agent = AgentId::generate();

        ledger.append(make_entry(&agent, MoneyDirection::Credit, 5000, MoneyEntryType::Settlement, "payout1"));
        ledger.append(make_entry(&agent, MoneyDirection::Debit, 2000, MoneyEntryType::PlatformFee, "fee"));
        ledger.append(make_entry(&agent, MoneyDirection::Credit, 1000, MoneyEntryType::Refund, "refund"));

        let net = ledger.net_balance(&agent).unwrap();
        assert_eq!(net.amount_minor_units, 4000); // 5000 - 2000 + 1000
    }

    #[test]
    fn test_filter_by_agent() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let agent1 = AgentId::generate();
        let agent2 = AgentId::generate();

        ledger.append(make_entry(&agent1, MoneyDirection::Debit, 1000, MoneyEntryType::Escrow, "e1"));
        ledger.append(make_entry(&agent2, MoneyDirection::Credit, 1000, MoneyEntryType::Settlement, "s1"));
        ledger.append(make_entry(&agent1, MoneyDirection::Credit, 500, MoneyEntryType::Refund, "r1"));

        assert_eq!(ledger.entries_for_agent(&agent1).len(), 2);
        assert_eq!(ledger.entries_for_agent(&agent2).len(), 1);
    }

    #[test]
    fn test_entries_immutable_via_api() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let agent = AgentId::generate();
        ledger.append(make_entry(&agent, MoneyDirection::Debit, 1000, MoneyEntryType::Escrow, "e1"));

        // entries() returns &[MoneyEntry], no &mut access
        let entries = ledger.entries();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_hold_and_release_balance() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let escrow = AgentId::generate();

        ledger.append(make_entry(&escrow, MoneyDirection::Hold, 5000, MoneyEntryType::Escrow, "hold"));
        ledger.append(make_entry(&escrow, MoneyDirection::Release, 5000, MoneyEntryType::Settlement, "release"));

        assert!(ledger.verify_balance().unwrap());
    }

    #[test]
    fn test_complex_balanced_ledger() {
        let mut ledger = MoneyLedger::new(SettlementId::generate());
        let payer = AgentId::generate();
        let payee = AgentId::generate();
        let platform = AgentId::generate();

        // Payer puts in 10000
        ledger.append(make_entry(&payer, MoneyDirection::Debit, 10000, MoneyEntryType::Escrow, "escrow"));
        // Payee gets 9500
        ledger.append(make_entry(&payee, MoneyDirection::Credit, 9500, MoneyEntryType::Settlement, "payout"));
        // Platform gets 500 fee
        ledger.append(make_entry(&platform, MoneyDirection::Credit, 500, MoneyEntryType::PlatformFee, "fee"));

        assert!(ledger.verify_balance().unwrap());

        let payer_net = ledger.net_balance(&payer).unwrap();
        assert_eq!(payer_net.amount_minor_units, -10000);

        let payee_net = ledger.net_balance(&payee).unwrap();
        assert_eq!(payee_net.amount_minor_units, 9500);

        let platform_net = ledger.net_balance(&platform).unwrap();
        assert_eq!(platform_net.amount_minor_units, 500);
    }
}
