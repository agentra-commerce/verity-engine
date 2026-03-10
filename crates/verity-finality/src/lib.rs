use serde::{Serialize, Deserialize};
use verity_kernel::{
    CanonicalTimestamp, SettlementId, ReceiptId, VerityId, VerityError,
};
use verity_outcomes::OutcomeClassification;

/// Finality determines whether an outcome can still be reversed.
/// Different payment rails have different finality windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityClass {
    /// Outcome is final. Cannot be reversed.
    Final,

    /// Outcome is confirmed but within a reversal window.
    /// Can still be reversed until the window expires.
    WithinReversalWindow {
        reversal_window_expires: CanonicalTimestamp,
    },

    /// Outcome is pending external confirmation.
    PendingConfirmation {
        expected_confirmation_by: CanonicalTimestamp,
    },

    /// Outcome has been reversed after initially being settled.
    Reversed {
        reversed_at: CanonicalTimestamp,
        reason: ReversalReason,
        original_finality: Box<FinalityClass>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReversalReason {
    Chargeback,
    Fraud,
    DisputeResolution,
    AdministrativeCorrection,
    AdapterFailure,
}

impl FinalityClass {
    /// Can this outcome still be reversed?
    pub fn is_reversible(&self) -> bool {
        matches!(self, FinalityClass::WithinReversalWindow { .. })
    }

    /// Is this outcome fully final (no further changes possible)?
    pub fn is_final(&self) -> bool {
        matches!(self, FinalityClass::Final)
    }

    /// Attempt to reverse this outcome. Returns error if not reversible.
    pub fn reverse(
        &self,
        reason: ReversalReason,
        timestamp: CanonicalTimestamp,
    ) -> Result<FinalityClass, VerityError> {
        match self {
            FinalityClass::Final => Err(VerityError::FinalityError(
                "cannot reverse a final outcome".to_string(),
            )),
            FinalityClass::WithinReversalWindow { reversal_window_expires } => {
                if timestamp.is_before(reversal_window_expires) {
                    Ok(FinalityClass::Reversed {
                        reversed_at: timestamp,
                        reason,
                        original_finality: Box::new(self.clone()),
                    })
                } else {
                    Err(VerityError::FinalityError(
                        "reversal window has expired".to_string(),
                    ))
                }
            }
            FinalityClass::PendingConfirmation { .. } => Err(VerityError::FinalityError(
                "cannot reverse a pending confirmation".to_string(),
            )),
            FinalityClass::Reversed { .. } => Err(VerityError::FinalityError(
                "outcome is already reversed".to_string(),
            )),
        }
    }

    /// Attempt to confirm a pending outcome.
    pub fn confirm(&self) -> Result<FinalityClass, VerityError> {
        match self {
            FinalityClass::PendingConfirmation { .. } => Ok(FinalityClass::Final),
            _ => Err(VerityError::FinalityError(
                "can only confirm a PendingConfirmation".to_string(),
            )),
        }
    }

    /// Check if reversal window has expired (making it effectively final).
    pub fn check_window_expiry(&self, now: &CanonicalTimestamp) -> FinalityClass {
        match self {
            FinalityClass::WithinReversalWindow { reversal_window_expires } => {
                if !now.is_before(reversal_window_expires) {
                    FinalityClass::Final
                } else {
                    self.clone()
                }
            }
            other => other.clone(),
        }
    }
}

/// Default finality characteristics per adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterType {
    Stripe,
    UsdcBase,
    UsdcEthereum,
    Test,
}

impl AdapterType {
    /// Default finality class for this adapter after successful execution.
    pub fn default_finality(&self, settled_at: &CanonicalTimestamp) -> FinalityClass {
        match self {
            AdapterType::Stripe => FinalityClass::WithinReversalWindow {
                reversal_window_expires: settled_at.add_days(120),
            },
            AdapterType::UsdcBase | AdapterType::UsdcEthereum => {
                FinalityClass::PendingConfirmation {
                    expected_confirmation_by: settled_at.add_minutes(5),
                }
            }
            AdapterType::Test => FinalityClass::Final,
        }
    }
}

/// Append-only log of all reversals. Critical for audit trail.
/// Invariant 8: Truth history is append-only.
pub struct ReversalJournal {
    entries: Vec<ReversalEntry>,
}

#[derive(Debug, Clone)]
pub struct ReversalEntry {
    pub settlement_id: SettlementId,
    pub receipt_id: ReceiptId,
    pub reversed_at: CanonicalTimestamp,
    pub reason: ReversalReason,
    pub original_outcome: OutcomeClassification,
    pub reversed_outcome: OutcomeClassification,
    pub reversal_verity_id: VerityId,
}

impl ReversalJournal {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn record(&mut self, entry: ReversalEntry) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[ReversalEntry] {
        &self.entries
    }

    pub fn entries_for_settlement(&self, id: &SettlementId) -> Vec<&ReversalEntry> {
        self.entries.iter().filter(|e| e.settlement_id == *id).collect()
    }
}

impl Default for ReversalJournal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> CanonicalTimestamp {
        CanonicalTimestamp::from_rfc3339(s).unwrap()
    }

    #[test]
    fn test_final_cannot_be_reversed() {
        let f = FinalityClass::Final;
        let result = f.reverse(ReversalReason::Chargeback, ts("2026-06-01T00:00:00+00:00"));
        assert!(result.is_err());
    }

    #[test]
    fn test_within_window_can_be_reversed() {
        let f = FinalityClass::WithinReversalWindow {
            reversal_window_expires: ts("2026-07-01T00:00:00+00:00"),
        };
        let result = f.reverse(
            ReversalReason::Chargeback,
            ts("2026-06-15T00:00:00+00:00"),
        );
        assert!(result.is_ok());
        let reversed = result.unwrap();
        assert!(matches!(reversed, FinalityClass::Reversed { .. }));
    }

    #[test]
    fn test_within_window_expired_cannot_reverse() {
        let f = FinalityClass::WithinReversalWindow {
            reversal_window_expires: ts("2026-06-01T00:00:00+00:00"),
        };
        let result = f.reverse(
            ReversalReason::Chargeback,
            ts("2026-07-01T00:00:00+00:00"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_window_expiry_becomes_final() {
        let f = FinalityClass::WithinReversalWindow {
            reversal_window_expires: ts("2026-06-01T00:00:00+00:00"),
        };
        let now = ts("2026-07-01T00:00:00+00:00");
        let checked = f.check_window_expiry(&now);
        assert_eq!(checked, FinalityClass::Final);
    }

    #[test]
    fn test_window_not_yet_expired() {
        let f = FinalityClass::WithinReversalWindow {
            reversal_window_expires: ts("2026-07-01T00:00:00+00:00"),
        };
        let now = ts("2026-06-01T00:00:00+00:00");
        let checked = f.check_window_expiry(&now);
        assert!(matches!(checked, FinalityClass::WithinReversalWindow { .. }));
    }

    #[test]
    fn test_pending_can_be_confirmed() {
        let f = FinalityClass::PendingConfirmation {
            expected_confirmation_by: ts("2026-06-01T00:05:00+00:00"),
        };
        let result = f.confirm();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FinalityClass::Final);
    }

    #[test]
    fn test_final_cannot_be_confirmed() {
        let f = FinalityClass::Final;
        assert!(f.confirm().is_err());
    }

    #[test]
    fn test_reversed_is_terminal() {
        let f = FinalityClass::Reversed {
            reversed_at: ts("2026-06-15T00:00:00+00:00"),
            reason: ReversalReason::Chargeback,
            original_finality: Box::new(FinalityClass::Final),
        };
        assert!(f.reverse(ReversalReason::Fraud, ts("2026-07-01T00:00:00+00:00")).is_err());
        assert!(f.confirm().is_err());
    }

    #[test]
    fn test_is_reversible() {
        assert!(!FinalityClass::Final.is_reversible());
        assert!(FinalityClass::WithinReversalWindow {
            reversal_window_expires: ts("2099-01-01T00:00:00+00:00"),
        }.is_reversible());
        assert!(!FinalityClass::PendingConfirmation {
            expected_confirmation_by: ts("2099-01-01T00:00:00+00:00"),
        }.is_reversible());
    }

    #[test]
    fn test_is_final() {
        assert!(FinalityClass::Final.is_final());
        assert!(!FinalityClass::WithinReversalWindow {
            reversal_window_expires: ts("2099-01-01T00:00:00+00:00"),
        }.is_final());
    }

    #[test]
    fn test_adapter_stripe_default() {
        let settled_at = ts("2026-03-01T00:00:00+00:00");
        let f = AdapterType::Stripe.default_finality(&settled_at);
        assert!(matches!(f, FinalityClass::WithinReversalWindow { .. }));
    }

    #[test]
    fn test_adapter_usdc_default() {
        let settled_at = ts("2026-03-01T00:00:00+00:00");
        let f = AdapterType::UsdcBase.default_finality(&settled_at);
        assert!(matches!(f, FinalityClass::PendingConfirmation { .. }));
    }

    #[test]
    fn test_adapter_test_default() {
        let settled_at = ts("2026-03-01T00:00:00+00:00");
        let f = AdapterType::Test.default_finality(&settled_at);
        assert_eq!(f, FinalityClass::Final);
    }

    #[test]
    fn test_reversal_journal() {
        let mut journal = ReversalJournal::new();
        let stl1 = SettlementId::generate();
        let stl2 = SettlementId::generate();

        journal.record(ReversalEntry {
            settlement_id: stl1.clone(),
            receipt_id: ReceiptId::generate(),
            reversed_at: ts("2026-06-15T00:00:00+00:00"),
            reason: ReversalReason::Chargeback,
            original_outcome: OutcomeClassification::Success,
            reversed_outcome: OutcomeClassification::Reversed,
            reversal_verity_id: VerityId::generate(),
        });

        journal.record(ReversalEntry {
            settlement_id: stl2.clone(),
            receipt_id: ReceiptId::generate(),
            reversed_at: ts("2026-06-16T00:00:00+00:00"),
            reason: ReversalReason::Fraud,
            original_outcome: OutcomeClassification::Success,
            reversed_outcome: OutcomeClassification::Reversed,
            reversal_verity_id: VerityId::generate(),
        });

        journal.record(ReversalEntry {
            settlement_id: stl1.clone(),
            receipt_id: ReceiptId::generate(),
            reversed_at: ts("2026-06-17T00:00:00+00:00"),
            reason: ReversalReason::AdministrativeCorrection,
            original_outcome: OutcomeClassification::Partial,
            reversed_outcome: OutcomeClassification::Reversed,
            reversal_verity_id: VerityId::generate(),
        });

        assert_eq!(journal.entries().len(), 3);
        assert_eq!(journal.entries_for_settlement(&stl1).len(), 2);
        assert_eq!(journal.entries_for_settlement(&stl2).len(), 1);
    }
}
