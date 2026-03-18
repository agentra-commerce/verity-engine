# verity-engine

**The open-source truth engine for XAP. Deterministic decision provenance and replay.**

[![CI](https://github.com/agentra-commerce/verity-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/agentra-commerce/verity-engine/actions)
[![Crates.io](https://img.shields.io/crates/v/verity-kernel)](https://crates.io/crates/verity-kernel)
[![Tests: 103 passing](https://img.shields.io/badge/Tests-103%20passing-brightgreen.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Patent Pending](https://img.shields.io/badge/Patent-Pending-blue.svg)](#)
[![Maintained by: Agentra Labs](https://img.shields.io/badge/Maintained%20by-Agentra%20Labs-blue.svg)](https://www.agentralabs.tech)

---

## What This Is

Verity is the truth engine underneath XAP. Every agent-to-agent economic interaction — every negotiation, every settlement, every condition verification — produces a governed record called a `VerityReceipt`. That record captures not just what happened, but why, with enough fidelity that any party can replay the decision independently and produce an identical outcome.

This is the Git analogy made concrete. Git captures every code change with cryptographic integrity and lets anyone replay history. Verity captures every settlement decision with cryptographic integrity and lets anyone replay the reasoning. [Agentra Rail](https://www.agentralabs.tech) is the GitHub — the commercial product built on top.

The engine is written in Rust. It is open source under MIT. It runs inside every XAP settlement.

---

## Why Open Source

The value of a truth engine depends entirely on whether it can be independently verified. A closed truth engine is not a truth engine — it is a claim. By publishing the source, any party can confirm that a Verity replay is deterministic, that the hash chain is correctly implemented, and that the outcome state machine has no hidden transitions. The patent is filed. The code is open. The combination is the moat.

---

## The Five Crates

```
verity-engine/
├── crates/
│   ├── verity-kernel      — canonical types, money (integer minor units), time, serialization
│   ├── verity-outcomes    — outcome state machine (SUCCESS/FAIL/UNKNOWN/DISPUTED/REVERSED)
│   ├── verity-integrity   — hash chains, Merkle trees, inclusion proofs
│   ├── verity-finality    — finality classes, reversal journals
│   └── verity-ledgers     — MoneyLedger, EvidenceLedger (append-only)
```

Each crate has a single responsibility. They compose. Nothing is coupled unnecessarily.

---

## verity-kernel

The foundation. Every other crate depends on it.

Provides canonical types that ensure determinism across the entire engine: integer-only money arithmetic, a time model with defined precision, and a serialization layer that produces identical bytes for identical inputs regardless of platform.

```rust
use verity_kernel::{Money, MinorUnits, VerityId};

// Money is always integer minor units. No floating point. Ever.
let amount = Money::new(MinorUnits(10_000), "USD"); // $100.00
let split = amount.split_bps(6000)?;                 // $60.00 (60%)

assert_eq!(split.minor_units(), 6000);
```

The `MinorUnits` type enforces this at the type level. There is no way to accidentally introduce a float.

---

## verity-outcomes

The state machine that governs every settlement decision.

Five outcomes. No others. No implicit transitions.

```
UNKNOWN   — initial state, verification not yet complete
SUCCESS   — conditions met, funds released
FAIL      — conditions not met, funds returned
DISPUTED  — one party has challenged, deterministic arbitration running
REVERSED  — settlement was final, now reversed via journal entry
```

`UNKNOWN` is a first-class state, not an error. When a quality check is ambiguous, when a condition verification times out, when evidence is insufficient — the system declares `UNKNOWN` and follows the pre-declared resolution path. It never guesses.

```rust
use verity_outcomes::{OutcomeStateMachine, Outcome, Transition};

let mut machine = OutcomeStateMachine::new();
assert_eq!(machine.current(), Outcome::Unknown);

// Deterministic condition verified
machine.transition(Transition::ConditionPassed)?;
assert_eq!(machine.current(), Outcome::Success);

// UNKNOWN -> SUCCESS after timeout refund is forbidden
// The engine enforces this — no escape hatch
let refunded = OutcomeStateMachine::new();
// refunded.transition(Transition::TimeoutRefund)?;  <- REFUNDED, cannot then become SUCCESS
```

---

## verity-integrity

Hash chains and Merkle trees for tamper-evident receipt chains.

Every `VerityReceipt` includes a `previous_hash` linking it to the prior receipt in that agent's chain. The chain is append-only. A broken chain — where a receipt's predecessor hash does not match — is detected immediately and the entire chain after the break is marked `UNVERIFIED`.

```rust
use verity_integrity::{HashChain, ReceiptHash};

let mut chain = HashChain::new();
let h1 = chain.append(receipt_1_bytes)?;
let h2 = chain.append(receipt_2_bytes)?;

// Verify the chain is intact
assert!(chain.verify().is_ok());

// Replay: given the same inputs, produces the same hash
let replay_hash = ReceiptHash::compute(inputs, rules, outcome)?;
assert_eq!(replay_hash, h2);
```

Inclusion proofs allow any party to verify a specific receipt is part of a chain without downloading the entire chain. This is the primitive that makes public verification of `AgentManifest` receipt hashes efficient.

---

## verity-finality

Finality classes and reversal journals.

Not all settlement rails have the same finality guarantees. A Stripe settlement can be reversed via chargeback. A USDC on-chain settlement is cryptographically final. Verity models this explicitly so that receipts accurately reflect the true finality of the underlying settlement.

```rust
use verity_finality::{FinalityClass, ReversalJournal};

// Stripe: reversible within chargeback window
let finality = FinalityClass::Reversible {
    window_seconds: 7_776_000,  // 90 days
    mechanism: "stripe_chargeback",
};

// USDC on-chain: irreversible
let finality = FinalityClass::Irreversible {
    chain: "base",
    tx_hash: "0xabc...",
};

// If a reversal occurs, it is journaled — not edited
let journal = ReversalJournal::new();
journal.record(original_receipt_id, reversal_reason)?;
// The original receipt still exists. History is append-only.
```

---

## verity-ledgers

Append-only ledgers for money and evidence.

`MoneyLedger` tracks the flow of funds through settlements with full provenance. `EvidenceLedger` stores the evidence that condition verifications relied on — the actual output, the scorer version, the scoring parameters. Both are append-only: no `UPDATE`, no `DELETE`, enforced at the database trigger level.

```rust
use verity_ledgers::{MoneyLedger, EvidenceLedger, EvidenceRef};

let mut money = MoneyLedger::new();
money.debit(payer_id, MinorUnits(10_000))?;
money.credit(payee_id, MinorUnits(6_000))?;
money.credit(platform_id, MinorUnits(4_000))?;

// Conservation invariant: debits == credits
assert!(money.is_balanced());

let evidence = EvidenceLedger::new();
let ref_ = evidence.store(EvidenceRef {
    content_hash: sha256(verification_output),
    content_type: "quality_score_result",
    stored_at: Utc::now(),
})?;
```

---

## The Replay Model

A `VerityReceipt` is a replayable record. Given the same inputs, the same rules, and the same state machine — the replay produces the identical outcome. This is the invariant that makes Verity useful for audits, disputes, and compliance.

```rust
use verity_integrity::Replayer;

let replayer = Replayer::new(verity_engine);

// Original settlement decision
let original = receipts.get(receipt_id)?;

// Replay it
let replayed = replayer.replay(original.input_state, original.rules_applied)?;

// Outcomes must match
assert_eq!(original.outcome, replayed.outcome);
assert_eq!(original.replay_hash, replayed.replay_hash);
```

If `original.outcome != replayed.outcome`, the engine logs a `VERITY_DIVERGENCE` event and flags the settlement for review. This should be impossible for deterministic decisions. If it ever happens, it indicates a bug in the engine — which is why the code is open.

---

## Integration with XAP

Verity is woven into the XAP settlement lifecycle, not bolted on after:

```
1. SettlementIntent created
   → Verity captures decision context BEFORE execution
   → VerityReceipt created with outcome = UNKNOWN

2. Settlement engine executes
   → Conditions verified, splits calculated, adapter called

3. Verity finalizes the truth record
   → Transitions outcome: UNKNOWN -> SUCCESS / FAIL / DISPUTED
   → Links: SettlementIntent + NegotiationContract + ExecutionReceipt + evidence

4. Receipt available for independent replay
   → Any party with verity-engine can verify the outcome
```

The capture happens before execution. If the engine crashes after capture but before receipt issuance, the orphaned Verity record is detected on restart and the receipt is completed. No decision is ever lost.

---

## The Stack

```
xap-protocol      — Open standard (MIT). The language agents speak.
verity-engine     — This repo. The truth engine underneath everything.
xap-sdk           — Python SDK. pip install xap-sdk.
Agentra Rail      — Commercial infrastructure. Production settlement at scale.
```

Verity-engine is a dependency of Agentra Rail's settlement engine. It is also usable standalone — any system that wants deterministic decision provenance can use these crates directly without adopting the full XAP protocol.

---

## Install

```toml
[dependencies]
verity-kernel   = "0.1"
verity-outcomes = "0.1"
verity-integrity = "0.1"
verity-finality  = "0.1"
verity-ledgers   = "0.1"
```

Or use the workspace-level dependency if you are building an XAP-compatible system:

```toml
[dependencies]
verity-engine = { git = "https://github.com/agentra-commerce/verity-engine" }
```

---

## Build and Test

```bash
git clone https://github.com/agentra-commerce/verity-engine
cd verity-engine
cargo build --workspace
cargo test --workspace
```

103 tests across all five crates. All pass on stable Rust.

---

## Design Invariants

These are not configurable. They are structural properties of the engine.

1. Money is always integer minor units. No float arithmetic anywhere in the codebase.
2. Outcome state transitions are explicit. There are no implicit jumps between states.
3. `UNKNOWN` is a valid terminal state, not an error. Its resolution path is pre-declared.
4. Hash chains are append-only. There is no mutation path.
5. Evidence is content-addressed. The hash of the evidence is what is stored, not a pointer.
6. Replay is deterministic. Same inputs + same rules = same outcome, every time.
7. Reversals are journaled, not edits. A reversed settlement still exists in the ledger.

Violating any of these makes the system not-Verity.

---

## Contributing

The most valuable contributions are correctness challenges.

If you can construct a scenario where `replay(original_inputs) != original_outcome` for a deterministic decision — that is a critical bug and we want to know immediately. Open an issue with the label `replay-divergence`.

If you find a state machine transition that should be forbidden but is not — open an issue with `state-machine-gap`.

If you are building an XAP-compatible implementation and needed something from the engine that is not exposed — open an issue with `api-gap`.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for guidelines.

---

## Related Repos

- [xap-protocol](https://github.com/agentra-commerce/xap-protocol) — The open economic protocol
- [xap-sdk](https://github.com/agentra-commerce/xap-sdk) — Python SDK for XAP
- [Agentra Rail](https://www.agentralabs.tech) — Production implementation

---

## Community

**Engine homepage:** [verityengine.io](https://verityengine.io)
**Discord:** [Join @agentralabs](https://discord.gg/agentralabs)
**X / Twitter:** [Follow @agentralab](https://x.com/agentralab)
**Email:** [hello@agentralabs.tech](mailto:hello@agentralabs.tech)

---

## License

MIT. The truth engine is free. Forever.

---

*verity-engine is maintained by [Agentra Labs](https://www.agentralabs.tech) and is the open-source foundation of [Agentra Rail](https://www.agentralabs.tech).*
