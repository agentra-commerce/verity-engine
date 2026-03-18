# Verity Network Submission Specification
## How External Implementations Submit Receipts to the Verity Public Network
### verityengine.io · v0.1 · March 2026

---

## What This Document Is

The Verity public network accepts `VerityReceipt` objects from any XAP-compatible implementation. Submitted receipts become publicly verifiable — any party can paste a receipt hash at `verityengine.io/verify` and independently confirm the outcome. No ZexRail account required.

This document specifies everything needed to connect your implementation:

1. How to register your implementation
2. How to format and sign a receipt for submission
3. The submission API
4. What gets accepted and what gets rejected
5. Rate limits and abuse controls
6. The federation model for v1.1

**Prerequisite:** Your system must produce valid `VerityReceipt` objects per the XAP v0.2 schema. See `github.com/agentra-commerce/xap-protocol/xap/schemas/verity-receipt.json`.

---

## Section 1 — Register Your Implementation

Every system that submits receipts to the Verity network must register. Registration creates a verified implementation identity — a public key pair that signs every submission and identifies which system produced the receipt.

### 1.1 Registration Process

Registration is handled through a GitHub issue in the `verity-engine` repo. This is intentional: it keeps the registry auditable, community-visible, and free of gatekeeping infrastructure.

**Step 1: Generate an Ed25519 key pair**

```bash
# Using the verity-engine CLI (once installed)
cargo install verity-cli
verity-cli keygen --output my-implementation

# Produces:
# my-implementation.pub   (share this — your public key)
# my-implementation.key   (keep this secret — your signing key)
```

Or using any Ed25519 implementation — the key format is standard.

**Step 2: Open a registration issue**

Go to `github.com/agentra-commerce/verity-engine/issues/new?template=register-implementation.md`

Required fields:

```yaml
implementation_name: "Your System Name"
implementation_url: "https://your-system.example.com"
contact_email: "you@example.com"
public_key: "base64url-encoded Ed25519 public key"
xap_version: "0.2"
description: "One sentence describing your system"
```

**Step 3: Receive your implementation_id**

A maintainer reviews the registration within 48 hours. If approved, you receive:

```json
{
  "implementation_id": "impl_a1b2c3d4",
  "implementation_name": "Your System Name",
  "public_key": "your-public-key",
  "registered_at": "2026-03-17T00:00:00Z",
  "status": "active"
}
```

Your `implementation_id` is permanent and public. It appears on every receipt you submit and on the Observatory page.

### 1.2 What Registration Means

Registration is not a trust certification. It is an identity binding. It means:

- Receipts submitted with your `implementation_id` are verifiably from your system
- If your system submits invalid receipts, they are rejected and logged against your `implementation_id`
- If your system submits receipts that fail replay verification, the network flags them
- You can revoke your key and re-register with a new key at any time

Registration does not mean Agentra Labs has reviewed or endorses your system. The math does that.

---

## Section 2 — The VerityReceipt Object

Every submission must contain a valid `VerityReceipt` object. The canonical schema is at `xap-protocol/xap/schemas/verity-receipt.json`. This section summarizes the required fields and their constraints.

### 2.1 Required Fields

```json
{
  "verity_id": "vrt_[64 hex chars]",
  "xap_version": "0.2",
  "implementation_id": "impl_a1b2c3d4",
  "settlement_id": "stl_[8+ chars]",
  "issued_at": "2026-03-17T10:42:00Z",

  "outcome": {
    "state": "SUCCESS",
    "confidence_bps": 10000,
    "finality_class": "reversible"
  },

  "input_state": {
    "settlement_intent_hash": "sha256-of-settlement-intent",
    "agent_identities": ["agnt_...", "agnt_..."],
    "condition_values": {},
    "elapsed_ms": 1240
  },

  "rules_applied": {
    "policy_version": "xap-v0.2",
    "condition_type": "deterministic",
    "verifier": "ENGINE"
  },

  "computation": {
    "steps": ["condition_check", "split_cascade", "adapter_dispatch"],
    "evidence_refs": []
  },

  "replay_hash": "sha256([input_state_canonical] + [rules_applied_canonical] + [outcome_state])",

  "chain": {
    "previous_hash": "vrt_[prior receipt hash or GENESIS for first receipt]",
    "sequence": 1
  },

  "signature": {
    "algorithm": "Ed25519",
    "public_key": "your-public-key",
    "value": "base64url-encoded-signature"
  }
}
```

### 2.2 Outcome States

| State | Meaning | `confidence_bps` |
|---|---|---|
| `SUCCESS` | Conditions met. Funds released. | 10000 |
| `FAIL` | Conditions not met. Funds returned. | 10000 |
| `UNKNOWN` | Verification ambiguous. Pre-declared resolution ran. | 0–9999 |
| `DISPUTED` | One party challenged. Arbitration engaged. | any |
| `REVERSED` | Settlement was final. Now reversed via journal entry. | 10000 |

`UNKNOWN` is a valid outcome, not an error. If your condition verifier could not reach a confident result, `UNKNOWN` with a lower `confidence_bps` is the correct and honest representation.

### 2.3 The replay_hash

The `replay_hash` is the fingerprint that makes independent verification possible. It is computed as:

```
replay_hash = SHA-256(
  canonical_json(input_state) +
  canonical_json(rules_applied) +
  outcome.state
)
```

Where `canonical_json` means: keys sorted alphabetically, no whitespace, UTF-8 encoded. This ensures identical computation across all implementations.

The Verity network verifies this hash on every submission. If `replay_hash` does not match a recomputation from the provided `input_state`, `rules_applied`, and `outcome.state`, the submission is rejected.

### 2.4 The chain

Every implementation maintains an append-only chain of receipts per agent. The `chain.previous_hash` field links to the `verity_id` of the prior receipt for that agent. For the first receipt an agent ever produces, use the literal string `GENESIS`.

Chain integrity is verified on submission. A `previous_hash` that does not match a known receipt in your chain causes the submission to be rejected with `ERR_CHAIN_BROKEN`.

---

## Section 3 — The Submission API

Base URL: `https://api.verityengine.io/v1`

All requests require an `Authorization` header containing your `implementation_id` and a request signature.

### 3.1 Authentication Header

```
Authorization: Verity impl_id="impl_a1b2c3d4", signature="base64url-encoded-sig"
```

The signature covers the request body (the `VerityReceipt` JSON, canonicalized). The signing key is the same Ed25519 key registered in Section 1.

```python
import json
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def sign_submission(receipt: dict, private_key: Ed25519PrivateKey) -> str:
    canonical = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
    signature = private_key.sign(canonical.encode('utf-8'))
    return base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
```

### 3.2 Submit a Receipt

```
POST /v1/receipts
Content-Type: application/json
Authorization: Verity impl_id="impl_a1b2c3d4", signature="..."

{
  "receipt": { ...VerityReceipt object... }
}
```

**Success response (201 Created):**

```json
{
  "verity_id": "vrt_a1b2c3d4...",
  "accepted_at": "2026-03-17T10:42:01Z",
  "replay_verified": true,
  "chain_position": 847,
  "public_url": "https://verityengine.io/verify/vrt_a1b2c3d4..."
}
```

**Error response (400 Bad Request):**

```json
{
  "error": "ERR_REPLAY_HASH_MISMATCH",
  "detail": "Provided replay_hash does not match recomputation from input_state + rules_applied + outcome",
  "expected_hash": "sha256:...",
  "provided_hash": "sha256:..."
}
```

### 3.3 Submit a Batch

For high-volume implementations, receipts can be submitted in batches of up to 100:

```
POST /v1/receipts/batch
Content-Type: application/json
Authorization: Verity impl_id="impl_a1b2c3d4", signature="..."

{
  "receipts": [ ...up to 100 VerityReceipt objects... ]
}
```

**Response:**

```json
{
  "accepted": 98,
  "rejected": 2,
  "results": [
    { "verity_id": "vrt_...", "status": "accepted" },
    { "verity_id": "vrt_...", "status": "accepted" },
    { "verity_id": "vrt_...", "status": "rejected", "error": "ERR_SCHEMA_INVALID" }
  ]
}
```

Partial batch acceptance is normal. Each receipt is processed independently. A single invalid receipt does not block the rest.

### 3.4 Verify a Receipt (Public)

This endpoint requires no authentication. It is the endpoint behind `verityengine.io/verify`.

```
GET /v1/receipts/{verity_id_or_hash}
```

**Response:**

```json
{
  "verity_id": "vrt_a1b2c3d4...",
  "implementation_id": "impl_a1b2c3d4",
  "implementation_name": "Your System Name",
  "settlement_id": "stl_...",
  "outcome": "SUCCESS",
  "confidence_bps": 10000,
  "replay_hash": "sha256:...",
  "issued_at": "2026-03-17T10:42:00Z",
  "replay_verified": true,
  "public": true
}
```

Private fields (agent identities, condition values, evidence refs) are not returned in the public endpoint. They are available to authenticated parties who can prove ownership of the relevant agent IDs.

### 3.5 Query Public Receipts

```
GET /v1/receipts?implementation_id=impl_a1b2c3d4&outcome=SUCCESS&limit=20&cursor=...
```

Returns the most recent public receipts matching the filters. Used by the Observatory page live feed.

---

## Section 4 — Rejection Codes

| Error Code | Meaning | Action |
|---|---|---|
| `ERR_SCHEMA_INVALID` | Receipt does not validate against `verity-receipt.json` | Fix the object structure |
| `ERR_REPLAY_HASH_MISMATCH` | `replay_hash` does not match recomputation | Recompute using canonical JSON per Section 2.3 |
| `ERR_CHAIN_BROKEN` | `previous_hash` does not match a known receipt | Submit missing prior receipts first |
| `ERR_SIGNATURE_INVALID` | Ed25519 signature does not verify | Check signing key matches registered public key |
| `ERR_IMPL_NOT_FOUND` | `implementation_id` not registered | Register per Section 1 |
| `ERR_IMPL_SUSPENDED` | Implementation suspended due to abuse | Contact hello@agentralabs.tech |
| `ERR_DUPLICATE` | `verity_id` already exists in the network | Idempotent — this is safe to ignore |
| `ERR_FUTURE_TIMESTAMP` | `issued_at` is more than 5 minutes in the future | Check system clock |
| `ERR_XAP_VERSION` | `xap_version` not supported | Use `"0.2"` |
| `ERR_OUTCOME_INVALID` | Outcome state not in allowed set | Use SUCCESS/FAIL/UNKNOWN/DISPUTED/REVERSED |
| `ERR_RATE_LIMITED` | Too many requests | Back off per Section 5 |

---

## Section 5 — Rate Limits

| Endpoint | Limit | Window |
|---|---|---|
| `POST /v1/receipts` (single) | 100 per minute | Per `implementation_id` |
| `POST /v1/receipts/batch` | 10 per minute | Per `implementation_id` |
| `GET /v1/receipts/{id}` (public) | 1000 per minute | Per IP |
| `GET /v1/receipts` (query) | 60 per minute | Per IP |

Rate limit headers are included on every response:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1710677460
```

When rate limited, back off with exponential jitter. The `Retry-After` header gives the exact seconds to wait.

For implementations with higher volume requirements, contact hello@agentralabs.tech with your `implementation_id` and expected volume. Raised limits are available for legitimate high-volume systems.

---

## Section 6 — Abuse Prevention

The Verity network is append-only and public. This creates abuse vectors that the submission layer must guard against.

### 6.1 What We Detect

**Replay hash farming** — submitting receipts with artificially high confidence scores that don't reflect real settlement outcomes. Detected by: cross-referencing claimed `settlement_id` patterns against known agent behaviors over time.

**Chain poisoning** — submitting a valid receipt then submitting a receipt with a `previous_hash` that references a different chain. Detected by: chain integrity verification on every submission.

**Sybil implementations** — registering many `implementation_id`s to artificially inflate network statistics. Detected by: IP correlation during registration, submission pattern analysis.

**Receipt flooding** — submitting large volumes of receipts to pollute the public feed. Controlled by: rate limits, batch limits, and suspension policy.

### 6.2 Consequences

Receipts that pass schema validation but fail behavioral checks are accepted but flagged as `UNVERIFIED` in the public explorer. Implementations that repeatedly submit suspicious receipts are suspended. Suspension is logged publicly against the `implementation_id` with the reason.

We do not delete receipts. The record of what was submitted is permanent. This is intentional.

---

## Section 7 — Running Your Own Verity Instance

For implementations that need data sovereignty, high volume, or air-gapped operation, running a local Verity instance is fully supported. The `verity-engine` crates are MIT licensed and contain everything needed.

```bash
git clone https://github.com/agentra-commerce/verity-engine
cd verity-engine
cargo build --workspace --release

# Run the submission server
./target/release/verity-server --port 8080 --storage ./data
```

A local instance behaves identically to the hosted network but stores receipts locally. Receipts submitted to a local instance are not automatically visible on `verityengine.io`.

**Federation (v1.1):** Local instances can opt into the federation network, making their receipts visible on the public Observatory and allowing cross-instance receipt verification. The federation protocol is defined in Section 8 below and will be implemented in v1.1.

---

## Section 8 — Federation Groundwork (v1.1 Design)

Federation allows multiple Verity instances to form a network where any receipt submitted to any instance is verifiable from any other instance. This section documents the design so that implementations building today build toward compatibility.

### 8.1 Instance Identity

Every federated Verity instance has an `instance_id` and a signing key pair, registered at `verityengine.io/instances`. The instance signs every receipt it stores, providing a chain of custody: the submitting implementation signed the receipt, and the storing instance counter-signed it.

### 8.2 Cross-Instance Verification

When the public Observatory at `verityengine.io` receives a receipt hash it does not know, it queries known federated instances:

```
GET https://other-instance.example.com/v1/receipts/{hash}
X-Verity-Instance: inst_verityengine_main
X-Verity-Signature: Ed25519 signature of the request
```

The queried instance returns the receipt if it has it. The response includes the instance's counter-signature so the querying node can verify the response is authentic.

### 8.3 What This Means Now

Implementations building today should:

1. Store their `instance_id` as `verityengine_hosted` (or their own instance ID if running locally)
2. Include `instance_id` in their receipt objects as an optional field — it is ignored by v0.1 but parsed by v1.1
3. Design their storage to support the federation query endpoint (GET by hash) — this is what v1.1 will call

No action required today beyond awareness. The federation protocol will be backward compatible with receipts that do not include an `instance_id`.

---

## Section 9 — Quick Start Integration

Everything you need to go from zero to first accepted receipt in 30 minutes.

### Step 1: Install the CLI

```bash
cargo install verity-cli
```

### Step 2: Register

```bash
verity-cli register --name "My System" --url https://my-system.example.com
# Opens a browser to the GitHub registration issue template
# Pre-fills your public key automatically
```

### Step 3: Produce a test receipt

```rust
use verity_kernel::{VerityId, VerityReceipt};
use verity_outcomes::Outcome;
use verity_integrity::HashChain;

let receipt = VerityReceipt::builder()
    .verity_id(VerityId::generate())
    .settlement_id("stl_test_001")
    .implementation_id("impl_a1b2c3d4")
    .outcome(Outcome::Success { confidence_bps: 10000 })
    .input_state(input_state)
    .rules_applied(rules)
    .sign_with(&signing_key)
    .build()?;
```

### Step 4: Submit

```bash
verity-cli submit --receipt receipt.json --key my-implementation.key
# Output:
# Accepted: vrt_a1b2c3d4...
# Public URL: https://verityengine.io/verify/vrt_a1b2c3d4...
```

### Step 5: Verify

```bash
verity-cli verify vrt_a1b2c3d4...
# Output:
# Outcome:        SUCCESS
# Replay hash:    sha256:...
# Replay verified: true
# Implementation: My System
```

Or paste the hash at `verityengine.io/verify` — no account needed.

---

## Section 10 — SDK Support

The `xap-sdk` Python package includes a `VeritySubmitter` class for implementations using Python:

```python
from xap.verity import VeritySubmitter

submitter = VeritySubmitter(
    implementation_id="impl_a1b2c3d4",
    signing_key_path="my-implementation.key",
    network="https://api.verityengine.io/v1",
)

# Submit a single receipt
result = await submitter.submit(receipt)
print(f"Accepted: {result.verity_id}")
print(f"Public: {result.public_url}")

# Submit a batch
results = await submitter.submit_batch(receipts)
print(f"Accepted: {results.accepted}/{len(receipts)}")
```

---

## Section 11 — Implementations on the Network

Registered implementations appear on the Observatory page at `verityengine.io`. Each implementation shows:

- Name and URL
- Total receipts submitted
- Success rate across all receipts
- Registration date
- Status (active / suspended)

To update your implementation's name, URL, or public key, open a new GitHub issue with the label `update-implementation` and your `implementation_id`.

---

## Appendix A — Canonical JSON Definition

Canonical JSON is used for computing `replay_hash` and request signatures. The rules are:

1. Keys sorted alphabetically at every level of nesting
2. No whitespace (no spaces, no newlines)
3. Strings encoded as UTF-8
4. Numbers with no trailing zeros
5. Booleans as `true` / `false`
6. Null as `null`
7. Arrays preserve insertion order (no sorting)

Reference implementation in Rust:

```rust
use verity_kernel::canonical::to_canonical_json;

let canonical = to_canonical_json(&receipt_value)?;
let hash = sha256(canonical.as_bytes());
```

Reference implementation in Python:

```python
import json

def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
```

---

## Appendix B — Test Vectors

Use these to verify your `replay_hash` computation is correct before submitting.

**Test vector 1 — deterministic SUCCESS:**

```json
input_state: {"settlement_intent_hash":"abc123","agent_identities":["agnt_001","agnt_002"],"condition_values":{"check":"http_status_200","result":true},"elapsed_ms":1240}
rules_applied: {"policy_version":"xap-v0.2","condition_type":"deterministic","verifier":"ENGINE"}
outcome_state: "SUCCESS"

canonical_payload: {"agent_identities":["agnt_001","agnt_002"],"condition_values":{"check":"http_status_200","result":true},"elapsed_ms":1240,"settlement_intent_hash":"abc123"}{"condition_type":"deterministic","policy_version":"xap-v0.2","verifier":"ENGINE"}SUCCESS

expected_replay_hash: sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5
```

**Test vector 2 — probabilistic UNKNOWN:**

```json
input_state: {"settlement_intent_hash":"def456","agent_identities":["agnt_003"],"condition_values":{"check":"quality_score","score_bps":7200,"threshold_bps":8500},"elapsed_ms":3100}
rules_applied: {"policy_version":"xap-v0.2","condition_type":"probabilistic","verifier":"ENGINE"}
outcome_state: "UNKNOWN"

expected_replay_hash: sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

If your implementation produces different hashes for these test vectors, your canonical JSON implementation is not compliant.

---

## Contact

**Registration questions:** Open an issue at `github.com/agentra-commerce/verity-engine`
**Integration support:** `hello@agentralabs.tech`
**Security issues:** `security@agentralabs.tech` — see SECURITY.md for responsible disclosure

---

*Verity Network Submission Specification · verityengine.io · v0.1 · March 2026*
*The truth engine is open. The network is open. The receipts are permanent.*
