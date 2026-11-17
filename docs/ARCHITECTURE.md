# Architecture

VGI is organized as **logical responsibilities across three trust domains**,
not as a pile of separate programs. This document explains the responsibilities,
the data that crosses between them, and the invariants that make the guarantees
hold.

## Trust domains

### 1. Untrusted intelligence & applications (`vgi.intelligence`)

Produces **proposals**. A proposal is a structured, non-authoritative request to
change state. The proposer holds no signing keys and no handle to the protected
resource. This is the domain a language model lives in; giving the model more
capability never gives it more authority, because authority lives elsewhere.

### 2. Independently protected authorization + execution

- **Authorization** (`vgi.governance`): `PolicyService` decides whether a
  proposed *effect* is permitted, against a versioned ruleset. `GrantAuthority`
  turns a permitted proposal into a **grant** — scoped to one effect identity,
  single-use, time-boxed, and signed with a private key no other domain holds.
- **Execution** (`vgi.execution`): `ResourceOwner` holds the protected resource
  and is its only mutator. It applies an effect only when presented with a valid,
  unconsumed grant bound to that exact effect. `FreshnessAuthority` is the
  independent **coordination store** — reservation, commitment and revocation
  state, kept outside the resource's rollback boundary.

These are grouped as one domain because both are "privileged," but they hold
*different* keys and *different* stores; the authority can sign grants but does
not touch the resource, and the resource owner can apply effects but cannot
forge grants.

### 3. Independently controlled assurance (`vgi.evidence`)

- `ReceiptStore` keeps signed receipts in a separate store.
- `Witness` answers "what does the resource actually say right now?" by reading
  the resource through its own independent path — not by trusting a receipt and
  not by asking the resource owner.

## The contracts (`vgi.contracts`)

Everything that crosses a boundary is a versioned contract with a **canonical
encoding** (sorted keys, no insignificant whitespace), so every party hashes and
signs the exact same bytes.

- **`Effect`** — the authoritative description of one state change: resource,
  operation, key, value, precondition. Its **identity** is
  `sha256(canonical(core_fields))`. Policy approves an identity; the grant binds
  to it; the resource owner applies only the effect whose identity matches.
  "Approximately the approved change" does not exist.
- **`Proposal`** — intelligence → authorization. No signature, no power.
- **`Grant`** / **`GrantToken`** — authorization → execution. Signed. Carries the
  effect, its identity, a freshness sequence, a policy decision id, and expiry.
- **`Receipt`** / **`SignedReceipt`** — execution → evidence. Signed. A *claim*
  about what happened.
- **`Observation`** — the witness's independent read of reality.

## The transaction, step by step

1. **Propose.** `Proposer` emits a `Proposal` for `config[key] = value`.
2. **Evaluate.** `PolicyService.evaluate` returns a decision bound to the effect
   identity. A denied decision stops here.
3. **Issue.** `GrantAuthority.issue` signs a `Grant`, stamping it with the next
   sequence from the `FreshnessAuthority`.
4. **Redeem.** `ResourceOwner.redeem_and_apply`:
   - validates the effect shape, verifies signature, authority identity, expiry,
     and that the requested effect identity equals the grant's — before writing
     anything;
   - under the resource write lock: returns the stored receipt if this grant is
     already in the local ledger (idempotent retry);
   - otherwise **reserves** the grant in the coordination store, atomically with
     the revocation check (the authorization cutoff). An existing `COMMITTED`
     reservation with no local record means the resource was rolled back →
     refused; an existing `PENDING` one means prior execution is undeterminable →
     `RecoveryBlocked` (`UNKNOWN`);
   - checks the precondition and applies the effect **and** records redemption in
     a single resource-DB transaction, then marks the grant `COMMITTED`;
   - signs and returns a receipt.
   The full classification table and the reasoning are in THREAT_MODEL.md.
5. **File & witness.** The `Broker` stores the receipt and asks the `Witness` to
   `reconcile`: the receipt must be authentic, bound to *this* effect's identity
   with an `applied` outcome, and agree with a fresh independent read.
   `TransactionResult.verified` is true only when all of that holds.

## Invariants

- **Effect binding.** The only effect the resource owner will apply is the one
  whose identity matches the grant. (`test_grant_for_other_effect_...`,
  `test_tampered_grant_body_is_denied`)
- **At most once, across crashes and resource rollback.** Reservation before
  commit + commitment after, in a store independent of the resource DB; the
  ambiguous case blocks rather than re-executes.
  (`test_spent_grant_stays_spent_after_resource_rollback`,
  `test_crash_after_commit_then_snapshot_restore_does_not_replay`)
- **Idempotent recovery.** Re-presenting a grant whose effect already applied
  returns the same receipt and never re-applies. (`test_retry_of_same_grant_...`)
- **Observation over assertion.** Verification trusts a direct read of the
  resource, never the receipt alone. (`test_witness_catches_drift_...`)

## Why these libraries

Ordinary technology before custom infrastructure:

- **Ed25519** (`cryptography`) for real asymmetric signing — the authority signs,
  everyone else only verifies.
- **SQLite** for the resource store, the redemption ledger, the freshness store,
  and the receipt store — real transactions, real durability, zero setup. Each
  logical store is a separate file precisely so their recovery is independent.
- **stdlib** for everything else.

Nothing here needs a bespoke kernel or a trained model to demonstrate the
authority and evidence boundaries. Those can come later, as separately evaluated
capabilities, once the boundary is proven.
