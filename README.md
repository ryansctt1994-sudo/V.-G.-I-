# VGI — Verified · Governed · Intelligence

One system, one codebase, one architecture — built the way the rebuild plan
says to build it: **not** by scaffolding seven empty modules, but by shipping
**one complete vertical workflow that actually works and is actually tested.**

This first slice is the *protected transaction* — the narrow, qualified
protected-execution service the plan names as the first deployable artifact:

> An untrusted intelligence proposes changing a protected configuration value.
> An independent authority issues a scoped, single-use, signed grant for that
> **exact** change. A protected resource owner validates the grant and applies
> only that effect. An independent witness confirms the real effect by direct
> observation. Recovery handles duplicates, crashes, and rollback.

Everything here runs with `python3` and one dependency (`cryptography`). No
services to stand up, no model keys required for the security core.

## Run it

```bash
pip install -e .            # or: pip install cryptography
python -m apps.cli.demo     # one transaction, end to end
python -m unittest discover -s tests -v
```

## What the tests prove

The suite includes the **negative regression tests** carried over from the
earlier research. These are the bar a clean rebuild has to clear:

| Guarantee | Test |
|---|---|
| **Direct-write denial** — no path to the resource without a valid grant | `test_no_ungated_mutation_method_exists`, `test_request_without_grant_is_denied` |
| **Grant integrity** — forged, tampered, or wrong-effect grants are refused | `test_forged_grant_from_attacker_key_is_denied`, `test_tampered_grant_body_is_denied`, `test_grant_for_other_effect_cannot_authorize_this_one` |
| **Replay resistance across snapshot restore** — a spent grant stays spent even if the resource DB is rolled back, including after a crash between commit and coordination | `test_spent_grant_stays_spent_after_resource_rollback`, `test_crash_after_commit_then_snapshot_restore_does_not_replay` |
| *(why that works)* — the counter-example when freshness is **not** independent | `test_counterexample_rolling_back_freshness_too_resurrects_authority` |
| **Receipt ≠ observation** — a signed receipt never substitutes for a direct read, and must be bound to the effect being checked | `test_witness_catches_drift_between_receipt_and_reality`, `test_fabricated_receipt_fails_signature_check`, `test_receipt_for_a_different_effect_is_not_trustworthy` |
| **Idempotent recovery** — honest retries apply exactly once | `test_retry_of_same_grant_is_idempotent` |
| **OS-enforced isolation** — kernel denies direct DB/WAL/credential access; grant-gated IPC only | `test_os_isolation` (needs root; skips otherwise) |
| **Concurrent redemption** — many owners, one effect | `test_concurrency` |
| **Revocation** — atomic with the reservation (the authorization cutoff); late revocations reported `too_late` | `test_revocation` |
| **IPC robustness** — malformed or stalled requests from an allowed peer can't stop the service (no root; handler logic needs no socket bind; skips as `BLOCKED_ENVIRONMENT` if sockets are denied) | `test_ipc_robustness` |
| **Fail-closed** — policy/chronicle failure permits no effect | `test_failclosed` |
| **Honest uncertainty** — unconfirmable external effect is `UNKNOWN`, never false `COMMITTED` | `test_outcomes` |
| **No unchecked "proof"** — a missing checker yields `BLOCKED_DEPENDENCY`, not a pass | `test_verification` |
| **Crash recovery** — real SIGKILL at each boundary + restart; no partial effect, no double-apply; an undeterminable prior execution **blocks as `UNKNOWN`** instead of re-running | `test_crash_recovery` |
| **Tamper-evident ledger** — hash chain detects alteration/delete/reorder; external checkpoint catches full rewrite | `test_ledger` |
| **Input hardening** — effect surface rejects any smuggled path/descriptor field | `test_input_hardening` |

Full claim-to-test mapping (including what is **not** yet built) is in
[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md).

## The architecture in one picture

```
  UNTRUSTED                 INDEPENDENTLY PROTECTED              INDEPENDENTLY CONTROLLED
  intelligence              authorization + execution           assurance

  ┌────────────┐  proposal  ┌──────────────┐   grant   ┌──────────────┐
  │  Proposer  │ ─────────▶ │ PolicyService│ ────────▶ │ ResourceOwner│
  │ (no keys,  │            │ GrantAuthority│  (signed, │ (sole mutator│
  │  no access)│            │  [priv key]  │ single-use)│  gated by    │
  └────────────┘            └──────┬───────┘   effect-  │  grant)      │
                                   │           bound     └──────┬───────┘
                            ┌──────▼───────┐                    │ receipt
                            │ Coordination │◀─ reserve/commit ──┤
                            │    store     │   (outside the      │
                            │ (independent │  rollback boundary) ▼
                            │  store)      │            ┌──────────────┐
                            └──────────────┘            │   Witness    │
                                                        │ (independent │
                                                        │  read path)  │
                                                        └──────────────┘
```

Three trust domains, and the key distribution **is** the boundary:

- The **grant authority** holds the only private key that can sign grants.
- The **resource owner** and **witness** hold only the authority's *public* key.
- The **resource owner** signs receipts with its own key; the **witness** holds
  only *its* public key.
- The **coordination store** (reservation, commitment, revocation) and the
  **resource database** are separate stores; restoring the resource from a
  snapshot must not restore the coordination store.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full design, the explicit
trust boundaries, and — importantly — what is proven here versus what is
deferred to production hardening.

## Layout

```
vgi/
  contracts/    versioned schemas, canonical encoding, effect identity, outcomes
  intelligence/ untrusted proposer (where a model plugs in later)
  governance/   policy, grant issuance                    (authorization domain)
  execution/    coordination store (reserve/commit/revoke),
                resource owner, broker,
                owner_service + ipc (separate-UID + authenticated IPC),
                outcome resolver                          (execution domain)
  evidence/     durable receipts, independent witness,
                hash-linked ledger (external-checkpoint)   (assurance domain)
  verification/ dependency preflight + fail-closed verifier
  crypto.py     Ed25519 signing primitives
  system.py     the one place that wires it all together
apps/cli/       the end-to-end demo
tests/          happy path + the negative regression suite (+ OS isolation)
docs/           architecture, threat model, traceability matrix
```

## Where this goes next

This slice now covers Phase 1 + Phase 2 plus the start of Phase 3 (evidence),
and the keystone hardening is done: the resource owner runs under a **separate OS
identity** with an **authenticated IPC** surface, so direct-write denial is
enforced by the kernel, not just the API (`test_os_isolation`). The roadmap from
here, each step earning its complexity through tests before the next is added:

1. **Observation independence** — a witness on a *separate* trust boundary
   (SEC-016, OBS-02). The hash-linked ledger is built, but it proves integrity
   relative to an external checkpoint — it does **not** provide observation
   independence; that is a different property.
2. **Governance registry** — versioned, immutable policy with amendment control
   (GOV-01..03, SEC-019) and a capability attenuator (PRIV-01, SEC-020).
3. **Richer resources & effects** — beyond single config keys, with a real
   external-effect confirmer feeding the outcome resolver.
4. **Intelligence integration** — plug a model into the proposer through the
   unprivileged interface, without changing its authority.
5. **Formal reasoning** — a real Lean/SMT check behind the existing dependency
   preflight (T13).

See [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) for the exact done / partial /
not-yet status against the full spec.

The rule throughout: the smallest set of capabilities that delivers the value,
and every security guarantee earns its place through execution and evidence.
