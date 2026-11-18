# Traceability

Every security claim maps to a test, and every test maps back to a claim. This
matrix is deliberately honest: `✓` means a test enforces it now, `◑` means
partially covered (the easy direction, or by-design rather than by-attack), and
`✗` means specified but not yet built. Nothing is marked done that a test does
not actually exercise.

Run everything with `python -m unittest discover -s tests`. The OS-isolation
family requires root and two non-root users; it skips cleanly otherwise — and a
skipped test verifies nothing. A `✓` below means "enforced by a test in this repo
and passing in the author's environment"; it is **not** a claim of independent
verification. That is tracked separately in the Definition of Done.

## Defects found by independent review (at `7c8a75a`)

An independent reviewer ran the suite (41 passed, 3 skipped — no root) and
reproduced four defects with additional probes. Each was reproduced again by the
author before fixing, and each now has a regression test that reproduces the
original probe:

| # | Defect at `7c8a75a` | Root cause | Fix | Regression test |
|---|---|---|---|---|
| D1 | Commit → SIGKILL before freshness advance → restore pre-commit resource snapshot → restart: grant applied **again** (new receipt). | Freshness was written only after the commit; a crash lost it, and startup recovery cannot rebuild a redemption the snapshot erased. | Reservation (`PENDING`) in the coordination store **before** the commit, `COMMITTED` after; `PENDING` + no local record is **blocked / UNKNOWN**, never re-executed. | `test_crash_recovery::test_crash_after_commit_then_snapshot_restore_does_not_replay` |
| D2 | Witness accepted a valid receipt for effect A as trustworthy against effect B when values matched. | `reconcile` checked signature and value, not effect identity. | Receipt must match the checked effect's identity and claim `applied`. | `test_negative::test_receipt_for_a_different_effect_is_not_trustworthy` |
| D3 | Revocation landing after the early check but before the transaction still applied. | Revocation was checked outside the transaction, with no defined cutoff. | Revocation moved into the coordination store and checked **atomically with the reservation** — the declared cutoff. | `test_revocation::test_revoke_racing_after_early_checks_is_still_honored` |
| D4 | A JSON array from an allowed peer raised `AttributeError` and terminated the service loop. | No envelope validation; the loop caught only two exception types. | Strict envelope validation; every per-connection failure contained in `serve_connection`; per-connection timeout. | `test_ipc_robustness` — handler logic over `socketpair` (no bind needed) plus the real loop on a bound socket. Mutation-checked: reverting to the D4 behaviour makes the socketpair tests fail. |

D1 also changed behavior that an earlier test had blessed: a crash mid-transaction
used to "complete on retry". It is now **blocked**, because from durable state it
is indistinguishable from D1. That test was changed deliberately, not loosened.

**Independent recheck at `89d0ccb`** (as reported by the reviewer): D1–D3 regression
tests pass; D4's connection-handling is now independently reproduced via the
`socketpair` tests; D4's bound-socket loop stays skipped (environment denies
socket creation); the two-uid OS-isolation tests stay skipped (no root). So D4 is
**partially reproduced** — handler logic verified, loop pending a socket-capable
environment.

The reviewer also raised two accuracy points, now fixed and tested in
`test_recovery_replacement`:
- `set` is idempotent only absent an intervening write; a replacement must target
  the presently-intended effect with a current-state precondition, not replay the
  old assignment verbatim.
- `COMMITTED` means the redemption transaction committed, not that the mutation
  applied (a rejected precondition also commits a record). `rolled_back` is the
  loss of a known committed redemption; its receipt distinguishes applied from
  rejected.

## Reviewer Priority 1 — govern replacement grants (done)

The reviewer's next-increment spec: link each replacement to the unresolved grant,
require a fresh policy decision, bind to the reviewed resource version, and record
what happened to both grants. Implemented and tested in
`test_replacement_governance`:

| Done-when | Test |
|---|---|
| A replacement cannot overwrite a newer update | `...update_between_review_and_redemption_rejects_replacement` |
| Enforced compare-and-set (authority **and** owner) | `...authority_refuses_replacement_without_precondition`, `...owner_refuses_replacement_without_precondition` |
| Link only to a genuinely unresolved grant | `...cannot_supersede_a_cleanly_committed_grant`, `...cannot_supersede_an_unknown_grant` |
| Original stays blocked / `UNKNOWN` after a successful replacement | `...successful_replacement_resolves_worklist_original_stays_unknown` |
| Concurrent replacements apply at most once | `...concurrent_replacements_apply_at_most_once` |
| Resolution survives a crash before it is recorded | `...resolution_is_reasserted_after_crash_before_record` |

Not addressed by this increment (still open, see below): JSON hardening (Priority
2), ledger↔broker integration (Priority 4), and the "expect-absent" precondition
gap.

## Adversarial regression tests (SEC-###)

| ID | Claim | Status | Test |
|----|-------|:------:|------|
| SEC-001 | Direct write to protected DB denied by OS | ✓ | `test_os_isolation::...isolation_and_authenticated_ipc` (sec001) |
| SEC-002 | WAL / sibling / dir access denied by OS | ✓ | same (sec002_wal, sec002_listdir) + creds |
| SEC-003 | Path / symlink substitution | ✓* | enforced: effect validator rejects path fields (`test_input_hardening`) + audited input inventory (THREAT_MODEL). *Scoped to the current effect surface. |
| SEC-004 | Inherited privileged descriptor | ✓ | same (sec004_leaked_fds == []) |
| SEC-005 | Valid grant submitted twice | ✓ | `test_protected_transaction::...idempotent` + IPC retry |
| SEC-006 | Concurrent redemption → one effect | ✓* | `test_concurrency`, `test_crash_recovery::...concurrent...`. *Scoped to the local transactional (SQLite) resource; external effects need their own recovery. |
| SEC-007 | Restore pre-consumption snapshot (incl. after a crash) | ✓* | `test_negative::...stays_spent_after_resource_rollback`, `test_crash_recovery::...snapshot_restore_does_not_replay`. *Assumes the coordination store is not rolled back with the resource (counter-example test shows why). |
| SEC-008 | Revoke before / racing redemption | ✓ | `test_revocation` — cutoff is the atomic reservation; late revocations report `too_late` |
| SEC-009 | Modify payload after signing | ✓ | `test_negative::...tampered_grant_body_is_denied` |
| SEC-010 | Substitute authorized resource path | ✓* | `test_os_isolation` (no client path) + effect-binding + validator. *Same scope caveat as SEC-003. |
| SEC-011 | Forge ALLOW without a grant | ✓ | `test_negative::...request_without_grant`, `...forged_grant` |
| SEC-012 | Policy service unavailable | ✓ | `test_failclosed::...policy_unavailable_blocks_grant_issuance` |
| SEC-013 | Chronicle write fails | ✓ | `test_failclosed::...chronicle_write_failure_rolls_back_effect` |
| SEC-014 | Crash after effect, before ack | ✓ | `test_crash_recovery` — real SIGKILL at before/after-reserve/mid/after-commit + restart; ambiguous cases block as UNKNOWN; `unresolved_grants()` lists them for an operator |
| SEC-015 | Alter a receipt / ledger, recompute hash | ✓* | `test_ledger` (tamper, delete, reorder; external checkpoint catches full rewrite). *Guarantee is conditional on an external anchor — see note below. |
| SEC-016 | Forge matching receipt + observation | ◑ | `test_negative::...fabricated_receipt...` (signature); observation independence under common control ✗ |
| SEC-017 | Verification command does not verify | ✓ | `test_verification::...non_verifying_command_is_not_verified` |
| SEC-018 | Mandatory dependency missing | ✓ | `test_verification::...missing_mandatory_dependency_blocks` |
| SEC-019 | Unauthorized policy amendment | ✗ | governance registry (GOV) not yet built |
| SEC-020 | Tool delegates stronger capability | ✗ | capability attenuator (PRIV-01) not yet built |
| SEC-021 | Malformed structured input | ◑ | `test_input_hardening` (effect shape) + `test_ipc_robustness` (envelope, framing, encoding, non-objects, stalls); raw-JSON duplicate keys and NaN/Infinity still accepted by the parser ✗ |
| SEC-022 | Shell metacharacters in parameters | ✗ | no shell surface yet; N/A until one exists |
| SEC-023 | Unauthorized outcome query | ✗ | outcome query API not yet built |
| SEC-024 | External confirmation unavailable | ✓ | `test_outcomes::...unavailable_is_unknown_not_committed` |

## Engineering invariants

| ID | Invariant | Status | Where |
|----|-----------|:------:|-------|
| AUTH-01 | AI proposals have no inherent authority | ✓ | proposer holds no keys; `test_request_without_grant` |
| AUTH-02 | Policy ALLOW is not an executable grant | ✓ | decision vs. grant separation; `test_forged_grant` |
| EXEC-01 | Owner validates auth against the exact effect | ✓ | effect-binding tests |
| EXEC-02 | Control failure prevents protected execution | ✓ | `test_failclosed` |
| EVID-01 | Evidence independently recomputed & authenticated | ✓* | witness reconcile + `test_ledger` recompute/verify. *Integrity is relative to an external checkpoint. |
| OBS-01 | Observation coverage matches effect surfaces | ◑ | witness reads the changed key |
| OBS-02 | Conflicting authentic observations block continuation | ◑ | OutcomeResolver CONFLICT; wired end-to-end ✗ |
| SEP-01 | Alignment / confidence / proof can't grant permission | ✓ | verification result never touches authorization |
| PRIV-01 | Delegation cannot expand privileges | ✗ | capability attenuator not yet built |
| GOV-01..03 | Governance self-relaxation / immutability / detectability | ✗ | governance registry not yet built |

## Definition of Done (milestone)

Two columns, because they are different claims. *Self-verified* = a test in this
repo enforces it and passes in the author's (root) environment. *Independent* =
what the reviewer's runs actually established: first at `7c8a75a`, then a recheck
at `353f245`. Recheck results are as reported by the reviewer; the author has not
reproduced the reviewer's environment.

| # | Item | Self-verified | Independent (reviewer: `7c8a75a`, recheck `353f245`) |
|---|------|:---:|---|
| 1 | Authorized protected write with exact-effect binding | ✓ | passed |
| 2 | Unauthorized direct write denied (OS-enforced) | ✓ (root only) | **not verified** — tests skipped without root |
| 3 | Duplicate & concurrent redemption cannot duplicate effects | ✓* | passed (*local transactional resource) |
| 4 | DB restoration cannot revive consumed grants | ✓ | failed at `7c8a75a` (D1); **passed** reviewer's recheck probe at `353f245` |
| 5 | Revoked or modified grants fail under ordering contract | ✓ | failed at `7c8a75a` (D3); **passed** reviewer's recheck at `353f245` |
| 6 | Crash / lost-ack outcomes reconcile correctly | ✓ | failed with rollback at `7c8a75a` (D1); **passed** reviewer's recheck at `353f245` — ambiguity now blocks (conditional on the coordination store surviving) |
| 7 | Chronicle / policy failures do not silently permit effects | ✓ | passed |
| 8 | Independent observer distinguishes real effects from fabricated records | ✓ | failed at `7c8a75a` (D2); **passed** reviewer's recheck at `353f245` |
| 9 | Mandatory verification deps execute or report BLOCKED_DEPENDENCY | ✓ | passed |
| 10 | Separate operator reproduces frozen tests | — | partial: one non-root run; root tests not run |

Items 4, 5, 6 and 8 were claimed done and **failed** independent probing at
`7c8a75a`; the reviewer's recheck at `353f245` reproduced fixes for D1–D3 (so these
four now have an independent pass, for those probes). Two items remain open and
there is still no honest single "N of 10":

- **Item 2 (OS isolation)** has never been independently verified: the two-uid
  tests need root and two non-root users, and the reviewer's environment has
  neither.
- **D4 (malformed IPC)** is now **partially reproduced** independently. At
  `89d0ccb` the reviewer ran the `socketpair` handler tests (no bind needed) and
  all four passed: malformed input, subsequent valid execution, timeout, uid
  refusal. The bound-socket *loop* test stays skipped where the environment denies
  socket creation — a skip verifies nothing, so the loop remains pending a
  socket-capable environment.

Reviewer recheck at `353f245`: 46 passed, 3 skipped, 1 failed in IPC test *setup*.
Reviewer recheck at `89d0ccb`: 53 passed, 4 skipped, 0 failed (setup fixed; D4
handler logic reproduced). Both as reported by the reviewer.

## Corrections to earlier summaries

Prior chat summaries overstated a few things; corrected here and in the threat model:

- "9 of 10 done" (at `7c8a75a`) was wrong: four claimed items failed independent
  review (D1–D4 above). The table above replaces any single count.
- An earlier chat summary said "7 of 10 solid" when the checklist showed 8 + 2.
- "Root peer refused" is an **application-level IPC authorization check**, not
  protection against a privileged host administrator (who is outside the attacker
  model). See THREAT_MODEL "Outside the attacker model".
- Path substitution is prevented for the **current effect surface**, established by
  an audited input inventory + a validator, not "by construction" in general.
- "One effect under concurrency" is scoped to the **local transactional resource**.
- The hash-linked ledger detects alteration **relative to an external checkpoint**;
  it does **not** establish observation independence — that is the witness's
  separate trust boundary, a different property.

## Not yet built (named so it is not mistaken for done)

- Observation independence under common control (SEC-016 full, OBS-02 wiring) — a
  separate trust boundary from the ledger, not provided by it.
- Governance registry + amendment control (GOV-01..03, SEC-019).
- Capability attenuator (PRIV-01, SEC-020).
- Broader input hardening at the trust boundary: raw-JSON duplicate keys,
  NaN/Infinity, rejected before policy/verify/execute (reviewer Priority 2).
- Ledger↔broker integration: how receipts reach the ledger after commit and how a
  retry handles interrupted publication (reviewer Priority 4).
- "Expect-absent" preconditions, and an operation to formally close a resolved
  blocked entry (replacement linkage itself is now built — see above).
- Observation independence under common control (SEC-016 full, OBS-02 wiring) — a
  separate trust boundary from the ledger, not provided by it.
- Governance registry + amendment control (GOV-01..03, SEC-019).
- Capability attenuator (PRIV-01, SEC-020).
- Unauthorized outcome-query protection (SEC-023) — no query API yet.
- Formal-proof adapter execution (T13) — the preflight exists; a real Lean/SMT
  check does not yet run.
- Non-idempotent / external effects (the one effect type is `set`).
- An actual independent-operator reproduction run (DoD #10); two-uid OS isolation
  and the D4 bound-socket loop still need a capable environment.
