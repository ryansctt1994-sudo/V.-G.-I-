# Traceability

Every security claim maps to a test, and every test maps back to a claim. This
matrix is deliberately honest: `✓` means a test enforces it now, `◑` means
partially covered (the easy direction, or by-design rather than by-attack), and
`✗` means specified but not yet built. Nothing is marked done that a test does
not actually exercise.

Run everything with `python -m unittest discover -s tests`. The OS-isolation
family requires root and two non-root users; it skips cleanly otherwise.

## Adversarial regression tests (SEC-###)

| ID | Claim | Status | Test |
|----|-------|:------:|------|
| SEC-001 | Direct write to protected DB denied by OS | ✓ | `test_os_isolation::...isolation_and_authenticated_ipc` (sec001) |
| SEC-002 | WAL / sibling / dir access denied by OS | ✓ | same (sec002_wal, sec002_listdir) + creds |
| SEC-003 | Path / symlink substitution | ✓* | enforced: effect validator rejects path fields (`test_input_hardening`) + audited input inventory (THREAT_MODEL). *Scoped to the current effect surface. |
| SEC-004 | Inherited privileged descriptor | ✓ | same (sec004_leaked_fds == []) |
| SEC-005 | Valid grant submitted twice | ✓ | `test_protected_transaction::...idempotent` + IPC retry |
| SEC-006 | Concurrent redemption → one effect | ✓* | `test_concurrency`, `test_crash_recovery::...concurrent...`. *Scoped to the local transactional (SQLite) resource; external effects need their own recovery. |
| SEC-007 | Restore pre-consumption snapshot | ✓ | `test_negative::...stays_spent_after_resource_rollback` |
| SEC-008 | Revoke before redemption | ✓ | `test_revocation::...revoke_before_redeem_is_refused` |
| SEC-009 | Modify payload after signing | ✓ | `test_negative::...tampered_grant_body_is_denied` |
| SEC-010 | Substitute authorized resource path | ✓* | `test_os_isolation` (no client path) + effect-binding + validator. *Same scope caveat as SEC-003. |
| SEC-011 | Forge ALLOW without a grant | ✓ | `test_negative::...request_without_grant`, `...forged_grant` |
| SEC-012 | Policy service unavailable | ✓ | `test_failclosed::...policy_unavailable_blocks_grant_issuance` |
| SEC-013 | Chronicle write fails | ✓ | `test_failclosed::...chronicle_write_failure_rolls_back_effect` |
| SEC-014 | Crash after effect, before ack | ✓ | `test_crash_recovery` — real SIGKILL at before/mid/after-commit + restart |
| SEC-015 | Alter a receipt / ledger, recompute hash | ✓* | `test_ledger` (tamper, delete, reorder; external checkpoint catches full rewrite). *Guarantee is conditional on an external anchor — see note below. |
| SEC-016 | Forge matching receipt + observation | ◑ | `test_negative::...fabricated_receipt...` (signature); observation independence under common control ✗ |
| SEC-017 | Verification command does not verify | ✓ | `test_verification::...non_verifying_command_is_not_verified` |
| SEC-018 | Mandatory dependency missing | ✓ | `test_verification::...missing_mandatory_dependency_blocks` |
| SEC-019 | Unauthorized policy amendment | ✗ | governance registry (GOV) not yet built |
| SEC-020 | Tool delegates stronger capability | ✗ | capability attenuator (PRIV-01) not yet built |
| SEC-021 | Malformed structured input | ◑ | `test_input_hardening` enforces effect shape; broader JSON/NaN/dup-key hardening ✗ |
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

| # | Item | Status |
|---|------|:------:|
| 1 | Authorized protected write with exact-effect binding | ✓ |
| 2 | Unauthorized direct write denied (OS-enforced) | ✓ |
| 3 | Duplicate & concurrent redemption cannot duplicate effects | ✓ |
| 4 | DB restoration cannot revive consumed grants | ✓ |
| 5 | Revoked or modified grants fail under ordering contract | ✓ |
| 6 | Crash / lost-ack outcomes reconcile correctly | ✓ (real SIGKILL at before/mid/after-commit + restart) |
| 7 | Chronicle / policy failures do not silently permit effects | ✓ |
| 8 | Independent observer distinguishes real effects from fabricated records | ✓ |
| 9 | Mandatory verification deps execute or report BLOCKED_DEPENDENCY | ✓ |
| 10 | Separate operator reproduces frozen tests | ◑ (tests are reproducible; an actual independent-operator run has not happened) |

**9 of 10 done, 1 partial.** The only remaining partial is #10, which is not a
code property but a process step: another person running the frozen suite on a
clean checkout. Everything else is enforced by a test in this repo.

## Corrections to earlier summaries

Prior chat summaries overstated a few things; corrected here and in the threat model:

- A chat summary said "7 of 10 solid" — the checklist showed 8 done + 2 partial at
  that point. It is now **9 done + 1 partial** after crash recovery landed.
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
- Broader input hardening: raw-JSON duplicate keys, NaN/Infinity (SEC-021 full).
- Unauthorized outcome-query protection (SEC-023) — no query API yet.
- Formal-proof adapter execution (T13) — the preflight exists; a real Lean/SMT
  check does not yet run.
- An actual independent-operator reproduction run (DoD #10).
