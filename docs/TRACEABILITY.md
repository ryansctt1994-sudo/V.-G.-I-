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
| SEC-003 | Path / symlink substitution | ◑ | same — by design: the request carries no client path to substitute |
| SEC-004 | Inherited privileged descriptor | ✓ | same (sec004_leaked_fds == []) |
| SEC-005 | Valid grant submitted twice | ✓ | `test_protected_transaction::...idempotent` + IPC retry |
| SEC-006 | Concurrent redemption → one effect | ✓ | `test_concurrency::...applies_once` |
| SEC-007 | Restore pre-consumption snapshot | ✓ | `test_negative::...stays_spent_after_resource_rollback` |
| SEC-008 | Revoke before redemption | ✓ | `test_revocation::...revoke_before_redeem_is_refused` |
| SEC-009 | Modify payload after signing | ✓ | `test_negative::...tampered_grant_body_is_denied` |
| SEC-010 | Substitute authorized resource path | ◑ | `test_os_isolation` (no client path) + effect-binding tests |
| SEC-011 | Forge ALLOW without a grant | ✓ | `test_negative::...request_without_grant`, `...forged_grant` |
| SEC-012 | Policy service unavailable | ✓ | `test_failclosed::...policy_unavailable_blocks_grant_issuance` |
| SEC-013 | Chronicle write fails | ✓ | `test_failclosed::...chronicle_write_failure_rolls_back_effect` |
| SEC-014 | Crash after effect, before ack | ◑ | idempotent-retry path (`test_protected_transaction`, IPC retry); real crash injection ✗ |
| SEC-015 | Alter a receipt, recompute hash | ◑ | `test_negative::...drift...` (observation); hash-linked ledger (EVD-02) ✗ |
| SEC-016 | Forge matching receipt + observation | ◑ | `test_negative::...fabricated_receipt...` (signature); common-control independence ✗ |
| SEC-017 | Verification command does not verify | ✓ | `test_verification::...non_verifying_command_is_not_verified` |
| SEC-018 | Mandatory dependency missing | ✓ | `test_verification::...missing_mandatory_dependency_blocks` |
| SEC-019 | Unauthorized policy amendment | ✗ | governance registry (GOV) not yet built |
| SEC-020 | Tool delegates stronger capability | ✗ | capability attenuator (PRIV-01) not yet built |
| SEC-021 | Malformed JSON / dup keys / NaN | ✗ | schema validator hardening not yet built |
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
| EVID-01 | Evidence independently recomputed & authenticated | ◑ | witness reconcile; hash-linked ledger ✗ |
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
| 6 | Crash / lost-ack outcomes reconcile correctly | ◑ (idempotent retry; real crash injection pending) |
| 7 | Chronicle / policy failures do not silently permit effects | ✓ |
| 8 | Independent observer distinguishes real effects from fabricated records | ✓ |
| 9 | Mandatory verification deps execute or report BLOCKED_DEPENDENCY | ✓ |
| 10 | Separate operator reproduces frozen tests | ◑ (tests are reproducible; independent-operator run pending) |

## Not yet built (named so it is not mistaken for done)

- Hash-linked evidence ledger (EVD-02) and ledger-tamper tests (SEC-015 full).
- Observation independence under common control (SEC-016 full, OBS-02 wiring).
- Governance registry + amendment control (GOV-01..03, SEC-019).
- Capability attenuator (PRIV-01, SEC-020).
- Input-hardening surface for malformed structured input (SEC-021).
- Real crash/fault injection harness (SEC-014 beyond idempotency).
- Formal-proof adapter execution (T13) — the preflight exists; a real Lean/SMT
  check does not yet run.
