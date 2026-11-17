# Threat Model

Being explicit about what is defended, against whom, and what is deferred is the
difference between a security claim and a slogan. This document states the
boundary this slice actually enforces — and, just as importantly, where it stops.

## Assets

- **The protected resource.** Here, a configuration key-value store. Its
  integrity (only authorized changes) and the auditability of changes to it.
- **The authority to change it.** Embodied in grants.
- **The evidence trail.** Receipts and observations that explain what happened.

## Principals

| Principal | Holds | Trusted to |
|---|---|---|
| Intelligence / applications | nothing privileged | propose only |
| Policy + grant authority | grant **private** key | decide and sign grants |
| Resource owner | receipt private key; authority **public** key | apply the exact granted effect |
| Freshness authority | its own store | spend each grant once |
| Witness / evidence | executor **public** key; independent read path | report reality |

## Adversary

The primary adversary is a **compromised or misaligned intelligence domain**: it
can craft arbitrary proposals, replay captured messages, and fabricate
plausible-looking artifacts. It does **not** hold any private key and cannot run
code inside the authorization, execution, or assurance domains.

A secondary concern is **operational recovery gone wrong**: a database snapshot
restored after a grant was spent, or drift/corruption of the resource behind the
owner's back.

### Outside the attacker model (what is NOT defended)

These are explicit so no result is read as more than it is:

- **A privileged host administrator / root / the kernel.** Anyone who can `setuid`
  to the owner's identity, read its `0600` files as root, `ptrace` it, or replace
  the kernel defeats the OS boundary. The isolation tests show a *less-privileged,
  different-uid* requester being denied — nothing more. In particular, the
  "root peer refused" result is an **application-level authorization check** in
  the IPC layer (an allow-list of requester uids); it is **not** evidence of
  protection against a host administrator, who would not need the socket at all.
- **A trusted time source.** Grant expiry uses local wall-clock time.
- **Availability / DoS, side channels, supply chain.** Out of scope for this slice.

## What is defended (and the test that shows it)

1. **No authority by default.** A proposal carries no power. The resource owner
   has no ungated write path; the sole entry point refuses to act without a
   valid grant. → `test_no_ungated_mutation_method_exists`,
   `test_request_without_grant_is_denied`
2. **Grants cannot be forged.** The resource owner verifies the grant signature
   against the authority's public key. An attacker's self-signed grant is
   refused. → `test_forged_grant_from_attacker_key_is_denied`
3. **Grants cannot be edited.** The grant is signed over its canonical bytes;
   altering the effect inside it breaks the signature and the identity binding.
   → `test_tampered_grant_body_is_denied`
4. **A grant authorizes one effect only.** Presenting a valid grant alongside a
   different effect is refused. → `test_grant_for_other_effect_cannot_authorize_this_one`
5. **Replay is refused, even across a snapshot restore of the resource DB —
   including after a crash between commit and coordination.** The coordination
   store (outside the resource's rollback boundary) records a reservation before
   the commit and the commitment after it. → `test_spent_grant_stays_spent_after_resource_rollback`,
   `test_crash_after_commit_then_snapshot_restore_does_not_replay`
6. **Honest retries are idempotent.** Exactly-once application under retry.
   → `test_retry_of_same_grant_is_idempotent`
7. **A receipt is never proof on its own.** The witness requires a valid
   signature, a receipt bound to *this* effect's identity with an `applied`
   outcome, and agreement with a direct read. → `test_witness_catches_drift_between_receipt_and_reality`,
   `test_fabricated_receipt_fails_signature_check`,
   `test_receipt_for_a_different_effect_is_not_trustworthy`
8. **Crashes leave no partial effect; lost acks don't double-apply; ambiguous
   crashes block.** Verified with real process termination (SIGKILL) at explicit
   boundaries and a restart. → `test_crash_recovery`
9. **No client-controlled path exists to substitute.** The effect surface is
   validated and admits no path/descriptor field. → `test_input_hardening`
10. **Revocation honors an explicit cutoff.** The revocation check and the
    reservation are one atomic transaction; a revocation that races the early
    checks is still honored, one after the cutoff is reported `too_late`.
    → `test_revocation`
11. **A malformed request from an allowed peer cannot stop the service.** Every
    per-connection failure is contained; stalled peers time out.
    → `test_ipc_robustness`

### Audited input inventory (basis for the path-substitution claim)

The claim "path/symlink substitution has no input to attack" rests on this
enumeration of every input the owner acts on, not on a general assertion:

| Input | Who controls it | Is it a path the owner opens? |
|-------|-----------------|-------------------------------|
| `effect` (resource, operation, key, value, precondition) | requester | no — logical names, validated shape |
| `grant_token` | authority (signed) | no |
| `request_id` | requester | no |
| resource DB / freshness DB paths | owner, fixed at construction | yes, but not client-supplied |
| socket path, keyfile path | owner/service, fixed | yes, but not client-supplied |
| file descriptors over IPC | — | none passed (no `SCM_RIGHTS`) |

If a future effect type introduces a client-influenced path, this table and the
validator must be revisited; the claim is scoped to the current surface.

### Concurrency guarantee is scoped to the transactional resource

"At most one effect under concurrency" (`test_concurrency`, `test_crash_recovery`)
is a property of the **local SQLite transactional resource**: the atomic
redemption record under `BEGIN IMMEDIATE` is the exactly-once authority. An
external, non-transactional effect is **not** covered by this and needs its own
recovery guarantee; the `UNKNOWN` outcome (EXE-06) is how the system refuses to
claim success it cannot confirm for such effects.

## The combined crash-and-rollback invariant, stated precisely

> A grant's effect is applied at most once, across crashes at any boundary and
> restoration of the resource store from any earlier snapshot — provided the
> coordination store is not itself rolled back.

### The protocol

The coordination store (`vgi/execution/freshness.py`) sits **outside** the
resource's rollback boundary. Under the resource write lock, the owner:

1. returns the stored receipt if a local redemption record exists;
2. **reserves** the grant in the coordination store (`PENDING`) — atomically with
   the revocation check; this is the authorization cutoff;
3. applies the effect and writes the redemption record in **one** resource
   transaction, and commits;
4. **marks** the grant `COMMITTED` in the coordination store.

`recover()` at startup marks `COMMITTED` every grant that has a local record
(repairing a crash between 3 and 4).

### How every retry is classified

| Coordination | Local record | Meaning | Result |
|---|---|---|---|
| none | none | never attempted | reserve and apply |
| any | present | committed here | stored receipt (idempotent) |
| `COMMITTED` | absent | resource rolled back after commit | refused |
| `PENDING` | absent | crashed before commit **or** committed then rolled back | **blocked — `UNKNOWN`** |

### Why the last row blocks instead of guessing

A write made only *after* the commit can be lost to a crash; a write made only
*before* it cannot prove the commit happened. With both stores intact, a
`PENDING` grant with no local record is genuinely ambiguous — and re-executing it
is exactly the defect found in review at `7c8a75a` (commit → crash before the
coordination write → restore the pre-commit snapshot → the grant applied again).
Moving the coordination write earlier alone would only move the gap.

So the system chooses **safety over liveness**: an ambiguous grant is never
re-executed automatically. The cost is real — an honest crash mid-transaction
(e.g. power loss) leaves that grant blocked, and recovery is an investigated,
human decision followed by a **new** grant. The service reports such attempts as
`UNKNOWN`, not `REFUSED`, because the system does not know what happened.

### The precondition, proven both ways

- Coordination store independent → replay refused
  (`test_spent_grant_stays_spent_after_resource_rollback`,
  `test_crash_after_commit_then_snapshot_restore_does_not_replay`).
- Coordination store rolled back together with the resource → the spent grant
  becomes spendable again
  (`test_counterexample_rolling_back_freshness_too_resurrects_authority`).

In production the coordination store is a separate service, a replicated log, or
a hardware monotonic counter / TPM — something whose state does not travel with a
resource-DB snapshot. This repo models it as a separate file; the independence of
its *durability* is an assumption the tests make explicit, not something a file
can enforce.

## What is deferred (honest limitations)

- **OS isolation is verified only where the tests can run as root.** The
  two-uid tests (`test_os_isolation`) skip without root and two non-root users;
  an independent review run without root therefore did **not** verify SEC-001..004.
  The in-process API boundary (no public ungated mutator) is tested everywhere.
- **Key custody.** Keys are generated in-memory for the demo. Production keys
  live in an HSM / KMS / the platform keystore, per domain.
- **Clock trust.** Expiry uses local wall-clock time. A hardened deployment needs
  a trusted time source.
- **Availability / DoS.** Out of scope for this slice by design.
- **Side channels, supply chain, and host compromise.** Out of scope here.

The point of the slice is to make the **authority and evidence boundaries**
real, testable, and regression-guarded first.
