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
5. **Replay is refused, even across a snapshot restore of the resource DB.** The
   freshness authority remembers the grant was spent, independently of the
   resource store. → `test_spent_grant_stays_spent_after_resource_rollback`
6. **Honest retries are idempotent.** Exactly-once application under retry.
   → `test_retry_of_same_grant_is_idempotent`
7. **A receipt is never proof on its own.** The witness reads reality directly;
   drift between receipt and reality, or a fabricated receipt, is caught.
   → `test_witness_catches_drift_between_receipt_and_reality`,
   `test_fabricated_receipt_fails_signature_check`
8. **Crashes leave no partial effect; lost acks don't double-apply.** Verified
   with real process termination (SIGKILL) at explicit boundaries and a restart.
   → `test_crash_recovery` (before / mid / after-commit + concurrent-retry)
9. **No client-controlled path exists to substitute.** The effect surface is
   validated and admits no path/descriptor field. → `test_input_hardening`

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

## The freshness invariant, stated precisely

> A consumed grant remains consumed across the supported recovery scenarios.

This holds **only because the freshness store has durability independent of the
resource store.** If both are rolled back together, authority is resurrected —
which is not a bug in the code but a violation of the invariant's precondition.
We prove this both ways:

- Independent freshness → replay refused (`test_spent_grant_stays_spent_...`).
- Freshness rolled back too → replay succeeds
  (`test_counterexample_rolling_back_freshness_too_resurrects_authority`).

In production the freshness authority is a separate service, a replicated log, or
a hardware monotonic counter / TPM — something whose state does not travel with a
resource-DB snapshot.

## What is deferred (honest limitations)

This is an **in-process reference implementation**. It models the trust
boundaries at the API surface and with separate keys and separate stores. It does
**not yet** enforce them at the operating-system level. Specifically:

- **Process / UID isolation.** In production the resource owner runs under its
  own OS identity with the resource DB owned `0600`, reachable only through an
  authenticated IPC surface, so that no other process — including a compromised
  intelligence domain — can open the file directly. Here, Python objects share a
  process; a caller with the interpreter could reach a private attribute. The
  negative tests assert the *designed* boundary (no public ungated mutator); the
  *enforced* boundary is production work. This is roadmap item 1.
- **Key custody.** Keys are generated in-memory for the demo. Production keys
  live in an HSM / KMS / the platform keystore, per domain.
- **Clock trust.** Expiry uses local wall-clock time. A hardened deployment needs
  a trusted time source.
- **Availability / DoS.** Out of scope for this slice by design.
- **Side channels, supply chain, and host compromise.** Out of scope here.

The point of the slice is to make the **authority and evidence boundaries**
real, testable, and regression-guarded first. The OS-level hardening attaches to
exactly these same seams without changing the contracts.
