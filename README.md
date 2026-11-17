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
| **Replay resistance across snapshot restore** — a spent grant stays spent even if the resource DB is rolled back | `test_spent_grant_stays_spent_after_resource_rollback` |
| *(why that works)* — the counter-example when freshness is **not** independent | `test_counterexample_rolling_back_freshness_too_resurrects_authority` |
| **Receipt ≠ observation** — a signed receipt never substitutes for a direct read | `test_witness_catches_drift_between_receipt_and_reality`, `test_fabricated_receipt_fails_signature_check` |
| **Idempotent recovery** — honest retries apply exactly once | `test_retry_of_same_grant_is_idempotent` |

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
                            │  Freshness   │◀── consume ────────┤
                            │  Authority   │   (independent      │
                            │ (independent │    durability)      ▼
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
- The **freshness authority** and the **resource database** are separate stores
  with independent durability.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full design, the explicit
trust boundaries, and — importantly — what is proven here versus what is
deferred to production hardening.

## Layout

```
vgi/
  contracts/    versioned schemas, canonical encoding, effect identity
  intelligence/ untrusted proposer (where a model plugs in later)
  governance/   policy evaluation + grant issuance   (authorization domain)
  execution/    freshness authority, resource owner, broker (execution domain)
  evidence/     durable receipts + independent witness (assurance domain)
  crypto.py     Ed25519 signing primitives
  system.py     the one place that wires it all together
apps/cli/       the end-to-end demo
tests/          happy path + the negative regression suite
docs/           architecture and threat model
```

## Where this goes next

This slice is Phase 1 + Phase 2 of the plan, plus the start of Phase 3
(evidence). The roadmap from here, each step earning its complexity through
tests before the next is added:

1. **Harden the boundary** — move the resource owner to a separate OS identity
   with an authenticated IPC surface, so direct-write denial is enforced by the
   OS, not just the API. (See the threat model's "deferred" section.)
2. **Richer resources & effects** — beyond single config keys.
3. **Intelligence integration** — plug a model into the proposer through the
   unprivileged interface, without changing its authority.
4. **Memory & orchestration** — durable workflows, retrieval, context.
5. **Formal reasoning & discovery** — independently checked proofs, evaluation.

The rule throughout: the smallest set of capabilities that delivers the value,
and every security guarantee earns its place through execution and evidence.
