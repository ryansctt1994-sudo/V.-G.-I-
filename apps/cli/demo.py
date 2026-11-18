"""End-to-end demo of one protected transaction.

Run from the repo root:

    python -m apps.cli.demo
"""

from __future__ import annotations

import tempfile

from vgi.system import build_system


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="vgi-demo-")
    sys = build_system(workdir)
    print(f"workdir: {workdir}\n")

    # 1. The untrusted intelligence proposes a change. No authority attached.
    proposal = sys.proposer.propose_config_change(
        "log.level", "debug", rationale="raise verbosity to debug a flaky job"
    )
    print(f"[intelligence] proposal {proposal.proposal_id}")
    print(f"               effect   {proposal.effect}")
    print(f"               effect id {proposal.effect_id[:16]}…\n")

    # 2-5. The broker drives governance -> execution -> evidence.
    result = sys.broker.run(proposal)

    g = result.grant.grant
    print(f"[governance]  grant {g['grant_id'][:24]}…")
    print(f"               bound to effect {g['effect_id'][:16]}… seq={g['freshness_seq']}")
    print(f"               signed by authority {result.grant.authority_key_id[:16]}…\n")

    r = result.receipt.receipt
    print(f"[execution]   receipt {r['receipt_id']} outcome={r['outcome']}")
    print(f"               {r['prior_value']!r} -> {r['new_value']!r}\n")

    rec = result.reconciliation
    o = rec.observation
    print(f"[evidence]    independent read of config[{proposal.effect['key']}] = {o.witnessed_value!r}")
    print(f"               receipt signature valid: {rec.receipt_signature_valid}")
    print(f"               receipt matches reality: {rec.receipt_matches_reality}")
    print(f"               freshness high-water:    {sys.freshness.high_water}\n")

    print(f"==> transaction verified: {result.verified}")
    sys.close()


if __name__ == "__main__":
    main()
