"""Anti-M: completion-contract review and opt-in local keyed attestation.

No automatic release or DONE state. A key proves possession, not identity.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import antim, sandbox, vault, verifier


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phicleanroom anti-m")
    sub = parser.add_subparsers(dest="command", required=True)
    for action in ("contract", "assess", "attest", "check-attestation"):
        cmd = sub.add_parser(action, help={
            "contract": "Freeze the currently eligible reference completion evidence",
            "assess": "Recheck an existing completion contract against current evidence",
            "attest": "Explicitly record a keyed human-held release-review attestation",
            "check-attestation": "Check MAC and refreshed evidence, without deploying",
        }[action])
        cmd.add_argument("--vault", type=Path, required=True)
        cmd.add_argument("--artifacts", type=Path, required=True)
        cmd.add_argument("--builder-receipt", type=Path, required=True)
        cmd.add_argument("--verifier-receipt", type=Path, required=True)
        if action == "contract":
            cmd.add_argument("--stage", required=True)
            cmd.add_argument("--out", required=True, type=Path)
        else:
            cmd.add_argument("--contract", required=True, type=Path)
        if action == "attest":
            cmd.add_argument("--key-file", required=True, type=Path)
            cmd.add_argument("--out", required=True, type=Path)
            cmd.add_argument("--signer", required=True)
            cmd.add_argument("--note", required=True)
            cmd.add_argument("--confirmation", required=True, help="Explicit full release-review confirmation phrase")
        if action == "check-attestation":
            cmd.add_argument("--key-file", required=True, type=Path)
            cmd.add_argument("--attestation", required=True, type=Path)
    opts = parser.parse_args(argv)
    try:
        root, files, built, checked = opts.vault, opts.artifacts, opts.builder_receipt, opts.verifier_receipt
        if opts.command == "contract":
            report = antim.create_contract(root, opts.stage, files, built, checked, opts.out)
        elif opts.command == "assess":
            report = antim.assess(root, files, built, checked, opts.contract)
        elif opts.command == "attest":
            report = antim.attest(
                root, files, built, checked, opts.contract, opts.key_file, opts.out,
                signer=opts.signer, note=opts.note, confirmation=opts.confirmation)
        else:
            report = antim.verify_attestation(
                root, files, built, checked, opts.contract, opts.key_file, opts.attestation)
    except (antim.CompletionError, vault.VaultError, sandbox.SandboxError,
            verifier.VerifyError, OSError, UnicodeError, ValueError, TypeError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    print("NO DEPLOYMENT, NO VERIFIED DONE STATE, NO AUTHENTICATED HUMAN IDENTITY.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
