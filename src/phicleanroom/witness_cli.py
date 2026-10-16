"""Offline witness CLI. No automatic DONE, signing, network or release."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import antim, sandbox, verifier, vault, witness


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phicleanroom witness")
    subs = parser.add_subparsers(dest="command", required=True)
    for action in ("checkpoint", "verify"):
        cmd = subs.add_parser(action, help={
            "checkpoint": "Freeze independently retainable evidence commitment (not yet anchored)",
            "verify": "Compare current evidence to checkpoint and REQUIRED independent expected hash",
        }[action])
        for option in ("vault", "artifacts", "builder-receipt", "verifier-receipt", "contract"):
            cmd.add_argument("--" + option, required=True, type=Path)
        if action == "checkpoint":
            cmd.add_argument("--out", required=True, type=Path,
                             help="create-only checkpoint JSON outside Vault and quarantine")
        else:
            cmd.add_argument("--checkpoint", required=True, type=Path)
            cmd.add_argument("--expected-checkpoint-sha256", required=True,
                             help="SHA-256 retained INDEPENDENTLY of this local checkpoint file")
    opts = parser.parse_args(argv)
    try:
        common = (opts.vault, opts.artifacts, opts.builder_receipt,
                  opts.verifier_receipt, opts.contract)
        if opts.command == "checkpoint":
            result = witness.checkpoint(*common, opts.out)
        else:
            result = witness.verify_checkpoint(*common, opts.checkpoint,
                                               opts.expected_checkpoint_sha256)
    except (witness.WitnessError, antim.CompletionError, sandbox.SandboxError,
            verifier.VerifyError, vault.VaultError, OSError, UnicodeError,
            TypeError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    print("NOT A SIGNATURE OR APPROVAL. No automatic DONE, deploy or public verification.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
