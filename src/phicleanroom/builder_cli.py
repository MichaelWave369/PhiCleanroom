"""CLI: an approved SPEC into a bounded, unverified reference artifact."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import builder, vault, sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phicleanroom builder")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("reference", help="Plan or execute the isolated synthetic reference builder")
    command.add_argument("--vault", required=True, type=Path)
    command.add_argument("--stage", required=True)
    command.add_argument("--image", required=True, help="trusted locally pinned Docker image ID")
    command.add_argument("--out", type=Path, help="new quarantined artifact directory")
    command.add_argument("--receipt", type=Path, help="new receipt file, outside Vault and artifacts")
    command.add_argument("--execute", action="store_true")
    command.add_argument("--acknowledge-docker-risk", action="store_true")
    command.add_argument("--timeout", type=int, default=60)
    opts = parser.parse_args(argv)
    try:
        receipt = builder.run_builder(
            opts.vault, opts.stage, opts.image, opts.out, opts.receipt,
            execute=opts.execute, acknowledge_docker_risk=opts.acknowledge_docker_risk,
            timeout=opts.timeout)
    except (builder.BuilderError, sandbox.SandboxError, vault.VaultError, OSError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True))
    if opts.execute:
        print("QUARANTINED ONLY: code not tested, approved or released.", file=sys.stderr)
    else:
        print("PLAN ONLY: no builder started; no files generated.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
