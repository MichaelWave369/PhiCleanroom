"""Explicit, fail-closed independent reference verification command."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import verifier, vault, sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phicleanroom verify")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("reference", help="Validate pinned source, run separate trusted verifier")
    c.add_argument("--vault", required=True, type=Path)
    c.add_argument("--stage", required=True)
    c.add_argument("--artifacts", required=True, type=Path)
    c.add_argument("--builder-receipt", required=True, type=Path)
    c.add_argument("--image", required=True, help="trusted, local verifier image ID")
    c.add_argument("--receipt", type=Path, help="new independent verification receipt")
    c.add_argument("--execute", action="store_true", help="explicitly launch verifier Docker worker")
    c.add_argument("--acknowledge-docker-risk", action="store_true")
    c.add_argument("--timeout", type=int, default=70)
    args = parser.parse_args(argv)
    try:
        report = verifier.verify(
            args.vault, args.stage, args.artifacts, args.builder_receipt,
            args.image, args.receipt, execute=args.execute,
            acknowledge_docker_risk=args.acknowledge_docker_risk,
            timeout=args.timeout)
    except (verifier.VerifyError, vault.VaultError, sandbox.SandboxError,
            OSError, UnicodeError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.execute:
        print("REFERENCE CHECKS PASSED: not approval, DONE, or permission to ship.", file=sys.stderr)
    else:
        print("PLAN ONLY: no source code executed or Docker launched.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
