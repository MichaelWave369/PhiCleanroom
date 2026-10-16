"""Run or plan the strictly bounded, human-approved Docker isolation probe."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import sandbox, vault


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phicleanroom sandbox")
    sub = parser.add_subparsers(dest="command", required=True)
    probe = sub.add_parser("probe", help="Validate stage and optionally run a no-network container probe")
    probe.add_argument("--vault", type=Path, required=True, help="Investigator-side Evidence Vault v2 directory")
    probe.add_argument("--stage", required=True, help="Frozen, reviewed stage SHA-256")
    probe.add_argument("--image", required=True, help="Locally pinned Docker image ID: sha256:<64 hex>")
    probe.add_argument("--receipt", type=Path, help="New receipt path, outside the Vault")
    probe.add_argument("--execute", action="store_true", help="Actually run the Docker probe; default only plans")
    probe.add_argument("--acknowledge-docker-risk", action="store_true",
                       help="Acknowledge Docker-daemon host privileges and trusted-image requirement")
    probe.add_argument("--timeout", type=int, default=60, help="Probe timeout in seconds, 5-120")
    opts = parser.parse_args(argv)
    try:
        result = sandbox.probe(
            opts.vault, opts.stage, opts.image, opts.receipt,
            execute=opts.execute, acknowledge_docker_risk=opts.acknowledge_docker_risk,
            timeout=opts.timeout,
        )
    except (sandbox.SandboxError, vault.VaultError, OSError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    if not opts.execute:
        print("PLAN ONLY: no Docker process started. Use --execute --acknowledge-docker-risk.", file=sys.stderr)
    else:
        print("PROBE PASS: not a security attestation or a release approval.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
