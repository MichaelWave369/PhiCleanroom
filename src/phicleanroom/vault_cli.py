"""CLI commands for the PhiCleanroom evidence vault."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import vault


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phicleanroom vault")
    parser.add_argument("--vault", required=True, type=Path, help="Local investigator-only vault directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create a new private evidence vault")
    ingest = commands.add_parser("ingest", help="Hash and store a source snapshot or evidence artifact")
    ingest.add_argument("--file", required=True, type=Path)
    stage = commands.add_parser("stage", help="Freeze a schema v2 candidate and verify its artifacts")
    stage.add_argument("--input", required=True, type=Path)
    verify = commands.add_parser("verify", help="Verify objects, ledger, and optional independent head")
    verify.add_argument("--expected-head", help="SHA-256 ledger head saved independently")
    for name in ("preview", "status", "review", "packet"):
        command = commands.add_parser(name)
        command.add_argument("--stage", required=True, help="Immutable staged candidate SHA-256")
        if name == "review":
            command.add_argument("--rule", required=True)
            command.add_argument("--decision", choices=("approve", "return", "reject"), required=True)
            command.add_argument("--reviewer", required=True)
            command.add_argument("--note", default="")
        if name == "packet":
            command.add_argument("--out", required=True, type=Path)
            command.add_argument("--receipt", type=Path)
    opts = parser.parse_args(args)
    root = opts.vault.expanduser()
    try:
        if opts.command == "init":
            vault.init_vault(root)
            print(f"VAULT CREATED: {root}")
        elif opts.command == "ingest":
            print(f"INGESTED SHA-256: {vault.ingest(root, opts.file)}")
        elif opts.command == "stage":
            print(f"STAGED SHA-256: {vault.stage(root, vault.load_json(opts.input))}")
        elif opts.command == "verify":
            with vault.vault_lock(root):
                events = vault.verify_history(root)
                head = events[-1]["event_hash"] if events else vault.GENESIS
                if opts.expected_head is not None and opts.expected_head != head:
                    raise vault.VaultError("ledger head mismatches independently retained anchor")
                print(f"VERIFIED: {len(events)} ledger events")
                print(f"LEDGER HEAD: {head}")
        elif opts.command == "review":
            digest = vault.review(root, opts.stage, opts.rule, opts.decision, opts.reviewer, opts.note)
            print(f"REVIEW RECORDED: {digest}")
            print("WARNING: reviewer identity is self-declared, not authenticated.")
        elif opts.command in ("preview", "status"):
            candidate, decisions, head = vault.status(root, opts.stage)
            print(f"STAGE: {opts.stage}")
            print(f"FEATURE: {candidate['feature']}")
            print(f"TARGET SNAPSHOT: {candidate['snapshot_sha256']}")
            for rule in candidate["rules"]:
                print(f"\n{rule['id']}: {rule['behavior']}")
                print(f"  decision: {decisions.get(rule['id'], 'pending')}")
                if opts.command == "preview":
                    for artifact in rule["evidence"]:
                        print(f"  {artifact['id']} [{artifact['provenance']}]: {artifact['summary']}")
            print(f"\nLEDGER HEAD: {head}")
            print("REVIEW THE ACTUAL EVIDENCE before recording approval.")
        elif opts.command == "packet":
            digest = vault.export_packet(root, opts.stage, opts.out, opts.receipt)
            print(f"EXPORTED: {opts.out / 'SPEC.md'}")
            print(f"SPEC SHA-256: {digest}")
            print("WARNING: builder packet is not a sandbox; provision isolated access separately.")
        return 0
    except (vault.VaultError, OSError, TypeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
