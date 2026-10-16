"""Command-line entrypoint for the first PhiCleanroom evidence gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .gates import approved_spec, audit_receipt, sha256_text, validate_document


def _outside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "vault":
        from .vault_cli import main as vault_main
        return vault_main(argv[1:])
    if argv and argv[0] == "agents":
        from .agents_cli import main as agents_main
        return agents_main(argv[1:])
    if argv and argv[0] == "sandbox":
        from .sandbox_cli import main as sandbox_main
        return sandbox_main(argv[1:])
    if argv and argv[0] == "builder":
        from .builder_cli import main as builder_main
        return builder_main(argv[1:])
    if argv and argv[0] == "verify":
        from .verifier_cli import main as verify_main
        return verify_main(argv[1:])
    parser = argparse.ArgumentParser(prog="phicleanroom")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Validate the reviewed evidence gate")
    check.add_argument("--input", required=True, type=Path)
    packet = sub.add_parser("packet", help="Export only SPEC.md to a new builder directory")
    packet.add_argument("--input", required=True, type=Path)
    packet.add_argument("--legacy-unverified", action="store_true", help="DANGEROUS: export from v1 metadata without verifying artifacts")
    packet.add_argument("--out", required=True, type=Path)
    packet.add_argument("--receipt", type=Path, help="Separate audit JSON, outside builder directory")
    args = parser.parse_args(argv)

    try:
        doc = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"INPUT ERROR: {exc}", file=sys.stderr)
        return 2
    errors = validate_document(doc)
    if errors:
        for error in errors:
            print(f"BLOCKED: {error}", file=sys.stderr)
        return 1
    if args.command == "check":
        print(f"ELIGIBLE: {len(doc['rules'])} explicitly approved rules (record claims, not independent proof)")
        return 0

    if not args.legacy_unverified:
        print("BLOCKED: v1 packet metadata is not verified. Use vault packet; or explicitly pass --legacy-unverified for demo compatibility.", file=sys.stderr)
        return 1
    directory = args.out.expanduser()
    receipt_path = args.receipt.expanduser() if args.receipt else None
    if not _outside(args.input, directory):
        print("BLOCKED: builder output directory may not contain the source JSON", file=sys.stderr)
        return 1
    if receipt_path is not None and not _outside(receipt_path, directory):
        print("BLOCKED: receipt must remain outside the builder directory", file=sys.stderr)
        return 1
    if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
        print("BLOCKED: builder directory must be absent or empty", file=sys.stderr)
        return 1
    if receipt_path is not None and receipt_path.exists():
        print("BLOCKED: receipt already exists; receipts are never overwritten", file=sys.stderr)
        return 1

    contents = approved_spec(doc)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        # x: do not clobber a concurrent file or silently rewrite an approval.
        with (directory / "SPEC.md").open("x", encoding="utf-8", newline="\n") as file:
            file.write(contents)
        if receipt_path is not None:
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            with receipt_path.open("x", encoding="utf-8", newline="\n") as file:
                json.dump(audit_receipt(doc, contents), file, indent=2, sort_keys=True)
                file.write("\n")
    except OSError as exc:
        print(f"WRITE ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"EXPORTED: {directory / 'SPEC.md'}")
    print(f"SPEC SHA-256: {sha256_text(contents)}")
    print("WARNING: packet-only export is not an isolated builder process.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
