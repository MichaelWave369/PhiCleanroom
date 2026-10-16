"""Human-governed provider-neutral role CLI: not an autonomous agent runner."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import agents, vault


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phicleanroom agents")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("providers", help="List implemented role adapters (no network needed)")
    inspect = sub.add_parser("investigate", help="Convert curated observations into an unverified v2 candidate")
    inspect.add_argument("--input", required=True, type=Path, help="Curated, authorized observation bundle JSON")
    inspect.add_argument("--out", required=True, type=Path, help="New candidate JSON, outside the builder packet")
    inspect.add_argument("--adapter", default="structured-offline-v1")
    judge = sub.add_parser("judge", help="Return nonauthoritative review advice for a v2 candidate")
    judge.add_argument("--input", required=True, type=Path)
    judge.add_argument("--vault", type=Path, help="Optional local vault; verify digests before advising")
    judge.add_argument("--out", required=True, type=Path, help="New advisory JSON outside builder packet")
    judge.add_argument("--adapter", default="rules-offline-v1")
    opts = parser.parse_args(argv)
    try:
        if opts.command == "providers":
            print(json.dumps(agents.providers(), sort_keys=True, indent=2))
            return 0
        # Output must not overwrite the input, the vault, or an existing artifact.
        if opts.out.exists() or opts.out.is_symlink():
            raise agents.AgentContractError("output must not exist")
        if opts.command == "investigate":
            candidate = agents.investigator_provider(opts.adapter).propose(vault.load_json(opts.input))
            if opts.out.resolve() == opts.input.resolve():
                raise agents.AgentContractError("output cannot overwrite input")
            agents.save_new_json(opts.out, candidate)
            print("CANDIDATE CREATED: " + str(opts.out))
            print("STATUS: OBSERVED only. No human verification, stage approval or builder packet.")
        elif opts.command == "judge":
            candidate = vault.load_json(opts.input)
            # Make the strict schema an enforced boundary even for model adapters.
            problems = vault.validate_candidate(candidate)
            if problems:
                raise agents.AgentContractError("invalid v2 candidate: " + "; ".join(problems[:5]))
            if opts.vault is not None:
                if opts.out.resolve() == opts.vault.resolve() or opts.vault.resolve() in opts.out.resolve().parents:
                    raise agents.AgentContractError("advisory output may not be stored in the evidence vault")
                inventory = agents.verify_inventory(opts.vault, candidate)
            else:
                inventory = None
            report = agents.judge_provider(opts.adapter).assess(candidate, inventory)
            # A judge is a classifier; never allow provider output with 'approve' semantics.
            if not isinstance(report, dict) or report.get("authority") != "NONE" or report.get("kind") != "ADVISORY_ONLY":
                raise agents.AgentContractError("judge output must be explicitly nonauthoritative")
            if report.get("decision") not in ("NEEDS_HUMAN_REVIEW", "RETURN_FOR_EVIDENCE"):
                raise agents.AgentContractError("judge decision is not an allowed advisory state")
            rules = report.get("rules")
            if not isinstance(rules, list) or len(rules) != len(candidate["rules"]):
                raise agents.AgentContractError("judge output is missing per-rule decisions")
            for rule, decision in zip(candidate["rules"], rules):
                if not isinstance(decision, dict) or decision.get("rule_id") != rule["id"] or decision.get("decision") not in ("NEEDS_HUMAN_REVIEW", "RETURN_FOR_EVIDENCE"):
                    raise agents.AgentContractError("judge output contains an invalid rule decision")
            agents.save_new_json(opts.out, report)
            print("ADVISORY CREATED: " + str(opts.out))
            print("DECISION: " + report["decision"])
            print("AUTHORITY: NONE. Human review in the Vault is still required.")
        return 0
    except (agents.AgentContractError, vault.VaultError, OSError, TypeError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
