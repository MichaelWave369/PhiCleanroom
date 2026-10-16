"""Provider-neutral investigator and judge contracts.

Default adapters are OFFLINE deterministic implementations, not AI models.
Neither adapter can approve a rule, write a vault event, or release code.
The only handoff is a validated v2 behavioral candidate (no raw evidence).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from . import vault
from .gates import ALLOWED_KINDS, HEX256, RULE_ID, _single_line


class AgentContractError(ValueError):
    """Invalid role contract or insufficient evidence."""


@runtime_checkable
class InvestigatorAdapter(Protocol):
    adapter_id: str

    def propose(self, observations: dict[str, Any]) -> dict[str, Any]:
        """Return a v2 unapproved candidate, never copied source code."""


@runtime_checkable
class JudgeAdapter(Protocol):
    adapter_id: str

    def assess(self, candidate: dict[str, Any], inventory: dict[str, bool] | None) -> dict[str, Any]:
        """Return typed advice. No approval or release authority."""


def _fields(value: dict[str, Any], expected: set[str], at: str) -> None:
    unknown = set(value) - expected
    if unknown:
        raise AgentContractError(f"{at}: unexpected fields: {', '.join(sorted(unknown))}")


def _name(value: Any, at: str) -> None:
    if not isinstance(value, str) or RULE_ID.fullmatch(value) is None:
        raise AgentContractError(f"{at} must be a short stable identifier")


def _hash(value: Any, at: str) -> None:
    if not isinstance(value, str) or HEX256.fullmatch(value) is None:
        raise AgentContractError(f"{at} must be lowercase SHA-256 hex")


def _line(value: Any, at: str, maximum: int) -> None:
    if not _single_line(value) or len(value) > maximum:
        raise AgentContractError(f"{at} must be 1-{maximum} single-line characters")


def validate_observations(doc: Any) -> dict[str, Any]:
    """Validate curated observable behaviors without accepting source-code fields."""
    if not isinstance(doc, dict):
        raise AgentContractError("observation bundle must be an object")
    _fields(doc, {"schema_version", "feature", "authorization", "snapshot_sha256", "findings"}, "bundle")
    if type(doc.get("schema_version")) is not int or doc["schema_version"] != 1:
        raise AgentContractError("observation bundle requires schema_version 1")
    _line(doc.get("feature"), "feature", 160)
    _hash(doc.get("snapshot_sha256"), "snapshot_sha256")
    auth = doc.get("authorization")
    if not isinstance(auth, dict):
        raise AgentContractError("authorization declaration missing")
    _fields(auth, {"scope", "basis", "approved_by"}, "authorization")
    for field in ("scope", "basis", "approved_by"):
        _line(auth.get(field), f"authorization.{field}", 400)
    findings = doc.get("findings")
    if not isinstance(findings, list) or not 1 <= len(findings) <= 64:
        raise AgentContractError("findings must contain 1-64 entries")
    rule_ids: set[str] = set()
    evidence_ids: set[str] = set()
    count = 0
    for i, rule in enumerate(findings):
        at = f"findings[{i}]"
        if not isinstance(rule, dict):
            raise AgentContractError(f"{at} must be an object")
        _fields(rule, {"id", "behavior", "evidence"}, at)
        _name(rule.get("id"), at + ".id")
        if rule["id"] in rule_ids:
            raise AgentContractError("duplicate finding id")
        rule_ids.add(rule["id"])
        _line(rule.get("behavior"), at + ".behavior", 2000)
        if chr(96) * 3 in rule["behavior"]:
            raise AgentContractError("code fences cannot cross into behavioral requirements")
        evidence = rule.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise AgentContractError(f"{at}: evidence must be a nonempty array")
        count += len(evidence)
        if count > 256:
            raise AgentContractError("too many evidence records (max 256)")
        for j, item in enumerate(evidence):
            ref = f"{at}.evidence[{j}]"
            if not isinstance(item, dict):
                raise AgentContractError(f"{ref} must be an object")
            _fields(item, {"id", "kind", "summary", "artifact_sha256"}, ref)
            _name(item.get("id"), ref + ".id")
            if item["id"] in evidence_ids:
                raise AgentContractError("duplicate evidence id")
            evidence_ids.add(item["id"])
            if not isinstance(item.get("kind"), str) or item["kind"] not in ALLOWED_KINDS:
                raise AgentContractError(f"{ref}.kind must be observation or test")
            _line(item.get("summary"), ref + ".summary", 500)
            _hash(item.get("artifact_sha256"), ref + ".artifact_sha256")
    return doc


class StructuredObservationInvestigator:
    """Offline adapter that cannot promote any evidence to VERIFIED."""

    adapter_id = "structured-offline-v1"

    def propose(self, observations: dict[str, Any]) -> dict[str, Any]:
        input_data = validate_observations(observations)
        candidate = {
            "schema_version": 2,
            "feature": input_data["feature"],
            "authorization": dict(input_data["authorization"]),
            "snapshot_sha256": input_data["snapshot_sha256"],
            "rules": [
                {"id": r["id"], "behavior": r["behavior"], "evidence": [
                    {"id": e["id"], "kind": e["kind"], "provenance": "OBSERVED",
                     "summary": e["summary"], "artifact_sha256": e["artifact_sha256"]}
                    for e in r["evidence"]
                ]}
                for r in input_data["findings"]
            ],
        }
        problems = vault.validate_candidate(candidate)
        if problems:
            raise AgentContractError("candidate schema invalid: " + "; ".join(problems[:5]))
        return candidate


def verify_inventory(root: Path, candidate: dict[str, Any]) -> dict[str, bool]:
    """Verify vault byte integrity, passing only booleans to the judge.

    A tampered ingested file raises a hard error; a missing reference is False.
    Vault integrity does NOT prove a behavior or authenticate a reviewer.
    """
    problems = vault.validate_candidate(candidate)
    if problems:
        raise AgentContractError("invalid v2 candidate: " + "; ".join(problems[:5]))
    with vault.vault_lock(root):
        history = vault.verify_history(root)
        known = {event["data"]["sha256"] for event in history if event["type"] == "INGEST"}
        digests = {candidate["snapshot_sha256"]}
        digests.update(e["artifact_sha256"] for r in candidate["rules"] for e in r["evidence"])
        result = {}
        for digest in digests:
            if digest not in known:
                result[digest] = False
            else:
                vault._verify_file(vault._artifact(root, digest), digest)
                result[digest] = True
        return result


class DeterministicEvidenceJudge:
    """Structured return-or-human-review advice, never automatic approval."""

    adapter_id = "rules-offline-v1"

    def assess(self, candidate: dict[str, Any], inventory: dict[str, bool] | None) -> dict[str, Any]:
        errors = vault.validate_candidate(candidate)
        if errors:
            raise AgentContractError("invalid v2 candidate: " + "; ".join(errors[:5]))
        if inventory is not None and (
            not isinstance(inventory, dict) or
            any(not isinstance(k, str) or type(v) is not bool for k, v in inventory.items())
        ):
            raise AgentContractError("inventory must map digests to boolean results")
        snapshot_ok = inventory is not None and inventory.get(candidate["snapshot_sha256"]) is True
        decisions = []
        for rule in candidate["rules"]:
            reasons = []
            if not snapshot_ok:
                reasons.append("TARGET_SNAPSHOT_UNCHECKED")
            if inventory is None or any(inventory.get(e["artifact_sha256"]) is not True for e in rule["evidence"]):
                reasons.append("EVIDENCE_BYTES_UNCHECKED")
            if any(e["provenance"] != "VERIFIED" for e in rule["evidence"]):
                reasons.append("HUMAN_VERIFICATION_REQUIRED")
            decision = "RETURN_FOR_EVIDENCE" if reasons else "NEEDS_HUMAN_REVIEW"
            decisions.append({"rule_id": rule["id"], "decision": decision, "reasons": reasons})
        ready = all(row["decision"] == "NEEDS_HUMAN_REVIEW" for row in decisions)
        return {
            "schema_version": 1,
            "kind": "ADVISORY_ONLY",
            "adapter": self.adapter_id,
            "candidate_sha256": hashlib.sha256(vault.canonical(candidate)).hexdigest(),
            "decision": "NEEDS_HUMAN_REVIEW" if ready else "RETURN_FOR_EVIDENCE",
            "rules": decisions,
            "authority": "NONE",
            "note": "Not evidence truth, approval, a staged review, or release authorization.",
        }


ALLOWED_ADVICE = frozenset({"NEEDS_HUMAN_REVIEW", "RETURN_FOR_EVIDENCE"})
ALLOWED_REASONS = frozenset({
    "TARGET_SNAPSHOT_UNCHECKED", "EVIDENCE_BYTES_UNCHECKED", "HUMAN_VERIFICATION_REQUIRED"
})


def validate_judge_report(candidate: dict[str, Any], report: Any) -> dict[str, Any]:
    """Validate the exact typed output before any future model adapter is accepted."""
    if not isinstance(report, dict):
        raise AgentContractError("judge response must be JSON object")
    _fields(report, {"schema_version", "kind", "adapter", "candidate_sha256",
                     "decision", "rules", "authority", "note"}, "judge output")
    expected_sha = hashlib.sha256(vault.canonical(candidate)).hexdigest()
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise AgentContractError("judge report version is invalid")
    if report.get("kind") != "ADVISORY_ONLY" or report.get("authority") != "NONE":
        raise AgentContractError("judge must never claim approval or release authority")
    if report.get("candidate_sha256") != expected_sha:
        raise AgentContractError("judge report is not bound to this candidate")
    _line(report.get("adapter"), "judge.adapter", 100)
    _line(report.get("note"), "judge.note", 500)
    if report.get("decision") not in ALLOWED_ADVICE:
        raise AgentContractError("judge overall advice not allowed")
    rows = report.get("rules")
    if not isinstance(rows, list) or len(rows) != len(candidate["rules"]):
        raise AgentContractError("judge must advise on every candidate rule")
    for original, row in zip(candidate["rules"], rows):
        if not isinstance(row, dict):
            raise AgentContractError("judge rule advice must be objects")
        _fields(row, {"rule_id", "decision", "reasons"}, "judge rule")
        if row.get("rule_id") != original["id"] or row.get("decision") not in ALLOWED_ADVICE:
            raise AgentContractError("judge returned wrong rule or invalid decision")
        reasons = row.get("reasons")
        if not isinstance(reasons, list) or len(set(map(str, reasons))) != len(reasons) or any(
            not isinstance(reason, str) or reason not in ALLOWED_REASONS for reason in reasons
        ):
            raise AgentContractError("judge reasons must be unique allowed enums")
        if (row["decision"] == "NEEDS_HUMAN_REVIEW") != (len(reasons) == 0):
            raise AgentContractError("judge decision/reason contradiction")
    aggregate = ("NEEDS_HUMAN_REVIEW" if all(row["decision"] == "NEEDS_HUMAN_REVIEW" for row in rows)
                 else "RETURN_FOR_EVIDENCE")
    if report["decision"] != aggregate:
        raise AgentContractError("judge aggregate disagrees with rule decisions")
    return report


INVESTIGATORS = {StructuredObservationInvestigator.adapter_id: StructuredObservationInvestigator}
JUDGES = {DeterministicEvidenceJudge.adapter_id: DeterministicEvidenceJudge}


def investigator_provider(name: str) -> InvestigatorAdapter:
    try:
        return INVESTIGATORS[name]()
    except KeyError as exc:
        raise AgentContractError(f"unknown investigator adapter: {name}") from exc


def judge_provider(name: str) -> JudgeAdapter:
    try:
        return JUDGES[name]()
    except KeyError as exc:
        raise AgentContractError(f"unknown judge adapter: {name}") from exc


def providers() -> dict[str, Any]:
    return {
        "schema_version": 1, "external_models_connected": False,
        "investigators": [{"id": name, "mode": "offline", "autonomous": False} for name in INVESTIGATORS],
        "judges": [{"id": name, "mode": "offline", "can_approve": False} for name in JUDGES],
    }


def save_new_json(target: Path, data: Any) -> None:
    if target.is_symlink() or target.exists():
        raise AgentContractError("output exists or is a symlink: " + str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8", newline="\n") as out:
        json.dump(data, out, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        out.write("\n")
