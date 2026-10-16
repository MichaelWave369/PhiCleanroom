"""Pure, fail-closed checks for approved behavioral specifications.

These checks verify record structure and stated approvals, not the truth of an
observer's claims. Independent evidence validation remains a reviewer duty.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any


PROVENANCE = frozenset(
    {"OBSERVED", "VERIFIED", "INFERRED", "DREAMED", "SIMULATED", "UNKNOWN"}
)
ALLOWED_KINDS = frozenset({"observation", "test"})
HEX256 = re.compile(r"^[0-9a-f]{64}$")
RULE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
VERSION = 1


def _string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _single_line(value: Any) -> bool:
    return _string(value) and "\n" not in value and "\r" not in value


def _timestamp(value: Any) -> bool:
    if not _string(value):
        return False
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return when.tzinfo is not None and when.utcoffset() is not None


def _keys(value: dict, allowed: set[str], label: str, errors: list[str]) -> None:
    extra = set(value) - allowed
    if extra:
        errors.append(f"{label}: unexpected fields {', '.join(sorted(extra))}")


def validate_document(doc: Any) -> list[str]:
    """Return policy/shape errors. An empty list means eligible for export.

    Importantly, eligible means recorded evidence and approval *claims* meet
    the stated policy. It is not independent proof that either is truthful.
    """
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["document must be a JSON object"]
    _keys(doc, {"schema_version", "feature", "authorization", "rules"}, "document", errors)
    if type(doc.get("schema_version")) is not int or doc["schema_version"] != VERSION:
        errors.append("schema_version must be integer 1")
    if not _single_line(doc.get("feature")) or len(doc["feature"]) > 160:
        errors.append("feature must be single-line text of 1-160 characters")

    auth = doc.get("authorization")
    if not isinstance(auth, dict):
        errors.append("authorization must be an object")
    else:
        _keys(auth, {"scope", "basis", "approved_by"}, "authorization", errors)
        for key in ("scope", "basis", "approved_by"):
            if not _string(auth.get(key)):
                errors.append(f"authorization.{key} is required")
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("rules must be a nonempty array")
        return errors

    seen_rules: set[str] = set()
    seen_evidence: set[str] = set()
    for index, rule in enumerate(rules):
        loc = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{loc} must be an object")
            continue
        _keys(rule, {"id", "behavior", "evidence", "review"}, loc, errors)
        rule_id = rule.get("id")
        if not _string(rule_id) or RULE_ID.fullmatch(rule_id) is None:
            errors.append(f"{loc}.id must be a short identifier")
        elif rule_id in seen_rules:
            errors.append(f"{loc}.id duplicates {rule_id}")
        else:
            seen_rules.add(rule_id)
        behavior = rule.get("behavior")
        if not _single_line(behavior) or len(behavior) > 2000:
            errors.append(f"{loc}.behavior must be 1-2000 characters of single-line behavior")
        elif "```" in behavior:
            errors.append(f"{loc}.behavior cannot contain fenced code")
        evidence = rule.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append(f"{loc}.evidence needs at least one record")
        else:
            for j, record in enumerate(evidence):
                at = f"{loc}.evidence[{j}]"
                if not isinstance(record, dict):
                    errors.append(f"{at} must be an object")
                    continue
                _keys(
                    record,
                    {"id", "kind", "provenance", "summary", "reference", "artifact_sha256"},
                    at,
                    errors,
                )
                evidence_id = record.get("id")
                if not _string(evidence_id) or RULE_ID.fullmatch(evidence_id) is None:
                    errors.append(f"{at}.id must be a short identifier")
                elif evidence_id in seen_evidence:
                    errors.append(f"{at}.id duplicates {evidence_id}")
                else:
                    seen_evidence.add(evidence_id)
                kind = record.get("kind")
                if not isinstance(kind, str) or kind not in ALLOWED_KINDS:
                    errors.append(f"{at}.kind must be observation or test")
                provenance = record.get("provenance")
                if not isinstance(provenance, str) or provenance not in PROVENANCE:
                    errors.append(f"{at}.provenance is not a recognized NBG category")
                elif provenance != "VERIFIED":
                    errors.append(f"{at}.provenance {provenance} cannot clear the gate")
                if not _string(record.get("summary")):
                    errors.append(f"{at}.summary is required")
                if not _string(record.get("reference")):
                    errors.append(f"{at}.reference is required")
                digest = record.get("artifact_sha256")
                if not isinstance(digest, str) or HEX256.fullmatch(digest) is None:
                    errors.append(f"{at}.artifact_sha256 must be lowercase SHA-256 hex")
        review = rule.get("review")
        if not isinstance(review, dict):
            errors.append(f"{loc}.review must be an object")
        else:
            _keys(review, {"status", "reviewer", "reviewed_at"}, f"{loc}.review", errors)
            if review.get("status") != "approved":
                errors.append(f"{loc}.review is not explicitly approved")
            if not _string(review.get("reviewer")):
                errors.append(f"{loc}.reviewer is required")
            if not _timestamp(review.get("reviewed_at")):
                errors.append(f"{loc}.reviewed_at must have an ISO-8601 timezone")
    return errors


def approved_spec(doc: dict[str, Any]) -> str:
    """Return *behavior only*. Do not include artifacts, logs, or reviewer notes."""
    errors = validate_document(doc)
    if errors:
        raise ValueError("Cannot export unapproved spec: " + "; ".join(errors))
    lines = [
        "# APPROVED BEHAVIORAL SPECIFICATION",
        "",
        f"Feature: {doc['feature']}",
        "",
        "This document describes observable behavior only. Implement independently.",
        "Do not request or access the investigated original or investigator records.",
        "",
    ]
    for rule in doc["rules"]:
        lines.extend((f"## {rule['id']}", "", rule["behavior"], ""))
    return "\n".join(lines)


def sha256_text(contents: str) -> str:
    return hashlib.sha256(contents.encode("utf-8")).hexdigest()


def audit_receipt(doc: dict[str, Any], spec_text: str) -> dict[str, Any]:
    """A separate, non-tamper-proof record; never deliver it to the builder."""
    errors = validate_document(doc)
    if errors:
        raise ValueError("Cannot record unapproved spec: " + "; ".join(errors))
    return {
        "schema_version": VERSION,
        "feature": doc["feature"],
        "spec_sha256": sha256_text(spec_text),
        "rules": [
            {
                "rule_id": rule["id"],
                "review": rule["review"],
                "evidence": [
                    {"id": e["id"], "artifact_sha256": e["artifact_sha256"]}
                    for e in rule["evidence"]
                ],
            }
            for rule in doc["rules"]
        ],
        "note": "Attests to reviewed metadata only; hashes require independent artifact verification.",
    }
