"""Evidence Vault v2: local SHA-256 objects and a linked review ledger.

The ledger requires an independently retained head hash to detect a full rewrite.
Reviewer names are declarations, not authenticated identities.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .gates import ALLOWED_KINDS, HEX256, PROVENANCE, RULE_ID, _single_line, sha256_text

GENESIS = "0" * 64


class VaultError(ValueError):
    """A fail-closed vault policy or integrity error."""


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise VaultError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(VaultError(f"invalid number {value}")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VaultError(f"cannot read {path}: {exc}") from exc


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha(value: Any) -> bool:
    return isinstance(value, str) and HEX256.fullmatch(value) is not None


def _fields(obj: dict[str, Any], expected: set[str], at: str, errors: list[str]) -> None:
    extra = set(obj) - expected
    if extra:
        errors.append(f"{at}: unexpected fields: {', '.join(sorted(extra))}")


def validate_candidate(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["candidate must be an object"]
    _fields(doc, {"schema_version", "feature", "authorization", "snapshot_sha256", "rules"}, "candidate", errors)
    if type(doc.get("schema_version")) is not int or doc["schema_version"] != 2:
        errors.append("schema_version must be integer 2")
    feature = doc.get("feature")
    if not _single_line(feature) or len(feature) > 160:
        errors.append("feature must be single-line text of 1-160 characters")
    if not _sha(doc.get("snapshot_sha256")):
        errors.append("snapshot_sha256 must be lowercase SHA-256")
    authorization = doc.get("authorization")
    if not isinstance(authorization, dict):
        errors.append("authorization must be an object")
    else:
        _fields(authorization, {"scope", "basis", "approved_by"}, "authorization", errors)
        for field in ("scope", "basis", "approved_by"):
            if not _single_line(authorization.get(field)):
                errors.append(f"authorization.{field} required")
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("rules must be a nonempty array")
        return errors
    rule_ids: set[str] = set()
    evidence_ids: set[str] = set()
    for i, rule in enumerate(rules):
        at = f"rules[{i}]"
        if not isinstance(rule, dict):
            errors.append(f"{at} must be an object")
            continue
        _fields(rule, {"id", "behavior", "evidence"}, at, errors)
        rid = rule.get("id")
        if not isinstance(rid, str) or RULE_ID.fullmatch(rid) is None or rid in rule_ids:
            errors.append(f"{at}.id invalid or duplicate")
        else:
            rule_ids.add(rid)
        behavior = rule.get("behavior")
        if not _single_line(behavior) or len(behavior) > 2000 or chr(96) * 3 in behavior:
            errors.append(f"{at}.behavior must be single-line text without code fences, max 2000 chars")
        evidence = rule.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append(f"{at}.evidence must be nonempty")
            continue
        for j, item in enumerate(evidence):
            at_e = f"{at}.evidence[{j}]"
            if not isinstance(item, dict):
                errors.append(f"{at_e} must be an object")
                continue
            _fields(item, {"id", "kind", "provenance", "summary", "artifact_sha256"}, at_e, errors)
            eid = item.get("id")
            if not isinstance(eid, str) or RULE_ID.fullmatch(eid) is None or eid in evidence_ids:
                errors.append(f"{at_e}.id invalid or duplicate")
            else:
                evidence_ids.add(eid)
            if not isinstance(item.get("kind"), str) or item["kind"] not in ALLOWED_KINDS:
                errors.append(f"{at_e}.kind invalid")
            if not isinstance(item.get("provenance"), str) or item["provenance"] not in PROVENANCE:
                errors.append(f"{at_e}.provenance invalid")
            if not _single_line(item.get("summary")):
                errors.append(f"{at_e}.summary required and single-line")
            if not _sha(item.get("artifact_sha256")):
                errors.append(f"{at_e}.artifact_sha256 invalid")
    return errors


def _valid(doc: Any) -> None:
    problems = validate_candidate(doc)
    if problems:
        raise VaultError("; ".join(problems))


def init_vault(root: Path) -> None:
    if root.exists() or root.is_symlink():
        raise VaultError("vault already exists")
    root.mkdir(parents=True)
    (root / "objects").mkdir()
    (root / "stages").mkdir()
    (root / "events.jsonl").open("x").close()


def _check_root(root: Path) -> None:
    for part in ("objects", "stages"):
        path = root / part
        if not path.is_dir() or path.is_symlink():
            raise VaultError(f"missing/unsafe vault {part}")
    log = root / "events.jsonl"
    if not log.is_file() or log.is_symlink():
        raise VaultError("missing/unsafe vault events.jsonl")


@contextmanager
def vault_lock(root: Path) -> Iterator[None]:
    _check_root(root)
    lock = root / ".lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise VaultError("vault locked: inspect stale locks manually") from exc
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(f"pid={os.getpid()}\n")
        yield
    finally:
        lock.unlink(missing_ok=True)


def _artifact(root: Path, sha: str, kind: str = "objects") -> Path:
    if not _sha(sha) or kind not in ("objects", "stages"):
        raise VaultError("invalid object reference")
    return root / kind / (sha if kind == "objects" else sha + ".json")


def _verify_file(path: Path, sha: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise VaultError(f"artifact missing or unsafe: {path}")
    if file_hash(path) != sha:
        raise VaultError(f"artifact digest mismatch: {path.name}")


def _read_events(root: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    previous = GENESIS
    try:
        with (root / "events.jsonl").open(encoding="utf-8") as file:
            for n, line in enumerate(file, 1):
                if not line.endswith("\n"):
                    raise VaultError(f"truncated event {n}")
                try:
                    event = json.loads(line, object_pairs_hook=_pairs)
                except json.JSONDecodeError as exc:
                    raise VaultError(f"bad event {n}: {exc}") from exc
                if not isinstance(event, dict) or set(event) != {"seq", "at", "type", "data", "prev", "event_hash"}:
                    raise VaultError(f"bad event fields at {n}")
                if type(event["seq"]) is not int or event["seq"] != n:
                    raise VaultError(f"event {n} sequence error")
                if not isinstance(event["type"], str) or event["type"] not in ("INGEST", "STAGE", "REVIEW"):
                    raise VaultError(f"event {n} type error")
                if not isinstance(event["data"], dict) or not _single_line(event["at"]):
                    raise VaultError(f"event {n} metadata error")
                if event["prev"] != previous:
                    raise VaultError(f"event {n} broken chain")
                expected = hashlib.sha256(canonical({k: v for k, v in event.items() if k != "event_hash"})).hexdigest()
                if event["event_hash"] != expected:
                    raise VaultError(f"event {n} hash mismatch")
                previous = expected
                events.append(event)
    except OSError as exc:
        raise VaultError(f"cannot read ledger: {exc}") from exc
    return events


def verify_history(root: Path) -> list[dict[str, Any]]:
    _check_root(root)
    events = _read_events(root)
    ingested: set[str] = set()
    stages: dict[str, dict[str, Any]] = {}
    for event in events:
        kind, data = event["type"], event["data"]
        if kind == "INGEST":
            if set(data) != {"sha256"}:
                raise VaultError("invalid INGEST fields")
            sha = data["sha256"]
            _verify_file(_artifact(root, sha), sha)
            ingested.add(sha)
        elif kind == "STAGE":
            if set(data) != {"sha256"}:
                raise VaultError("invalid STAGE fields")
            sha = data["sha256"]
            path = _artifact(root, sha, "stages")
            _verify_file(path, sha)
            candidate = load_json(path)
            _valid(candidate)
            needed = {candidate["snapshot_sha256"]}
            needed.update(item["artifact_sha256"] for rule in candidate["rules"] for item in rule["evidence"])
            if not needed.issubset(ingested):
                raise VaultError("stage contains non-ingested artifact/snapshot")
            stages[sha] = candidate
        else:
            if set(data) != {"stage_sha256", "rule_id", "decision", "reviewer", "note"}:
                raise VaultError("invalid REVIEW fields")
            candidate = stages.get(data["stage_sha256"])
            if candidate is None or data["rule_id"] not in {r["id"] for r in candidate["rules"]}:
                raise VaultError("REVIEW refers to unknown stage/rule")
            if data["decision"] not in ("approve", "return", "reject"):
                raise VaultError("invalid REVIEW decision")
            matched = next(rule for rule in candidate["rules"] if rule["id"] == data["rule_id"])
            if data["decision"] == "approve" and any(item["provenance"] != "VERIFIED" for item in matched["evidence"]):
                raise VaultError("ledger includes invalid approval of non-VERIFIED evidence")
            if not _single_line(data["reviewer"]) or not isinstance(data["note"], str):
                raise VaultError("invalid REVIEW metadata")
    return events


def _append(root: Path, history: list[dict[str, Any]], kind: str, data: dict[str, Any]) -> str:
    event = {
        "seq": len(history) + 1,
        "at": datetime.now(timezone.utc).isoformat(),
        "type": kind, "data": data,
        "prev": history[-1]["event_hash"] if history else GENESIS,
    }
    event["event_hash"] = hashlib.sha256(canonical(event)).hexdigest()
    with (root / "events.jsonl").open("a", encoding="utf-8", newline="\n") as file:
        file.write(canonical(event).decode("utf-8") + "\n")
        file.flush()
        os.fsync(file.fileno())
    return event["event_hash"]


def ingest(root: Path, source: Path) -> str:
    with vault_lock(root):
        history = verify_history(root)
        if not source.is_file():
            raise VaultError("evidence path is not a file")
        temp: str | None = None
        try:
            hasher = hashlib.sha256()
            with tempfile.NamedTemporaryFile(dir=root / "objects", prefix=".tmp-", delete=False) as file:
                temp = file.name
                with source.open("rb") as incoming:
                    for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
                        hasher.update(chunk)
                        file.write(chunk)
                file.flush()
                os.fsync(file.fileno())
            sha = hasher.hexdigest()
            path = _artifact(root, sha)
            known = {e["data"]["sha256"] for e in history if e["type"] == "INGEST"}
            if sha in known:
                _verify_file(path, sha)
            else:
                if path.exists():
                    raise VaultError("orphan object exists; refusing ambiguous ingest")
                os.link(temp, path)
                _append(root, history, "INGEST", {"sha256": sha})
            return sha
        except OSError as exc:
            raise VaultError(f"ingest I/O error: {exc}") from exc
        finally:
            if temp:
                Path(temp).unlink(missing_ok=True)


def stage(root: Path, doc: dict[str, Any]) -> str:
    _valid(doc)
    raw = canonical(doc)
    sha = hashlib.sha256(raw).hexdigest()
    with vault_lock(root):
        history = verify_history(root)
        ingested = {e["data"]["sha256"] for e in history if e["type"] == "INGEST"}
        required = {doc["snapshot_sha256"]}
        required.update(e["artifact_sha256"] for rule in doc["rules"] for e in rule["evidence"])
        for item_sha in required:
            if item_sha not in ingested:
                raise VaultError(f"non-ingested artifact/snapshot: {item_sha}")
            _verify_file(_artifact(root, item_sha), item_sha)
        prior = {e["data"]["sha256"] for e in history if e["type"] == "STAGE"}
        path = _artifact(root, sha, "stages")
        if sha not in prior:
            if path.exists():
                raise VaultError("orphan stage exists")
            with path.open("xb") as file:
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            _append(root, history, "STAGE", {"sha256": sha})
        return sha


def _load_stage(root: Path, sha: str, history: list[dict[str, Any]]) -> dict[str, Any]:
    if sha not in {e["data"]["sha256"] for e in history if e["type"] == "STAGE"}:
        raise VaultError("stage does not exist in verified history")
    path = _artifact(root, sha, "stages")
    _verify_file(path, sha)
    doc = load_json(path)
    _valid(doc)
    return doc


def _decisions(history: list[dict[str, Any]], sha: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for event in history:
        if event["type"] == "REVIEW" and event["data"]["stage_sha256"] == sha:
            result[event["data"]["rule_id"]] = event["data"]["decision"]
    return result


def review(root: Path, sha: str, rule_id: str, decision: str, reviewer: str, note: str) -> str:
    if decision not in ("approve", "return", "reject") or not _single_line(reviewer):
        raise VaultError("invalid review decision or reviewer")
    if not isinstance(note, str) or (decision != "approve" and not note.strip()):
        raise VaultError("return/reject requires a reason")
    with vault_lock(root):
        history = verify_history(root)
        candidate = _load_stage(root, sha, history)
        rule = next((rule for rule in candidate["rules"] if rule["id"] == rule_id), None)
        if rule is None:
            raise VaultError("unknown rule")
        if decision == "approve" and any(item["provenance"] != "VERIFIED" for item in rule["evidence"]):
            raise VaultError("cannot approve non-VERIFIED evidence")
        return _append(root, history, "REVIEW", {
            "stage_sha256": sha, "rule_id": rule_id,
            "decision": decision, "reviewer": reviewer, "note": note,
        })


def status(root: Path, sha: str) -> tuple[dict[str, Any], dict[str, str], str]:
    with vault_lock(root):
        history = verify_history(root)
        return (_load_stage(root, sha, history), _decisions(history, sha),
                history[-1]["event_hash"] if history else GENESIS)


def render_spec(doc: dict[str, Any]) -> str:
    _valid(doc)
    lines = [
        "# APPROVED BEHAVIORAL SPECIFICATION", "",
        f"Feature: {doc['feature']}", "",
        "Implement these observable behaviors independently.",
        "Do not access investigator records or original source material.", "",
    ]
    for rule in doc["rules"]:
        lines.extend((f"## {rule['id']}", "", rule["behavior"], ""))
    return "\n".join(lines)


def export_packet(root: Path, sha: str, destination: Path, receipt: Path | None = None) -> str:
    with vault_lock(root):
        history = verify_history(root)
        doc = _load_stage(root, sha, history)
        decisions = _decisions(history, sha)
        if any(decisions.get(rule["id"]) != "approve" for rule in doc["rules"]):
            raise VaultError("all staged rules require current explicit approval")
        if any(e["provenance"] != "VERIFIED" for r in doc["rules"] for e in r["evidence"]):
            raise VaultError("non-VERIFIED evidence cannot be exported")
        hashes = {doc["snapshot_sha256"]}
        hashes.update(e["artifact_sha256"] for r in doc["rules"] for e in r["evidence"])
        for evidence_sha in hashes:
            _verify_file(_artifact(root, evidence_sha), evidence_sha)
        if destination.resolve() == root.resolve() or root.resolve() in destination.resolve().parents:
            raise VaultError("builder packet cannot be inside vault")
        if destination.resolve() in root.resolve().parents:
            raise VaultError("builder packet cannot contain vault")
        if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
            raise VaultError("builder packet directory must be absent or empty")
        if receipt is not None:
            if receipt.resolve() == destination.resolve() or destination.resolve() in receipt.resolve().parents:
                raise VaultError("receipt must be outside builder packet")
            if receipt.exists():
                raise VaultError("receipt exists; never overwrite audit receipts")
        spec = render_spec(doc)
        try:
            destination.mkdir(parents=True, exist_ok=True)
            with (destination / "SPEC.md").open("x", encoding="utf-8", newline="\n") as out:
                out.write(spec)
            if receipt is not None:
                receipt.parent.mkdir(parents=True, exist_ok=True)
                audit = {
                    "schema_version": 2, "stage_sha256": sha,
                    "snapshot_sha256": doc["snapshot_sha256"],
                    "spec_sha256": sha256_text(spec),
                    "ledger_head": history[-1]["event_hash"] if history else GENESIS,
                    "rule_decisions": decisions,
                    "note": "Locally verified hashes; reviewer identity is self-declared. Externally anchor the ledger head.",
                }
                with receipt.open("x", encoding="utf-8", newline="\n") as out:
                    json.dump(audit, out, sort_keys=True, indent=2)
                    out.write("\n")
        except OSError as exc:
            raise VaultError(f"packet I/O error: {exc}") from exc
        return sha256_text(spec)
