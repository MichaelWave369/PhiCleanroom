"""Anti-M v1: fail-closed evidence readiness and keyed local release attestation.

This module NEVER deploys, marks a project DONE, or authenticates a human's
identity. It can verify that a caller possessed a private local HMAC key when
attesting to a precisely frozen completion contract. HMAC is symmetric, not
a public-key signature or externally anchored audit system.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import sandbox, vault, verifier

CONTRACT_KIND = "ANTI_M_COMPLETION_CONTRACT_V1"
ATTESTATION_KIND = "ANTI_M_KEYED_ATTESTATION_V1"
CHECK_SUITE = "reference-exact-title-acceptance-v1"
MAX_JSON = 32 * 1024
MAX_SOURCE = 16 * 1024
APPROVAL = "I AUTHORIZE THIS EXACT CANDIDATE FOR RELEASE REVIEW"


class CompletionError(ValueError):
    """Anti-M found missing or contradictory evidence. No release allowed."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and sandbox.STAGE_SHA.fullmatch(value) is not None


def _safe_json(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_JSON:
        raise CompletionError("missing, symlinked, or oversized JSON input: " + str(path))
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates,
                           parse_constant=lambda name: (_ for _ in ()).throw(CompletionError("invalid JSON constant")))
    except (ValueError, UnicodeError) as exc:
        raise CompletionError("invalid input JSON: " + str(path)) from exc
    if not isinstance(value, dict):
        raise CompletionError("expected JSON object")
    return value, _sha(raw)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CompletionError("duplicate JSON key " + key)
        result[key] = value
    return result


def _keys(data: dict[str, Any], expected: set[str], label: str) -> None:
    if set(data) != expected:
        raise CompletionError(label + ": unexpected or missing fields")


def _regular_source(directory: Path) -> tuple[str, Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise CompletionError("quarantine directory is missing or unsafe")
    if [p.name for p in directory.iterdir()] != ["search.py"]:
        raise CompletionError("quarantine must contain only search.py")
    source = directory / "search.py"
    if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_SOURCE:
        raise CompletionError("source is unsafe or too large")
    raw = source.read_bytes()
    if not raw:
        raise CompletionError("source cannot be empty")
    try:
        raw.decode("utf-8")
    except UnicodeError as exc:
        raise CompletionError("source must be UTF-8") from exc
    return _sha(raw), source


def _not_within(value: Path, directory: Path) -> bool:
    a, b = value.resolve(), directory.resolve()
    return a != b and b not in a.parents and a not in b.parents


def _separate_destination(path: Path, vault_dir: Path, quarantine: Path, protected: list[Path]) -> None:
    if path.exists() or path.is_symlink():
        raise CompletionError("output already exists; never overwrite approval records")
    if not _not_within(path, vault_dir) or not _not_within(path, quarantine):
        raise CompletionError("output must be outside Vault and quarantine")
    if any(path.resolve() == earlier.resolve() for earlier in protected):
        raise CompletionError("output cannot overlap an input or private key")


def _head(root: Path, stage: str) -> tuple[str, str]:
    """Recheck stage/current per-rule decisions, return current head and spec digest."""
    with tempfile.TemporaryDirectory(prefix="anti-m-approved-") as temp:
        packet = Path(temp) / "packet"
        spec_sha = vault.export_packet(root, stage, packet)
        if sorted(p.name for p in packet.iterdir()) != ["SPEC.md"]:
            raise CompletionError("Vault emitted an unexpected builder packet")
        if sandbox._spec_digest(packet / "SPEC.md") != spec_sha:
            raise CompletionError("SPEC digest changed")
    # status() separately verifies the full ledger and frozen candidate.
    candidate, decisions, head = vault.status(root, stage)
    if any(decisions.get(r["id"]) != "approve" for r in candidate["rules"]):
        raise CompletionError("frozen requirements no longer approved")
    return head, spec_sha


def _evidence(root: Path, stage: str, artifacts: Path, builder_receipt: Path,
              verifier_receipt: Path) -> dict[str, Any]:
    if not _valid_hash(stage):
        raise CompletionError("invalid stage SHA-256")
    source_sha, _ = _regular_source(artifacts)
    head, spec_sha = _head(root, stage)
    built, built_sha = _safe_json(builder_receipt)
    # Reuse the independent-verifier's complete builder receipt validation.
    # It also verifies recorded image pin, data shape and security flags.
    if builder_receipt.resolve() == verifier_receipt.resolve():
        raise CompletionError("builder and verifier receipts cannot be the same file")
    if not _not_within(builder_receipt, root) or not _not_within(verifier_receipt, root):
        raise CompletionError("input receipts cannot be stored inside the Vault")
    if not _not_within(builder_receipt, artifacts) or not _not_within(verifier_receipt, artifacts):
        raise CompletionError("receipts must be separate from quarantine")
    verifier._load_receipt(builder_receipt, stage, spec_sha, source_sha)
    checked, verified_sha = _safe_json(verifier_receipt)
    required = {"schema_version", "kind", "stage_sha256", "spec_sha256",
                "source_sha256", "verifier_image_id", "suite", "status",
                "authority", "checks", "mutants", "note"}
    _keys(checked, required, "independent verifier receipt")
    if type(checked["schema_version"]) is not int or checked["schema_version"] != 1:
        raise CompletionError("invalid verifier receipt version")
    if (checked["kind"] != "INDEPENDENT_VERIFICATION_RECEIPT" or
        checked["status"] != "REFERENCE_CHECKS_PASS" or
        checked["authority"] != "NONE" or
        checked["suite"] != CHECK_SUITE or
        (checked["stage_sha256"], checked["spec_sha256"], checked["source_sha256"])
        != (stage, spec_sha, source_sha)):
        raise CompletionError("verifier receipt is not bound to current source, spec and stage")
    sandbox._image(checked["verifier_image_id"])
    if not isinstance(checked["note"], str):
        raise CompletionError("invalid verifier receipt note")
    # Reconstruct only the verifier worker's strict result envelope and check
    # all required passing assertions and three unique source-level mutations.
    worker_report = {key: checked[key] for key in (
        "schema_version", "stage_sha256", "spec_sha256", "source_sha256",
        "suite", "authority", "checks", "mutants",
    )}
    worker_report.update({
        "kind": verifier.KIND, "status": "CHECKS_PASS_MUTANTS_KILLED"
    })
    verifier.validate_result(json.dumps(worker_report, sort_keys=True), stage, spec_sha, source_sha)
    return {
        "stage_sha256": stage, "spec_sha256": spec_sha,
        "source_sha256": source_sha, "vault_ledger_head": head,
        "builder_receipt_sha256": built_sha, "verifier_receipt_sha256": verified_sha,
        "builder_image_id": built["image_id"],
        "verifier_image_id": checked["verifier_image_id"],
    }


def _contract(data: dict[str, Any]) -> None:
    expected = {"schema_version", "kind", "scope", "stage_sha256", "spec_sha256",
                "source_sha256", "vault_ledger_head", "builder_receipt_sha256",
                "verifier_receipt_sha256", "builder_image_id", "verifier_image_id",
                "required_checks", "required_mutants", "requires_human_release"}
    _keys(data, expected, "completion contract")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise CompletionError("completion schema must equal 1")
    if data["kind"] != CONTRACT_KIND or data["scope"] != "reference-exact-title-v1":
        raise CompletionError("unsupported completion scope")
    if data["required_checks"] != list(verifier.REQUIRED_CHECKS) or data["required_mutants"] != list(verifier.REQUIRED_MUTANTS):
        raise CompletionError("completion cannot weaken or omit required tests")
    if data["requires_human_release"] is not True:
        raise CompletionError("manual release requirement cannot be bypassed")
    for key in ("stage_sha256", "spec_sha256", "source_sha256", "vault_ledger_head",
                "builder_receipt_sha256", "verifier_receipt_sha256"):
        if not _valid_hash(data[key]):
            raise CompletionError("invalid contract digest: " + key)
    for key in ("builder_image_id", "verifier_image_id"):
        sandbox._image(data[key])


def create_contract(root: Path, stage: str, artifacts: Path,
                    built: Path, verified: Path, out: Path) -> dict[str, Any]:
    _separate_destination(out, root, artifacts, [built, verified])
    evidence = _evidence(root, stage, artifacts, built, verified)
    contract = {
        "schema_version": 1, "kind": CONTRACT_KIND,
        "scope": "reference-exact-title-v1",
        **evidence,
        "required_checks": list(verifier.REQUIRED_CHECKS),
        "required_mutants": list(verifier.REQUIRED_MUTANTS),
        "requires_human_release": True,
    }
    _contract(contract)
    _save_new(out, contract)
    return {"status": "READY_FOR_HUMAN_RELEASE_REVIEW",
            "authority": "NONE", "contract_sha256": _sha(out.read_bytes()),
            "stage_sha256": stage, "source_sha256": evidence["source_sha256"]}


def assess(root: Path, artifacts: Path, built: Path, verified: Path,
           contract_path: Path) -> dict[str, Any]:
    contract, contract_hash = _safe_json(contract_path)
    _contract(contract)
    observed = _evidence(root, contract["stage_sha256"], artifacts, built, verified)
    for name, expected in observed.items():
        if contract[name] != expected:
            raise CompletionError("stale/changed completion contract: " + name)
    return {
        "status": "READY_FOR_HUMAN_RELEASE_REVIEW", "authority": "NONE",
        "contract_sha256": contract_hash,
        "stage_sha256": contract["stage_sha256"],
        "source_sha256": contract["source_sha256"],
        "vault_ledger_head": contract["vault_ledger_head"],
    }


def _save_new(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def _key(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise CompletionError("human-held attestation key must be a regular file")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise CompletionError("attestation key must have mode 0600 or stricter")
    raw = path.read_bytes()
    if len(raw) != 32:
        raise CompletionError("attestation key must contain exactly 32 random bytes")
    return raw


def _signed_payload(contract_hash: str, signer: str, note: str, at: str,
                    decision: str) -> dict[str, Any]:
    return {
        "schema_version": 1, "kind": ATTESTATION_KIND,
        "contract_sha256": contract_hash,
        "claimed_signer": signer, "note": note, "recorded_at": at,
        "decision": decision,
        "authority": "LOCAL_KEY_ATTESTATION_ONLY",
        "scope": "RELEASE_REVIEW_NOT_DEPLOYMENT",
    }


def attest(root: Path, artifacts: Path, built: Path, verified: Path,
           contract: Path, key_file: Path, out: Path, *,
           signer: str, note: str, confirmation: str) -> dict[str, Any]:
    if confirmation != APPROVAL:
        raise CompletionError("explicit confirmation phrase required; no automatic release")
    if not isinstance(signer, str) or not 1 <= len(signer.strip()) <= 100 or "\n" in signer:
        raise CompletionError("claimed signer name required")
    if not isinstance(note, str) or not 10 <= len(note.strip()) <= 1000:
        raise CompletionError("meaningful release review note required")
    for path in (key_file, contract):
        if not _not_within(path, root) or not _not_within(path, artifacts):
            raise CompletionError("key and contract must remain outside Vault and quarantine")
    _separate_destination(out, root, artifacts, [built, verified, contract, key_file])
    ready = assess(root, artifacts, built, verified, contract)
    key = _key(key_file)
    payload = _signed_payload(
        ready["contract_sha256"], signer.strip(), note.strip(),
        datetime.now(timezone.utc).isoformat(), "ATTEST_RELEASE_REVIEWED"
    )
    payload["hmac_sha256"] = hmac.new(key, vault.canonical(payload), hashlib.sha256).hexdigest()
    _save_new(out, payload)
    return {"status": "LOCAL_KEY_ATTESTATION_RECORDED", "authority": "NO_DEPLOYMENT",
            "contract_sha256": ready["contract_sha256"], "attestation_sha256": _sha(out.read_bytes())}


def verify_attestation(root: Path, artifacts: Path, built: Path, verified: Path,
                       contract: Path, key_file: Path, attestation: Path) -> dict[str, Any]:
    ready = assess(root, artifacts, built, verified, contract)
    payload, attestation_hash = _safe_json(attestation)
    _keys(payload, {"schema_version", "kind", "contract_sha256", "claimed_signer",
                    "note", "recorded_at", "decision", "authority", "scope",
                    "hmac_sha256"}, "attestation")
    if (type(payload["schema_version"]) is not int or payload["schema_version"] != 1 or
        payload["kind"] != ATTESTATION_KIND or
        payload["contract_sha256"] != ready["contract_sha256"] or
        payload["decision"] != "ATTEST_RELEASE_REVIEWED" or
        payload["authority"] != "LOCAL_KEY_ATTESTATION_ONLY" or
        payload["scope"] != "RELEASE_REVIEW_NOT_DEPLOYMENT" or
        not isinstance(payload["claimed_signer"], str) or not payload["claimed_signer"].strip() or
        not isinstance(payload["note"], str) or len(payload["note"].strip()) < 10 or
        not isinstance(payload["recorded_at"], str)):
        raise CompletionError("invalid or stale human attestation")
    claimed = payload.pop("hmac_sha256")
    if not _valid_hash(claimed):
        raise CompletionError("invalid attestation MAC")
    actual = hmac.new(_key(key_file), vault.canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, claimed):
        raise CompletionError("attestation MAC did not match human-held local key")
    return {
        "status": "KEYED_RELEASE_REVIEW_ATTESTATION_VALID",
        "authority": "NO_DEPLOYMENT_OR_DONE",
        "contract_sha256": ready["contract_sha256"],
        "attestation_sha256": attestation_hash,
        "claimed_signer": payload["claimed_signer"],
    }
