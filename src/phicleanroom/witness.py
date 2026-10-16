"""Offline out-of-band checkpoints for Anti-M completion evidence.

A checkpoint is a consistency commitment, not a signature or proof of truth.
Verification REQUIRES a separately retained expected SHA-256. Without it,
replacing the complete local evidence set could go undetected.

No network calls, keys, release authority, evidence copying or source runs.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import antim, sandbox

KIND = "PHICLEANROOM_EXTERNAL_WITNESS_V1"
REQUIRED = frozenset({
    "schema_version", "kind", "scope", "authority", "contract_sha256",
    "stage_sha256", "spec_sha256", "source_sha256", "vault_ledger_head",
    "builder_receipt_sha256", "verifier_receipt_sha256",
    "builder_image_id", "verifier_image_id", "note",
})
NOTE = "Local evidence commitment only; not an authenticated witness or release approval."


class WitnessError(ValueError):
    """Independent checkpoint is missing, invalid, stale or not anchored."""


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _require_hash(value: Any, what: str) -> None:
    if not isinstance(value, str) or sandbox.STAGE_SHA.fullmatch(value) is None:
        raise WitnessError(what + " must be lowercase 64-character SHA-256")


def _safe_external(path: Path, vault_dir: Path, quarantine: Path,
                   others: tuple[Path, ...], *, new: bool) -> None:
    if path.is_symlink() or (new and path.exists()):
        raise WitnessError("checkpoint destination exists or is a symlink")
    if not antim._not_within(path, vault_dir) or not antim._not_within(path, quarantine):
        raise WitnessError("checkpoint must be separate from Vault and quarantine")
    if any(path.resolve() == other.resolve() for other in others):
        raise WitnessError("checkpoint path conflicts with an evidence input")


def _snapshot(vault_dir: Path, quarantine: Path, built: Path, verified: Path,
              contract_path: Path) -> dict[str, Any]:
    # assess() re-verifies current Vault approvals, source bytes and receipts.
    ready = antim.assess(vault_dir, quarantine, built, verified, contract_path)
    contract, actual_hash = antim._safe_json(contract_path)
    antim._contract(contract)
    if ready["contract_sha256"] != actual_hash:
        raise WitnessError("completion contract changed during inspection")
    return {
        "schema_version": 1,
        "kind": KIND,
        "scope": "reference-exact-title-v1",
        "authority": "NONE",
        "contract_sha256": actual_hash,
        "stage_sha256": contract["stage_sha256"],
        "spec_sha256": contract["spec_sha256"],
        "source_sha256": contract["source_sha256"],
        "vault_ledger_head": contract["vault_ledger_head"],
        "builder_receipt_sha256": contract["builder_receipt_sha256"],
        "verifier_receipt_sha256": contract["verifier_receipt_sha256"],
        "builder_image_id": contract["builder_image_id"],
        "verifier_image_id": contract["verifier_image_id"],
        "note": NOTE,
    }


def _validate(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != REQUIRED:
        raise WitnessError("witness checkpoint has missing or unknown fields")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise WitnessError("unsupported witness schema version")
    if (doc["kind"] != KIND or doc["scope"] != "reference-exact-title-v1" or
            doc["authority"] != "NONE" or doc["note"] != NOTE):
        raise WitnessError("witness checkpoint may not claim approval or release")
    for key in (
        "contract_sha256", "stage_sha256", "spec_sha256", "source_sha256",
        "vault_ledger_head", "builder_receipt_sha256", "verifier_receipt_sha256",
    ):
        _require_hash(doc[key], key)
    for key in ("builder_image_id", "verifier_image_id"):
        sandbox._image(doc[key])
    if doc["builder_image_id"] == doc["verifier_image_id"]:
        raise WitnessError("builder and verifier image cannot be the same")
    return doc


def checkpoint(vault_dir: Path, quarantine: Path, built: Path, verified: Path,
               contract: Path, out: Path) -> dict[str, Any]:
    """Create a new checkpoint. It has NO independent trust until anchored."""
    _safe_external(out, vault_dir, quarantine, (built, verified, contract), new=True)
    snapshot = _validate(_snapshot(vault_dir, quarantine, built, verified, contract))
    antim._save_new(out, snapshot)
    digest = _digest(out.read_bytes())
    return {
        "status": "CHECKPOINT_CREATED_UNANCHORED",
        "authority": "NONE",
        "checkpoint_sha256": digest,
        "stage_sha256": snapshot["stage_sha256"],
        "vault_ledger_head": snapshot["vault_ledger_head"],
        "warning": "Save checkpoint SHA-256 in a separately controlled offline record. "
                   "Keeping it beside the checkpoint does not protect against coordinated rewriting.",
    }


def verify_checkpoint(vault_dir: Path, quarantine: Path, built: Path, verified: Path,
                      contract: Path, checkpoint_path: Path,
                      expected_checkpoint_sha256: str) -> dict[str, Any]:
    """Require an outside expected hash, then recheck all CURRENT evidence."""
    _require_hash(expected_checkpoint_sha256, "independently retained expected checkpoint hash")
    _safe_external(checkpoint_path, vault_dir, quarantine,
                   (built, verified, contract), new=False)
    # Parse via duplicate-key rejecting, bounded Anti-M loader.
    doc, actual_digest = antim._safe_json(checkpoint_path)
    if actual_digest != expected_checkpoint_sha256:
        raise WitnessError("checkpoint bytes differ from independently retained expected SHA-256")
    recorded = _validate(doc)
    current = _validate(_snapshot(vault_dir, quarantine, built, verified, contract))
    if recorded != current:
        changed = sorted(key for key in REQUIRED if recorded[key] != current[key])
        raise WitnessError("checkpoint is stale or rewritten: " + ", ".join(changed))
    return {
        "status": "INDEPENDENT_CHECKPOINT_MATCH",
        "authority": "NO_APPROVAL_NO_DONE_NO_DEPLOY",
        "checkpoint_sha256": actual_digest,
        "contract_sha256": current["contract_sha256"],
        "vault_ledger_head": current["vault_ledger_head"],
        "note": "Current evidence matches the supplied checkpoint and expected digest. "
                "Trust depends on the expected digest being retained independently.",
    }
