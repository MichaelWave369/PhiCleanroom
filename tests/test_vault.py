import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from phicleanroom import vault
from phicleanroom.cli import main


class EvidenceVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "investigator-vault"
        vault.init_vault(self.store)
        self.snapshot = self.root / "owned-snapshot.json"
        self.snapshot.write_text('{"owned_app":"demo","build":"1"}', encoding="utf-8")
        self.evidence = self.root / "observed.json"
        self.evidence.write_text('{"query":"milk","result":["Buy milk"]}', encoding="utf-8")
        self.snapshot_sha = vault.ingest(self.store, self.snapshot)
        self.evidence_sha = vault.ingest(self.store, self.evidence)
        self.candidate = {
            "schema_version": 2,
            "feature": "Owned sample search",
            "authorization": {
                "scope": "Locally created demo app",
                "basis": "Original author permits inspection",
                "approved_by": "test operator",
            },
            "snapshot_sha256": self.snapshot_sha,
            "rules": [
                {
                    "id": "R1",
                    "behavior": "Searching a title term returns the matching item.",
                    "evidence": [{
                        "id": "E1",
                        "kind": "test",
                        "provenance": "VERIFIED",
                        "summary": "Tested the title search on the pinned build",
                        "artifact_sha256": self.evidence_sha,
                    }],
                }
            ],
        }

    def test_integration_exports_behavior_only_and_separate_receipt(self):
        stage = vault.stage(self.store, self.candidate)
        doc, decisions, head = vault.status(self.store, stage)
        self.assertEqual(decisions, {})
        self.assertEqual(doc["snapshot_sha256"], self.snapshot_sha)
        with self.assertRaises(vault.VaultError):
            vault.export_packet(self.store, stage, self.root / "isolated")
        decision_hash = vault.review(self.store, stage, "R1", "approve", "reviewer", "read actual evidence")
        self.assertEqual(len(decision_hash), 64)
        packet = self.root / "builder-packet"
        receipt = self.root / "audit.json"
        spec_sha = vault.export_packet(self.store, stage, packet, receipt)
        self.assertEqual([p.name for p in packet.iterdir()], ["SPEC.md"])
        spec = (packet / "SPEC.md").read_text()
        self.assertIn("Searching a title", spec)
        self.assertNotIn("reviewer", spec)
        self.assertNotIn("pinned build", spec)
        self.assertNotIn(self.evidence_sha, spec)
        self.assertEqual(json.loads(receipt.read_text())["spec_sha256"], spec_sha)
        self.assertEqual(vault.verify_history(self.store)[-1]["event_hash"], decision_hash)
        self.assertNotEqual(head, decision_hash)

    def test_uningested_evidence_is_blocked(self):
        self.candidate["rules"][0]["evidence"][0]["artifact_sha256"] = "f" * 64
        with self.assertRaisesRegex(vault.VaultError, "non-ingested"):
            vault.stage(self.store, self.candidate)

    def test_uningested_snapshot_is_blocked(self):
        self.candidate["snapshot_sha256"] = "f" * 64
        with self.assertRaises(vault.VaultError):
            vault.stage(self.store, self.candidate)

    def test_artifact_mutation_invalidates_entire_vault(self):
        stage = vault.stage(self.store, self.candidate)
        vault.review(self.store, stage, "R1", "approve", "reviewer", "")
        (self.store / "objects" / self.evidence_sha).write_bytes(b"tampered")
        with self.assertRaisesRegex(vault.VaultError, "digest mismatch"):
            vault.export_packet(self.store, stage, self.root / "builder")

    def test_staged_candidate_change_requires_new_approval(self):
        stage_one = vault.stage(self.store, self.candidate)
        vault.review(self.store, stage_one, "R1", "approve", "reviewer", "")
        changed = copy.deepcopy(self.candidate)
        changed["rules"][0]["behavior"] = "A different behavioral requirement."
        stage_two = vault.stage(self.store, changed)
        self.assertNotEqual(stage_one, stage_two)
        with self.assertRaisesRegex(vault.VaultError, "current explicit approval"):
            vault.export_packet(self.store, stage_two, self.root / "builder")

    def test_return_after_approve_blocks_export(self):
        stage = vault.stage(self.store, self.candidate)
        vault.review(self.store, stage, "R1", "approve", "reviewer", "")
        vault.review(self.store, stage, "R1", "return", "reviewer", "evidence incomplete")
        with self.assertRaises(vault.VaultError):
            vault.export_packet(self.store, stage, self.root / "builder")

    def test_nonverified_evidence_cannot_be_approved(self):
        self.candidate["rules"][0]["evidence"][0]["provenance"] = "INFERRED"
        stage = vault.stage(self.store, self.candidate)
        with self.assertRaisesRegex(vault.VaultError, "non-VERIFIED"):
            vault.review(self.store, stage, "R1", "approve", "reviewer", "")

    def test_ledger_edit_detected(self):
        stage = vault.stage(self.store, self.candidate)
        events_path = self.store / "events.jsonl"
        contents = events_path.read_text()
        contents = contents.replace('"type":"STAGE"', '"type":"REVIEW"')
        events_path.write_text(contents)
        with self.assertRaises(vault.VaultError):
            vault.verify_history(self.store)

    def test_duplicate_json_key_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"schema_version":2,"schema_version":1}')
        with self.assertRaisesRegex(vault.VaultError, "duplicate JSON key"):
            vault.load_json(path)

    def test_unapproved_preview_does_not_export(self):
        stage = vault.stage(self.store, self.candidate)
        self.assertEqual(main(["vault", "--vault", str(self.store), "preview", "--stage", stage]), 0)
        self.assertFalse((self.root / "builder").exists())

    def test_receipt_and_builder_separation(self):
        stage = vault.stage(self.store, self.candidate)
        vault.review(self.store, stage, "R1", "approve", "reviewer", "")
        packet = self.root / "builder"
        with self.assertRaises(vault.VaultError):
            vault.export_packet(self.store, stage, packet, packet / "audit.json")
        self.assertFalse(packet.exists())
        with self.assertRaises(vault.VaultError):
            vault.export_packet(self.store, stage, self.store / "builder")

    def test_path_cannot_include_existing_vault(self):
        stage = vault.stage(self.store, self.candidate)
        vault.review(self.store, stage, "R1", "approve", "reviewer", "")
        with self.assertRaises(vault.VaultError):
            vault.export_packet(self.store, stage, self.root)

    def test_review_requires_reason_on_return(self):
        stage = vault.stage(self.store, self.candidate)
        with self.assertRaises(vault.VaultError):
            vault.review(self.store, stage, "R1", "return", "reviewer", "")

    def test_cli_roundtrip(self):
        candidate_path = self.root / "candidate.json"
        candidate_path.write_text(json.dumps(self.candidate))
        self.assertEqual(main(["vault", "--vault", str(self.store), "stage", "--input", str(candidate_path)]), 0)
        stage_sha = hashlib.sha256(vault.canonical(self.candidate)).hexdigest()
        self.assertEqual(main(["vault", "--vault", str(self.store), "review", "--stage", stage_sha,
                               "--rule", "R1", "--decision", "approve", "--reviewer", "tester"]), 0)
        self.assertEqual(main(["vault", "--vault", str(self.store), "packet", "--stage", stage_sha,
                               "--out", str(self.root / "fresh")]), 0)
        self.assertEqual(main(["vault", "--vault", str(self.store), "verify"]), 0)


if __name__ == "__main__":
    unittest.main()
