"""Negative-control tests for independently anchored Anti-M witness checkpoints."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from phicleanroom import antim, sandbox, vault, verifier, witness
from phicleanroom.cli import main


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.vault_dir = self.work / "vault"
        vault.init_vault(self.vault_dir)
        snapshot = self.work / "snapshot.json"
        evidence = self.work / "evidence.json"
        snapshot.write_text('{"owner":"test","version":1}', encoding="utf-8")
        evidence.write_text('{"query":"A","result":"A"}', encoding="utf-8")
        snapshot_sha = vault.ingest(self.vault_dir, snapshot)
        evidence_sha = vault.ingest(self.vault_dir, evidence)
        candidate = {
            "schema_version": 2,
            "feature": "Owned synthetic title search",
            "authorization": {
                "scope": "Synthetic test fixture", "basis": "Test author created it",
                "approved_by": "Fixture author",
            },
            "snapshot_sha256": snapshot_sha,
            "rules": [{
                "id": "R1",
                "behavior": "An exact title query finds its matching item.",
                "evidence": [{
                    "id": "E1", "kind": "test", "provenance": "VERIFIED",
                    "summary": "Synthetic test-only observation",
                    "artifact_sha256": evidence_sha,
                }],
            }],
        }
        self.stage = vault.stage(self.vault_dir, candidate)
        vault.review(self.vault_dir, self.stage, "R1", "approve", "Test reviewer",
                     "Approved first-party synthetic test input")
        with tempfile.TemporaryDirectory() as temp:
            self.spec_sha = vault.export_packet(self.vault_dir, self.stage, Path(temp) / "packet")
        self.quarantine = self.work / "quarantine"
        self.quarantine.mkdir()
        self.source = self.quarantine / "search.py"
        self.source.write_text(
            'def search(items, query):\n    return [x for x in items if x.get("title") == query]\n',
            encoding="utf-8")
        self.source_sha = vault.file_hash(self.source)
        self.image = "sha256:" + "a" * 64
        self.verifier_image = "sha256:" + "b" * 64
        self.builder_path = self.work / "builder.json"
        self.verifier_path = self.work / "verifier.json"
        self.contract = self.work / "contract.json"
        self.checkpoint_file = self.work / "witness.json"
        self.builder_doc = {
            "schema_version": 1, "kind": "INDEPENDENT_BUILDER_RECEIPT",
            "status": "QUARANTINED_UNVERIFIED",
            "stage_sha256": self.stage, "spec_sha256": self.spec_sha,
            "image_id": self.image, "authority": "NONE",
            "builder": "reference-exact-title-v1",
            "container_policy": sandbox.policy(),
            "artifacts": [{"path": "search.py", "sha256": self.source_sha}],
            "note": "Owned synthetic test fixture only.",
        }
        self.verifier_doc = {
            "schema_version": 1, "kind": "INDEPENDENT_VERIFICATION_RECEIPT",
            "stage_sha256": self.stage, "spec_sha256": self.spec_sha,
            "source_sha256": self.source_sha,
            "verifier_image_id": self.verifier_image,
            "suite": "reference-exact-title-acceptance-v1",
            "status": "REFERENCE_CHECKS_PASS", "authority": "NONE",
            "checks": [{"id": item, "status": "PASS"} for item in verifier.REQUIRED_CHECKS],
            "mutants": [
                {"id": name, "status": "KILLED_ASSERTION",
                 "source_sha256": sha(name), "failed_check": "exact_title"}
                for name in verifier.REQUIRED_MUTANTS
            ],
            "note": "Owned synthetic test fixture, no external execution.",
        }
        self.builder_path.write_text(json.dumps(self.builder_doc), encoding="utf-8")
        self.verifier_path.write_text(json.dumps(self.verifier_doc), encoding="utf-8")
        antim.create_contract(self.vault_dir, self.stage, self.quarantine,
                              self.builder_path, self.verifier_path, self.contract)

    def common(self):
        return (self.vault_dir, self.quarantine, self.builder_path,
                self.verifier_path, self.contract)

    def freeze(self):
        return witness.checkpoint(*self.common(), self.checkpoint_file)

    def verify(self, expected):
        return witness.verify_checkpoint(*self.common(), self.checkpoint_file, expected)

    def test_checkpoint_creation_is_unanchored_until_digest_is_saved_elsewhere(self):
        receipt = self.freeze()
        self.assertEqual(receipt["status"], "CHECKPOINT_CREATED_UNANCHORED")
        self.assertEqual(receipt["authority"], "NONE")
        self.assertEqual(receipt["checkpoint_sha256"], vault.file_hash(self.checkpoint_file))
        self.assertEqual(self.verify(receipt["checkpoint_sha256"])["status"],
                         "INDEPENDENT_CHECKPOINT_MATCH")
        self.assertEqual(self.verify(receipt["checkpoint_sha256"])["authority"],
                         "NO_APPROVAL_NO_DONE_NO_DEPLOY")

    def test_independent_expected_digest_required_and_strict(self):
        receipt = self.freeze()
        with self.assertRaisesRegex(witness.WitnessError, "must be lowercase"):
            self.verify("")
        with self.assertRaisesRegex(witness.WitnessError, "independently retained"):
            self.verify("0" * 64)
        self.assertEqual(self.verify(receipt["checkpoint_sha256"])["checkpoint_sha256"],
                         receipt["checkpoint_sha256"])

    def test_mutated_checkpoint_bytes_fail_against_old_independent_digest(self):
        receipt = self.freeze()
        original = json.loads(self.checkpoint_file.read_text(encoding="utf-8"))
        original["note"] = "Local file fully replaced by adversary"
        self.checkpoint_file.write_text(json.dumps(original), encoding="utf-8")
        with self.assertRaisesRegex(witness.WitnessError, "independently retained"):
            self.verify(receipt["checkpoint_sha256"])
        # Recomputing a new digest next to the forged file provides no independent trust.
        with self.assertRaises(witness.WitnessError):
            self.verify(vault.file_hash(self.checkpoint_file))

    def test_recomputed_valid_looking_checkpoint_is_still_bound_to_old_anchor(self):
        receipt = self.freeze()
        changed = json.loads(self.checkpoint_file.read_text())
        changed["source_sha256"] = "f" * 64
        self.checkpoint_file.write_text(json.dumps(changed, sort_keys=True))
        attacker_new_hash = vault.file_hash(self.checkpoint_file)
        self.assertNotEqual(attacker_new_hash, receipt["checkpoint_sha256"])
        with self.assertRaisesRegex(witness.WitnessError, "independently retained"):
            self.verify(receipt["checkpoint_sha256"])
        with self.assertRaisesRegex(witness.WitnessError, "stale or rewritten"):
            self.verify(attacker_new_hash)

    def test_changed_source_fails_even_with_original_checkpoint_file(self):
        digest = self.freeze()["checkpoint_sha256"]
        self.source.write_text("def search(*args):\n    return []\n", encoding="utf-8")
        with self.assertRaises((antim.CompletionError, verifier.VerifyError)):
            self.verify(digest)

    def test_tampered_receipts_fail_even_if_checkpoint_unchanged(self):
        digest = self.freeze()["checkpoint_sha256"]
        self.builder_doc["note"] = "changed receipt text"
        self.builder_path.write_text(json.dumps(self.builder_doc), encoding="utf-8")
        with self.assertRaisesRegex(antim.CompletionError, "builder_receipt_sha256"):
            self.verify(digest)

    def test_new_vault_ledger_event_invalidates_witness(self):
        digest = self.freeze()["checkpoint_sha256"]
        vault.review(self.vault_dir, self.stage, "R1", "approve", "Test reviewer", "New review event")
        with self.assertRaisesRegex(antim.CompletionError, "vault_ledger_head"):
            self.verify(digest)

    def test_revoked_vault_approval_blocks_even_previous_checkpoint(self):
        digest = self.freeze()["checkpoint_sha256"]
        vault.review(self.vault_dir, self.stage, "R1", "return", "Test reviewer", "Withdraw approval")
        with self.assertRaises(vault.VaultError):
            self.verify(digest)

    def test_checkpoint_not_created_if_broken_mutation_evidence(self):
        self.verifier_doc["mutants"][0]["status"] = "SURVIVED"
        self.verifier_path.write_text(json.dumps(self.verifier_doc), encoding="utf-8")
        with self.assertRaises((antim.CompletionError, verifier.VerifyError)):
            self.freeze()
        self.assertFalse(self.checkpoint_file.exists())

    def test_checkpoint_never_written_inside_vault_or_quarantine_or_over_input(self):
        for place in (self.vault_dir / "witness.json", self.quarantine / "witness.json",
                      self.builder_path, self.contract):
            with self.subTest(place=place), self.assertRaises(witness.WitnessError):
                witness.checkpoint(*self.common(), place)
        self.freeze()
        with self.assertRaisesRegex(witness.WitnessError, "exists"):
            self.freeze()

    def test_reject_unknown_fields_and_fake_signature_claim(self):
        result = self.freeze()
        original = json.loads(self.checkpoint_file.read_text())
        original["authority"] = "APPROVED"
        self.checkpoint_file.write_text(json.dumps(original, sort_keys=True))
        with self.assertRaisesRegex(witness.WitnessError, "approval"):
            self.verify(vault.file_hash(self.checkpoint_file))
        original["authority"] = "NONE"
        original["verified_human"] = True
        self.checkpoint_file.write_text(json.dumps(original, sort_keys=True))
        with self.assertRaisesRegex(witness.WitnessError, "unknown"):
            self.verify(vault.file_hash(self.checkpoint_file))
        self.assertNotEqual(vault.file_hash(self.checkpoint_file),
                            result["checkpoint_sha256"])

    def test_duplicate_json_keys_fail_closed(self):
        self.freeze()
        self.checkpoint_file.write_text('{"kind":"x","kind":"y"}', encoding="utf-8")
        with self.assertRaises(antim.CompletionError):
            self.verify(vault.file_hash(self.checkpoint_file))

    def test_cli_roundtrip_and_required_anchor_flag(self):
        flags = ["--vault", str(self.vault_dir), "--artifacts", str(self.quarantine),
                 "--builder-receipt", str(self.builder_path),
                 "--verifier-receipt", str(self.verifier_path),
                 "--contract", str(self.contract)]
        self.assertEqual(main(["witness", "checkpoint", *flags,
                               "--out", str(self.checkpoint_file)]), 0)
        expected = vault.file_hash(self.checkpoint_file)
        self.assertEqual(main(["witness", "verify", *flags,
                               "--checkpoint", str(self.checkpoint_file),
                               "--expected-checkpoint-sha256", expected]), 0)
        self.assertEqual(main(["witness", "verify", *flags,
                               "--checkpoint", str(self.checkpoint_file),
                               "--expected-checkpoint-sha256", "e" * 64]), 1)


if __name__ == "__main__":
    unittest.main()
