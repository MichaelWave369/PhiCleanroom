"""Anti-M v1 controls: hash-bound completion and nonautomatic keyed release review."""
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from phicleanroom import antim, sandbox, vault, verifier
from phicleanroom.cli import main


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AntiMTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.private = self.root / "evidence-vault"
        vault.init_vault(self.private)
        self.snapshot = self.root / "snapshot.json"
        self.evidence = self.root / "observed.json"
        self.snapshot.write_text('{"version":"owned-test"}', encoding="utf-8")
        self.evidence.write_text('{"query":"A","result":"A"}', encoding="utf-8")
        a = vault.ingest(self.private, self.snapshot)
        b = vault.ingest(self.private, self.evidence)
        self.candidate = {
            "schema_version": 2, "feature": "Synthetic title search",
            "authorization": {
                "scope": "Owned fixture", "basis": "Created by this test",
                "approved_by": "Test fixture owner",
            },
            "snapshot_sha256": a,
            "rules": [{
                "id": "R1", "behavior": "An exact title query finds its matching item.",
                "evidence": [{
                    "id": "E1", "kind": "test", "provenance": "VERIFIED",
                    "summary": "Synthetic recorded test-only observation",
                    "artifact_sha256": b,
                }],
            }],
        }
        self.stage = vault.stage(self.private, self.candidate)
        vault.review(self.private, self.stage, "R1", "approve", "fixture reviewer", "checked synthetic fixture")
        with tempfile.TemporaryDirectory() as temp:
            self.spec_sha = vault.export_packet(self.private, self.stage, Path(temp) / "packet")
        self.quarantine = self.root / "quarantined"
        self.quarantine.mkdir()
        self.source = self.quarantine / "search.py"
        self.source.write_text('def search(items, query):\n    return [x for x in items if x.get("title") == query]\n', encoding="utf-8")
        self.source_sha = vault.file_hash(self.source)
        self.image = "sha256:" + "a" * 64
        self.other_image = "sha256:" + "c" * 64
        self.built = self.root / "builder-receipt.json"
        self.verified = self.root / "verifier-receipt.json"
        self.contract = self.root / "completion-contract.json"
        self.attestation = self.root / "human-attestation.json"
        self.keyfile = self.root / "private-attestation.key"
        self.keyfile.write_bytes(os.urandom(32))
        if os.name == "posix":
            self.keyfile.chmod(0o600)
        self.builder_doc = {
            "schema_version": 1, "kind": "INDEPENDENT_BUILDER_RECEIPT",
            "status": "QUARANTINED_UNVERIFIED",
            "stage_sha256": self.stage, "spec_sha256": self.spec_sha,
            "image_id": self.image, "authority": "NONE",
            "builder": "reference-exact-title-v1",
            "container_policy": sandbox.policy(),
            "artifacts": [{"path": "search.py", "sha256": self.source_sha}],
            "note": "Test fixture only. Not a release.",
        }
        self.verifier_doc = {
            "schema_version": 1, "kind": "INDEPENDENT_VERIFICATION_RECEIPT",
            "stage_sha256": self.stage, "spec_sha256": self.spec_sha,
            "source_sha256": self.source_sha,
            "verifier_image_id": self.other_image,
            "suite": "reference-exact-title-acceptance-v1",
            "status": "REFERENCE_CHECKS_PASS", "authority": "NONE",
            "checks": [{"id": key, "status": "PASS"} for key in verifier.REQUIRED_CHECKS],
            "mutants": [
                {"id": name, "status": "KILLED_ASSERTION",
                 "source_sha256": sha(name), "failed_check": "exact_title"}
                for name in verifier.REQUIRED_MUTANTS
            ],
            "note": "Synthetic test fixture only, not real verifier execution.",
        }
        self.write_receipts()

    def write_receipts(self):
        self.built.write_text(json.dumps(self.builder_doc, sort_keys=True), encoding="utf-8")
        self.verified.write_text(json.dumps(self.verifier_doc, sort_keys=True), encoding="utf-8")

    def make_contract(self):
        return antim.create_contract(self.private, self.stage, self.quarantine,
                                    self.built, self.verified, self.contract)

    def inspect(self):
        return antim.assess(self.private, self.quarantine, self.built,
                           self.verified, self.contract)

    def sign(self):
        return antim.attest(
            self.private, self.quarantine, self.built, self.verified,
            self.contract, self.keyfile, self.attestation,
            signer="Fixture reviewer",
            note="Reviewed the frozen synthetic artifact and tests.",
            confirmation=antim.APPROVAL,
        )

    def test_contract_only_eligible_for_review_not_done(self):
        result = self.make_contract()
        self.assertEqual(result["status"], "READY_FOR_HUMAN_RELEASE_REVIEW")
        self.assertEqual(result["authority"], "NONE")
        self.assertEqual(self.inspect()["contract_sha256"], result["contract_sha256"])
        doc = json.loads(self.contract.read_text())
        self.assertTrue(doc["requires_human_release"])
        self.assertEqual(doc["source_sha256"], self.source_sha)
        self.assertEqual(doc["required_mutants"], list(verifier.REQUIRED_MUTANTS))
        self.assertFalse(self.attestation.exists())

    def test_keyed_attestation_requires_explicit_phrase_and_remains_non_deploying(self):
        self.make_contract()
        with self.assertRaisesRegex(antim.CompletionError, "confirmation"):
            antim.attest(
                self.private, self.quarantine, self.built, self.verified,
                self.contract, self.keyfile, self.attestation, signer="Fixture",
                note="Meaningful review note", confirmation="yes")
        self.assertFalse(self.attestation.exists())
        result = self.sign()
        self.assertEqual(result["status"], "LOCAL_KEY_ATTESTATION_RECORDED")
        self.assertEqual(result["authority"], "NO_DEPLOYMENT")
        verified = antim.verify_attestation(
            self.private, self.quarantine, self.built, self.verified,
            self.contract, self.keyfile, self.attestation)
        self.assertEqual(verified["status"], "KEYED_RELEASE_REVIEW_ATTESTATION_VALID")
        self.assertEqual(verified["authority"], "NO_DEPLOYMENT_OR_DONE")

    def test_key_mismatch_and_attestation_modification_fail(self):
        self.make_contract()
        self.sign()
        wrong = self.root / "wrong.key"
        wrong.write_bytes(os.urandom(32))
        if os.name == "posix":
            wrong.chmod(0o600)
        with self.assertRaisesRegex(antim.CompletionError, "MAC"):
            antim.verify_attestation(self.private, self.quarantine, self.built,
                                     self.verified, self.contract, wrong, self.attestation)
        altered = json.loads(self.attestation.read_text())
        altered["claimed_signer"] = "Imposter"
        self.attestation.write_text(json.dumps(altered))
        with self.assertRaisesRegex(antim.CompletionError, "MAC"):
            antim.verify_attestation(self.private, self.quarantine, self.built,
                                     self.verified, self.contract, self.keyfile, self.attestation)

    def test_revoked_vault_review_invalidates_contract_and_attestation(self):
        self.make_contract()
        self.sign()
        vault.review(self.private, self.stage, "R1", "return", "fixture reviewer", "new question")
        with self.assertRaises((antim.CompletionError, vault.VaultError)):
            self.inspect()
        with self.assertRaises((antim.CompletionError, vault.VaultError)):
            antim.verify_attestation(self.private, self.quarantine, self.built,
                                     self.verified, self.contract, self.keyfile, self.attestation)

    def test_new_review_event_invalidates_frozen_ledger_head(self):
        self.make_contract()
        vault.review(self.private, self.stage, "R1", "approve", "fixture reviewer", "re-approved")
        with self.assertRaisesRegex(antim.CompletionError, "vault_ledger_head"):
            self.inspect()

    def test_mutation_of_source_or_receipts_invalidates_contract(self):
        self.make_contract()
        self.source.write_text("def search(*a):\n    return []\n")
        with self.assertRaises((antim.CompletionError, verifier.VerifyError)):
            self.inspect()
        self.source.write_text('def search(items, query):\n    return [x for x in items if x.get("title") == query]\n')
        self.builder_doc["note"] = "metadata changed"
        self.write_receipts()
        with self.assertRaisesRegex(antim.CompletionError, "builder_receipt_sha256"):
            self.inspect()
        self.make_contract  # existing frozen file cannot be replaced
        self.builder_doc["note"] = "Test fixture only. Not a release."
        self.verifier_doc["note"] = "Receipt changed"
        self.write_receipts()
        with self.assertRaisesRegex(antim.CompletionError, "verifier_receipt_sha256"):
            self.inspect()

    def test_failed_or_absent_mutation_report_cannot_create_contract(self):
        for bad in ("SURVIVED", "CRASH", "NOT_RUN"):
            original = copy.deepcopy(self.verifier_doc)
            self.verifier_doc["mutants"][0]["status"] = bad
            self.write_receipts()
            with self.subTest(bad=bad), self.assertRaises(verifier.VerifyError):
                antim.create_contract(self.private, self.stage, self.quarantine,
                                     self.built, self.verified, self.contract)
            self.assertFalse(self.contract.exists())
            self.verifier_doc = original

    def test_contract_cannot_weaken_checks_or_approval_requirement(self):
        self.make_contract()
        doc = json.loads(self.contract.read_text())
        doc["requires_human_release"] = False
        self.contract.write_text(json.dumps(doc))
        with self.assertRaises(antim.CompletionError):
            self.inspect()
        doc["requires_human_release"] = True
        doc["required_mutants"] = doc["required_mutants"][:-1]
        self.contract.write_text(json.dumps(doc))
        with self.assertRaises(antim.CompletionError):
            self.inspect()

    def test_symlinks_extra_files_and_unsafe_output_paths_block(self):
        with self.assertRaises(antim.CompletionError):
            antim.create_contract(self.private, self.stage, self.quarantine,
                                  self.built, self.verified, self.private / "completion.json")
        with self.assertRaises(antim.CompletionError):
            antim.create_contract(self.private, self.stage, self.quarantine,
                                  self.built, self.verified, self.quarantine / "completion.json")
        (self.quarantine / "extra.py").write_text("extra")
        with self.assertRaises(antim.CompletionError):
            self.make_contract()

    def test_weak_keys_and_existing_outputs_fail(self):
        self.make_contract()
        self.keyfile.write_bytes(b"too-short")
        with self.assertRaisesRegex(antim.CompletionError, "32 random"):
            self.sign()
        self.keyfile.write_bytes(os.urandom(32))
        if os.name == "posix":
            self.keyfile.chmod(0o644)
            with self.assertRaisesRegex(antim.CompletionError, "0600"):
                self.sign()
            self.keyfile.chmod(0o600)
        self.sign()
        with self.assertRaisesRegex(antim.CompletionError, "already exists"):
            self.sign()

    def test_cli_round_trip(self):
        common = ["--vault", str(self.private), "--artifacts", str(self.quarantine),
                  "--builder-receipt", str(self.built), "--verifier-receipt", str(self.verified)]
        self.assertEqual(main(["anti-m", "contract", *common, "--stage", self.stage,
                               "--out", str(self.contract)]), 0)
        self.assertEqual(main(["anti-m", "assess", *common, "--contract", str(self.contract)]), 0)
        self.assertEqual(main(["anti-m", "attest", *common, "--contract", str(self.contract),
                               "--key-file", str(self.keyfile), "--out", str(self.attestation),
                               "--signer", "Fixture reviewer", "--note", "Verified CI test ownership",
                               "--confirmation", antim.APPROVAL]), 0)
        self.assertEqual(main(["anti-m", "check-attestation", *common, "--contract", str(self.contract),
                               "--key-file", str(self.keyfile),
                               "--attestation", str(self.attestation)]), 0)


if __name__ == "__main__":
    unittest.main()
