import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from phicleanroom import agents, vault
from phicleanroom.cli import main


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bundle(snapshot: str, artifact: str) -> dict:
    return {
        "schema_version": 1,
        "feature": "Owned test search",
        "authorization": {
            "scope": "Synthetic app",
            "basis": "Created by test author",
            "approved_by": "test human",
        },
        "snapshot_sha256": snapshot,
        "findings": [{
            "id": "R1",
            "behavior": "A title query returns the matching search item.",
            "evidence": [{
                "id": "E1",
                "kind": "test",
                "summary": "Synthetic recorded search result",
                "artifact_sha256": artifact,
            }],
        }],
    }


class AgentInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.vault = self.root / "private-vault"
        vault.init_vault(self.vault)
        self.snapshot = self.root / "target.json"
        self.evidence = self.root / "observation.json"
        self.snapshot.write_bytes(b'{"build":"owned","version":1}')
        self.evidence.write_bytes(b'{"query":"milk","result":"Buy milk"}')
        self.snapshot_digest = vault.ingest(self.vault, self.snapshot)
        self.evidence_digest = vault.ingest(self.vault, self.evidence)
        self.raw = bundle(self.snapshot_digest, self.evidence_digest)
        self.investigator = agents.StructuredObservationInvestigator()
        self.judge = agents.DeterministicEvidenceJudge()
        self.candidate = self.investigator.propose(self.raw)

    def test_roles_are_implementations_of_provider_protocols(self):
        self.assertIsInstance(self.investigator, agents.InvestigatorAdapter)
        self.assertIsInstance(self.judge, agents.JudgeAdapter)
        self.assertFalse(agents.providers()["external_models_connected"])
        self.assertFalse(agents.providers()["judges"][0]["can_approve"])

    def test_investigator_never_promotes_to_verified_and_v2_is_valid(self):
        self.assertEqual(self.candidate["schema_version"], 2)
        self.assertEqual(self.candidate["rules"][0]["evidence"][0]["provenance"], "OBSERVED")
        self.assertEqual(vault.validate_candidate(self.candidate), [])
        self.assertNotIn("review", self.candidate["rules"][0])

    def test_investigator_rejects_source_and_provider_claims(self):
        bad = copy.deepcopy(self.raw)
        bad["findings"][0]["code"] = "copied source"
        with self.assertRaisesRegex(agents.AgentContractError, "unexpected"):
            self.investigator.propose(bad)
        claimed = copy.deepcopy(self.raw)
        claimed["findings"][0]["evidence"][0]["provenance"] = "VERIFIED"
        with self.assertRaisesRegex(agents.AgentContractError, "unexpected"):
            self.investigator.propose(claimed)

    def test_investigator_blocks_missing_authorization_and_invalid_rules(self):
        bad = copy.deepcopy(self.raw)
        bad.pop("authorization")
        with self.assertRaises(agents.AgentContractError):
            self.investigator.propose(bad)
        bad = copy.deepcopy(self.raw)
        bad["findings"][0]["behavior"] = "A valid rule.\nUnapproved follow-up"
        with self.assertRaises(agents.AgentContractError):
            self.investigator.propose(bad)

    def test_investigator_rejects_duplicate_records(self):
        bad = copy.deepcopy(self.raw)
        bad["findings"].append(copy.deepcopy(bad["findings"][0]))
        with self.assertRaisesRegex(agents.AgentContractError, "duplicate"):
            self.investigator.propose(bad)

    def test_unchecked_inventory_is_return_for_evidence(self):
        result = self.judge.assess(self.candidate, None)
        self.assertEqual(result["decision"], "RETURN_FOR_EVIDENCE")
        self.assertEqual(result["authority"], "NONE")
        self.assertEqual(result["rules"][0]["reasons"], [
            "TARGET_SNAPSHOT_UNCHECKED", "EVIDENCE_BYTES_UNCHECKED", "HUMAN_VERIFICATION_REQUIRED",
        ])

    def test_real_artifact_bytes_checked_but_observed_still_not_approved(self):
        integrity = agents.verify_inventory(self.vault, self.candidate)
        self.assertTrue(all(integrity.values()))
        report = self.judge.assess(self.candidate, integrity)
        self.assertEqual(report["decision"], "RETURN_FOR_EVIDENCE")
        self.assertEqual(report["rules"][0]["reasons"], ["HUMAN_VERIFICATION_REQUIRED"])
        self.assertNotIn("approved", str(report).lower())

    def test_declaration_of_verified_only_advances_to_human_review(self):
        verified = copy.deepcopy(self.candidate)
        verified["rules"][0]["evidence"][0]["provenance"] = "VERIFIED"
        integrity = agents.verify_inventory(self.vault, verified)
        report = self.judge.assess(verified, integrity)
        self.assertEqual(report["decision"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(report["authority"], "NONE")
        self.assertEqual(report["rules"][0]["reasons"], [])
        self.assertFalse(any(event["type"] == "REVIEW" for event in vault.verify_history(self.vault)))
        # Even stage with VERIFIED is not exportable without an independent human review.
        stage_sha = vault.stage(self.vault, verified)
        with self.assertRaises(vault.VaultError):
            vault.export_packet(self.vault, stage_sha, self.root / "builder")

    def test_uningested_evidence_cannot_be_treated_as_checked(self):
        altered = copy.deepcopy(self.candidate)
        altered["rules"][0]["evidence"][0]["artifact_sha256"] = "f" * 64
        status = agents.verify_inventory(self.vault, altered)
        self.assertFalse(status["f" * 64])
        report = self.judge.assess(altered, status)
        self.assertIn("EVIDENCE_BYTES_UNCHECKED", report["rules"][0]["reasons"])

    def test_tampered_evidence_hard_fails_before_judge(self):
        (self.vault / "objects" / self.evidence_digest).write_bytes(b"tampered")
        with self.assertRaisesRegex(vault.VaultError, "digest mismatch"):
            agents.verify_inventory(self.vault, self.candidate)

    def test_invalid_or_forged_inventory_fails_closed(self):
        with self.assertRaises(agents.AgentContractError):
            self.judge.assess(self.candidate, {self.snapshot_digest: "true"})
        with self.assertRaises(agents.AgentContractError):
            self.judge.assess({"schema_version": 3}, {})
        result = self.judge.assess(self.candidate, {})
        self.assertEqual(result["decision"], "RETURN_FOR_EVIDENCE")

    def test_unknown_provider_does_not_autodiscover_external_code(self):
        with self.assertRaises(agents.AgentContractError):
            agents.investigator_provider("made-up-model")
        with self.assertRaises(agents.AgentContractError):
            agents.judge_provider("made-up-model")

    def test_cli_end_to_end_no_approval_or_vault_mutation_by_judge(self):
        input_path = self.root / "observations.json"
        candidate_path = self.root / "proposal.json"
        report_path = self.root / "advice.json"
        input_path.write_text(json.dumps(self.raw), encoding="utf-8")
        self.assertEqual(main(["agents", "providers"]), 0)
        self.assertEqual(main(["agents", "investigate", "--input", str(input_path), "--out", str(candidate_path)]), 0)
        self.assertTrue(candidate_path.is_file())
        self.assertEqual(main(["agents", "judge", "--input", str(candidate_path), "--vault", str(self.vault),
                               "--out", str(report_path)]), 0)
        result = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(result["authority"], "NONE")
        self.assertEqual(result["decision"], "RETURN_FOR_EVIDENCE")
        self.assertFalse(any(e["type"] == "REVIEW" for e in vault.verify_history(self.vault)))
        self.assertEqual(main(["agents", "judge", "--input", str(candidate_path), "--vault", str(self.vault),
                               "--out", str(report_path)]), 1)

    def test_cli_refuses_to_write_advisory_inside_vault(self):
        src = self.root / "candidate.json"
        src.write_text(json.dumps(self.candidate), encoding="utf-8")
        output = self.vault / "report.json"
        self.assertEqual(main(["agents", "judge", "--input", str(src), "--vault", str(self.vault),
                               "--out", str(output)]), 1)
        self.assertFalse(output.exists())

    def test_cli_without_vault_cannot_claim_integrity(self):
        src = self.root / "candidate.json"
        src.write_text(json.dumps(self.candidate), encoding="utf-8")
        report = self.root / "report.json"
        self.assertEqual(main(["agents", "judge", "--input", str(src), "--out", str(report)]), 0)
        self.assertIn("TARGET_SNAPSHOT_UNCHECKED", json.loads(report.read_text())["rules"][0]["reasons"])

    def test_judge_cannot_generate_approved_status(self):
        proposal = self.judge.assess(self.candidate, agents.verify_inventory(self.vault, self.candidate))
        choices = {row["decision"] for row in proposal["rules"]}
        self.assertTrue(choices <= {"RETURN_FOR_EVIDENCE", "NEEDS_HUMAN_REVIEW"})
        self.assertEqual(proposal["kind"], "ADVISORY_ONLY")


if __name__ == "__main__":
    unittest.main()
