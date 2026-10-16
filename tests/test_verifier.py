"""Host verifier tests do not execute untrusted source on host."""
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phicleanroom import sandbox, verifier
from phicleanroom.cli import main

STAGE = "b" * 64
IMAGE = "sha256:" + "a" * 64
SPEC = ("# APPROVED BEHAVIORAL SPECIFICATION\n\nFeature: Synthetic\n\n"
        "Implement these observable behaviors independently.\n"
        "Do not access investigator records or original source material.\n\n"
        "## R1\n\nAn exact title query finds its matching item.\n")
SPEC_SHA = hashlib.sha256(SPEC.encode()).hexdigest()
SOURCE = 'def search(items, query):\n    return [item for item in items if item.get("title") == query]\n'
SOURCE_SHA = hashlib.sha256(SOURCE.encode()).hexdigest()


def approved_export(vault_dir, stage, output):
    assert stage == STAGE
    output.mkdir()
    (output / "SPEC.md").write_text(SPEC, encoding="utf-8")
    return SPEC_SHA


def good_result():
    return {
        "schema_version": 1, "kind": verifier.KIND, "stage_sha256": STAGE,
        "spec_sha256": SPEC_SHA, "source_sha256": SOURCE_SHA,
        "suite": "reference-exact-title-acceptance-v1",
        "checks": [{"id": name, "status": "PASS"} for name in verifier.REQUIRED_CHECKS],
        "mutants": [
            {"id": name, "status": "KILLED_ASSERTION",
             "source_sha256": hashlib.sha256(name.encode()).hexdigest(),
             "failed_check": "exact_title"} for name in verifier.REQUIRED_MUTANTS
        ],
        "status": "CHECKS_PASS_MUTANTS_KILLED", "authority": "NONE",
    }


def build_receipt():
    return {
        "schema_version": 1, "kind": "INDEPENDENT_BUILDER_RECEIPT",
        "status": "QUARANTINED_UNVERIFIED", "stage_sha256": STAGE,
        "spec_sha256": SPEC_SHA, "image_id": IMAGE, "authority": "NONE",
        "builder": "reference-exact-title-v1", "container_policy": sandbox.policy(),
        "artifacts": [{"path": "search.py", "sha256": SOURCE_SHA}],
        "note": "Demo worker: no release authority.",
    }


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault = self.root / "vault"
        self.vault.mkdir()
        self.artifacts = self.root / "quarantine"
        self.artifacts.mkdir()
        (self.artifacts / "search.py").write_text(SOURCE, encoding="utf-8")
        self.builder_receipt = self.root / "build.json"
        self.builder_receipt.write_text(json.dumps(build_receipt()))
        self.verification_receipt = self.root / "verified.json"

    def test_accepts_only_full_pinned_suite(self):
        report = good_result()
        self.assertEqual(verifier.validate_result(json.dumps(report), STAGE, SPEC_SHA, SOURCE_SHA), report)
        for key, wrong in (("status", "DONE"), ("authority", "APPROVED"),
                           ("spec_sha256", "f"*64), ("source_sha256", "e"*64),
                           ("stage_sha256", "d"*64), ("suite", "unknown")):
            altered = copy.deepcopy(report)
            altered[key] = wrong
            with self.subTest(key=key), self.assertRaises(verifier.VerifyError):
                verifier.validate_result(json.dumps(altered), STAGE, SPEC_SHA, SOURCE_SHA)

    def test_required_mutants_cannot_survive_or_be_missing(self):
        for changed in ("SURVIVED", "CRASH", "TIMEOUT"):
            altered = good_result()
            altered["mutants"][1]["status"] = changed
            with self.assertRaises(verifier.VerifyError):
                verifier.validate_result(json.dumps(altered), STAGE, SPEC_SHA, SOURCE_SHA)
        for value in ([good_result()["mutants"][0]], []):
            altered = good_result()
            altered["mutants"] = value
            with self.assertRaises(verifier.VerifyError):
                verifier.validate_result(json.dumps(altered), STAGE, SPEC_SHA, SOURCE_SHA)
        altered = good_result()
        altered["mutants"][1]["source_sha256"] = altered["mutants"][0]["source_sha256"]
        with self.assertRaisesRegex(verifier.VerifyError, "duplicated"):
            verifier.validate_result(json.dumps(altered), STAGE, SPEC_SHA, SOURCE_SHA)

    def test_missing_or_failed_acceptance_check_blocks(self):
        altered = good_result()
        altered["checks"][2]["status"] = "FAIL"
        with self.assertRaises(verifier.VerifyError):
            verifier.validate_result(json.dumps(altered), STAGE, SPEC_SHA, SOURCE_SHA)
        altered = good_result()
        altered["checks"] = altered["checks"][:-1]
        with self.assertRaises(verifier.VerifyError):
            verifier.validate_result(json.dumps(altered), STAGE, SPEC_SHA, SOURCE_SHA)

    def test_malformed_and_duplicate_output_rejected(self):
        for response in ("not JSON", '{"kind":1,"kind":2}', "{}", "x"*33000):
            with self.subTest(sample=response[:12]), self.assertRaises(verifier.VerifyError):
                verifier.validate_result(response, STAGE, SPEC_SHA, SOURCE_SHA)

    def test_input_receipt_and_source_are_bound_to_exact_bytes(self):
        value = verifier._load_receipt(self.builder_receipt, STAGE, SPEC_SHA, SOURCE_SHA)
        self.assertEqual(value["status"], "QUARANTINED_UNVERIFIED")
        altered = build_receipt()
        altered["artifacts"][0]["sha256"] = "f"*64
        self.builder_receipt.write_text(json.dumps(altered))
        with self.assertRaises(verifier.VerifyError):
            verifier._load_receipt(self.builder_receipt, STAGE, SPEC_SHA, SOURCE_SHA)

    def test_plan_does_not_launch_or_create_output(self):
        def denied(*args, **kwargs):
            raise AssertionError("Docker should never execute during plan")
        with patch.object(verifier.vault, "export_packet", side_effect=approved_export):
            report = verifier.verify(self.vault, STAGE, self.artifacts,
                                     self.builder_receipt, IMAGE, runner=denied)
        self.assertEqual(report["status"], "PLAN_ONLY")
        self.assertFalse(self.verification_receipt.exists())

    def test_execution_runs_separate_image_and_creates_receipt(self):
        calls = []
        def pretend(argv, **kwargs):
            calls.append(argv)
            if argv[1] == "rm":
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, json.dumps(good_result()), "")
        with patch.object(verifier.vault, "export_packet", side_effect=approved_export):
            result = verifier.verify(
                self.vault, STAGE, self.artifacts, self.builder_receipt,
                IMAGE, self.verification_receipt, execute=True,
                acknowledge_docker_risk=True, runner=pretend)
        self.assertEqual(result["status"], "REFERENCE_CHECKS_PASS")
        self.assertEqual(result["authority"], "NONE")
        self.assertEqual(len(calls), 2)
        argv = calls[0]
        self.assertEqual(argv[-1], "/app/verify_worker.py")
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network")+1], "none")
        self.assertIn("PHICLEANROOM_STAGE_SHA="+STAGE, argv)
        self.assertEqual(sorted(p.name for p in self.artifacts.iterdir()), ["search.py"])
        receipt = json.loads(self.verification_receipt.read_text())
        self.assertEqual(receipt["source_sha256"], SOURCE_SHA)

    def test_bad_mutant_never_writes_receipt(self):
        result = good_result()
        result["mutants"][0]["status"] = "SURVIVED"
        def runner(argv, **kwargs):
            if argv[1] == "rm":
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, json.dumps(result), "")
        with patch.object(verifier.vault, "export_packet", side_effect=approved_export):
            with self.assertRaises(verifier.VerifyError):
                verifier.verify(self.vault, STAGE, self.artifacts,
                                self.builder_receipt, IMAGE, self.verification_receipt,
                                execute=True, acknowledge_docker_risk=True, runner=runner)
        self.assertFalse(self.verification_receipt.exists())

    def test_source_tamper_and_sibling_files_block(self):
        (self.artifacts / "search.py").write_text("def search(*args): return []")
        with self.assertRaisesRegex(verifier.VerifyError, "builder receipt"):
            with patch.object(verifier.vault, "export_packet", side_effect=approved_export):
                verifier.verify(self.vault, STAGE, self.artifacts, self.builder_receipt, IMAGE)
        (self.artifacts / "extra.txt").write_text("forbidden")
        with self.assertRaises(verifier.VerifyError):
            verifier.verify(self.vault, STAGE, self.artifacts, self.builder_receipt, IMAGE)

    def test_forbid_output_within_vault_or_quarantine_and_unconsented_execution(self):
        with self.assertRaises(verifier.VerifyError):
            verifier.verify(self.vault, STAGE, self.artifacts, self.builder_receipt,
                            IMAGE, self.artifacts / "receipt.json")
        with self.assertRaises(verifier.VerifyError):
            verifier.verify(self.vault, STAGE, self.artifacts, self.builder_receipt,
                            IMAGE, self.vault / "receipt.json")
        with self.assertRaisesRegex(verifier.VerifyError, "acknowledge"):
            verifier.verify(self.vault, STAGE, self.artifacts, self.builder_receipt,
                            IMAGE, self.verification_receipt, execute=True)

    def test_cli_rejects_invalid_stage(self):
        status = main(["verify", "reference", "--vault", str(self.vault),
                       "--stage", "bad", "--artifacts", str(self.artifacts),
                       "--builder-receipt", str(self.builder_receipt), "--image", IMAGE])
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
