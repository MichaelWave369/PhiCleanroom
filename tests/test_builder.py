import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phicleanroom import builder, sandbox
from phicleanroom.cli import main

IMAGE = "sha256:" + "a" * 64
STAGE = "b" * 64
SPEC = ("# APPROVED BEHAVIORAL SPECIFICATION\n\n"
        "Feature: synthetic\n\n"
        "Implement these observable behaviors independently.\n"
        "Do not access investigator records or original source material.\n\n"
        "## R1\n\nAn exact title query finds its matching item.\n")
SPEC_SHA = hashlib.sha256(SPEC.encode()).hexdigest()
CONTENT = "def search(items, query):\n    return [item for item in items if item.get('title') == query]\n"


def pretend_export(root, stage, destination):
    assert stage == STAGE
    destination.mkdir()
    (destination / "SPEC.md").write_text(SPEC, encoding="utf-8")
    return SPEC_SHA


def candidate_response(**changes):
    envelope = {
        "kind": builder.KIND, "schema_version": 1,
        "spec_sha256": SPEC_SHA, "generator": "reference-exact-title-v1",
        "status": "UNVERIFIED_CANDIDATE", "authority": "NONE",
        "artifacts": [{
            "path": "search.py", "content": CONTENT,
            "sha256": hashlib.sha256(CONTENT.encode()).hexdigest(),
        }],
    }
    envelope.update(changes)
    return json.dumps(envelope)


class IndependentBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / "vault"
        self.private.mkdir()
        self.output = self.root / "quarantined"
        self.receipt = self.root / "build-receipt.json"

    def test_refuses_untested_or_forged_artifact_bytes(self):
        for altered in (
            candidate_response(spec_sha256="f" * 64),
            candidate_response(authority="APPROVED"),
            candidate_response(status="DONE"),
            candidate_response(generator="opportunistic-provider"),
            candidate_response(artifacts=[]),
            candidate_response(artifacts=[{"path": "../escape.py", "content": CONTENT,
                                           "sha256": hashlib.sha256(CONTENT.encode()).hexdigest()}]),
            candidate_response(artifacts=[{"path": "search.py", "content": CONTENT, "sha256": "f" * 64}]),
            candidate_response(artifacts=[{"path": "search.py", "content": CONTENT,
                                           "sha256": hashlib.sha256(CONTENT.encode()).hexdigest(),
                                           "original_source": "forbidden"}]),
            '{"kind":"anything","kind":"other"}',
            "not json",
        ):
            with self.subTest(s=altered[:50]):
                with self.assertRaises(builder.BuilderError):
                    builder.validate_artifacts(altered, SPEC_SHA)

    def test_valid_artifact_has_consistent_digest_but_no_validation(self):
        result = builder.validate_artifacts(candidate_response(), SPEC_SHA)
        self.assertEqual(result[0]["path"], "search.py")
        self.assertEqual(result[0]["content"], CONTENT)
        self.assertEqual(len(result), 1)

    def test_docker_cmd_remains_spec_only_with_fixed_reference_entrypoint(self):
        command = builder.reference_argv(IMAGE, self.root / "packet", "phicleanroom-1234abcd5678ef00")
        self.assertEqual(command[-1], "/app/reference_builder.py")
        self.assertIn("--network", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop", command)
        self.assertNotIn("--privileged", command)
        self.assertEqual(sum("dst=/approved,readonly" in arg for arg in command), 1)

    def test_plan_never_executes_or_writes_outputs(self):
        def bad_runner(*a, **k):
            raise AssertionError("Docker should not launch")
        with patch.object(builder.vault, "export_packet", side_effect=pretend_export):
            result = builder.run_builder(self.private, STAGE, IMAGE,
                                         runner=bad_runner, execute=False)
        self.assertEqual(result["status"], "PLAN_ONLY")
        self.assertEqual(result["authority"], "NONE")
        self.assertFalse(self.output.exists())

    def test_execute_requires_explicit_consent_and_destinations(self):
        with self.assertRaisesRegex(builder.BuilderError, "acknowledge"):
            builder.run_builder(self.private, STAGE, IMAGE, self.output, self.receipt, execute=True)
        with self.assertRaisesRegex(builder.BuilderError, "--out and --receipt"):
            builder.run_builder(self.private, STAGE, IMAGE, execute=True, acknowledge_docker_risk=True)

    def test_execute_writes_quarantine_and_receipt_outside_private_vault(self):
        calls = []
        def fake_runner(argv, **kwargs):
            calls.append(argv)
            if argv[1] == "rm":
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, candidate_response(), "")
        with patch.object(builder.vault, "export_packet", side_effect=pretend_export):
            result = builder.run_builder(
                self.private, STAGE, IMAGE, self.output, self.receipt,
                execute=True, acknowledge_docker_risk=True, runner=fake_runner)
        self.assertEqual(result["status"], "QUARANTINED_UNVERIFIED")
        self.assertEqual(len(calls), 2)
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), ["search.py"])
        self.assertEqual((self.output / "search.py").read_text(), CONTENT)
        metadata = json.loads(self.receipt.read_text())
        self.assertNotIn(CONTENT, self.receipt.read_text())
        self.assertEqual(metadata["authority"], "NONE")
        self.assertEqual(metadata["artifacts"][0]["sha256"],
                         hashlib.sha256(CONTENT.encode()).hexdigest())
        self.assertNotIn("DONE", metadata["status"])

    def test_bad_response_never_creates_output_or_receipt(self):
        def fake_runner(argv, **kwargs):
            if argv[1] == "rm":
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, candidate_response(authority="SHIP"), "")
        with patch.object(builder.vault, "export_packet", side_effect=pretend_export):
            with self.assertRaises(builder.BuilderError):
                builder.run_builder(self.private, STAGE, IMAGE, self.output, self.receipt,
                                    execute=True, acknowledge_docker_risk=True, runner=fake_runner)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.receipt.exists())

    def test_disallow_overlap_or_existing_outputs(self):
        for out, receipt in ((self.private / "artifacts", self.receipt),
                             (self.root, self.receipt),
                             (self.output, self.private / "receipt.json"),
                             (self.output, self.output / "receipt.json")):
            with self.subTest(out=out):
                with self.assertRaises(builder.BuilderError):
                    builder.run_builder(self.private, STAGE, IMAGE, out, receipt,
                                        execute=True, acknowledge_docker_risk=True)
        self.output.mkdir()
        with self.assertRaises(builder.BuilderError):
            builder.run_builder(self.private, STAGE, IMAGE, self.output, self.receipt,
                                execute=True, acknowledge_docker_risk=True)

    def test_digest_disagreement_blocks_any_execution(self):
        def wrong_export(root, stage, packet):
            pretend_export(root, stage, packet)
            return "f" * 64
        with patch.object(builder.vault, "export_packet", side_effect=wrong_export):
            with self.assertRaisesRegex(builder.BuilderError, "digest mismatch"):
                builder.run_builder(self.private, STAGE, IMAGE)
        self.assertFalse(self.output.exists())

    def test_cli_fail_closed_on_unapproved_stage(self):
        self.assertEqual(main(["builder", "reference",
                               "--vault", str(self.private), "--stage", "invalid",
                               "--image", IMAGE]), 1)


if __name__ == "__main__":
    unittest.main()
