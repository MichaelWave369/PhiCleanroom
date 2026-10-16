import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phicleanroom import sandbox
from phicleanroom.cli import main

IMAGE = "sha256:" + "a" * 64
STAGE = "b" * 64
SPEC = "# APPROVED BEHAVIORAL SPECIFICATION\n\nFeature: synthetic\n\n## R1\n\nObservable behavior.\n"
SPEC_SHA = hashlib.sha256(SPEC.encode()).hexdigest()


def pretend_export(root, stage, target):
    assert stage == STAGE
    target.mkdir()
    (target / "SPEC.md").write_text(SPEC, encoding="utf-8")
    return SPEC_SHA


def probe_response(**changes):
    report = {
        "kind": sandbox.PROBE_KIND, "spec_sha256": SPEC_SHA,
        "network_reachable": False, "forbidden_paths_visible": False,
        "root_writable": False, "status": "PASS",
    }
    report.update(changes)
    return json.dumps(report)


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.vault = self.root / "private-vault"
        self.vault.mkdir()
        self.receipt = self.root / "probe-receipt.json"

    def test_docker_command_uses_fixed_constrained_argv(self):
        command = sandbox.docker_argv(IMAGE, self.root / "packet", "phicleanroom-1234abcd5678ef00")
        text = " ".join(command)
        for item in ("--network none", "--read-only", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--user 65532:65532",
                     "--pull=never", "--pids-limit 64", "--memory 256m",
                     "--entrypoint python3", "dst=/approved,readonly"):
            self.assertIn(item, text)
        for forbidden in ("/investigator", "/original", "/var/run/docker.sock",
                          "--privileged", "dst=/output"):
            self.assertNotIn(forbidden, text)

    def test_unpinned_and_injectable_images_rejected(self):
        for image in ("python:latest", "sha256:" + "A" * 64,
                      "repo@sha256:" + "a" * 64, "sha256:aa;docker exec"):
            with self.subTest(image=image):
                with self.assertRaises(sandbox.SandboxError):
                    sandbox.docker_argv(image, self.root, "phicleanroom-1234abcd5678ef00")

    def test_no_execute_or_ack_means_no_docker(self):
        with patch.object(sandbox.vault, "export_packet", side_effect=pretend_export):
            result = sandbox.probe(self.vault, STAGE, IMAGE)
        self.assertEqual(result["status"], "PLANNED_ONLY")
        self.assertNotIn("probe", result)
        with self.assertRaisesRegex(sandbox.SandboxError, "acknowledge"):
            sandbox.probe(self.vault, STAGE, IMAGE, self.receipt, execute=True)
        with self.assertRaisesRegex(sandbox.SandboxError, "receipt"):
            sandbox.probe(self.vault, STAGE, IMAGE, execute=True, acknowledge_docker_risk=True)

    def test_good_probe_receipt_is_metadata_only(self):
        commands = []
        def runner(command, **opts):
            commands.append(command)
            if command[1] == "rm":
                return subprocess.CompletedProcess(command, 0, "", "")
            self.assertEqual(opts["timeout"], 60)
            return subprocess.CompletedProcess(command, 0, probe_response(), "")
        with patch.object(sandbox.vault, "export_packet", side_effect=pretend_export):
            result = sandbox.probe(self.vault, STAGE, IMAGE, self.receipt,
                                   execute=True, acknowledge_docker_risk=True, runner=runner)
        self.assertEqual(result["status"], "PROBE_PASS")
        self.assertEqual(len(commands), 2)
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(saved["authority"], "NONE")
        self.assertNotIn(SPEC, self.receipt.read_text())

    def test_failure_does_not_leave_a_fake_pass_receipt(self):
        def runner(command, **opts):
            if command[1] == "rm":
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 0, probe_response(network_reachable=True), "")
        with patch.object(sandbox.vault, "export_packet", side_effect=pretend_export):
            with self.assertRaisesRegex(sandbox.SandboxError, "network_reachable"):
                sandbox.probe(self.vault, STAGE, IMAGE, self.receipt,
                              execute=True, acknowledge_docker_risk=True, runner=runner)
        self.assertFalse(self.receipt.exists())

    def test_fake_stdout_digest_or_boolean_is_refused(self):
        for output in ("not json", probe_response(spec_sha256="f" * 64),
                       probe_response(status="FAIL"), probe_response(root_writable=True),
                       probe_response(network_reachable="false")):
            with self.subTest(output=output[:35]):
                with self.assertRaises(sandbox.SandboxError):
                    sandbox.validate_probe_output(output, SPEC_SHA)

    def test_receipt_cannot_overwrite_or_live_in_vault(self):
        with self.assertRaisesRegex(sandbox.SandboxError, "vault"):
            sandbox.probe(self.vault, STAGE, IMAGE, self.vault / "receipt.json")
        self.receipt.write_text("existing")
        with self.assertRaisesRegex(sandbox.SandboxError, "cannot overwrite"):
            sandbox.probe(self.vault, STAGE, IMAGE, self.receipt)

    def test_wrong_export_digest_blocks_start(self):
        def wrong(root, stage, path):
            pretend_export(root, stage, path)
            return "f" * 64
        with patch.object(sandbox.vault, "export_packet", side_effect=wrong):
            with self.assertRaisesRegex(sandbox.SandboxError, "SHA-256 mismatch"):
                sandbox.probe(self.vault, STAGE, IMAGE)

    def test_invalid_stage_timeout_and_cli_fail_closed(self):
        with self.assertRaises(sandbox.SandboxError):
            sandbox.probe(self.vault, "bad", IMAGE)
        with self.assertRaises(sandbox.SandboxError):
            sandbox.probe(self.vault, STAGE, IMAGE, timeout=900)
        self.assertEqual(main(["sandbox", "probe", "--vault", str(self.vault),
                               "--stage", "invalid", "--image", IMAGE]), 1)


if __name__ == "__main__":
    unittest.main()
