"""Exercise immutable image validation for the successful CI artifact."""

import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
REVISION = "a" * 40
OPERATOR = "ghcr.io/example/breakglass-operator"
WEBUI = "ghcr.io/example/breakglass-webui"


class ReleaseManifestTests(unittest.TestCase):
    def test_gate_selects_only_the_successful_matching_main_run(self):
        def run(identity, **changes):
            return dict(id=identity, head_sha=REVISION, head_branch="main", event="push",
                        status="completed", conclusion="success", **changes)

        passed = run(9)
        failed = {**passed, "id": 10, "conclusion": "failure"}
        wrong_source = {**passed, "id": 11, "head_sha": "b" * 40}
        wrong_branch = {**passed, "id": 12, "head_branch": "feature"}
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "outputs"
            result = subprocess.run([
                "python3", str(ROOT / "hack/require-release-ci.py"), REVISION,
                "--github-output", str(output),
            ], input=json.dumps({"workflow_runs": [passed, failed, wrong_source, wrong_branch]}),
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), "run_id=9\n")

    def test_only_matching_bundle_can_supply_image_digests(self):
        for case in ["valid", "wrong-source", "wrong-repository", "mutable-tag"]:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                manifest = {
                    "schemaVersion": 1,
                    "sourceRevision": REVISION if case != "wrong-source" else "b" * 40,
                    "images": {
                        "operator": OPERATOR + "@sha256:" + "c" * 64,
                        "webui": WEBUI + "@sha256:" + "d" * 64,
                    },
                }
                if case == "wrong-repository":
                    manifest["images"]["webui"] = "ghcr.io/other/webui@sha256:" + "d" * 64
                if case == "mutable-tag":
                    manifest["images"]["webui"] = WEBUI + ":latest"
                path = pathlib.Path(directory) / "release.json"
                output = pathlib.Path(directory) / "outputs"
                path.write_text(json.dumps(manifest))
                result = subprocess.run([
                    "python3", str(ROOT / "hack/read-release-images.py"), str(path), REVISION,
                    "--operator-repository", OPERATOR, "--webui-repository", WEBUI,
                    "--github-output", str(output),
                ], capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode == 0, case == "valid", result.stderr)
                if case == "valid":
                    self.assertIn("webui_digest=sha256:" + "d" * 64, output.read_text())
                else:
                    self.assertFalse(output.exists(), "invalid bundle must not produce workflow outputs")


if __name__ == "__main__":
    unittest.main()
