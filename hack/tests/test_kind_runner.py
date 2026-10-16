"""Check context isolation/cleanup without claiming a real Kind qualification."""

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLUSTER = "breakglass-operator-runner-e2e"


class KindRunnerTests(unittest.TestCase):
    def test_rejects_non_test_cluster_before_calling_cluster_tools(self):
        env = dict(os.environ, KIND_CLUSTER="production")
        result = subprocess.run(["bash", str(ROOT / "hack/run-kind-e2e.sh"), "helm"],
                                env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing cluster", result.stderr)

    def test_existing_cluster_gets_private_context_and_failure_diagnostics(self):
        for failed in [False, True]:
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                work = pathlib.Path(directory)
                binaries = work / "bin"
                binaries.mkdir()
                normal = work / "normal-kubeconfig"
                normal.write_text("normal-context-must-not-change")
                scripts = {
                    "docker": "exit 0",
                    "make": "exit 0",
                    "kind": '''
if [[ "$1 $2" == 'get clusters' ]]; then echo "$KIND_CLUSTER";
elif [[ "$1 $2" == 'export kubeconfig' ]]; then
  while [[ "$1" != --kubeconfig ]]; do shift; done
  echo "kind-$KIND_CLUSTER" > "$2"
elif [[ "$1" == delete ]]; then touch "$GUARD_DIRECTORY/deleted";
fi
''',
                    "kubectl": '''
if [[ "$1 $2" == 'config current-context' ]]; then cat "$KUBECONFIG"; fi
''',
                    "go": '''
[[ "$KUBECONFIG" != "$GUARD_NORMAL" ]] || exit 42
[[ "$(cat "$KUBECONFIG")" == "kind-$KIND_CLUSTER" ]] || exit 43
echo "$KUBECONFIG" > "$GUARD_DIRECTORY/observed"
exit "$GUARD_EXIT_CODE"
''',
                }
                for name, script in scripts.items():
                    path = binaries / name
                    path.write_text("#!/usr/bin/env bash\nset -eu\n" + script + "\n")
                    path.chmod(0o755)
                env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
                           KIND="kind", KUBECTL="kubectl", KIND_CLUSTER=CLUSTER,
                           KUBECONFIG=str(normal), TMPDIR=directory, GUARD_NORMAL=str(normal),
                           GUARD_DIRECTORY=directory, GUARD_EXIT_CODE="1" if failed else "0",
                           E2E_ARTIFACT_DIR=str(work / "artifacts"), KEEP_TEST_CLUSTER="false")
                result = subprocess.run(["bash", str(ROOT / "hack/run-kind-e2e.sh"), "helm"],
                                        env=env, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 1 if failed else 0, result.stderr)
                self.assertEqual(normal.read_text(), "normal-context-must-not-change")
                private = pathlib.Path((work / "observed").read_text().strip())
                self.assertNotEqual(private, normal)
                self.assertEqual(private.exists(), failed)
                self.assertEqual((work / "deleted").exists(), not failed)
                self.assertTrue((work / "artifacts/test.log").exists())


if __name__ == "__main__":
    unittest.main()
