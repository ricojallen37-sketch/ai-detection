import os
import subprocess
import sys
import unittest


REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
VERIFY_SCRIPT = os.path.join(REPO_ROOT, "verify_commitment.py")


class VerifyCommitmentTests(unittest.TestCase):
    def test_verify_commitment_script_runs(self):
        result = subprocess.run(
            [sys.executable, VERIFY_SCRIPT],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("COMBINED BUNDLE", result.stdout)


if __name__ == "__main__":
    unittest.main()
