from __future__ import annotations

import sys
import unittest

from testcrewai.tools.shell_runner import ShellRunner


class ShellRunnerTestCase(unittest.TestCase):
    def test_run_success(self) -> None:
        runner = ShellRunner()
        result = runner.run([sys.executable, "-c", "print('ok')"], timeout_sec=3)
        self.assertEqual(result.return_code, 0)
        self.assertIn("ok", result.stdout)
        self.assertFalse(result.timed_out)

    def test_run_timeout(self) -> None:
        runner = ShellRunner()
        result = runner.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout_sec=1)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.return_code, 124)

    def test_run_with_stdin(self) -> None:
        runner = ShellRunner()
        result = runner.run(
            [sys.executable, "-c", "import sys; data=sys.stdin.read(); print(data.upper())"],
            timeout_sec=3,
            stdin_text="abc",
        )
        self.assertEqual(result.return_code, 0)
        self.assertIn("ABC", result.stdout)


if __name__ == "__main__":
    unittest.main()
