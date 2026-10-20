"""Check that the GUI acceptance harness rejects failure paths, without a GUI."""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "linux_desktop_smoke", Path(__file__).with_name("test-linux-desktop.py")
)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

IDLE = """
import signal, sys, time
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
print("READY", flush=True)
while True: time.sleep(0.02)
"""


@unittest.skipUnless(os.name == "posix", "Process-group harness requires POSIX")
class DesktopHarnessTests(unittest.TestCase):
    def exercise(self, script, query=None, shutdown_timeout=1):
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "desktop.log"
            observed_pids = []

            def ready(pid):
                observed_pids.append(pid)
                return "READY" in log.read_text()

            smoke.exercise_desktop(
                [sys.executable, "-c", script],
                dict(os.environ),
                log,
                find_window=ready if query is None else query,
                startup_timeout=1,
                shutdown_timeout=shutdown_timeout,
                stability_period=0.1,
            )
            self.assertTrue(observed_pids)
            self.assertEqual(len(set(observed_pids)), 1)

    def test_visible_window_and_clean_exit(self):
        self.exercise(IDLE)

    def test_early_startup_failure_is_not_a_pass(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "before showing"):
            self.exercise("raise SystemExit(1)", query=lambda _: False)

    def test_running_process_without_a_window_is_not_a_pass(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "did not show"):
            self.exercise(IDLE, query=lambda _: False)

    def test_crash_after_window_creation_is_not_a_pass(self):
        script = 'import time\nprint("READY", flush=True)\ntime.sleep(0.07)\nraise SystemExit(1)'
        with self.assertRaises(smoke.SmokeFailure):
            self.exercise(script)

    def test_window_disappearing_while_process_lives_is_not_a_pass(self):
        visibility = iter([True, False])
        with self.assertRaisesRegex(smoke.SmokeFailure, "window disappeared"):
            self.exercise(IDLE, query=lambda _: next(visibility))

    def test_shutdown_hang_is_not_a_pass(self):
        script = IDLE.replace("lambda *_: sys.exit(0)", "signal.SIG_IGN")
        with self.assertRaisesRegex(smoke.SmokeFailure, "graceful shutdown"):
            self.exercise(script, shutdown_timeout=0.05)


if __name__ == "__main__":
    unittest.main()
