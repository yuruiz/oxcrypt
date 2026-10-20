#!/usr/bin/env python3
"""Verify a Linux desktop window and graceful exit on an isolated X11 display."""

import argparse
import contextlib
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time


class SmokeFailure(RuntimeError):
    pass


def visible_window(pid):
    # --all requires both the process ID and the title to match.
    result = subprocess.run(
        [
            "xdotool", "search", "--all", "--onlyvisible",
            "--pid", str(pid), "--name", "^Oxcrypt$",
        ],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise SmokeFailure(f"Window inspection failed: {result.stderr.strip()}")
    return result.returncode == 0 and bool(result.stdout.strip())


def exercise_desktop(
    command, environment, log_path, find_window=visible_window,
    startup_timeout=30, shutdown_timeout=10, stability_period=1,
):
    """Fail on early exit, absent windows, startup crashes, or unclean shutdown."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as log:
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + startup_timeout
            while True:
                status = process.poll()
                if status is not None:
                    raise SmokeFailure(f"Desktop exited before showing a window: {status}")
                if find_window(process.pid):
                    break
                if time.monotonic() >= deadline:
                    raise SmokeFailure("Desktop did not show its window before the deadline")
                time.sleep(0.05)

            # A tray process can remain alive after its startup window disappears.
            stable_until = time.monotonic() + stability_period
            while time.monotonic() < stable_until:
                status = process.poll()
                if status is not None:
                    raise SmokeFailure(f"Desktop exited immediately after showing a window: {status}")
                if not find_window(process.pid):
                    raise SmokeFailure("Desktop window disappeared during startup")
                time.sleep(min(0.05, max(0, stable_until - time.monotonic())))

            process.send_signal(signal.SIGINT)
            try:
                status = process.wait(timeout=shutdown_timeout)
            except subprocess.TimeoutExpired as error:
                raise SmokeFailure("Desktop did not complete graceful shutdown") from error
            if status != 0:
                raise SmokeFailure(f"Desktop shutdown failed: {status}")
        finally:
            # Only this test's process group is affected, including webview helpers.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--log", type=Path, default=Path("target/linux-desktop-smoke.log"))
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("This acceptance test requires Linux")
    if not os.environ.get("DISPLAY") or shutil.which("xdotool") is None:
        parser.error("Run under xvfb-run with xdotool installed")
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"Desktop executable is missing or not executable: {binary}")

    # Both GUI configuration and the shared CLI mount registry are disposable.
    with tempfile.TemporaryDirectory(prefix="oxcrypt-desktop-smoke-") as root:
        root = Path(root)
        environment = dict(os.environ)
        for name, directory in (
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_RUNTIME_DIR", "runtime"),
        ):
            path = root / directory
            path.mkdir(mode=0o700)
            environment[name] = str(path)
        environment.update(
            OXCRYPT_CONFIG_DIR=str(root / "config" / "oxcrypt"),
            GDK_BACKEND="x11",
            LIBGL_ALWAYS_SOFTWARE="1",
            RUST_LOG="info",
        )
        try:
            exercise_desktop([str(binary)], environment, args.log)
        except (OSError, subprocess.TimeoutExpired, SmokeFailure) as error:
            print(f"FAIL: {error}", file=sys.stderr)
            if args.log.exists():
                print(args.log.read_text(errors="replace")[-12000:], file=sys.stderr)
            return 1
    print("PASS: OxCrypt displayed its own window and exited cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
