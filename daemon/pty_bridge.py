"""PTY spawning and WebSocket ↔ PTY bidirectional proxy."""

import asyncio
import json
import os
import pty
import signal
import subprocess
import time
from typing import Callable

from .audit import AuditSession


class PTYError(Exception):
    """PTY operation error."""

    pass


async def run_pty_session(
    shell: str,
    ws_send: Callable,
    ws_recv: Callable,
    audit_session: AuditSession,
    admin_name: str,
    session_id: str,
    idle_timeout_seconds: int,
    hard_timeout_seconds: int,
) -> int:
    """
    Spawn shell under PTY and proxy WebSocket ↔ PTY bidirectionally.

    Args:
        shell: Path to shell (e.g., /bin/bash)
        ws_send: Async callable(message: str | bytes) to send to WebSocket
        ws_recv: Async callable() -> str | bytes to receive from WebSocket
        audit_session: AuditSession for logging
        admin_name: Admin username for logging
        session_id: Session ID for logging
        idle_timeout_seconds: Close if stdin+stdout silent (SEC-REV-3)
        hard_timeout_seconds: Force close after this long (SEC-REV-9)

    Returns: PTY exit code

    Proxying logic:
    - Client sends BINARY frames for PTY stdin (raw UTF-8 bytes).
    - Client sends TEXT (JSON) frames for control: {type: "resize", cols, rows}.
    - Daemon sends PTY output as BINARY frames; control messages as TEXT.
    - ws_recv() returns:
        * bytes   -> stdin
        * str     -> JSON control frame
        * None    -> peer closed; end the session
    - Idle timeout: both stdin AND stdout silent (SEC-REV-3).
    - Hard timeout: force close regardless of activity (SEC-REV-9).
    """
    pid, master_fd = pty.openpty()

    if pid == 0:
        # Child process: exec shell
        os.setsid()  # New session group
        os.dup2(master_fd, 0)  # stdin
        os.dup2(master_fd, 1)  # stdout
        os.dup2(master_fd, 2)  # stderr
        os.execv(shell, [shell, "-i"])  # Interactive login shell
        os._exit(127)

    # Parent: manage PTY
    try:
        # Make PTY non-blocking
        os.set_blocking(master_fd, False)

        # Track timeouts
        session_start = time.time()
        last_activity = session_start
        last_stdin = session_start
        last_stdout = session_start

        while True:
            # Check hard timeout
            elapsed = time.time() - session_start
            if elapsed > hard_timeout_seconds:
                audit_session.write_warning(f"hard timeout at {time.time()}")
                os.kill(pid, signal.SIGTERM)
                break

            # Check idle timeout (both stdin AND stdout silent)
            now = time.time()
            stdin_idle = now - last_stdin
            stdout_idle = now - last_stdout
            if stdin_idle > idle_timeout_seconds and stdout_idle > idle_timeout_seconds:
                audit_session.write_warning(f"idle timeout at {time.time()}")
                os.kill(pid, signal.SIGTERM)
                break

            # Read from PTY (non-blocking, timeout 0.1s)
            try:
                await asyncio.sleep(0.01)  # Yield control
                data = os.read(master_fd, 4096)
                if data:
                    audit_session.write_stdout(data)
                    await ws_send(data)  # Binary frame
                    last_stdout = time.time()
                    last_activity = time.time()
            except (OSError, BlockingIOError):
                pass  # No data available

            # Receive from WebSocket (non-blocking, timeout 0.1s)
            try:
                msg = await asyncio.wait_for(ws_recv(), timeout=0.1)
                if msg is None:
                    # Peer closed — signal the shell and exit the loop.
                    os.kill(pid, signal.SIGHUP)
                    break
                if isinstance(msg, (bytes, bytearray)):
                    data = bytes(msg)
                    # Defence-in-depth cap: the UI already caps pastes at 4KB
                    # (SEC-REV-8 client-side), enforce server-side too so a
                    # patched browser cannot flood the PTY.
                    if len(data) > 4096:
                        await ws_send(
                            json.dumps({
                                "type": "error",
                                "message": "stdin frame exceeds 4KB limit",
                            })
                        )
                        continue
                    os.write(master_fd, data)
                    audit_session.write_stdin(data)
                    last_stdin = time.time()
                    last_activity = time.time()
                elif isinstance(msg, str):
                    try:
                        msg_json = json.loads(msg)
                    except json.JSONDecodeError:
                        continue
                    if msg_json.get("type") == "resize":
                        cols = int(msg_json.get("cols", 80))
                        rows = int(msg_json.get("rows", 24))
                        _set_pty_size(master_fd, rows, cols)

            except asyncio.TimeoutError:
                pass  # No data available

            # Check if child exited
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                # Child exited; read any remaining PTY data
                try:
                    while True:
                        data = os.read(master_fd, 4096)
                        if not data:
                            break
                        audit_session.write_stdout(data)
                        await ws_send(data)
                except OSError:
                    pass

                # Determine exit code
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    exit_code = 128 + os.WTERMSIG(status)
                else:
                    exit_code = 1

                audit_session.close(exit_code=exit_code)
                return exit_code

    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            pass


def _set_pty_size(fd: int, rows: int, cols: int) -> None:
    """Set PTY window size (TIOCSWINSZ)."""
    import fcntl
    import struct
    import termios

    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass  # Ignore errors
