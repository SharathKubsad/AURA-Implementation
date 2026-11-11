"""Utility to check and terminate any process listening on a specified port."""

from __future__ import annotations

import sys
import time
import psutil


def free_port(port: int = 8000) -> None:
    print(f"[*] Checking for previously running server instances on port {port}...")
    killed_pids: set[int] = set()

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []

    for conn in conns:
        if conn.laddr.port == port and conn.status == "LISTEN" and conn.pid:
            killed_pids.add(conn.pid)

    if not killed_pids:
        for p in psutil.process_iter(["pid", "name"]):
            try:
                for c in p.net_connections(kind="inet"):
                    if c.laddr.port == port and c.status == "LISTEN":
                        killed_pids.add(p.pid)
            except Exception:
                continue

    if killed_pids:
        for pid in killed_pids:
            try:
                proc = psutil.Process(pid)
                pname = proc.name()
                proc.kill()
                print(f"[*] Found existing server process: {pname} (PID {pid}). Terminated.")
            except Exception as e:
                print(f"[!] Note: Could not terminate PID {pid}: {e}")
        time.sleep(1)
        print(f"[*] Port {port} freed successfully. Ready for clean launch.")
    else:
        print(f"[*] Port {port} is clean and available.")


if __name__ == "__main__":
    target_port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    free_port(target_port)
