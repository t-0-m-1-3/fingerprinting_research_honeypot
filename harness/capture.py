"""tcpdump capture management for the fingerprinting harness."""

import json
import subprocess
import signal
import time
from pathlib import Path

from . import config


def find_bridge_interface() -> str:
    """Find the Docker bridge interface for the harness network."""
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", config.HARNESS_NETWORK],
            capture_output=True, text=True, check=True,
        )
        data = json.loads(result.stdout)
        if data:
            net_id = data[0].get("Id", "")[:12]
            bridge_name = data[0].get("Options", {}).get(
                "com.docker.network.bridge.name", f"br-{net_id}"
            )
            return bridge_name
    except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError):
        pass
    raise RuntimeError(
        f"Cannot find bridge interface for network '{config.HARNESS_NETWORK}'. "
        "Is the harness network created?"
    )


def start_capture(pcap_path: Path) -> subprocess.Popen:
    """Start tcpdump on the harness bridge interface. Returns the process handle."""
    bridge_if = find_bridge_interface()
    pcap_path.parent.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        [
            "sudo", "tcpdump",
            "-i", bridge_if,
            "-w", str(pcap_path),
            "-s", "0",
            f"tcp port {config.HONEYPOT_PORT}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    # Give tcpdump time to start capturing
    time.sleep(1)
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        raise RuntimeError(f"tcpdump failed to start: {stderr}")

    print(f"  tcpdump capturing on {bridge_if} → {pcap_path}")
    return proc


def stop_capture(proc: subprocess.Popen) -> None:
    """Stop tcpdump gracefully."""
    if proc.poll() is None:
        # Send SIGTERM via sudo kill (tcpdump runs as root)
        subprocess.run(["sudo", "kill", str(proc.pid)], capture_output=True)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "kill", "-9", str(proc.pid)], capture_output=True)
            proc.wait(timeout=3)
    print("  tcpdump stopped")
