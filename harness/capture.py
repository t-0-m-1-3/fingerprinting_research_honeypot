"""tcpdump capture management for the fingerprinting harness.

Runs tcpdump inside a privileged Docker container with host networking,
capturing on the Docker bridge interface. This avoids sudo on the host.
"""

import json
import subprocess
import time
from pathlib import Path

from . import config

TCPDUMP_IMAGE = "nicolaka/netshoot:latest"
TCPDUMP_CONTAINER = "harness-tcpdump"


def find_bridge_interface() -> str:
    """Find the Docker bridge interface for the harness network."""
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
    raise RuntimeError(
        f"Cannot find bridge interface for network '{config.HARNESS_NETWORK}'."
    )


def start_capture(pcap_path: Path) -> None:
    """Start tcpdump in a Docker container with host networking.

    Uses --network host so it can capture on the br-* bridge interface
    where all harness container traffic is visible.
    """
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    bridge_if = find_bridge_interface()

    # Stop any leftover capture container
    subprocess.run(
        ["docker", "rm", "-f", TCPDUMP_CONTAINER],
        capture_output=True,
    )

    # Run tcpdump with host networking to access the bridge interface directly.
    # NET_ADMIN + NET_RAW capabilities are needed for packet capture.
    subprocess.run(
        [
            "docker", "run", "-d",
            "--name", TCPDUMP_CONTAINER,
            "--network", "host",
            "--cap-add", "NET_ADMIN",
            "--cap-add", "NET_RAW",
            "-v", f"{pcap_path.parent}:/captures",
            TCPDUMP_IMAGE,
            "tcpdump",
            "-i", bridge_if,
            "-w", f"/captures/{pcap_path.name}",
            "-s", "0",
            f"tcp port {config.HONEYPOT_PORT}",
        ],
        check=True, capture_output=True,
    )

    # Give tcpdump time to start
    time.sleep(2)

    # Verify it's running
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", TCPDUMP_CONTAINER],
        capture_output=True, text=True,
    )
    if result.stdout.strip() != "true":
        logs = subprocess.run(
            ["docker", "logs", TCPDUMP_CONTAINER],
            capture_output=True, text=True,
        )
        raise RuntimeError(f"tcpdump container failed to start: {logs.stderr}")

    print(f"  tcpdump capturing on {bridge_if} (container) → {pcap_path}")


def stop_capture() -> None:
    """Stop the tcpdump container gracefully."""
    # SIGTERM lets tcpdump flush the pcap
    subprocess.run(
        ["docker", "stop", "-t", "5", TCPDUMP_CONTAINER],
        capture_output=True,
    )
    subprocess.run(
        ["docker", "rm", "-f", TCPDUMP_CONTAINER],
        capture_output=True,
    )
    print("  tcpdump stopped")
