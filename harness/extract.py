"""JA3/JA4 extraction from PCAP files."""

import csv
import io
import json
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class FingerprintObservation:
    source_ip: str
    dest_ip: str
    timestamp: str
    ja3_hash: str
    ja3_full: str


def extract_ja3_from_pcap(pcap_path: Path) -> list[FingerprintObservation]:
    """Extract JA3 fingerprints from a PCAP using tshark."""
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    result = subprocess.run(
        [
            "tshark", "-r", str(pcap_path),
            "-Y", "tls.handshake.type == 1",
            "-T", "fields",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tls.handshake.ja3",
            "-e", "tls.handshake.ja3_full",
            "-E", "separator=|",
            "-E", "header=n",
        ],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"tshark failed: {result.stderr}")

    observations = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) >= 4:
            observations.append(FingerprintObservation(
                timestamp=parts[0].strip(),
                source_ip=parts[1].strip(),
                dest_ip=parts[2].strip(),
                ja3_hash=parts[3].strip(),
                ja3_full=parts[4].strip() if len(parts) > 4 else "",
            ))

    return observations


def extract_ja4_from_pcap(pcap_path: Path) -> dict[str, list[str]]:
    """Extract JA4 fingerprints grouped by source IP. Returns {ip: [ja4_strings]}.

    Tries pyja4/ja4 CLI first, falls back to manual computation hint.
    """
    ja4_by_ip: dict[str, list[str]] = {}

    # Try the ja4 CLI tool (pip install ja4 / pyja4)
    for cmd in ["ja4", "python3 -m ja4"]:
        try:
            result = subprocess.run(
                cmd.split() + ["-r", str(pcap_path), "--json"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                for entry in data:
                    ip = entry.get("source_ip", entry.get("src", ""))
                    ja4 = entry.get("ja4", entry.get("JA4", ""))
                    if ip and ja4:
                        ja4_by_ip.setdefault(ip, []).append(ja4)
                return ja4_by_ip
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            continue

    # Fallback: extract raw TLS fields for manual JA4 computation
    print("  WARN: ja4 CLI not found. Extracting raw TLS fields for manual JA4 computation.")
    print("  Install: pip install pyja4  OR  pip install ja4")

    result = subprocess.run(
        [
            "tshark", "-r", str(pcap_path),
            "-Y", "tls.handshake.type == 1",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "tls.handshake.version",
            "-e", "tls.handshake.ciphersuite",
            "-e", "tls.handshake.extensions.supported_version",
            "-e", "tls.handshake.extension.type",
            "-e", "tls.handshake.extensions_alpn_str",
            "-E", "separator=|",
        ],
        capture_output=True, text=True,
    )

    if result.returncode == 0:
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|")
            ip = parts[0].strip() if parts else ""
            if ip:
                ja4_by_ip.setdefault(ip, []).append(f"raw_tls_fields:{line.strip()}")

    return ja4_by_ip


def correlate_fingerprints(
    ja3_observations: list[FingerprintObservation],
    ja4_by_ip: dict[str, list[str]],
    ip_to_tool: dict[str, str],
) -> dict[str, dict]:
    """Correlate extracted fingerprints with tool names via IP mapping.

    Returns {tool_name: {ja3_hashes: set, ja4_strings: set, sessions: int}}.
    """
    results: dict[str, dict] = {}

    for obs in ja3_observations:
        tool = ip_to_tool.get(obs.source_ip)
        if not tool:
            continue
        if tool not in results:
            results[tool] = {"ja3_hashes": set(), "ja4_strings": set(), "sessions": 0}
        results[tool]["ja3_hashes"].add(obs.ja3_hash)
        results[tool]["sessions"] += 1

    for ip, ja4_list in ja4_by_ip.items():
        tool = ip_to_tool.get(ip)
        if not tool:
            continue
        if tool not in results:
            results[tool] = {"ja3_hashes": set(), "ja4_strings": set(), "sessions": 0}
        for ja4 in ja4_list:
            results[tool]["ja4_strings"].add(ja4)

    # Convert sets to sorted lists for serialization
    for tool_data in results.values():
        tool_data["ja3_hashes"] = sorted(tool_data["ja3_hashes"])
        tool_data["ja4_strings"] = sorted(tool_data["ja4_strings"])

    return results
