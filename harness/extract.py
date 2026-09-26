"""JA3/JA4 extraction from PCAP files.

Can be run standalone:
    python3 -m harness.extract captures/llm-tools-test.pcap
    python3 -m harness.extract captures/*.pcap --dest-ip 172.30.0.2
    python3 -m harness.extract captures/*.pcap --ip-map '{"172.30.0.75":"hackingbuddygpt"}'
"""

import argparse
import csv
import io
import json
import subprocess
import sys
from collections import defaultdict
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


def extract_ja4_from_pcap(pcap_path: Path, dest_ip: str | None = None) -> dict[str, list[str]]:
    """Extract JA4 fingerprints grouped by source IP. Returns {ip: [ja4_strings]}.

    Uses ja4plus CLI (pip install ja4plus).

    Args:
        dest_ip: If set, only include ClientHellos destined for this IP.
                 Use "172.30.0.2" to filter to honeypot traffic only
                 (excludes Ollama/LLM API traffic).
    """
    ja4_by_ip: dict[str, list[str]] = {}

    # Try ja4plus CLI — venv path first since sg docker / nix-shell may lose PATH
    venv_ja4 = str(Path(__file__).parent.parent / ".venv" / "bin" / "ja4plus")
    for cmd in [[venv_ja4], ["ja4plus"], ["python3", "-m", "ja4plus"]]:
        try:
            result = subprocess.run(
                cmd + ["--format", "json", "--types", "ja4",
                       "analyze", str(pcap_path)],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    ip = entry.get("src_ip", "")
                    dst = entry.get("dst_ip", "")
                    ja4 = entry.get("fingerprint", "")
                    if dest_ip and dst != dest_ip:
                        continue
                    if ip and ja4:
                        ja4_by_ip.setdefault(ip, []).append(ja4)
                return ja4_by_ip
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            continue

    # Fallback: extract raw TLS fields via tshark
    print("  WARN: ja4plus CLI not found. Install: pip install ja4plus")
    print("  Falling back to raw TLS field extraction.")

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


def main():
    parser = argparse.ArgumentParser(
        description="Extract JA4 fingerprints from PCAP files",
    )
    parser.add_argument("pcaps", nargs="+", help="PCAP file(s) to analyze")
    parser.add_argument("--dest-ip", help="Filter to traffic destined for this IP")
    parser.add_argument(
        "--ip-map", help='JSON mapping source IPs to tool names, e.g. \'{"172.30.0.75":"hackingbuddygpt"}\'',
    )
    parser.add_argument("--format", choices=["table", "json"], default="table")
    args = parser.parse_args()

    ip_map = json.loads(args.ip_map) if args.ip_map else {}

    for pcap_file in args.pcaps:
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            print(f"ERROR: {pcap_path} not found", file=sys.stderr)
            continue

        print(f"\n=== {pcap_path.name} ===")
        ja4_by_ip = extract_ja4_from_pcap(pcap_path, dest_ip=args.dest_ip)

        if not ja4_by_ip:
            print("  No JA4 fingerprints found.")
            continue

        # Deduplicate: group unique JA4s per source IP
        summary: dict[str, dict] = {}
        for ip, ja4_list in sorted(ja4_by_ip.items()):
            unique_ja4s = sorted(set(ja4_list))
            tool = ip_map.get(ip, ip)
            summary[tool] = {
                "source_ip": ip,
                "sessions": len(ja4_list),
                "unique_ja4s": unique_ja4s,
            }

        if args.format == "json":
            print(json.dumps(summary, indent=2))
        else:
            for tool, data in summary.items():
                label = tool if tool != data["source_ip"] else data["source_ip"]
                print(f"\n  {label} ({data['sessions']} sessions)")
                for ja4 in data["unique_ja4s"]:
                    parts = ja4.split("_")
                    if len(parts) == 3:
                        print(f"    JA4: {ja4}")
                        print(f"      cipher_hash: {parts[1]}  ext_hash: {parts[2]}")
                    else:
                        print(f"    {ja4}")


if __name__ == "__main__":
    main()
