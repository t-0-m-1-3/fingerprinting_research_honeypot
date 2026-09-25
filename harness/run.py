#!/usr/bin/env python3
"""Fingerprinting harness orchestrator.

Spins up the honeypot, runs scanner tools in isolated Docker containers,
captures TLS traffic, extracts JA3/JA4 fingerprints, and merges results
into the fingerprint database.

Usage:
    python3 -m harness.run --tools curl
    python3 -m harness.run --tools nikto,gobuster,ffuf
    python3 -m harness.run --category cat1-scanners
    python3 -m harness.run --all
    python3 -m harness.run --tools curl --dry-run
"""

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import config
from .capture import start_capture, stop_capture
from .extract import extract_ja3_from_pcap, extract_ja4_from_pcap, correlate_fingerprints
from .db import load_db, save_db, merge_fingerprint
from .report import generate_report

HARNESS_DIR = Path(__file__).parent
PROJECT_ROOT = HARNESS_DIR.parent
CAPTURES_DIR = HARNESS_DIR / "captures"
REPORTS_DIR = HARNESS_DIR / "reports"
COMPOSE_FILE = HARNESS_DIR / "docker-compose.harness.yml"


def ensure_network() -> None:
    """Create the harness Docker network if it doesn't exist."""
    result = subprocess.run(
        ["docker", "network", "inspect", config.HARNESS_NETWORK],
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"  Creating network {config.HARNESS_NETWORK} ({config.HARNESS_SUBNET})")
        subprocess.run(
            [
                "docker", "network", "create",
                "--driver", "bridge",
                "--subnet", config.HARNESS_SUBNET,
                config.HARNESS_NETWORK,
            ],
            check=True, capture_output=True,
        )


def ensure_honeypot() -> None:
    """Start the honeypot and attach it to the harness network."""
    # Build and start honeypot
    print("  Starting honeypot...")
    subprocess.run(
        ["docker", "compose", "-f", str(PROJECT_ROOT / "honeypot" / "docker-compose.yml"),
         "up", "-d", "--build"],
        check=True, capture_output=True, cwd=str(PROJECT_ROOT / "honeypot"),
    )

    # Connect honeypot to harness network with static IP
    container_name = "quiet-room-honeypot"
    result = subprocess.run(
        ["docker", "network", "connect", "--ip", config.HONEYPOT_IP,
         config.HARNESS_NETWORK, container_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0 and "already exists" not in result.stderr:
        # Might already be connected
        if "Error" in result.stderr:
            print(f"  WARN: {result.stderr.strip()}")

    # Wait for honeypot to be healthy
    for _ in range(10):
        check = subprocess.run(
            ["docker", "exec", container_name,
             "curl", "-sf", "http://localhost:8080/api/v1/health"],
            capture_output=True,
        )
        if check.returncode == 0:
            print(f"  Honeypot ready at {config.HONEYPOT_IP}:{config.HONEYPOT_PORT}")
            return
        time.sleep(1)
    print("  WARN: Honeypot health check did not pass, proceeding anyway")


def ensure_ollama() -> None:
    """Start the Ollama sidecar container on harness-net and pull the model."""
    # Check if already running with model present
    result = subprocess.run(
        ["docker", "inspect", config.OLLAMA_CONTAINER],
        capture_output=True,
    )
    if result.returncode == 0:
        # Check if model is already pulled
        model_check = subprocess.run(
            ["docker", "exec", config.OLLAMA_CONTAINER, "ollama", "list"],
            capture_output=True, text=True,
        )
        if config.OLLAMA_MODEL in (model_check.stdout or ""):
            print(f"  Ollama ready at {config.OLLAMA_IP}:{config.OLLAMA_PORT} with {config.OLLAMA_MODEL}")
            return
        # Container exists but model missing — need to pull
        print(f"  Ollama running but model {config.OLLAMA_MODEL} not found, pulling...")
    else:
        print(f"  Starting Ollama ({config.OLLAMA_IMAGE})...")
        subprocess.run(
            [
                "docker", "run", "-d",
                "--name", config.OLLAMA_CONTAINER,
                "--network", config.HARNESS_NETWORK,
                "--ip", config.OLLAMA_IP,
                config.OLLAMA_IMAGE,
            ],
            check=True, capture_output=True,
        )

    # Wait for Ollama API to be ready
    for i in range(30):
        check = subprocess.run(
            ["docker", "exec", config.OLLAMA_CONTAINER,
             "ollama", "list"],
            capture_output=True,
        )
        if check.returncode == 0:
            break
        time.sleep(2)
    else:
        print("  WARN: Ollama health check timed out")
        return

    # Check if model already exists
    model_check = subprocess.run(
        ["docker", "exec", config.OLLAMA_CONTAINER, "ollama", "list"],
        capture_output=True, text=True,
    )
    if config.OLLAMA_MODEL in (model_check.stdout or ""):
        print(f"  Ollama ready at {config.OLLAMA_IP}:{config.OLLAMA_PORT} with {config.OLLAMA_MODEL}")
        return

    # Temporarily connect to default bridge for internet access (model download)
    print(f"  Pulling model {config.OLLAMA_MODEL} (connecting to internet temporarily)...")
    subprocess.run(
        ["docker", "network", "connect", "bridge", config.OLLAMA_CONTAINER],
        capture_output=True,
    )
    try:
        subprocess.run(
            ["docker", "exec", config.OLLAMA_CONTAINER,
             "ollama", "pull", config.OLLAMA_MODEL],
            check=True, timeout=900,
        )
    finally:
        # Always disconnect from internet after pull
        subprocess.run(
            ["docker", "network", "disconnect", "bridge", config.OLLAMA_CONTAINER],
            capture_output=True,
        )
    print(f"  Ollama ready at {config.OLLAMA_IP}:{config.OLLAMA_PORT} with {config.OLLAMA_MODEL}")


def stop_ollama() -> None:
    """Stop and remove the Ollama sidecar container."""
    subprocess.run(
        ["docker", "rm", "-f", config.OLLAMA_CONTAINER],
        capture_output=True,
    )


def build_tool_image(tool: config.ToolSpec) -> str:
    """Build the Docker image for a tool. Returns the image tag."""
    if not tool.dockerfile:
        # Validation tools use existing images
        if tool.name == "curl":
            return "curlimages/curl:latest"
        return ""

    tag = f"harness-{tool.name}:latest"
    dockerfile_path = HARNESS_DIR / "tools" / tool.dockerfile

    if not dockerfile_path.exists():
        raise FileNotFoundError(
            f"Dockerfile not found: {dockerfile_path}. "
            f"Tool '{tool.name}' may not be implemented yet."
        )

    print(f"  Building {tag}...")
    subprocess.run(
        ["docker", "build", "-t", tag, "-f", str(dockerfile_path), str(HARNESS_DIR)],
        check=True, capture_output=True,
    )
    return tag


def get_tool_version(image: str, tool: config.ToolSpec) -> str:
    """Extract the tool's version string from its container."""
    if not tool.version_command:
        return "unknown"

    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", ""] + [image] + tool.version_command,
            capture_output=True, text=True, timeout=15,
        )
        version = result.stdout.strip().split("\n")[0] if result.stdout else ""
        return version or result.stderr.strip().split("\n")[0]
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return "unknown"


def run_tool(image: str, tool: config.ToolSpec) -> dict:
    """Run a tool container against the honeypot. Returns metadata."""
    # Substitute target placeholders in scan command
    cmd = []
    for arg in tool.scan_command:
        cmd.append(
            arg.replace("{target_url}", config.TARGET_URL)
               .replace("{target_ip}", config.HONEYPOT_IP)
               .replace("{target_host}", config.HONEYPOT_IP)
               .replace("{target_port}", str(config.HONEYPOT_PORT))
        )

    docker_cmd = [
        "docker", "run", "--rm",
        "--network", config.HARNESS_NETWORK,
        "--ip", tool.static_ip,
    ]

    if tool.needs_wordlist:
        wordlist_dir = HARNESS_DIR / "wordlists"
        docker_cmd += ["-v", f"{wordlist_dir}:/wordlists:ro"]

    # Mount wrapper scripts if the scan command references them
    scripts_dir = HARNESS_DIR / "scripts"
    if any("/scripts/" in arg for arg in tool.scan_command):
        docker_cmd += ["-v", f"{scripts_dir}:/scripts:ro"]

    # Inject LLM provider env vars (API keys, endpoints)
    for env_key, env_val in tool.llm_env_vars.items():
        # Substitute target placeholders in env values
        env_val = (env_val
                   .replace("{target_url}", config.TARGET_URL)
                   .replace("{target_ip}", config.HONEYPOT_IP)
                   .replace("{target_port}", str(config.HONEYPOT_PORT)))
        # Resolve {ENV_VAR} placeholders from host environment
        if env_val.startswith("{") and env_val.endswith("}"):
            host_key = env_val[1:-1]
            env_val = os.environ.get(host_key, "")
            if not env_val and host_key.endswith("_API_KEY"):
                print(f"  WARN: {host_key} not set in environment")
        docker_cmd += ["-e", f"{env_key}={env_val}"]

    docker_cmd += ["--entrypoint", ""]
    docker_cmd += [image] + cmd

    start = time.time()
    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True, text=True,
            timeout=tool.timeout_seconds,
        )
        duration = round(time.time() - start, 1)
        return {
            "exit_code": result.returncode,
            "duration": duration,
            "error": result.stderr[:500] if result.returncode != 0 else "",
        }
    except subprocess.TimeoutExpired:
        duration = round(time.time() - start, 1)
        return {
            "exit_code": -1,
            "duration": duration,
            "error": f"Timeout after {tool.timeout_seconds}s",
        }


def main():
    parser = argparse.ArgumentParser(description="TLS Fingerprinting Harness")
    parser.add_argument("--tools", help="Comma-separated tool names")
    parser.add_argument("--category", help="Run all tools in a category")
    parser.add_argument("--all", action="store_true", help="Run all tools")
    parser.add_argument("--dry-run", action="store_true", help="Print what would run")
    parser.add_argument("--skip-build", action="store_true", help="Reuse cached images")
    args = parser.parse_args()

    tool_names = args.tools.split(",") if args.tools else None
    try:
        tools = config.resolve_tool_names(tool_names, args.category, args.all)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    run_id = str(uuid.uuid4())[:8]
    print(f"\nFingerprinting Harness — run {run_id}")
    print(f"  Tools: {', '.join(t.name for t in tools)}")

    if args.dry_run:
        print("\n  DRY RUN — would execute:")
        for t in tools:
            cmd_str = " ".join(t.scan_command).replace("{target_url}", config.TARGET_URL)
            print(f"    {t.name} ({t.static_ip}): {cmd_str}")
        return

    # Setup
    needs_ollama = any(t.needs_ollama for t in tools)
    print("\n[1/5] Setting up infrastructure...")
    ensure_network()
    ensure_honeypot()
    if needs_ollama:
        ensure_ollama()

    # Start capture
    print("\n[2/5] Starting packet capture...")
    pcap_path = CAPTURES_DIR / f"{run_id}.pcap"
    start_capture(pcap_path)

    # Run tools
    print(f"\n[3/5] Running {len(tools)} tools...")
    metadata: dict[str, dict] = {}
    ip_to_tool: dict[str, str] = {}

    for tool in tools:
        print(f"\n  --- {tool.name} ({tool.category}) ---")
        ip_to_tool[tool.static_ip] = tool.name

        try:
            if not args.skip_build:
                image = build_tool_image(tool)
            else:
                image = f"harness-{tool.name}:latest" if tool.dockerfile else "curlimages/curl:latest"

            version = get_tool_version(image, tool)
            print(f"  Version: {version}")

            print(f"  Running scan (timeout {tool.timeout_seconds}s)...")
            result = run_tool(image, tool)
            result["version"] = version
            metadata[tool.name] = result

            status = "OK" if result["exit_code"] == 0 else f"exit {result['exit_code']}"
            print(f"  Done in {result['duration']}s — {status}")

        except FileNotFoundError as e:
            print(f"  SKIP: {e}")
            metadata[tool.name] = {"exit_code": -2, "duration": 0, "error": str(e), "version": "n/a"}
        except Exception as e:
            print(f"  ERROR: {e}")
            metadata[tool.name] = {"exit_code": -3, "duration": 0, "error": str(e), "version": "n/a"}

    # Stop capture
    print("\n[4/5] Stopping capture and extracting fingerprints...")
    time.sleep(2)  # Let final packets flush
    stop_capture()

    # Extract fingerprints
    ja3_observations = extract_ja3_from_pcap(pcap_path)
    ja4_by_ip = extract_ja4_from_pcap(pcap_path)
    tool_results = correlate_fingerprints(ja3_observations, ja4_by_ip, ip_to_tool)

    print(f"  Extracted {len(ja3_observations)} JA3 observations")
    print(f"  JA4 data for {len(ja4_by_ip)} source IPs")

    # Merge into database
    print("\n[5/5] Merging into fingerprint database...")
    db = load_db()
    merge_results: list[tuple[str, bool, str]] = []

    for tool_name, tr in tool_results.items():
        is_new, desc = merge_fingerprint(
            db=db,
            tool_name=tool_name,
            tool_version=metadata.get(tool_name, {}).get("version", ""),
            ja3_hashes=tr["ja3_hashes"],
            ja4_strings=tr["ja4_strings"],
            sessions=tr["sessions"],
            run_id=run_id,
        )
        merge_results.append((tool_name, is_new, desc))

    save_db(db)

    # Generate report
    report_path = generate_report(
        run_id=run_id,
        tool_results=tool_results,
        merge_results=merge_results,
        metadata=metadata,
        report_dir=REPORTS_DIR,
    )


if __name__ == "__main__":
    main()
