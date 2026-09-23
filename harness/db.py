"""Fingerprint database merge logic."""

import json
from datetime import datetime, timezone
from pathlib import Path


DB_PATH = Path(__file__).parent.parent / "ja4_fingerprints.json"


def load_db(path: Path | None = None) -> dict:
    """Load the fingerprint database."""
    path = path or DB_PATH
    with open(path) as f:
        return json.load(f)


def save_db(db: dict, path: Path | None = None) -> None:
    """Save the fingerprint database."""
    path = path or DB_PATH
    db["version"] = "2.1.0"
    db["generated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(path, "w") as f:
        json.dump(db, f, indent=2)
        f.write("\n")


def find_existing_fingerprint(db: dict, tool_name: str, cipher_hash: str, ext_hash: str) -> dict | None:
    """Find an existing fingerprint entry by tool + JA4 inner hashes."""
    for fp in db.get("fingerprints", []):
        if fp.get("tool") != tool_name:
            continue
        components = fp.get("ja4_components", {})
        if (components.get("cipher_hash") == cipher_hash and
                components.get("ext_hash") == ext_hash):
            return fp
    return None


def merge_fingerprint(
    db: dict,
    tool_name: str,
    tool_version: str,
    ja3_hashes: list[str],
    ja4_strings: list[str],
    sessions: int,
    run_id: str,
) -> tuple[bool, str]:
    """Merge a new fingerprint observation into the database.

    Returns (is_new, description).
    """
    now = datetime.now(timezone.utc).isoformat()

    # Parse JA4 components from the first non-raw JA4 string
    cipher_hash = ext_hash = ""
    ja4_full = ""
    cipher_count = 0
    alpn = "none"

    for ja4 in ja4_strings:
        if ja4.startswith("raw_tls_fields:"):
            continue
        ja4_full = ja4
        parts = ja4.split("_")
        if len(parts) == 3:
            prefix, cipher_hash, ext_hash = parts
            # Parse cipher count and ALPN from prefix
            # Format: t13i3011h2 → cipher_count=30, alpn=h2
            if len(prefix) >= 7:
                try:
                    cipher_count = int(prefix[4:6])
                except ValueError:
                    pass
                alpn_code = prefix[8:] if len(prefix) > 8 else "00"
                alpn = {"h1": "http/1.1", "h2": "h2", "hq": "h3"}.get(alpn_code, "none")
        break

    if not cipher_hash:
        # Only have JA3, no JA4 — still worth recording
        existing = None
        for fp in db.get("fingerprints", []):
            if fp.get("tool") == tool_name:
                existing = fp
                break

        if existing:
            existing.setdefault("harness_metadata", {})["last_seen"] = now
            existing["harness_metadata"]["last_run_id"] = run_id
            obs = existing.get("sessions_observed", {})
            obs["harness"] = obs.get("harness", 0) + sessions
            return False, f"Updated {tool_name} (JA3 only, no JA4 extracted)"

        new_entry = {
            "tool": tool_name,
            "version": tool_version,
            "ja3_hash": {"harness": ja3_hashes[0] if ja3_hashes else ""},
            "sessions_observed": {"harness": sessions},
            "harness_metadata": {
                "first_seen": now,
                "last_seen": now,
                "last_run_id": run_id,
            },
        }
        db.setdefault("fingerprints", []).append(new_entry)
        return True, f"New fingerprint for {tool_name} (JA3 only)"

    # Have JA4 — check for existing
    existing = find_existing_fingerprint(db, tool_name, cipher_hash, ext_hash)

    if existing:
        existing.setdefault("harness_metadata", {})["last_seen"] = now
        existing["harness_metadata"]["last_run_id"] = run_id
        if tool_version and tool_version != existing.get("version", ""):
            existing.setdefault("harness_metadata", {}).setdefault("version_history", []).append(
                {"version": tool_version, "seen": now}
            )
        obs = existing.get("sessions_observed", {})
        obs["harness"] = obs.get("harness", 0) + sessions
        return False, f"Updated {tool_name} — cipher_hash {cipher_hash} already known"

    new_entry = {
        "tool": tool_name,
        "version": tool_version,
        "tls_library": "",
        "ja3_hash": {"harness": ja3_hashes[0] if ja3_hashes else ""},
        "ja4": {"harness": ja4_full},
        "ja4_components": {
            "cipher_hash": cipher_hash,
            "ext_hash": ext_hash,
            "cipher_count": cipher_count,
            "alpn": alpn,
        },
        "sessions_observed": {"harness": sessions},
        "detection_confidence": "pending",
        "harness_metadata": {
            "first_seen": now,
            "last_seen": now,
            "first_run_id": run_id,
            "last_run_id": run_id,
        },
    }
    db.setdefault("fingerprints", []).append(new_entry)
    return True, f"NEW fingerprint: {tool_name} — cipher_hash {cipher_hash}, ext_hash {ext_hash}"
