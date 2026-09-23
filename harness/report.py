"""Report generation for fingerprinting harness runs."""

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_report(
    run_id: str,
    tool_results: dict[str, dict],
    merge_results: list[tuple[str, bool, str]],
    metadata: dict,
    report_dir: Path,
) -> Path:
    """Generate a markdown report for a harness run.

    Args:
        run_id: UUID for this run
        tool_results: {tool_name: {ja3_hashes, ja4_strings, sessions}}
        merge_results: [(tool_name, is_new, description), ...]
        metadata: {tool_name: {version, start_time, end_time, exit_code}}
        report_dir: directory to write the report
    """
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{run_id}.md"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    new_count = sum(1 for _, is_new, _ in merge_results if is_new)
    updated_count = sum(1 for _, is_new, _ in merge_results if not is_new)

    lines = [
        f"# Harness Run Report",
        f"",
        f"**Run ID:** `{run_id}`",
        f"**Date:** {now}",
        f"**Tools:** {len(tool_results)}",
        f"**New fingerprints:** {new_count}",
        f"**Updated fingerprints:** {updated_count}",
        f"",
        f"## Results",
        f"",
        f"| Tool | Version | Sessions | JA3 Hashes | JA4 Strings | Status |",
        f"|------|---------|----------|------------|-------------|--------|",
    ]

    for tool_name, is_new, desc in merge_results:
        tr = tool_results.get(tool_name, {})
        meta = metadata.get(tool_name, {})
        version = meta.get("version", "?")
        sessions = tr.get("sessions", 0)
        ja3_count = len(tr.get("ja3_hashes", []))
        ja4_count = len(tr.get("ja4_strings", []))
        status = "NEW" if is_new else "updated"
        lines.append(f"| {tool_name} | {version} | {sessions} | {ja3_count} | {ja4_count} | {status} |")

    lines.append("")
    lines.append("## Details")
    lines.append("")

    for tool_name, is_new, desc in merge_results:
        tr = tool_results.get(tool_name, {})
        meta = metadata.get(tool_name, {})
        lines.append(f"### {tool_name}")
        lines.append(f"")
        lines.append(f"- **Version:** {meta.get('version', '?')}")
        lines.append(f"- **Exit code:** {meta.get('exit_code', '?')}")
        lines.append(f"- **Duration:** {meta.get('duration', '?')}s")
        lines.append(f"- **Sessions:** {tr.get('sessions', 0)}")

        if tr.get("ja3_hashes"):
            lines.append(f"- **JA3:** `{'`, `'.join(tr['ja3_hashes'][:5])}`")
        if tr.get("ja4_strings"):
            for ja4 in tr["ja4_strings"][:5]:
                if not ja4.startswith("raw_tls_fields:"):
                    lines.append(f"- **JA4:** `{ja4}`")

        lines.append(f"- **{desc}**")
        lines.append("")

    # Errors
    errors = [(name, m) for name, m in metadata.items() if m.get("exit_code", 0) != 0]
    if errors:
        lines.append("## Errors")
        lines.append("")
        for name, m in errors:
            lines.append(f"- **{name}**: exit code {m['exit_code']}")
            if m.get("error"):
                lines.append(f"  ```")
                lines.append(f"  {m['error'][:500]}")
                lines.append(f"  ```")
        lines.append("")

    report_content = "\n".join(lines)
    report_path.write_text(report_content)

    # Also print summary to stdout
    print(f"\n{'='*60}")
    print(f"  Run {run_id}")
    print(f"  {len(tool_results)} tools, {new_count} new, {updated_count} updated")
    print(f"{'='*60}")
    for tool_name, is_new, desc in merge_results:
        marker = " NEW " if is_new else "  ~  "
        print(f"  [{marker}] {desc}")
    print(f"\n  Report: {report_path}")

    return report_path
