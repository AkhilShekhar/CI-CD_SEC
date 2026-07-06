"""Orchestrator: crawls the filesystem, runs the 4 rules from rules.py on
every scannable file, filters false positives, and writes security_report.md."""

import os
import subprocess
from pathlib import Path

from rules import ALL_RULES, Finding, apply_false_positive_filter
from github_comment import post_or_update_comment

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".yml", ".yaml", ".json", ".env", ".toml", ".cfg", ".ini", ".sh", ".txt",
}

IGNORE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "env", "site-packages", "__pycache__"}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def get_changed_files(base_ref: str) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACM", f"{base_ref}...HEAD"],
            capture_output=True, text=True, check=True,
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]
    except subprocess.CalledProcessError:
        return []


def walk_repo(root: str) -> list[str]:
    files = []
    root_path = Path(root)
    for path in root_path.rglob("*"):
        if not path.is_file() or path.suffix not in SCANNABLE_EXTENSIONS:
            continue
        rel = path.relative_to(root_path)
        if set(rel.parts) & IGNORE_DIRS:
            continue
        files.append(str(rel))
    return files


def resolve_target_files(root: str, diff_only: bool, base_ref: str) -> list[str]:
    if diff_only:
        changed = [f for f in get_changed_files(base_ref) if Path(f).suffix in SCANNABLE_EXTENSIONS]
        if changed:
            return changed
    return walk_repo(root)


def scan_files(root: str, files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel_path in files:
        full_path = Path(root) / rel_path
        try:
            content = full_path.read_text(errors="ignore")
        except (FileNotFoundError, IsADirectoryError):
            continue
        for rule_id, rule_fn in ALL_RULES.items():
            findings.extend(rule_fn(rel_path, content))
    return findings


def build_report(findings: list[Finding]) -> str:
    active = sorted([f for f in findings if not f.suppressed], key=lambda f: SEVERITY_ORDER[f.severity])
    suppressed = [f for f in findings if f.suppressed]

    lines = ["## 🔒 SecScan Security Report", ""]

    if not active:
        lines.append("✅ No security issues found in the scanned files.")
    else:
        counts = {}
        for f in active:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = " · ".join(f"{SEVERITY_EMOJI[sev]} {count} {sev}" for sev, count in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER[kv[0]]))
        lines.append(f"**{len(active)} issue(s) found:** {summary}")
        lines.append("")
        lines.append("| Severity | Rule | File:Line | Issue |")
        lines.append("|---|---|---|---|")
        for f in active:
            lines.append(f"| {SEVERITY_EMOJI[f.severity]} {f.severity} | {f.rule_id} | `{f.file}:{f.line}` | {f.message} |")
        lines.append("")
        lines.append("<details><summary>Show matched snippets</summary>")
        lines.append("")
        for f in active:
            lines.append(f"**`{f.file}:{f.line}`** ({f.rule_id}) — {f.message}")
            lines.append(f"```\n{f.snippet}\n```")
        lines.append("</details>")

    if suppressed:
        lines.append("")
        lines.append(f"<details><summary>ℹ️ {len(suppressed)} finding(s) suppressed as likely false positives</summary>")
        lines.append("")
        for f in suppressed:
            lines.append(f"- `{f.file}:{f.line}` ({f.rule_id}): {f.message} — _{f.suppressed_reason}_")
        lines.append("</details>")

    lines.append("")
    lines.append("<!-- secscan-report -->")
    return "\n".join(lines)


def main():
    root = os.environ.get("SCAN_ROOT", ".")
    output_dir = os.environ.get("OUTPUT_DIR", "./secscan-output")
    print("output_dir is:", output_dir)

    diff_only = os.environ.get("DIFF_ONLY", "true").lower() == "true"
    base_ref = os.environ.get("BASE_REF", "origin/main")

    files = resolve_target_files(root, diff_only, base_ref)
    findings = scan_files(root, files)
    findings = apply_false_positive_filter(findings)
    report = build_report(findings)

    out_dir_path = Path(output_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    (out_dir_path / "security_report.md").write_text(report)
    print(report)

    post_or_update_comment(report)

    active_critical_high = [f for f in findings if not f.suppressed and f.severity in ("critical", "high")]
    if active_critical_high:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
