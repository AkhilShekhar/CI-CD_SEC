"""Core detection engine: 4 rules that each scan one file's content and
return a list of Finding objects. Also holds the false-positive filter that
sits between "raw matches" and "what we actually report"."""

import math
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    severity: str          # critical | high | medium | low
    file: str
    line: int
    message: str
    snippet: str
    suppressed: bool = False
    suppressed_reason: str = ""


# ---------------------------------------------------------------------------
# Shared false-positive helpers
# ---------------------------------------------------------------------------

PLACEHOLDER_HINTS = (
    "changeme", "change_me", "your_key", "your-key", "xxxx", "example",
    "dummy", "sample", "placeholder", "insert_key_here", "todo", "fixme",
    "<your", "{{", "${", "process.env", "os.environ", "os.getenv",
)

TEST_PATH_HINTS = ("test", "tests", "__tests__", "fixture", "fixtures", "mock", "mocks", "example", "examples")


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(hint in low for hint in PLACEHOLDER_HINTS)


def is_test_or_example_path(file_path: str) -> bool:
    parts = file_path.lower().replace("\\", "/").split("/")
    return any(p in TEST_PATH_HINTS for p in parts)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


# ---------------------------------------------------------------------------
# Rule A: hardcoded API keys
# ---------------------------------------------------------------------------

API_KEY_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("stripe_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("github_token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    (
        "generic_assigned_secret",
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{16,})['\"]"
        ),
    ),
]


def rule_a_api_keys(file_path: str, content: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        line_already_matched_specific = False
        for name, pattern in API_KEY_PATTERNS:
            if name == "generic_assigned_secret" and line_already_matched_specific:
                continue
            for match in pattern.finditer(line):
                if name != "generic_assigned_secret":
                    line_already_matched_specific = True
                value = match.group(2) if match.groups() and len(match.groups()) > 1 else match.group(0)
                findings.append(
                    Finding(
                        rule_id="A",
                        severity="critical" if name != "generic_assigned_secret" else "high",
                        file=file_path,
                        line=i,
                        message=f"Possible hardcoded {name.replace('_', ' ')}",
                        snippet=line.strip()[:200],
                    )
                )
    return findings



# ---------------------------------------------------------------------------
# Rule B: JWT secret / bypass issues
# ---------------------------------------------------------------------------

JWT_HARDCODED_SECRET = re.compile(
    r"(?i)jwt\.(?:sign|encode)\s*\([^)]*['\"]([^'\"]{4,})['\"]"
)
JWT_ALG_NONE = re.compile(r"(?i)algorithms?\s*[:=]\s*(\[)?\s*['\"]none['\"]")
JWT_VERIFY_DISABLED = re.compile(r"(?i)verify['\"]?\s*[:=]\s*['\"]?(false)")


def rule_b_jwt(file_path: str, content: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        if JWT_ALG_NONE.search(line):
            findings.append(Finding(
                rule_id="B", severity="critical", file=file_path, line=i,
                message="JWT algorithm explicitly set to 'none' (signature bypass)",
                snippet=line.strip()[:200],
            ))
        if JWT_VERIFY_DISABLED.search(line) and "jwt" in line.lower():
            findings.append(Finding(
                rule_id="B", severity="critical", file=file_path, line=i,
                message="JWT verification explicitly disabled",
                snippet=line.strip()[:200],
            ))
        m = JWT_HARDCODED_SECRET.search(line)
        if m:
            findings.append(Finding(
                rule_id="B", severity="high", file=file_path, line=i,
                message="Possible hardcoded JWT signing secret",
                snippet=line.strip()[:200],
            ))
    return findings


# ---------------------------------------------------------------------------
# Rule C: insecure dependencies + hardcoded webhook URLs
# ---------------------------------------------------------------------------

WEBHOOK_PATTERNS = [
    ("discord_webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[\w/]+")),
    ("generic_webhook_with_secret", re.compile(r"https?://[^\s'\"]+/webhook[^\s'\"]*[?&](?:token|key|secret)=[^\s'\"&]+", re.IGNORECASE)),
]

# Minimal, illustrative known-bad pin list. In a real deployment this would
# be replaced by a call to the OSV.dev API; kept local/offline here so the
# tool has no network dependency and is deterministic in tests.
KNOWN_VULNERABLE_PY_PACKAGES = {
    "pyyaml": {"<5.4": "CVE-2020-14343 (arbitrary code execution via full_load)"},
    "requests": {"<2.20.0": "CVE-2018-18074 (auth header leak on redirect)"},
    "django": {"<3.2.14": "multiple known CVEs, upgrade recommended"},
    "flask": {"<2.2.5": "CVE-2023-30861 (session cookie disclosure)"},
    "urllib3": {"<1.26.5": "CVE-2021-33503 (ReDoS)"},
    "jinja2": {"<2.11.3": "CVE-2020-28493 (ReDoS)"},
}


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in v.split("."):
        digits = re.match(r"\d+", chunk)
        parts.append(int(digits.group(0)) if digits else 0)
    return tuple(parts)


def _version_matches_constraint(version: str, constraint: str) -> bool:
    """Supports simple '<X.Y.Z' constraints, which is all KNOWN_VULNERABLE_PY_PACKAGES uses."""
    if constraint.startswith("<"):
        return _version_tuple(version) < _version_tuple(constraint[1:])
    return False


def rule_c_dependencies_and_webhooks(file_path: str, content: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        for name, pattern in WEBHOOK_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id="C", severity="high", file=file_path, line=i,
                    message=f"Hardcoded {name.replace('_', ' ')} URL (treat as a secret)",
                    snippet=line.strip()[:200],
                ))

    if file_path.endswith("requirements.txt"):
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            m = re.match(r"^([A-Za-z0-9_\-.]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)", stripped)
            if not m:
                continue
            pkg, version = m.group(1).lower(), m.group(2)
            if pkg in KNOWN_VULNERABLE_PY_PACKAGES:
                for constraint, desc in KNOWN_VULNERABLE_PY_PACKAGES[pkg].items():
                    if _version_matches_constraint(version, constraint):
                        findings.append(Finding(
                            rule_id="C", severity="high", file=file_path, line=i,
                            message=f"{pkg}=={version} matches known-vulnerable range {constraint}: {desc}",
                            snippet=stripped[:200],
                        ))
    return findings


# ---------------------------------------------------------------------------
# Rule D: insecure CORS configuration
# ---------------------------------------------------------------------------

CORS_WILDCARD_ORIGIN = re.compile(r"(?i)access-control-allow-origin['\"]?\s*[:=]\s*['\"]?\*")
CORS_WILDCARD_WITH_CREDENTIALS = re.compile(r"(?i)credentials['\"]?\s*[:=]\s*['\"]?(true)")
FLASK_CORS_WILDCARD = re.compile(r"(?i)CORS\s*\(\s*app\s*,\s*(?:resources\s*=\s*.*?)?origins\s*=\s*['\"]\*['\"]")
EXPRESS_CORS_WILDCARD = re.compile(r"(?i)cors\s*\(\s*\{\s*origin\s*:\s*['\"]\*['\"]")


def rule_d_cors(file_path: str, content: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    has_wildcard_origin_line = None

    for i, line in enumerate(lines, start=1):
        if CORS_WILDCARD_ORIGIN.search(line):
            has_wildcard_origin_line = i
            findings.append(Finding(
                rule_id="D", severity="medium", file=file_path, line=i,
                message="CORS Access-Control-Allow-Origin set to wildcard '*'",
                snippet=line.strip()[:200],
            ))
        if FLASK_CORS_WILDCARD.search(line):
            findings.append(Finding(
                rule_id="D", severity="medium", file=file_path, line=i,
                message="Flask-CORS configured with wildcard origin '*'",
                snippet=line.strip()[:200],
            ))
        if EXPRESS_CORS_WILDCARD.search(line):
            findings.append(Finding(
                rule_id="D", severity="medium", file=file_path, line=i,
                message="Express cors() configured with wildcard origin '*'",
                snippet=line.strip()[:200],
            ))
        near_wildcard_origin = has_wildcard_origin_line is not None and (i - has_wildcard_origin_line) <= 5
        if near_wildcard_origin and CORS_WILDCARD_WITH_CREDENTIALS.search(line):
            findings.append(Finding(
                rule_id="D", severity="critical", file=file_path, line=i,
                message="CORS wildcard origin combined with credentials=true (major misconfiguration)",
                snippet=line.strip()[:200],
            ))
    return findings


ALL_RULES = {
    "A": rule_a_api_keys,
    "B": rule_b_jwt,
    "C": rule_c_dependencies_and_webhooks,
    "D": rule_d_cors,
}


# ---------------------------------------------------------------------------
# False-positive filter
# ---------------------------------------------------------------------------

def apply_false_positive_filter(findings: list[Finding], allowlist_patterns: list[str] | None = None) -> list[Finding]:
    """Marks findings as suppressed rather than deleting them, so the report
    can still say '12 findings suppressed as likely false positives'."""
    allowlist_patterns = allowlist_patterns or []
    compiled_allowlist = [re.compile(p) for p in allowlist_patterns]

    for f in findings:
        if is_test_or_example_path(f.file):
            f.suppressed = True
            f.suppressed_reason = "file path looks like a test/example/fixture"
            continue
        if looks_like_placeholder(f.snippet):
            f.suppressed = True
            f.suppressed_reason = "value looks like a placeholder, not a real secret"
            continue
        if any(p.search(f.snippet) for p in compiled_allowlist):
            f.suppressed = True
            f.suppressed_reason = "matched an allowlist pattern"
            continue
        if f.rule_id == "A":
            # generic secret-looking strings with low entropy are usually
            # short human-readable words, not real random secrets
            candidate = f.snippet
            if shannon_entropy(candidate) < 3.0 and len(candidate) < 24:
                f.suppressed = True
                f.suppressed_reason = "low entropy, unlikely to be a real secret"
    return findings
