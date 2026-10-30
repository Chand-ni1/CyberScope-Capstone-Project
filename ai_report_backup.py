#!/usr/bin/env python3
"""Create a compact Gemini-powered HTML report from existing scan results."""

import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{MODEL}:generateContent"
)
MAX_EVIDENCE_CHARS = 24000
MAX_FILE_CHARS = 5000

# Keep likely findings; ignore noisy installation/debug output.
KEEP = re.compile(
    r"\b(target|host|open|closed|filtered|port|tcp|udp|service|version|"
    r"cve-\d{4}-\d+|cvss|vulnerab|exploit|severity|critical|high|medium|low|"
    r"risk|dns|whois|subdomain|http|https|status|dirb|dirbuster|pwnxss|"
    r"xss|sql.?injection|sqli|directory|discovered|finding|nmap|"
    r"certificate|tls|ssl|server:|technolog|warning|error)\b",
    re.I,
)
SKIP_DIRS = {".git", "__pycache__", "venv", ".venv"}
SKIP_NAMES = {"ai_vulnerability_assessment_report.html", "index.html"}


def collect_evidence(results_dir: Path) -> str:
    chunks, seen = [], set()
    total = 0

    if not results_dir.is_dir():
        raise FileNotFoundError(f"Results folder not found: {results_dir}")

    for path in sorted(results_dir.rglob("*")):
        if not path.is_file() or path.name.lower() in SKIP_NAMES:
            continue
        if any(part in SKIP_DIRS or part.startswith(".") for part in path.parts):
            continue
        if path.suffix.lower() in {".html", ".htm", ".png", ".jpg", ".jpeg", ".pdf", ".zip"}:
            continue
        try:
            raw = path.read_text(errors="ignore")[:MAX_FILE_CHARS]
        except OSError:
            continue
        lines = []
        for line in raw.splitlines():
            line = " ".join(line.strip().split())
            if not line or not KEEP.search(line):
                continue
            if re.search(r"(installing|download(ed|ing)? package|setting up |progress:|"
                         r"debug:|traceback|permission denied while installing)", line, re.I):
                continue
            key = line.lower()
            if key in seen:
                continue
            seen.add(key)
            lines.append(line[:500])
        if lines:
            block = f"\n[FILE: {path.name}]\n" + "\n".join(lines)
            remaining = MAX_EVIDENCE_CHARS - total
            if remaining <= 0:
                break
            block = block[:remaining]
            chunks.append(block)
            total += len(block)
    return "\n".join(chunks).strip()


def fallback_html(target: str, evidence: str, reason: str = "") -> str:
    note = f"<p><b>AI report note:</b> {html.escape(reason)}</p>" if reason else ""
    body = html.escape(evidence or "No relevant scan findings were found in the Results folder.")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Vulnerability Assessment Report</title>
<style>body{{font:16px Arial,sans-serif;max-width:1000px;margin:35px auto;padding:0 18px;color:#222}}
h1,h2{{color:#17365d}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:16px;border-radius:8px}}
small{{color:#555}}</style></head><body>
<h1>Vulnerability Assessment Report</h1><p><b>Target:</b> {html.escape(target)}</p>
{note}<h2>Collected Scan Evidence</h2><pre>{body}</pre>
<small>Generated from existing local scan files. Findings require manual validation.</small>
</body></html>"""


def ask_gemini(api_key: str, target: str, evidence: str) -> str:
    prompt = f"""Create a professional, concise HTML vulnerability assessment report.
Target: {target}

Use ONLY the evidence below. Do not invent findings, CVEs, CVSS scores, versions,
or test results. If a category has no evidence, say "Not identified in supplied
scan evidence." Distinguish confirmed observations from possible risks. Include:
Executive Summary, Target & Recon, Open Ports and Services, Vulnerability/CVE
Findings (include CVSS only if present), Web Findings, Risk Summary, and
Remediation Priorities. Escape HTML properly. Return ONLY a complete HTML
document beginning with <!doctype html> or <html>. Use readable CSS and tables
where helpful. Keep the report focused and not excessively long.

SCAN EVIDENCE:
{evidence}
"""
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 10000},
    }
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        method="POST",
    )
     with urllib.request.urlopen(request, timeout=90) as response:
        data = json.loads(response.read().decode())

    candidate = data["candidates"][0]

    print("Gemini finish reason:", candidate.get("finishReason"))
    print("Gemini usage:", data.get("usageMetadata", {}))

    return candidate["content"]["parts"][0]["text"].strip() 


def main() -> int:
    base = Path(__file__).resolve().parent
    results_dir = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else base / "Results"
    output = Path(sys.argv[2]).expanduser() if len(sys.argv) > 2 else results_dir / "AI_Vulnerability_Assessment_Report.html"
    target = os.getenv("SCAN_TARGET", "Not supplied")
    try:
        evidence = collect_evidence(results_dir)
    except (OSError, FileNotFoundError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    reason = ""
    report = ""
    if not evidence:
        reason = "No relevant findings were extracted from the existing result files."
    elif not api_key:
        reason = "GEMINI_API_KEY is not set; showing a local evidence-only report."
    else:
        try:
            report = ask_gemini(api_key, target, evidence)
            print("Gemini response preview:", repr(report[:500]))
            print("Gemini response ending:", repr(report[-300:]))
            if "<html" not in report.lower() or "</html>" not in report.lower():
                raise ValueError("Gemini response was not a complete HTML document.")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
            reason = f"Gemini report generation failed: {exc}"

    if not report:
        report = fallback_html(target, evidence, reason)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"[+] Report saved: {output}")
    if reason:
        print(f"[!] {reason}")
    else:
        print(f"[+] Gemini model used: {MODEL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
