
#!/usr/bin/env python3

import os
import sys
import json
import time
import re
import html
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# =========================================================
# CONFIGURATION
# =========================================================

API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip()

MAX_EVIDENCE_CHARS = 18000
MAX_FILE_CHARS = 4000
MAX_RETRIES = 3
REQUEST_TIMEOUT = 90

KEEP = re.compile(
    r"CVE-\d{4}-\d+|"
    r"\bcritical\b|\bhigh\b|\bmedium\b|\blow\b|"
    r"\bopen\b|\bfiltered\b|\bclosed\b|"
    r"\bport\b|\bservice\b|\bproduct\b|\bversion\b|"
    r"\bvulnerab\w*\b|\bexploit\w*\b|\bsecurity\b|"
    r"\bcvss\b|\brisk\b|\bssl\b|\btls\b|"
    r"\bsql injection\b|\bxss\b|\bdirectory listing\b|"
    r"\bhttp\b|\bhttps\b|\bdns\b|\bsubdomain\b|"
    r"\bserver\b|\btechnolog\w*\b|\btitle\b|"
    r"\bstate\b|\bhost\b|\baddress\b",
    re.IGNORECASE
)

# =========================================================
# COLLECT SCAN EVIDENCE
# =========================================================

def collect_evidence(results_dir):
    root = Path(results_dir)

    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(
            f"Results directory not found: {root}"
        )

    sections = []
    seen = set()
    total_chars = 0

    ignored_dirs = {
        ".git", "__pycache__", "venv", ".venv",
        "node_modules"
    }

    ignored_suffixes = {
        ".html", ".htm", ".png", ".jpg", ".jpeg",
        ".gif", ".pdf", ".zip", ".gz", ".pyc"
    }

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        if any(part in ignored_dirs for part in path.parts):
            continue

        if path.suffix.lower() in ignored_suffixes:
            continue

        try:
            if path.stat().st_size == 0:
                continue

            with path.open(
                "r", encoding="utf-8", errors="ignore"
            ) as file:
                content = file.read(MAX_FILE_CHARS * 3)

        except (OSError, PermissionError):
            continue

        important_lines = []

        for line in content.splitlines():
            line = line.strip()

            if not line or not KEEP.search(line):
                continue

            # Avoid duplicate lines across files.
            normalized = re.sub(r"\s+", " ", line).lower()

            if normalized in seen:
                continue

            seen.add(normalized)
            important_lines.append(line[:500])

        if not important_lines:
            continue

        section = (
            f"\n--- FILE: {path.relative_to(root)} ---\n"
            + "\n".join(important_lines)
        )

        section = section[:MAX_FILE_CHARS]

        remaining = MAX_EVIDENCE_CHARS - total_chars

        if remaining <= 0:
            break

        section = section[:remaining]
        sections.append(section)
        total_chars += len(section)

    if not sections:
        return (
            "No matching scan evidence was found in the "
            "Results directory. The directory may be empty, "
            "or its files may not contain recognized evidence."
        )

    return "\n".join(sections)


# =========================================================
# FALLBACK HTML REPORT
# =========================================================

def fallback_html(target, evidence, reason):
    safe_target = html.escape(target)
    safe_reason = html.escape(reason)
    safe_evidence = html.escape(evidence)

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberScope Vulnerability Assessment</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #f3f6fa;
    color: #1e293b;
    margin: 0;
    padding: 24px;
    line-height: 1.6;
}}
.container {{
    max-width: 1050px;
    margin: auto;
    background: white;
    padding: 28px;
    border-radius: 12px;
    box-shadow: 0 4px 18px #0001;
}}
h1 {{ color: #0f766e; }}
h2 {{ color: #155e75; }}
.notice {{
    background: #fff7ed;
    border-left: 5px solid #ea580c;
    padding: 14px;
    overflow-wrap: anywhere;
}}
pre {{
    background: #0f172a;
    color: #e2e8f0;
    padding: 18px;
    border-radius: 8px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}}
.small {{ color: #64748b; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
<h1>CyberScope Vulnerability Assessment Report</h1>
<p><strong>Target:</strong> {safe_target}</p>
<p><strong>Generated:</strong> {generated}</p>

<div class="notice">
<strong>Notice:</strong> The AI-generated report could not
be completed. This is a fallback report containing selected
scan evidence, not a completed AI analysis.
<br><strong>Reason:</strong> {safe_reason}
</div>

<h2>Collected Scan Evidence</h2>
<pre>{safe_evidence}</pre>

<h2>Important Limitations</h2>
<ul>
<li>Only the evidence shown above is available in this report.</li>
<li>Missing evidence does not prove that a vulnerability exists
or that a system is secure.</li>
<li>Verify findings manually before taking action.</li>
</ul>
<p class="small">Generated by CyberScope.</p>
</div>
</body>
</html>
"""


# =========================================================
# GEMINI API REQUEST
# =========================================================

def ask_gemini(target, evidence):
    if not API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Configure your API key "
            "in the environment before running this script."
        )

    api_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        + MODEL
        + ":generateContent"
    )

    prompt = f"""
You are writing a professional cybersecurity vulnerability
assessment report for CyberScope.

Target: {target}

Use only the supplied scan evidence. Do not invent scan results,
open ports, CVEs, CVSS scores, technologies, or vulnerabilities.

Requirements:
1. Return one complete, standalone HTML document only.
2. Include <!DOCTYPE html>, <html>, <head>, <body>, and </html>.
3. Use embedded CSS. Make the report clean, responsive, and
   professional, with a dark navy and teal visual theme.
4. Include an executive summary, target information, findings,
   risk assessment, evidence, and recommendations.
5. Use a table for findings where suitable.
6. Clearly distinguish confirmed evidence from potential concerns.
7. If CVSS scores or risk ratings are absent, write "Not provided".
8. Do not claim a vulnerability is confirmed unless the evidence
   supports that conclusion.
9. If evidence is limited, explicitly explain the limitation.
10. Keep the report concise. Do not add JavaScript or external assets.
11. Escape special characters in HTML appropriately.
12. Finish the HTML document completely with </body></html>.

SCAN EVIDENCE:
{evidence}
"""

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
     "generationConfig": {
    "temperature": 0.2,
    "maxOutputTokens": 8192,
    "thinkingConfig": {
        "thinkingLevel": "low"
    }
}
    }

    request = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": API_KEY
        },
        method="POST"
    )

    last_error = None

    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(
                request, timeout=REQUEST_TIMEOUT
            ) as response:
                response_text = response.read().decode(
                    "utf-8", errors="replace"
                )

            data = json.loads(response_text)

            candidates = data.get("candidates", [])

            if not candidates:
                message = data.get("error", {}).get(
                    "message", "Gemini returned no candidates."
                )
                raise RuntimeError(message)

            candidate = candidates[0]
            finish_reason = candidate.get("finishReason", "UNKNOWN")

            parts = candidate.get("content", {}).get("parts", [])

            generated_text = "\n".join(
                part.get("text", "")
                for part in parts
                if part.get("text")
            ).strip()

            usage = data.get("usageMetadata", {})

            print(f"Gemini finish reason: {finish_reason}")

            if usage:
                print(
                    "Gemini token usage:",
                    json.dumps(usage)
                )

            if finish_reason == "MAX_TOKENS":
                raise RuntimeError(
                    "Gemini reached its output token limit. "
                    "The generated HTML may be incomplete."
                )

            if not generated_text:
                raise RuntimeError(
                    "Gemini returned an empty response."
                )

            # Remove Markdown fences if the model adds them.
            generated_text = re.sub(
                r"^\s*```(?:html)?\s*",
                "",
                generated_text,
                flags=re.IGNORECASE
            )
            generated_text = re.sub(
                r"\s*```\s*$",
                "",
                generated_text
            ).strip()

            lower_text = generated_text.lower()

            if "<html" not in lower_text:
                raise RuntimeError(
                    "Gemini response does not contain an HTML document."
                )

            if "</html>" not in lower_text:
                raise RuntimeError(
                    "Gemini response was truncated: missing </html>."
                )

            if "<body" not in lower_text or "</body>" not in lower_text:
                raise RuntimeError(
                    "Gemini returned an incomplete HTML body."
                )

            return generated_text

        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode(
                "utf-8", errors="replace"
            )

            last_error = (
                f"HTTP {exc.code}: {error_body[:700]}"
            )

            if exc.code not in (429, 500, 502, 503, 504):
                raise RuntimeError(last_error) from exc

        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError
        ) as exc:
            last_error = str(exc)

        except RuntimeError as exc:
            last_error = str(exc)

            # Do not retry known incomplete/invalid HTML responses.
            if (
                "truncated" in last_error.lower()
                or "incomplete html" in last_error.lower()
                or "does not contain an html" in last_error.lower()
                or "token limit" in last_error.lower()
            ):
                raise

            # Retry temporary API errors and empty candidates.
            if attempt == MAX_RETRIES - 1:
                raise

        if attempt < MAX_RETRIES - 1:
            wait_seconds = 2 ** (attempt + 1)
            print(
                f"Gemini request failed: {last_error}"
            )
            print(
                f"Retrying in {wait_seconds} seconds "
                f"({attempt + 2}/{MAX_RETRIES})..."
            )
            time.sleep(wait_seconds)

    raise RuntimeError(
        last_error or "Gemini request failed after retries."
    )


# =========================================================
# MAIN
# =========================================================

def main():
    results_dir = Path(
        sys.argv[1] if len(sys.argv) > 1 else "Results"
    )

    output_file = Path(
        sys.argv[2]
        if len(sys.argv) > 2
        else str(results_dir / "AI_Vulnerability_Assessment_Report.html")
    )

    target = os.getenv("TARGET", "Not specified")

    if len(sys.argv) > 3:
        target = sys.argv[3]

    print("[*] Collecting existing scan evidence...")
    print(f"[*] Results directory: {results_dir}")

    try:
        evidence = collect_evidence(results_dir)
    except (OSError, FileNotFoundError) as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)

    print(f"[*] Evidence collected: {len(evidence)} characters")
    print(f"[*] Target: {target}")
    print(f"[*] Gemini model: {MODEL}")

    output_file.parent.mkdir(
        parents=True, exist_ok=True
    )

    try:
        print("[*] Requesting HTML report from Gemini...")
        report = ask_gemini(target, evidence)

        # Write only after the HTML has passed validation.
        output_file.write_text(
            report, encoding="utf-8"
        )

        print("[+] AI-generated HTML report saved:")
        print(f"    {output_file}")

    except Exception as exc:
        print(f"[!] Gemini report generation failed: {exc}")
        print("[*] Creating a fallback evidence report...")

        report = fallback_html(
            target, evidence, str(exc)
        )

        output_file.write_text(
            report, encoding="utf-8"
        )

        print("[+] Fallback HTML report saved:")
        print(f"    {output_file}")
        print(
            "[!] This is a fallback report, "
            "not an AI-generated analysis."
        )


if __name__ == "__main__":
    main()

