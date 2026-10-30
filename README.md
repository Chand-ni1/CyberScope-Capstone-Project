# 🔐 CyberScope
### Automated Vulnerability Assessment & AI-Assisted Security Reporting Tool

**CyberScope** is a Bash-based cybersecurity tool developed in Kali Linux to automate vulnerability assessment and security reporting. It combines reconnaissance, network scanning, selected web security checks, and AI-assisted HTML report generation using the Google Gemini API.

## ✨ Key Features

- **Automated Reconnaissance:** Uses tools such as WHOIS, DIG, and DNSRecon.
- **Network Scanning:** Uses Nmap for port scanning and service detection.
- **Vulnerability Assessment:** Collects vulnerability-related findings, including CVEs when detected.
- **Web Security Checks:** Supports selected modules such as DIRB and PwnXSS, depending on configuration.
- **AI-Assisted Reporting:** Uses Python and the Gemini API to generate an HTML assessment report.
- **Organized Results:** Saves scan evidence and reports for later review.

## ⚙️ How It Works

1. Enter a target IP address, domain, or URL.
2. CyberScope performs the configured reconnaissance and assessment tasks.
3. Scan results are saved in the `Results/` directory.
4. The Python reporting module collects and filters relevant evidence.
5. Gemini processes the evidence and generates an HTML report.
6. Open the generated report in a web browser.

## 🧰 Technologies

- Kali Linux
- Bash
- Python 3
- Nmap
- WHOIS, DIG, DNSRecon
- DIRB and PwnXSS (optional modules)
- Google Gemini API
- HTML/CSS

## 🚀 Usage

### 1. Install dependencies

```bash
sudo apt update
sudo apt install -y python3 nmap curl jq
```

Install any additional dependencies required by your enabled modules.

### 2. Configure the Gemini API key

```bash
export GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
```

Keep your API key private. Do not upload it to GitHub.

### 3. Run CyberScope

```bash
bash script.sh
```

Follow the prompts to enter your authorized assessment target.

### 4. Generate a report from existing results

```bash
python3 ai_report.py Results Results/AI_Vulnerability_Assessment_Report.html 192.168.1.10
```

Replace `192.168.1.10` with your actual target. This command uses existing scan results and does not rerun the scans.

### 5. Open the report

```bash
xdg-open Results/AI_Vulnerability_Assessment_Report.html
```

## 🛠️ Common Errors & Solutions

| Error | Solution |
|---|---|
| `SyntaxError` at line 1 | Remove Markdown code fences such as ` ```python ` from the Python file. |
| `IndentationError` | Correct Python indentation and run `python3 -m py_compile ai_report.py`. |
| `Target: Not specified` | Pass the target as the third command-line argument. |
| `GEMINI_API_KEY is not set` | Configure the API key using `export GEMINI_API_KEY="YOUR_KEY"`. |
| `MAX_TOKENS` | Reduce the evidence size, shorten the report prompt, or lower the thinking level if supported. |
| HTTP `503` | Retry after a short delay; the API service may be temporarily unavailable. |
| Model not found | Verify that the configured Gemini model ID is available to your API account. |
| Results directory not found | Run the command from the project directory and check that `Results/` exists. |
| Optional tool missing | Install the required tool or skip that module if supported. |

## ⚠️ Disclaimer

CyberScope is intended for educational purposes and authorized security testing only. Scan results and AI-generated findings should be reviewed and verified before making security decisions.

**Use responsibly. Test ethically.**


