#!/usr/bin/env bash
# CyberScope - Automated Cybersecurity Assessment & Reporting Tool
# Use only on systems you own or are explicitly authorized to test.
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || {
    echo "[!] Could not enter project directory: $SCRIPT_DIR" >&2
    exit 1
}

# -------------------- Color Definitions ---------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${CYAN}*************************************************************************************************************************${NC}"
echo -e "${CYAN}=========================================================================================================================${NC}"
echo "                                             "
echo -e "${RED}   CC CC  YY  YY  BB B BB   EE E EE  RR R RR          SS S     CC CC    OO OO    PP P PP  EE E EE     ${NC}"
echo -e "${RED} CC         YY    BB     B  EE       RR     R       SS       CC       OO     OO  PP    PP EE          ${NC}"
echo -e "${RED}CC          YY    BB  BB    EE E EE  RR R RR    ---   S SS  CC       OO       OO PP P PP  EE E EE     ${NC}"
echo -e "${RED} CC         YY    BB     B  EE       RR   R              SS  CC       OO     OO  PP       EE          ${NC} "
echo -e "${RED}   CC CC    YY    BB B BB   EE E EE  RR     RR       S SS      CC CC    OO OO    PP       EE E EE     ${NC} "
echo "                                                           "                                        
echo -e "${CYAN}==========================================================================================================================${NC}"
echo -e "${CYAN}**************************************************************************************************************************${NC}"
echo "  "
#!/bin/bash

# ============================================================
#                    CYBERSCOPE
# Automated Cybersecurity Assessment & Reporting Tool
#
# Environment: Kali Linux
# Language: Bash
#
# Use only against systems you are authorized to test.
# ============================================================


# ============================================================
# 1. COLOR DEFINITIONS
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'


# ============================================================
# 2. RESULT DIRECTORIES
# ============================================================

RESULTS="Results"
RECON="$RESULTS/reconnaissance"
NMAP_DIR="$RESULTS/nmap"
WEB_DIR="$RESULTS/web"

mkdir -p "$RESULTS"
mkdir -p "$RECON"
mkdir -p "$NMAP_DIR"
mkdir -p "$WEB_DIR"

REPORT="$RESULTS/scans.txt"


# ============================================================
# 3. BANNER
# ============================================================

clear

echo -e "${CYAN}****************************************************************${NC}"
echo -e "${CYAN}                  C Y B E R S C O P E                         ${NC}"
echo -e "${CYAN}       Automated Cybersecurity Assessment Tool                 ${NC}"
echo -e "${CYAN}****************************************************************${NC}"
echo


# ============================================================
# 4. TARGET INPUT
# ============================================================

read -rp "Enter the Target IP / URL / Domain: " INPUT

# Preserve the original input
ORIGINAL_INPUT="$(echo "$INPUT" | xargs)"

# Check empty target
if [[ -z "$ORIGINAL_INPUT" ]]; then
    echo -e "${RED}[!] Target cannot be empty.${NC}"
    exit 1
fi

# Prepare URL for web assessment
if [[ "$ORIGINAL_INPUT" =~ ^https?:// ]]; then
    WEB_URL="${ORIGINAL_INPUT%/}/"
else
    WEB_URL="http://${ORIGINAL_INPUT%/}/"
fi

# Prepare host/IP for network tools
TARGET="${ORIGINAL_INPUT#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%%/*}"
TARGET="$(echo "$TARGET" | xargs)"

echo -e "${GREEN}[+] Target identified: ${TARGET}${NC}"
echo -e "${GREEN}[+] Web URL prepared: ${WEB_URL}${NC}"
echo ""

# ============================================================
# 5. REPORT HEADER
# ============================================================

cat > "$REPORT" << EOF
==============================================================
              AUTOMATED VULNERABILITY ASSESSMENT
                            REPORT
==============================================================

Target       : $TARGET
Date         : $(date '+%Y-%m-%d %H:%M:%S')

==============================================================

EOF


# ============================================================
# 6. CHECK REQUIRED TOOLS
# ============================================================

echo -e "${CYAN}[*] Checking required tools...${NC}"

TOOLS=("nmap" "whois" "dig" "dnsrecon")

for TOOL in "${TOOLS[@]}"; do

    if command -v "$TOOL" >/dev/null 2>&1; then

        echo -e "${GREEN}[+] $TOOL found.${NC}"

    else

        echo -e "${YELLOW}[!] $TOOL is not installed.${NC}"

    fi

done

echo


# ============================================================
# 7. TARGET REACHABILITY
# ============================================================

echo -e "${GREEN}[*] Checking target availability...${NC}"

if ping -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then

    echo -e "${GREEN}[+] Target responded to ping.${NC}"

    echo "Target reachability: ICMP response received." >> "$REPORT"

else

    echo -e "${YELLOW}[!] Ping did not receive a response.${NC}"
    echo -e "${CYAN}[*] Trying Nmap host discovery...${NC}"

    if nmap -sn "$TARGET" >/dev/null 2>&1; then

        echo -e "${GREEN}[+] Target appears reachable according to Nmap.${NC}"

        echo "Target reachability: Nmap host discovery successful." \
            >> "$REPORT"

    else

        echo -e "${RED}[!] Target could not be confirmed as reachable.${NC}"

        echo "Target reachability: Not confirmed." >> "$REPORT"

        exit 1

    fi

fi

echo >> "$REPORT"


# ============================================================
# 8. RECONNAISSANCE
# ============================================================

echo
echo -e "${CYAN}==============================================================${NC}"
echo -e "${CYAN}                    RECONNAISSANCE                            ${NC}"
echo -e "${CYAN}==============================================================${NC}"


# ------------------------------------------------------------
# 8.1 NMAP RECONNAISSANCE
# ------------------------------------------------------------

echo -e "${CYAN}[*] Running Nmap reconnaissance...${NC}"

if nmap -sn "$TARGET" \
    > "$RECON/nmap_recon.txt" 2>&1; then

    echo -e "${GREEN}[+] Nmap reconnaissance completed.${NC}"

else

    echo -e "${YELLOW}[!] Nmap reconnaissance returned an error.${NC}"

fi


# ------------------------------------------------------------
# 8.2 WHOIS
# ------------------------------------------------------------

echo -e "${CYAN}[*] Running WHOIS reconnaissance...${NC}"

if command -v whois >/dev/null 2>&1; then

    whois "$TARGET" \
        > "$RECON/whois_results.txt" 2>&1

    echo -e "${GREEN}[+] WHOIS completed.${NC}"

else

    echo -e "${YELLOW}[!] WHOIS is not installed.${NC}"

    echo "WHOIS: Tool not available." \
        > "$RECON/whois_results.txt"

fi


# ------------------------------------------------------------
# 8.3 DIG
# ------------------------------------------------------------

echo -e "${CYAN}[*] Running DIG DNS reconnaissance...${NC}"

if command -v dig >/dev/null 2>&1; then

    {
        echo "================================================"
        echo "              DIG DNS RECONNAISSANCE"
        echo "================================================"

        echo
        echo "===== A RECORD ====="
        dig "$TARGET" A

        echo
        echo "===== AAAA RECORD ====="
        dig "$TARGET" AAAA

        echo
        echo "===== MX RECORD ====="
        dig "$TARGET" MX

        echo
        echo "===== NS RECORD ====="
        dig "$TARGET" NS

        echo
        echo "===== TXT RECORD ====="
        dig "$TARGET" TXT

        echo
        echo "===== PTR RECORD ====="
        dig -x "$TARGET"

    } > "$RECON/dig_results.txt" 2>&1

    echo -e "${GREEN}[+] DIG reconnaissance completed.${NC}"

else

    echo -e "${YELLOW}[!] DIG is not installed.${NC}"

fi


# ------------------------------------------------------------
# 8.4 DNSRECON
# ------------------------------------------------------------

echo -e "${CYAN}[*] Running DNSRecon reconnaissance...${NC}"

if command -v dnsrecon >/dev/null 2>&1; then

    dnsrecon -d "$TARGET" \
        > "$RECON/dnsrecon_results.txt" 2>&1

    echo -e "${GREEN}[+] DNSRecon completed.${NC}"

else

    echo -e "${YELLOW}[!] DNSRecon is not installed.${NC}"

fi


# ============================================================
# 9. FULL TCP PORT SCAN
# ============================================================

echo
echo -e "${CYAN}==============================================================${NC}"
echo -e "${CYAN}                    PORT SCANNING                             ${NC}"
echo -e "${CYAN}==============================================================${NC}"

echo -e "${CYAN}[*] Scanning TCP ports 1-65535...${NC}"

if nmap -p- --open "$TARGET" \
    > "$NMAP_DIR/nmap_ports_results.txt" 2>&1; then

    echo -e "${GREEN}[+] Full TCP port scan completed.${NC}"

else

    echo -e "${RED}[!] Port scan failed.${NC}"

fi


# ============================================================
# 10. SERVICE & VERSION DETECTION
# ============================================================

echo
echo -e "${CYAN}[*] Detecting services and versions...${NC}"

if nmap -sV --open "$TARGET" \
    > "$NMAP_DIR/nmap_service_versions.txt" 2>&1; then

    echo -e "${GREEN}[+] Service/version detection completed.${NC}"

else

    echo -e "${RED}[!] Service/version detection failed.${NC}"

fi


# ============================================================
# 11. VULNERABILITY + CVE/CVSS ASSESSMENT
# ============================================================

echo
echo -e "${CYAN}==============================================================${NC}"
echo -e "${CYAN}             VULNERABILITY + CVE ASSESSMENT                  ${NC}"
echo -e "${CYAN}==============================================================${NC}"

echo -e "${CYAN}[*] Running vulnerability and CVE assessment...${NC}"

VULN_SCAN="$NMAP_DIR/vulnerability_results.txt"

if nmap -sV \
    --script vuln,vulners \
    --top-ports 100 \
    -T4 \
    "$TARGET" \
    > "$VULN_SCAN" 2>&1; then

    echo -e "${GREEN}[+] Vulnerability/CVE assessment completed.${NC}"

else

    echo -e "${YELLOW}[!] Vulnerability/CVE assessment returned an error.${NC}"

fi


# ============================================================
# 12. VULNERABILITY FINDINGS
# ============================================================

echo
echo -e "${CYAN}[*] Processing vulnerability findings...${NC}"

{
    echo
    echo "=============================================================="
    echo "                 VULNERABILITY FINDINGS"
    echo "=============================================================="
    echo

    if grep -qiE \
        "VULNERABLE|CVE-[0-9]{4}-[0-9]{4,}" \
        "$VULN_SCAN"; then

        echo "Nmap vulnerability/CVE findings:"
        echo "--------------------------------------------------------------"

        grep -iE \
            "VULNERABLE|CVE-[0-9]{4}-[0-9]{4,}|Risk factor|CVSS" \
            "$VULN_SCAN" || true

    else

        echo "No obvious vulnerability/CVE findings were reported."

    fi

} >> "$REPORT"


# ============================================================
# 13. CVSS THREAT LEVEL ANALYSIS
# ============================================================

echo
echo -e "${CYAN}[*] Processing available CVSS scores...${NC}"

{
    echo
    echo "=============================================================="
    echo "                    CVSS THREAT LEVEL"
    echo "=============================================================="
    echo

    echo "Severity scale:"
    echo "9.0 - 10.0 : CRITICAL"
    echo "7.0 - 8.9  : HIGH"
    echo "4.0 - 6.9  : MEDIUM"
    echo "0.1 - 3.9  : LOW"
    echo "0.0        : NONE"
    echo

} >> "$REPORT"


# Temporary file for CVSS processing
CVSS_TEMP=$(mktemp)

trap 'rm -f "$CVSS_TEMP"' EXIT


# Look for CVE followed by a decimal score
grep -oE \
    'CVE-[0-9]{4}-[0-9]{4,}[^[:space:]]*[[:space:]]+[0-9]+\.[0-9]+' \
    "$VULN_SCAN" \
    > "$CVSS_TEMP" 2>/dev/null || true


if [[ -s "$CVSS_TEMP" ]]; then

    while read -r LINE; do

        CVE=$(echo "$LINE" |
            grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' |
            head -1)

        SCORE=$(echo "$LINE" |
            grep -oE '[0-9]+\.[0-9]+' |
            tail -1)

        if [[ -n "$CVE" && -n "$SCORE" ]]; then

            THREAT="UNKNOWN"

            if awk "BEGIN {exit !($SCORE >= 9.0)}"; then

                THREAT="CRITICAL"

            elif awk "BEGIN {exit !($SCORE >= 7.0)}"; then

                THREAT="HIGH"

            elif awk "BEGIN {exit !($SCORE >= 4.0)}"; then

                THREAT="MEDIUM"

            elif awk "BEGIN {exit !($SCORE > 0.0)}"; then

                THREAT="LOW"

            else

                THREAT="NONE"

            fi

            echo "CVE        : $CVE" >> "$REPORT"
            echo "CVSS Score : $SCORE" >> "$REPORT"
            echo "Threat     : $THREAT" >> "$REPORT"
            echo "--------------------------------------------------------------" \
                >> "$REPORT"

                    fi

    done < "$CVSS_TEMP"

else

    echo "No CVSS scores were available from the scan output." \
        >> "$REPORT"

    echo -e \
        "${YELLOW}[!] No CVSS scores were available.${NC}"

fi


# ============================================================
# 14. WEB SERVICE DETECTION
# ============================================================

echo
echo -e "${CYAN}[*] Checking for web services...${NC}"

SERVICE_FILE="$NMAP_DIR/nmap_service_versions.txt"

if grep -Eiq \
    'http|https|apache|nginx|iis|lighttpd|tomcat' \
    "$SERVICE_FILE"; then

    WEB_FOUND="yes"

    echo -e "${GREEN}[+] Web service detected.${NC}"

else

    WEB_FOUND="no"

    echo -e "${YELLOW}[!] No web service detected.${NC}"
    echo -e "${CYAN}[*] Web security assessment will be skipped.${NC}"

fi

echo "Web service detected: $WEB_FOUND" >> "$REPORT"


# ============================================================
# 15. WEB ASSESSMENT PLACEHOLDER
# ============================================================

if [[ "$WEB_FOUND" == "yes" ]]; then

    echo
    echo -e "${GREEN}[+] Web assessment stage is available.${NC}"

    echo
    echo "Web service detected." > "$WEB_DIR/web_service_status.txt"
    else

    echo "No web service detected. Web assessment skipped." \
        > "$WEB_DIR/web_service_status.txt"

fi
 # ============================================================
#16. Dirbuster 
# ============================================================   
echo ""
echo "[*] DirBuster Web Directory Assessment"

read -rp "Do you want to provide a wordlist? (y/n): " USE_WORDLIST

if [[ "$USE_WORDLIST" =~ ^[Yy]$ ]]; then

    read -rp "Enter wordlist path: " WORDLIST

    if [[ ! -f "$WORDLIST" ]]; then
        echo "[!] Wordlist not found. Skipping DirBuster."

    else
        echo "[*] Running DirBuster with supplied wordlist..."

        dirb "$WEB_URL" "$WORDLIST" \
            > "$WEB_DIR/dirbuster_results.txt" 2>&1

        echo "[+] DirBuster assessment completed."
        echo "[+] Results saved to: $WEB_DIR/dirbuster_results.txt"
    fi

else

    WORDLIST="/usr/share/wordlists/dirb/common.txt"

    if [[ -f "$WORDLIST" ]]; then

        echo "[*] Using default wordlist..."
        echo "[*] Running DirBuster..."

        dirb "$WEB_URL" "$WORDLIST" \
            > "$WEB_DIR/dirbuster_results.txt" 2>&1

        echo "[+] DirBuster assessment completed."
        echo "[+] Results saved to: $WEB_DIR/dirbuster_results.txt"

    else

        echo "[!] Default wordlist not found."
        echo "[!] DirBuster assessment skipped."

    fi

fi

# ==========================================
# PwnXSS Setup and Assessment
# ==========================================

echo "[*] Setting up PwnXSS..."

PWNXSS_DIR="$HOME/PwnXSS"
PWNXSS_SCRIPT="$PWNXSS_DIR/pwnxss.py"
PWNXSS_RESULTS="$WEB_DIR/pwnxss_results.txt"

mkdir -p "$WEB_DIR"

# Check required system commands
if ! command -v sudo >/dev/null 2>&1 ||
   ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] Required package manager or sudo not found."
    exit 1
fi

# Install missing dependencies
if ! command -v git >/dev/null 2>&1 ||
   ! dpkg-query -W -f='${Status}' python3-bs4 python3-requests 2>/dev/null |
       grep -q "install ok installed"; then
    echo "[*] Installing required dependencies..."
    sudo apt-get update &&
    sudo apt-get install -y git python3-bs4 python3-requests
    if [[ $? -ne 0 ]]; then
        echo "[!] Dependency installation failed."
        exit 1
    fi
fi

# Clone the repository only if it isn't already present
if [[ ! -f "$PWNXSS_SCRIPT" ]]; then
    if [[ -d "$PWNXSS_DIR" ]]; then
        echo "[!] PwnXSS directory exists but pwnxss.py is missing."
        exit 1
    fi

    echo "[*] Cloning PwnXSS repository..."
    if ! git clone https://github.com/pwn0sec/PwnXSS.git "$PWNXSS_DIR"; then
        echo "[!] Repository clone failed."
        exit 1
    fi
fi

# Check target URL
if [[ -z "$WEB_URL" ]]; then
    echo "[!] WEB_URL is missing. Assessment skipped."
    exit 1
fi

# Run PwnXSS against an authorized lab target
echo "[*] Running PwnXSS..."

if python3 "$PWNXSS_SCRIPT" -u "$WEB_URL" \
    > "$PWNXSS_RESULTS" 2>&1; then
    echo "[+] PwnXSS process completed."
else
    echo "[!] PwnXSS encountered an error."
    echo "[!] Check the saved output."
fi

echo "[+] Results saved to: $PWNXSS_RESULTS"

# ==========================================
# SQL Injection Assessment - CyberScope
# ==========================================

echo "[*] Basic SQL Injection Assessment"

SQLI_RESULTS="$WEB_DIR/sqli_results.txt"
mkdir -p "$WEB_DIR"

if [[ -z "$WEB_URL" ]]; then
    echo "[!] Target URL missing. Skipping SQLi assessment."
    echo "Status: Skipped - target URL missing." > "$SQLI_RESULTS"

else
    {
        echo "CyberScope - SQL Injection Assessment"
        echo "====================================="
        echo "Target: $WEB_URL"
        echo "Assessment: DVWA SQL Injection lab"
        echo "Status: Automated injection testing not performed"
        echo
        echo "Verification checklist:"
        echo "[ ] Check whether the id parameter is injectable"
        echo "[ ] Record database names observed in the lab"
        echo "[ ] Record tables observed in the dvwa database"
        echo "[ ] Verify findings and document remediation"
    } > "$SQLI_RESULTS"

    echo "[+] SQLi assessment record created."
    echo "[+] Results saved to: $SQLI_RESULTS"
fi




# ============================================================
# 16. GENERAL RECOMMENDATIONS
# ============================================================

{
    echo
    echo "=============================================================="
    echo "                 GENERAL RECOMMENDATIONS"
    echo "=============================================================="
    echo

    echo "1. Patch vulnerable software and services."
    echo "2. Review identified CVEs and vendor advisories."
    echo "3. Restrict unnecessary exposed ports."
    echo "4. Disable unnecessary services."
    echo "5. Keep operating systems and applications updated."
    echo "6. Investigate Critical and High severity findings first."
    echo

} >> "$REPORT"


# ============================================================
# 17. ASSESSMENT SUMMARY
# ============================================================

{
    echo
    echo "=============================================================="
    echo "                  ASSESSMENT COMPLETE"
    echo "=============================================================="
    echo

    echo "Target       : $TARGET"
    echo "Date         : $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    echo "Main report  : $REPORT"
    echo "Recon folder : $RECON"
    echo "Nmap folder  : $NMAP_DIR"
    echo "Web folder   : $WEB_DIR"
    echo

} >> "$REPORT"


# ============================================================
# 18. FINAL TERMINAL MESSAGE
# ============================================================

echo
echo -e "${GREEN}==============================================================${NC}"
echo -e "${GREEN}              CYBERSCOPE ASSESSMENT COMPLETE                  ${NC}"
echo -e "${GREEN}==============================================================${NC}"

echo
echo -e "${CYAN}[*] Main report:${NC} $REPORT"
echo -e "${CYAN}[*] All results saved inside:${NC} $RESULTS/"
echo
# ------------------------------------------------------------

# ------------------------------------------------------------
# AI HTML Report Generation (uses existing Results; no rescanning)
# ------------------------------------------------------------
echo
echo "[*] Generating AI Vulnerability Assessment Report..."

if [[ ! -f "$SCRIPT_DIR/ai_report.py" ]]; then
    echo "[!] Missing Python report generator: $SCRIPT_DIR/ai_report.py" >&2
    exit 1
fi

python3 "$SCRIPT_DIR/ai_report.py" \
    "$SCRIPT_DIR/Results" \
    "$SCRIPT_DIR/Results/AI_Vulnerability_Assessment_Report.html"
AI_STATUS=$?

if [[ $AI_STATUS -eq 0 ]]; then
    echo "[+] AI HTML report generated successfully."
else
    echo "[!] AI report generation failed (exit code $AI_STATUS)." >&2
    exit "$AI_STATUS"
fi
