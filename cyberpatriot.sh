#!/usr/bin/env bash
# CyberPatriot Ultimate Hardening Suite
# Version 8.1 - Final

set -eo pipefail
umask 077

# Configuration
CONFIG_FILE="/etc/cyberpatriot.conf"
LOG_DIR="/var/log/cyberpatriot"
BACKUP_DIR="/var/backups/cyberpatriot"
SCAN_DIR="$LOG_DIR/scans"
REPORT_DIR="$LOG_DIR/reports"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

initialize() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}Run as root!${NC}" >&2 && exit 1
    mkdir -p "$LOG_DIR" "$BACKUP_DIR" "$SCAN_DIR" "$REPORT_DIR"
    chmod 700 "$LOG_DIR" "$BACKUP_DIR"
    [[ -f "$CONFIG_FILE" ]] || generate_default_config
    source "$CONFIG_FILE"
}

generate_default_config() {
    cat > "$CONFIG_FILE" <<-EOF
ENABLE_FIREWALL=true
ENABLE_SCANS=true
ENABLE_USER_HARDENING=true
ENABLE_SERVICE_HARDENING=true
ENABLE_FORENSICS=true
ENABLE_REPORTING=true
EOF
}

install_dependencies() {
    echo -e "${BLUE}[+] Installing Dependencies${NC}"
    if ! apt-get update -qq; then
        echo -e "${RED}Failed to update packages${NC}" >&2
        return 1
    fi
    
    local deps=(
        ufw clamav rkhunter lynis aide
        auditd chkrootkit gnupg python3-reportlab
        xdg-utils ss
    )
    
    if ! apt-get install -y --no-install-recommends "${deps[@]}"; then
        echo -e "${RED}Failed to install packages${NC}" >&2
        return 1
    fi
    
    pip3 install -q reportlab || echo -e "${YELLOW}Python reportlab install failed${NC}" >&2
}

firewall_hardening() {
    echo -e "${BLUE}[1] Configuring Firewall${NC}"
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw limit ssh/tcp
    ufw --force enable
}

user_security() {
    echo -e "${BLUE}[2] Hardening Users${NC}"
    sed -i 's/^\(PASS_MAX_DAYS\s*\).*/\190/' /etc/login.defs
    sed -i 's/^\(PASS_MIN_DAYS\s*\).*/\17/' /etc/login.defs
    useradd -D -f 30
    awk -F: '($2 == "") {print $1}' /etc/shadow | xargs -r passwd -l
}

service_hardening() {
    echo -e "${BLUE}[3] Securing Services${NC}"
    systemctl -q mask avahi-daemon cups
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

forensic_checks() {
    echo -e "${BLUE}[4] Forensic Analysis${NC}"
    find / -type f \( -perm -4000 -o -perm -2000 \) ! -path "/proc/*" -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/suid_sgid.log"
    find / -xdev -type f -perm -o+w -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/world_writable.log"
    ss -tulpn > "$SCAN_DIR/open_ports.log"
}

system_scans() {
    echo -e "${BLUE}[5] Running Scans${NC}"
    clamscan -r --infected --exclude-dir="^/(sys|proc)" / > "$SCAN_DIR/clamav.log" 2>&1
    rkhunter --check --sk > "$SCAN_DIR/rkhunter.log"
    lynis audit system --quick > "$SCAN_DIR/lynis.log"
}

secure_backup() {
    echo -e "${BLUE}[6] Creating Backup${NC}"
    local passphrase=$(head -c32 /dev/urandom | base64)
    tar -czf - /etc /home 2>/dev/null | gpg --batch --symmetric --passphrase "$passphrase" -o "$BACKUP_DIR/backup_$(date +%F).tar.gz.gpg"
    chmod 600 "$BACKUP_DIR"/*
}

generate_report() {
    echo -e "${BLUE}[7] Generating Report${NC}"
    python3 - <<EOF
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph

doc = SimpleDocTemplate("${REPORT_DIR}/report_$(date +%s).pdf", pagesize=letter)
story = [Paragraph("CyberPatriot Report - %s" % datetime.now().strftime('%Y-%m-%d %H:%M'))]
doc.build(story)
EOF
}

cyber_resources() {
    resources=(
        "Competition Portal:https://www.uscyberpatriot.org"
        "Practice Images:https://cyberpatriot.org/Pages/Competition/Practice-Images.aspx"
        "Scoring Guides:https://cyberpatriot.org/Pages/Competition/Competition-Scoring.aspx"
    )
    
    echo -e "${GREEN}Available Resources:${NC}"
    for i in "${!resources[@]}"; do
        echo "$((i+1)). ${resources[i]%%:*}"
    done
    
    read -rp "Select resource (0 to cancel): " res
    [[ $res -eq 0 ]] && return
    
    url="${resources[$((res-1))]#*:}"
    if [[ -n "$url" ]]; then
        xdg-open "$url" 2>/dev/null || echo -e "Visit: $url"
    fi
}

run_all_features() {
    firewall_hardening
    user_security
    service_hardening
    forensic_checks
    system_scans
    secure_backup
    generate_report
}

feature_menu() {
    clear
    echo -e "${GREEN}=== CyberPatriot Toolkit ==="
    echo "1.  Firewall Setup"
    echo "2.  User Security"
    echo "3.  Service Hardening"
    echo "4.  Forensic Checks"
    echo "5.  Security Scans"
    echo "6.  Secure Backup"
    echo "7.  Generate Report"
    echo "8.  Competition Resources"
    echo "9.  Run All Features"
    echo "10. Install Dependencies"
    echo "11. Exit"
}

main() {
    initialize
    while true; do
        feature_menu
        read -rp "Enter choice (1-11): " choice
        case $choice in
            1)  firewall_hardening ;;
            2)  user_security ;;
            3)  service_hardening ;;
            4)  forensic_checks ;;
            5)  system_scans ;;
            6)  secure_backup ;;
            7)  generate_report ;;
            8)  cyber_resources ;;
            9)  run_all_features ;;
            10) install_dependencies ;;
            11) exit 0 ;;
            *)  echo -e "${RED}Invalid option${NC}" >&2 ;;
        esac
        read -rp "Press Enter to continue..."
    done
}

main
