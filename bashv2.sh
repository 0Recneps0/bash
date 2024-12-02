#!/usr/bin/env bash

# Enhanced System Security and Administration Script
# Version 3.2 (Added Password Management)

# Strict error handling and security settings
set -euo pipefail
umask 077  # Restrict default file permissions

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Constants
SCRIPT_NAME=$(basename "$0")
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_DIR=~/Desktop/system_logs
LOG_FILE="${LOG_DIR}/security_${TIMESTAMP}.log"
BACKUP_DIR=~/Desktop/secure_backups
SCAN_DIR="${LOG_DIR}/security_scans"
CONFIG_BACKUP_DIR="${BACKUP_DIR}/configs"
SENSITIVE_DIRS=("/etc" "/home" "/root")
MAX_LOG_AGE=30  # Days to keep log files

# Logging Function
log_message() {
    local log_level="${2:-INFO}"
    local message="$1"
    mkdir -p "$LOG_DIR" || { echo "Failed to create log directory"; exit 1; }
    chmod 700 "$LOG_DIR"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${log_level}] ${message}" | tee -a "$LOG_FILE"
    find "$LOG_DIR" -type f -name "security_*.log" -mtime +$MAX_LOG_AGE -delete
}

# Dependency Check
check_dependencies() {
    local critical_dependencies=("ufw" "systemctl" "apt-get" "fail2ban" "auditd" "chkrootkit" "rkhunter" "clamav" "rsync" "pandoc" "passwd")
    log_message "Checking system dependencies..." "DEPENDENCY"
    for dep in "${critical_dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            log_message "CRITICAL: Dependency missing: $dep. Attempting installation..." "ERROR"
            if ! apt-get update && apt-get install -y "$dep"; then
                log_message "FAILED to install $dep. Please resolve manually." "CRITICAL"
            fi
        fi
    done
}

# Firewall Configuration
configure_firewall() {
    log_message "Configuring advanced firewall rules..." "FIREWALL"
    apt-get install -y ufw || { log_message "Failed to install UFW." "ERROR"; return 1; }
    ufw default deny incoming
    ufw default allow outgoing
    ufw limit ssh
    read -rp "Do you want to open any specific ports? (comma-separated, or press Enter to skip): " ports
    if [[ -n "$ports" ]]; then
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            ufw allow "$port"
            log_message "Opened port: $port" "FIREWALL"
        done
    fi
    if ! ufw enable; then
        log_message "Failed to enable UFW. Check configuration manually." "ERROR"
        return 1
    fi
    log_message "UFW enabled successfully." "FIREWALL"
}

# Security Scans
run_security_scan() {
    log_message "Starting comprehensive security scan..." "SCAN"
    mkdir -p "$SCAN_DIR" || { log_message "Failed to create scan directory." "ERROR"; exit 1; }
    chmod 700 "$SCAN_DIR"

    # Lynis check
    if command -v lynis &>/dev/null; then
        log_message "Running Lynis security audit..." "SCAN"
        lynis audit system > "${SCAN_DIR}/lynis_scan_${TIMESTAMP}.log"
    else
        log_message "Lynis not found. Skipping Lynis scan." "WARN"
    fi

    chkrootkit > "${SCAN_DIR}/rootkit_scan_${TIMESTAMP}.log"
    rkhunter --check --sk > "${SCAN_DIR}/rkhunter_scan_${TIMESTAMP}.log"
    clamscan -r / > "${SCAN_DIR}/malware_scan_${TIMESTAMP}.log"
    log_message "Security scan completed. Check scan logs for details." "SCAN"
}

# Backup with Encryption
secure_backup() {
    local gpg_passphrase="your_secure_passphrase_here"  # Replace with a secure passphrase
    mkdir -p "$BACKUP_DIR" "$CONFIG_BACKUP_DIR" || { log_message "Failed to create backup directories." "ERROR"; exit 1; }
    chmod 700 "$BACKUP_DIR" "$CONFIG_BACKUP_DIR"
    log_message "Starting secure system backup..." "BACKUP"
    for dir in "${SENSITIVE_DIRS[@]}"; do
        backup_file="${BACKUP_DIR}/backup_${dir//\//_}_${TIMESTAMP}.tar.gz.gpg"
        tar -czf - "$dir" | gpg --batch --passphrase "$gpg_passphrase" -c > "$backup_file"
        log_message "Encrypted backup created: $backup_file" "BACKUP"
    done
}

# Change User Password
change_user_password() {
    read -rp "Enter the username to change password for: " username
    if id "$username" &>/dev/null; then
        log_message "Changing password for user: $username" "PASSWORD"
        passwd "$username" || log_message "Failed to change password for $username." "ERROR"
    else
        log_message "User $username does not exist." "ERROR"
    fi
}

# Cron Management
manage_cron() {
    local cron_job="0 2 * * * $SCRIPT_NAME > /dev/null 2>&1"
    if crontab -l | grep -qF "$cron_job"; then
        log_message "Cron job already exists." "SCHEDULE"
    else
        (crontab -l; echo "$cron_job") | crontab -
        log_message "Cron job added successfully." "SCHEDULE"
    fi
}

# Report Generation
generate_report() {
    local report_file="${LOG_DIR}/security_report_${TIMESTAMP}.md"
    if ! command -v pandoc &>/dev/null; then
        log_message "Pandoc not found. Cannot generate PDF report." "ERROR"
        return 1
    fi
    log_message "Generating security report..." "REPORT"
    echo "# Security Report - ${TIMESTAMP}" > "$report_file"
    echo "## System Logs" >> "$report_file"
    tail "${LOG_DIR}/failed_login_${TIMESTAMP}.log" >> "$report_file" 2>/dev/null || echo "No failed login log found." >> "$report_file"
    echo "## Security Scans" >> "$report_file"
    tail "${SCAN_DIR}/lynis_scan_${TIMESTAMP}.log" >> "$report_file" 2>/dev/null || echo "No Lynis scan log found." >> "$report_file"
    pandoc "$report_file" -o "${LOG_DIR}/security_report_${TIMESTAMP}.pdf"
    log_message "Report generated: ${LOG_DIR}/security_report_${TIMESTAMP}.pdf" "REPORT"
}

# Main Menu
main_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== Enhanced System Security Management ===${NC}"
        echo -e "${YELLOW}1.  Update & Upgrade System${NC}"
        echo -e "${YELLOW}2.  Configure Firewall${NC}"
        echo -e "${YELLOW}3.  Run Comprehensive Security Scan${NC}"
        echo -e "${YELLOW}4.  Create Secure Backup${NC}"
        echo -e "${YELLOW}5.  Change User Password${NC}"
        echo -e "${YELLOW}6.  Manage Scheduled Tasks${NC}"
        echo -e "${YELLOW}7.  Generate Security Report${NC}"
        echo -e "${RED}8.  Exit${NC}"
        read -rp "Select an option (1-8): " choice
        case $choice in
            1) apt-get update -y && apt-get upgrade -y ;;
            2) configure_firewall ;;
            3) run_security_scan ;;
            4) secure_backup ;;
            5) change_user_password ;;
            6) manage_cron ;;
            7) generate_report ;;
            8) log_message "Exiting script." "EXIT"; exit 0 ;;
            *) echo -e "${RED}Invalid option. Try again.${NC}"; sleep 2 ;;
        esac
    done
}

# Prerequisite Checks and Execution
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root. Use sudo.${NC}"
    exit 1
fi

check_dependencies
main_menu
