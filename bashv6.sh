#!/usr/bin/env bash
# CyberPatriot Ultimate Hardening Suite (Copy with Improvements)
# Version 8.2 - Enhanced & Bug Fixed

set -euo pipefail
umask 077

# Configuration
readonly CONFIG_FILE="/etc/cyberpatriot.conf"
readonly LOG_DIR="/var/log/cyberpatriot"
readonly BACKUP_DIR="/var/backups/cyberpatriot"
readonly SCAN_DIR="$LOG_DIR/scans"
readonly REPORT_DIR="$LOG_DIR/reports"
readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_PID=$$

# Color codes - Fixed escape sequences
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Color output toggle
COLOR_OUTPUT=true
if [[ -z "${TERM:-}" ]] || [[ "${DISABLE_COLOR:-false}" == "true" ]]; then
    COLOR_OUTPUT=false
fi
color_echo() {
    if $COLOR_OUTPUT; then
        echo -e "$@"
    else
        shift
        echo "$@"
    fi
}

# Global non-interactive flag
NON_INTERACTIVE=false

# Logging function
log() {
    local level="$1"
    shift
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_DIR/cyberpatriot.log"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# Enhanced error handling
error_exit() {
    log_error "$1"
    if $COLOR_OUTPUT; then
        echo -e "${RED}Error: $1${NC}" >&2
    else
        echo "Error: $1" >&2
    fi
    exit "${2:-1}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Validate config file syntax before sourcing
validate_config() {
    local config="$1"
    if ! bash -n "$config" 2>/dev/null; then
        error_exit "Configuration file $config has syntax errors."
    fi
}

# Enhanced initialization with better error handling
initialize() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Use: sudo $0"
    fi

    # Check if system is supported
    if [[ ! -f /etc/os-release ]]; then
        error_exit "Unsupported system: /etc/os-release not found"
    fi

    # Source OS info
    . /etc/os-release
    log_info "Running on: $PRETTY_NAME"

    # Create directories with proper error handling
    for dir in "$LOG_DIR" "$BACKUP_DIR" "$SCAN_DIR" "$REPORT_DIR"; do
        if ! mkdir -p "$dir"; then
            error_exit "Failed to create directory: $dir"
        fi
        chmod 700 "$dir"
    done

    # Generate or source config
    if [[ ! -f "$CONFIG_FILE" ]]; then
        generate_default_config
    fi

    validate_config "$CONFIG_FILE"
    if ! source "$CONFIG_FILE"; then
        error_exit "Failed to source configuration file: $CONFIG_FILE"
    fi

    log_info "Initialization completed successfully"
}

# Enhanced config generation
generate_default_config() {
    log_info "Generating default configuration"

    if ! cat > "$CONFIG_FILE" <<-'EOF'; then
# CyberPatriot Configuration File
ENABLE_FIREWALL=true
ENABLE_SCANS=true
ENABLE_USER_HARDENING=true
ENABLE_SERVICE_HARDENING=true
ENABLE_FORENSICS=true
ENABLE_REPORTING=true

# Advanced settings
SSH_PORT=22
MAX_LOGIN_ATTEMPTS=3
PASSWORD_MIN_LENGTH=8
BACKUP_RETENTION_DAYS=30
SCAN_EXCLUDE_PATHS="/proc /sys /dev /tmp /var/cache /var/lib/docker"
DISABLE_COLOR=false
NON_INTERACTIVE=false
EOF
        error_exit "Failed to create configuration file"
    fi

    chmod 600 "$CONFIG_FILE"
    log_info "Default configuration created at $CONFIG_FILE"
}

# Print help message
print_help() {
    cat <<EOF
Usage: $SCRIPT_NAME [--help] [--non-interactive] [--disable-color]

Options:
  --help             Show this help message and exit
  --non-interactive  Run in non-interactive mode (default answers: No)
  --disable-color    Disable colored output
EOF
}

# Enhanced dependency installation with better error handling
install_dependencies() {
    log_info "Installing dependencies"
    color_echo "${BLUE}[+] Installing Dependencies${NC}"

    # Update package lists
    if ! apt-get update -qq; then
        error_exit "Failed to update package lists"
    fi

    # Define dependencies with better organization
    local security_deps=(
        ufw iptables-persistent
        clamav clamav-daemon
        rkhunter chkrootkit
        lynis aide
        auditd
    )

    local system_deps=(
        gnupg2 curl wget
        python3 python3-pip python3-venv
        xdg-utils tree
        net-tools psmisc
        fail2ban
    )

    local all_deps=("${security_deps[@]}" "${system_deps[@]}")

    # Install packages with better error handling
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${all_deps[@]}"; then
        log_error "Some packages failed to install, continuing with available tools"
    fi

    # Install Python packages in virtual environment
    setup_python_environment

    # Update security databases
    update_security_databases

    log_info "Dependency installation completed"
}

# Setup Python virtual environment
setup_python_environment() {
    local venv_dir="/opt/cyberpatriot-venv"

    if [[ ! -d "$venv_dir" ]]; then
        python3 -m venv "$venv_dir" || log_warn "Failed to create Python virtual environment"
    fi

    if [[ -f "$venv_dir/bin/activate" ]]; then
        source "$venv_dir/bin/activate"
        pip install --upgrade pip
        deactivate
    fi
}

# Update security databases
update_security_databases() {
    log_info "Updating security databases"

    # Update ClamAV database
    if command_exists freshclam; then
        freshclam || log_warn "Failed to update ClamAV database"
    fi

    # Update rkhunter database
    if command_exists rkhunter; then
        rkhunter --update || log_warn "Failed to update rkhunter database"
    fi
}

# Enhanced firewall configuration
firewall_hardening() {
    # Configure firewall if enabled
    if [[ "${ENABLE_FIREWALL:-true}" != "true" ]]; then
        log_info "Firewall hardening disabled in config"
        return 0
    fi

    log_info "Configuring firewall"
    color_echo "${BLUE}[1] Configuring Firewall${NC}"

    # Reset UFW
    ufw --force reset >/dev/null 2>&1

    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny forward

    # Allow SSH with rate limiting
    ufw limit "${SSH_PORT:-22}/tcp" comment "SSH with rate limiting"

    # Common secure services (optional)
    local allow_https="n"
    if ! $NON_INTERACTIVE; then
        read -rp "Allow HTTPS (443/tcp)? [y/N]: " -n 1 allow_https
        echo
    fi
    if [[ $allow_https =~ ^[Yy]$ ]]; then
        ufw allow 443/tcp comment "HTTPS"
    fi

    # Enable firewall
    ufw --force enable

    # Configure fail2ban if available
    if command_exists fail2ban-client; then
        setup_fail2ban
    fi

    log_info "Firewall configuration completed"
}

# Setup fail2ban
setup_fail2ban() {
    log_info "Configuring fail2ban"

    cat > /etc/fail2ban/jail.local <<-EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = ${MAX_LOGIN_ATTEMPTS:-3}
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT:-22}
EOF

    systemctl enable fail2ban || true
    systemctl restart fail2ban || true
}

# Enhanced user security
user_security() {
    # Harden user security if enabled
    if [[ "${ENABLE_USER_HARDENING:-true}" != "true" ]]; then
        log_info "User hardening disabled in config"
        return 0
    fi

    log_info "Hardening user security"
    color_echo "${BLUE}[2] Hardening Users${NC}"

    # Backup original files
    cp /etc/login.defs "$BACKUP_DIR/login.defs.backup.$(date +%s)" 2>/dev/null || true
    cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.backup.$(date +%s)" 2>/dev/null || true

    # Configure password policies
    sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t'"${PASSWORD_MIN_LENGTH:-8}"'/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs

    # Set account lockout for new users
    useradd -D -f 30

    # Lock accounts with empty passwords
    local empty_passwd_users
    empty_passwd_users=$(awk -F: '($2 == "" && $1 != "root") {print $1}' /etc/shadow 2>/dev/null || true)

    if [[ -n "$empty_passwd_users" ]]; then
        color_echo "${YELLOW}Found users with empty passwords:${NC}"
        echo "$empty_passwd_users"

        while IFS= read -r user; do
            if [[ -n "$user" ]]; then
                passwd -l "$user"
                log_info "Locked user account: $user"
            fi
        done <<< "$empty_passwd_users"
    fi

    # Remove unauthorized users (interactive)
    review_user_accounts

    log_info "User security hardening completed"
}

# Interactive user account review
review_user_accounts() {
    color_echo "${CYAN}Reviewing user accounts...${NC}"

    # Get all human users (UID >= 1000)
    local human_users
    human_users=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

    if [[ -n "$human_users" ]]; then
        color_echo "${YELLOW}Found human user accounts:${NC}"
        echo "$human_users"

        local review_accounts="n"
        if ! $NON_INTERACTIVE; then
            read -rp "Review each account? [y/N]: " -n 1 review_accounts
            echo
        fi

        if [[ $review_accounts =~ ^[Yy]$ ]]; then
            while IFS= read -r user; do
                if [[ -n "$user" ]]; then
                    color_echo "${CYAN}User: $user${NC}"
                    id "$user" 2>/dev/null || true
                    local lock_user="n"
                    if ! $NON_INTERACTIVE; then
                        read -rp "Lock this account? [y/N]: " -n 1 lock_user
                        echo
                    fi
                    if [[ $lock_user =~ ^[Yy]$ ]]; then
                        usermod -L "$user"
                        log_info "Locked user account: $user"
                    fi
                fi
            done <<< "$human_users"
        fi
    fi
}

# Enhanced service hardening
service_hardening() {
    # Harden services if enabled
    if [[ "${ENABLE_SERVICE_HARDENING:-true}" != "true" ]]; then
        log_info "Service hardening disabled in config"
        return 0
    fi

    log_info "Securing services"
    color_echo "${BLUE}[3] Securing Services${NC}"

    # Backup SSH config
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup.$(date +%s)"

    # Harden SSH configuration
    harden_ssh_config

    # Disable unnecessary services
    disable_unnecessary_services

    # Configure audit daemon
    configure_auditd

    log_info "Service hardening completed"
}

# Comprehensive SSH hardening
harden_ssh_config() {
    log_info "Hardening SSH configuration"

    local ssh_config="/etc/ssh/sshd_config"

    # Apply SSH hardening settings
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$ssh_config"
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$ssh_config"
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$ssh_config"
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$ssh_config"
    sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$ssh_config"
    sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/' "$ssh_config"
    sed -i 's/^#*Port.*/Port '"${SSH_PORT:-22}"'/' "$ssh_config"

    # Add additional security settings if not present
    if ! grep -q "Protocol 2" "$ssh_config"; then
        echo "Protocol 2" >> "$ssh_config"
    fi

    # Test SSH configuration
    if sshd -t; then
        systemctl restart sshd || true
        log_info "SSH configuration updated and restarted"
    else
        log_error "SSH configuration test failed, not restarting service"
        return 1
    fi
}

# Disable unnecessary services
disable_unnecessary_services() {
    local services_to_disable=(
        avahi-daemon
        cups
        bluetooth
        apache2
        nginx
        vsftpd
        telnet
        rsh-server
        nis
    )

    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            systemctl disable "$service" >/dev/null 2>&1 || true
            log_info "Disabled service: $service"
        fi
        if systemctl is-active "$service" >/dev/null 2>&1; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            log_info "Stopped service: $service"
        fi
    done
}

# Configure audit daemon
configure_auditd() {
    if command_exists auditctl; then
        log_info "Configuring audit daemon"

        # Basic audit rules
        cat > /etc/audit/rules.d/cyberpatriot.rules <<-'EOF'
# CyberPatriot Audit Rules
-w /etc/passwd -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/shadow -p wa -k shadow_modification
-w /etc/sudoers -p wa -k sudo_modification
-w /var/log/auth.log -p wa -k auth_log
-w /bin/su -p x -k su_usage
-w /usr/bin/sudo -p x -k sudo_usage
-w /etc/ssh/sshd_config -p wa -k ssh_config
EOF

        systemctl enable auditd || true
        systemctl restart auditd || true
    fi
}

# Enhanced forensic checks
forensic_checks() {
    # Run forensic checks if enabled
    if [[ "${ENABLE_FORENSICS:-true}" != "true" ]]; then
        log_info "Forensic checks disabled in config"
        return 0
    fi

    log_info "Running forensic analysis"
    color_echo "${BLUE}[4] Forensic Analysis${NC}"

    set +e  # Allow non-fatal errors in this function

    # Find SUID/SGID files
    color_echo "${CYAN}Searching for SUID/SGID files...${NC}"
    find / -type f \( -perm -4000 -o -perm -2000 \) ! -path "/proc/*" ! -path "/sys/*" \
        -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/suid_sgid.log" || true
    touch "$SCAN_DIR/suid_sgid.log"

    # Find world-writable files
    color_echo "${CYAN}Searching for world-writable files...${NC}"
    find / -xdev -type f -perm -o+w ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" \
        -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/world_writable.log" || true
    touch "$SCAN_DIR/world_writable.log"

    # Check for files with no owner
    color_echo "${CYAN}Searching for files with no owner...${NC}"
    find / -xdev \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" \
        -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/no_owner.log" || true
    touch "$SCAN_DIR/no_owner.log"

    # Check network connections
    color_echo "${CYAN}Checking network connections...${NC}"
    if command_exists ss; then
        ss -tulpn > "$SCAN_DIR/open_ports.log" 2>/dev/null || true
    elif command_exists netstat; then
        netstat -tulpn > "$SCAN_DIR/open_ports.log" 2>/dev/null || true
    else
        echo "No network tool found" > "$SCAN_DIR/open_ports.log"
    fi
    touch "$SCAN_DIR/open_ports.log"

    # Check running processes
    color_echo "${CYAN}Checking running processes...${NC}"
    ps aux > "$SCAN_DIR/running_processes.log" 2>/dev/null || true
    touch "$SCAN_DIR/running_processes.log"

    # Check crontabs (only human users)
    color_echo "${CYAN}Checking scheduled tasks...${NC}"
    {
        echo "=== System Crontab ==="
        cat /etc/crontab 2>/dev/null || echo "No system crontab"
        echo -e "\n=== User Crontabs ==="
        for user in $(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd); do
            crontab -u "$user" -l 2>/dev/null && echo "--- End of $user crontab ---" || true
        done
    } > "$SCAN_DIR/crontabs.log" 2>/dev/null || true
    touch "$SCAN_DIR/crontabs.log"

    # Check startup scripts
    color_echo "${CYAN}Checking startup scripts...${NC}"
    ls -la /etc/init.d/ > "$SCAN_DIR/init_scripts.log" 2>/dev/null || true
    touch "$SCAN_DIR/init_scripts.log"
    systemctl list-unit-files --type=service > "$SCAN_DIR/systemd_services.log" 2>/dev/null || true
    touch "$SCAN_DIR/systemd_services.log"

    set -e  # Restore error handling

    # Print summary of findings
    local suid_count world_writable_count no_owner_count
    suid_count=$(wc -l < "$SCAN_DIR/suid_sgid.log" 2>/dev/null || echo 0)
    world_writable_count=$(wc -l < "$SCAN_DIR/world_writable.log" 2>/dev/null || echo 0)
    no_owner_count=$(wc -l < "$SCAN_DIR/no_owner.log" 2>/dev/null || echo 0)

    color_echo "${YELLOW}Forensic Summary:${NC}"
    color_echo "  SUID/SGID files found: $suid_count"
    color_echo "  World-writable files found: $world_writable_count"
    color_echo "  Files with no owner/group: $no_owner_count"
    color_echo "  See $SCAN_DIR for full logs."

    color_echo "${CYAN}Forensics Log Files:${NC}"
    color_echo "  SUID/SGID log:         $SCAN_DIR/suid_sgid.log"
    color_echo "  World-writable log:    $SCAN_DIR/world_writable.log"
    color_echo "  No owner/group log:    $SCAN_DIR/no_owner.log"
    color_echo "  Open ports log:        $SCAN_DIR/open_ports.log"
    color_echo "  Running processes log: $SCAN_DIR/running_processes.log"
    color_echo "  Crontabs log:          $SCAN_DIR/crontabs.log"
    color_echo "  Init scripts log:      $SCAN_DIR/init_scripts.log"
    color_echo "  Systemd services log:  $SCAN_DIR/systemd_services.log"

    log_info "Forensic Summary: SUID/SGID files: $suid_count, World-writable: $world_writable_count, No owner/group: $no_owner_count. See $SCAN_DIR for full logs."

    log_info "Forensic analysis completed"
    return 0
}

# Enhanced system scans
system_scans() {
    # Run system scans if enabled
    if [[ "${ENABLE_SCANS:-true}" != "true" ]]; then
        log_info "System scans disabled in config"
        return 0
    fi

    log_info "Running security scans"
    color_echo "${BLUE}[5] Running Security Scans${NC}"

    # ClamAV scan
    local clam_pid=""
    if command_exists clamscan; then
        color_echo "${CYAN}Running ClamAV scan...${NC}"
        clamscan -r --infected --exclude-dir="^/(sys|proc|dev|var/cache|var/lib/docker)" / > "$SCAN_DIR/clamav.log" 2>&1 &
        clam_pid=$!
    fi

    # Rootkit Hunter scan
    if command_exists rkhunter; then
        color_echo "${CYAN}Running Rootkit Hunter scan...${NC}"
        rkhunter --check --skip-keypress --report-warnings-only > "$SCAN_DIR/rkhunter.log" 2>&1
    fi

    # Lynis security audit
    if command_exists lynis; then
        color_echo "${CYAN}Running Lynis security audit...${NC}"
        lynis audit system --quick --no-colors > "$SCAN_DIR/lynis.log" 2>&1
    fi

    # chkrootkit scan
    if command_exists chkrootkit; then
        color_echo "${CYAN}Running chkrootkit scan...${NC}"
        chkrootkit > "$SCAN_DIR/chkrootkit.log" 2>&1
    fi

    # Wait for ClamAV to complete if it was started
    if [[ -n "${clam_pid:-}" ]]; then
        color_echo "${CYAN}Waiting for ClamAV scan to complete...${NC}"
        wait "$clam_pid" || true
    fi

    log_info "Security scans completed"
}

# Enhanced backup with better encryption
secure_backup() {
    log_info "Creating secure backup"
    color_echo "${BLUE}[6] Creating Secure Backup${NC}"

    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/system_backup_$timestamp.tar.gz.gpg"
    local passphrase_file="$BACKUP_DIR/.passphrase_$timestamp"

    # Generate strong passphrase
    local passphrase
    passphrase=$(openssl rand -base64 32)
    echo "$passphrase" > "$passphrase_file"
    chmod 600 "$passphrase_file"

    color_echo "${CYAN}Creating encrypted backup...${NC}"

    # Create backup with exclusions
    {
        tar --exclude='/proc/*' --exclude='/sys/*' --exclude='/dev/*' \
            --exclude='/tmp/*' --exclude='/var/tmp/*' --exclude='/run/*' \
            --exclude='/mnt/*' --exclude='/media/*' --exclude='/lost+found' \
            --exclude='/home/*/Downloads/*' --exclude='/home/*/.cache/*' \
            --exclude='/var/cache/*' --exclude='/var/lib/docker/*' \
            --exclude="$BACKUP_DIR/*" \
            -czf - /etc /home /var/log /root 2>/dev/null
    } | gpg --batch --symmetric --cipher-algo AES256 \
            --passphrase "$passphrase" -o "$backup_file"

    if [[ $? -eq 0 ]]; then
        chmod 600 "$backup_file"
        color_echo "${GREEN}Backup created: $backup_file${NC}"
        color_echo "${YELLOW}Passphrase stored in: $passphrase_file${NC}"
        color_echo "${RED}WARNING: Backup passphrase is stored in plain text. Move it to a secure location!${NC}"
        log_info "Secure backup created successfully"

        # Clean old backups
        cleanup_old_backups
    else
        log_error "Backup creation failed"
        rm -f "$backup_file" "$passphrase_file"
        return 1
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    local retention_days="${BACKUP_RETENTION_DAYS:-30}"

    find "$BACKUP_DIR" -name "system_backup_*.tar.gz.gpg" -mtime +$retention_days -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name ".passphrase_*" -mtime +$retention_days -delete 2>/dev/null || true

    log_info "Cleaned up backups older than $retention_days days"
}

# Enhanced report generation
generate_report() {
    # Generate report if enabled
    if [[ "${ENABLE_REPORTING:-true}" != "true" ]]; then
        log_info "Report generation disabled in config"
        return 0
    fi

    log_info "Generating comprehensive report"
    color_echo "${BLUE}[7] Generating Report${NC}"

    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="$REPORT_DIR/cyberpatriot_report_$timestamp"

    # Generate text report
    generate_text_report "$report_file.txt"

    # Generate HTML report
    generate_html_report "$report_file.html"

    color_echo "${GREEN}Reports generated in: $REPORT_DIR${NC}"
    log_info "Report generation completed"
}

# Generate comprehensive text report
generate_text_report() {
    local report_file="$1"

    cat > "$report_file" <<-EOF
CyberPatriot Security Assessment Report
Generated: $(date)
System: $(uname -a)
Distribution: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')

=== EXECUTIVE SUMMARY ===
This report contains the results of automated security hardening and assessment
performed by the CyberPatriot Ultimate Hardening Suite.

=== SYSTEM INFORMATION ===
Hostname: $(hostname)
Uptime: $(uptime)
Kernel: $(uname -r)
Architecture: $(uname -m)

=== SECURITY SCAN RESULTS ===
EOF

    # Add scan summaries if files exist
    if [[ -f "$SCAN_DIR/lynis.log" ]]; then
        echo -e "\n--- Lynis Security Audit Summary ---" >> "$report_file"
        grep -E "(Warning|Suggestion)" "$SCAN_DIR/lynis.log" | head -20 >> "$report_file" 2>/dev/null || true
    fi

    if [[ -f "$SCAN_DIR/rkhunter.log" ]]; then
        echo -e "\n--- Rootkit Hunter Summary ---" >> "$report_file"
        grep -E "(Warning|Found)" "$SCAN_DIR/rkhunter.log" | head -10 >> "$report_file" 2>/dev/null || true
    fi

    if [[ -f "$SCAN_DIR/clamav.log" ]]; then
        echo -e "\n--- ClamAV Scan Summary ---" >> "$report_file"
        grep -E "(FOUND|Infected)" "$SCAN_DIR/clamav.log" >> "$report_file" 2>/dev/null || echo "No infections found" >> "$report_file"
    fi

    echo -e "\n=== FORENSIC FINDINGS ===" >> "$report_file"

    if [[ -f "$SCAN_DIR/suid_sgid.log" ]]; then
        echo -e "\nSUID/SGID Files Found: $(wc -l < "$SCAN_DIR/suid_sgid.log")" >> "$report_file"
    fi

    if [[ -f "$SCAN_DIR/world_writable.log" ]]; then
        echo -e "World-Writable Files Found: $(wc -l < "$SCAN_DIR/world_writable.log")" >> "$report_file"
    fi

    echo -e "\n=== RECOMMENDATIONS ===" >> "$report_file"
    echo "1. Review all scan logs in $SCAN_DIR" >> "$report_file"
    echo "2. Address any security warnings found" >> "$report_file"
    echo "3. Regularly update system packages" >> "$report_file"
    echo "4. Monitor system logs for suspicious activity" >> "$report_file"
    echo "5. Test backup restoration procedures" >> "$report_file"

    chmod 600 "$report_file"
}

# Generate HTML report with scan summaries
generate_html_report() {
    local report_file="$1"
    local lynis_summary rkhunter_summary clamav_summary

    lynis_summary=""
    rkhunter_summary=""
    clamav_summary=""

    if [[ -f "$SCAN_DIR/lynis.log" ]]; then
        lynis_summary=$(grep -E "(Warning|Suggestion)" "$SCAN_DIR/lynis.log" | head -10)
    fi
    if [[ -f "$SCAN_DIR/rkhunter.log" ]]; then
        rkhunter_summary=$(grep -E "(Warning|Found)" "$SCAN_DIR/rkhunter.log" | head -5)
    fi
    if [[ -f "$SCAN_DIR/clamav.log" ]]; then
        clamav_summary=$(grep -E "(FOUND|Infected)" "$SCAN_DIR/clamav.log")
        [[ -z "$clamav_summary" ]] && clamav_summary="No infections found"
    fi

    cat > "$report_file" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>CyberPatriot Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; }
        .warning { color: #d63384; }
        .success { color: #198754; }
        .info { color: #0dcaf0; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CyberPatriot Security Assessment Report</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>System:</strong> $(hostname) - $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')</p>
    </div>

    <div class="section">
        <h2>System Information</h2>
        <pre>$(uname -a)</pre>
        <p><strong>Uptime:</strong> $(uptime)</p>
    </div>

    <div class="section">
        <h2>Security Scan Summaries</h2>
        <h3>Lynis</h3>
        <pre>${lynis_summary:-No summary}</pre>
        <h3>Rootkit Hunter</h3>
        <pre>${rkhunter_summary:-No summary}</pre>
        <h3>ClamAV</h3>
        <pre>${clamav_summary:-No summary}</pre>
    </div>

    <div class="section">
        <h2>Next Steps</h2>
        <ul>
            <li>Review all scan results in detail</li>
            <li>Address any security warnings</li>
            <li>Implement additional security measures as needed</li>
            <li>Schedule regular security assessments</li>
        </ul>
    </div>
    <div class="section warning">
        <strong>WARNING:</strong> Backup passphrase is stored in plain text in the backup directory. Move it to a secure location!
    </div>
</body>
</html>
EOF

    chmod 600 "$report_file"
}

# Enhanced competition resources with error handling
cyber_resources() {
    log_info "Displaying competition resources"

    local resources=(
        "Competition Portal:https://www.uscyberpatriot.org"
        "Practice Images:https://cyberpatriot.org/Pages/Competition/Practice-Images.aspx"
        "Scoring Guides:https://cyberpatriot.org/Pages/Competition/Competition-Scoring.aspx"
        "Training Materials:https://cyberpatriot.org/Pages/Competition/Training-Materials.aspx"
        "FAQ:https://cyberpatriot.org/Pages/Competition/FAQ.aspx"
    )

    color_echo "${GREEN}=== CyberPatriot Competition Resources ===${NC}"
    for i in "${!resources[@]}"; do
        local title="${resources[i]%%:*}"
        echo "$((i+1)). $title"
    done
    echo "0. Cancel"

    while true; do
        local res
        if $NON_INTERACTIVE; then
            res=0
        else
            read -rp "Select resource (0-${#resources[@]}): " res
        fi

        if [[ "$res" =~ ^[0-9]+$ ]]; then
            if [[ $res -eq 0 ]]; then
                return 0
            elif [[ $res -ge 1 && $res -le ${#resources[@]} ]]; then
                local url="${resources[$((res-1))]#*:}"
                color_echo "${BLUE}Opening: $url${NC}"

                if command_exists xdg-open; then
                    xdg-open "$url" 2>/dev/null || color_echo "${YELLOW}Please visit: $url${NC}"
                else
                    color_echo "${YELLOW}Please visit: $url${NC}"
                fi
                break
            else
                color_echo "${RED}Invalid selection. Please choose 0-${#resources[@]}${NC}"
            fi
        else
            color_echo "${RED}Please enter a valid number${NC}"
        fi
        $NON_INTERACTIVE && break
    done
}

# Run all features with progress tracking
run_all_features() {
    set +e  # Allow all features to run even if one fails
    log_info "Starting comprehensive security hardening"
    color_echo "${GREEN}=== Running All Security Features ===${NC}"

    # List features except system_scans
    local features=(
        "firewall_hardening:Firewall Configuration"
        "user_security:User Security Hardening"
        "service_hardening:Service Hardening"
        "forensic_checks:Forensic Analysis"
        "secure_backup:Secure Backup"
        "generate_report:Report Generation"
    )

    local total=$(( ${#features[@]} + 1 ))  # +1 for optional system_scans
    local current=0

    for feature in "${features[@]}"; do
        local func_name="${feature%%:*}"
        local display_name="${feature#*:}"

        ((current++))
        color_echo "${CYAN}[$current/$total] $display_name${NC}"

        if "$func_name"; then
            color_echo "${GREEN}✓ $display_name completed${NC}"
        else
            color_echo "${RED}✗ $display_name failed${NC}"
            log_error "$display_name failed"
        fi

        echo "---"
    done

    # Prompt for security scans last
    local run_scans="n"
    if $NON_INTERACTIVE; then
        run_scans="n"
    else
        read -rp "Run Security Scans (ClamAV, Lynis, rkhunter, etc)? [y/N]: " -n 1 run_scans
        echo
    fi
    ((current++))
    if [[ $run_scans =~ ^[Yy]$ ]]; then
        color_echo "${CYAN}[$current/$total] Security Scans${NC}"
        if system_scans; then
            color_echo "${GREEN}✓ Security Scans completed${NC}"
        else
            color_echo "${RED}✗ Security Scans failed${NC}"
            log_error "Security Scans failed"
        fi
        echo "---"
    else
        color_echo "${YELLOW}Security Scans skipped by user.${NC}"
        log_info "Security Scans skipped by user."
    fi

    color_echo "${GREEN}=== All features completed ===${NC}"
    log_info "Comprehensive security hardening completed"
    set -e  # Restore error handling
}

# Enhanced menu with better formatting
feature_menu() {
    # Clear screen if possible
    command_exists clear && clear || printf '\033[2J\033[H'

    color_echo "${GREEN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    color_echo "${GREEN}┃        CyberPatriot Toolkit            ┃${NC}"
    color_echo "${GREEN}┃     Enhanced Security Suite v8.2       ┃${NC}"
    color_echo "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┗${NC}"
    echo
    color_echo "${BLUE}Security Features:${NC}"
    echo "  1.  🛡️ Firewall Setup & Configuration"
    echo "  2.  🔒 User Security Hardening"
    echo "  3.  ⚙️  Service Hardening"
    echo "  4.  🔍 Forensic Analysis"
    echo "  5.  🛡  Security Scans"
    echo "  6.  💾 Secure Backup"
    echo "  7.  📄 Generate Reports"
    echo
    color_echo "${BLUE}Utilities:${NC}"
    echo "  8.  📚 Competition Resources"
    echo "  9.  📦 Run All Features"
    echo "  10. 🔧 Install Dependencies"
    echo "  11. ℹ️  System Status"
    echo "  12. 📜 View Logs"
    echo "  13. 🚪 Exit"
    echo
}

# New system status function
system_status() {
    color_echo "${BLUE}=== System Status ===${NC}"

    # Firewall status
    if command_exists ufw; then
        color_echo "${CYAN}Firewall Status:${NC}"
        ufw status | head -5
        echo
    fi

    # Service status
    color_echo "${CYAN}Critical Services:${NC}"
    local services=("ssh" "ufw" "fail2ban" "auditd")
    for service in "${services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            color_echo "  ✓ $service: ${GREEN}Active${NC}"
        else
            color_echo "  ✗ $service: ${RED}Inactive${NC}"
        fi
    done
    echo

    # Disk usage
    color_echo "${CYAN}Disk Usage:${NC}"
    df -h / | tail -1
    echo

    # Memory usage
    color_echo "${CYAN}Memory Usage:${NC}"
    free -h | grep "Mem:"
    echo

    # Recent logins
    color_echo "${CYAN}Recent Logins (last 5):${NC}"
    last -5 | head -5
}

# View logs function
view_logs() {
    color_echo "${BLUE}=== Available Logs ===${NC}"
    echo "1. Main Log"
    echo "2. Scan Results"
    echo "3. System Log (auth)"
    echo "4. Firewall Log"
    echo "5. Forensics Logs"
    echo "0. Back"

    local log_choice
    if $NON_INTERACTIVE; then
        log_choice=0
    else
        read -rp "Select log to view: " log_choice
    fi

    case $log_choice in
        1)
            if [[ -f "$LOG_DIR/cyberpatriot.log" ]]; then
                color_echo "${CYAN}=== Main Log (last 50 lines) ===${NC}"
                tail -50 "$LOG_DIR/cyberpatriot.log"
            else
                color_echo "${YELLOW}No main log found${NC}"
            fi
            ;;
        2)
            color_echo "${CYAN}=== Available Scan Results ===${NC}"
            ls -la "$SCAN_DIR/" 2>/dev/null || echo "No scan results found"
            ;;
        3)
            if [[ -f /var/log/auth.log ]]; then
                color_echo "${CYAN}=== Authentication Log (last 20 lines) ===${NC}"
                tail -20 /var/log/auth.log
            else
                color_echo "${YELLOW}No auth log found${NC}"
            fi
            ;;
        4)
            if [[ -f /var/log/ufw.log ]]; then
                color_echo "${CYAN}=== Firewall Log (last 20 lines) ===${NC}"
                tail -20 /var/log/ufw.log
            else
                color_echo "${YELLOW}No firewall log found${NC}"
            fi
            ;;
        5)
            # Forensics logs submenu
            color_echo "${CYAN}=== Forensics Logs ===${NC}"
            echo "1. SUID/SGID log"
            echo "2. World-writable log"
            echo "3. No owner/group log"
            echo "4. Open ports log"
            echo "5. Running processes log"
            echo "6. Crontabs log"
            echo "7. Init scripts log"
            echo "8. Systemd services log"
            echo "0. Back"
            local forensics_choice
            if $NON_INTERACTIVE; then
                forensics_choice=0
            else
                read -rp "Select forensics log to view: " forensics_choice
            fi
            case $forensics_choice in
                1) color_echo "${CYAN}=== SUID/SGID log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/suid_sgid.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                2) color_echo "${CYAN}=== World-writable log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/world_writable.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                3) color_echo "${CYAN}=== No owner/group log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/no_owner.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                4) color_echo "${CYAN}=== Open ports log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/open_ports.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                5) color_echo "${CYAN}=== Running processes log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/running_processes.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                6) color_echo "${CYAN}=== Crontabs log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/crontabs.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                7) color_echo "${CYAN}=== Init scripts log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/init_scripts.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                8) color_echo "${CYAN}=== Systemd services log (first 40 lines) ===${NC}"; head -40 "$SCAN_DIR/systemd_services.log" 2>/dev/null || color_echo "${YELLOW}Not found${NC}";;
                0) return 0;;
                *) color_echo "${RED}Invalid selection${NC}";;
            esac
            ;;
        0)
            return 0
            ;;
        *)
            color_echo "${RED}Invalid selection${NC}"
            ;;
    esac
}

# Signal handling
cleanup() {
    log_info "Script interrupted, cleaning up..."
    exit 130
}

trap cleanup SIGINT SIGTERM

# Enhanced main function with better error handling
main() {
    # Parse arguments
    for arg in "$@"; do
        case "$arg" in
            --help)
                print_help
                exit 0
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                ;;
            --disable-color)
                COLOR_OUTPUT=false
                ;;
        esac
    done

    # Initialize system
    initialize

    # Check for required tools
    local missing_tools=()
    local required_tools=("apt-get" "systemctl" "ufw")

    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error_exit "Missing required tools: ${missing_tools[*]}"
    fi

    log_info "CyberPatriot toolkit started by user: $(whoami)"

    # Main menu loop
    while true; do
        feature_menu
        local choice
        if $NON_INTERACTIVE; then
            choice=13
        else
            read -rp "Enter choice (1-13): " choice
        fi

        case $choice in
            1)
                firewall_hardening
                ;;
            2)
                user_security
                ;;
            3)
                service_hardening
                ;;
            4)
                forensic_checks
                ;;
            5)
                system_scans
                ;;
            6)
                secure_backup
                ;;
            7)
                generate_report
                ;;
            8)
                cyber_resources
                ;;
            9)
                run_all_features
                ;;
            10)
                install_dependencies
                ;;
            11)
                system_status
                ;;
            12)
                view_logs
                ;;
            13)
                color_echo "${GREEN}Thank you for using CyberPatriot Toolkit!${NC}"
                log_info "CyberPatriot toolkit session ended"
                exit 0
                ;;
            *)
                color_echo "${RED}Invalid option. Please choose 1-13.${NC}" >&2
                ;;
        esac

        echo
        if ! $NON_INTERACTIVE; then
            read -rp "Press Enter to continue..." -t 30 || true
            echo
        fi
    done
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi