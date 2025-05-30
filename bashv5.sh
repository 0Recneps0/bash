#!/usr/bin/env bash
# CyberPatriot Ultimate Hardening Suite
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

# Logging function
log() {
    local level="$1"
    shift
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_DIR/cyberpatriot.log"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# Enhanced error handling
error_exit() {
    log_error "$1"
    echo -e "${RED}Error: $1${NC}" >&2
    exit "${2:-1}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
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
SCAN_EXCLUDE_PATHS="/proc /sys /dev /tmp"
EOF
        error_exit "Failed to create configuration file"
    fi
    
    chmod 600 "$CONFIG_FILE"
    log_info "Default configuration created at $CONFIG_FILE"
}

# Enhanced dependency installation with better error handling
install_dependencies() {
    log_info "Installing dependencies"
    echo -e "${BLUE}[+] Installing Dependencies${NC}"
    
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
    if [[ "${ENABLE_FIREWALL:-true}" != "true" ]]; then
        log_info "Firewall hardening disabled in config"
        return 0
    fi

    log_info "Configuring firewall"
    echo -e "${BLUE}[1] Configuring Firewall${NC}"
    
    # Reset UFW
    ufw --force reset >/dev/null 2>&1
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny forward
    
    # Allow SSH with rate limiting
    ufw limit "${SSH_PORT:-22}/tcp" comment "SSH with rate limiting"
    
    # Common secure services (optional)
    read -rp "Allow HTTPS (443/tcp)? [y/N]: " -n 1 allow_https
    echo
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

    systemctl enable fail2ban
    systemctl restart fail2ban
}

# Enhanced user security
user_security() {
    if [[ "${ENABLE_USER_HARDENING:-true}" != "true" ]]; then
        log_info "User hardening disabled in config"
        return 0
    fi

    log_info "Hardening user security"
    echo -e "${BLUE}[2] Hardening Users${NC}"
    
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
        echo -e "${YELLOW}Found users with empty passwords:${NC}"
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
    echo -e "${CYAN}Reviewing user accounts...${NC}"
    
    # Get all human users (UID >= 1000)
    local human_users
    human_users=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)
    
    if [[ -n "$human_users" ]]; then
        echo -e "${YELLOW}Found human user accounts:${NC}"
        echo "$human_users"
        
        read -rp "Review each account? [y/N]: " -n 1 review_accounts
        echo
        
        if [[ $review_accounts =~ ^[Yy]$ ]]; then
            while IFS= read -r user; do
                if [[ -n "$user" ]]; then
                    echo -e "${CYAN}User: $user${NC}"
                    id "$user" 2>/dev/null || true
                    read -rp "Lock this account? [y/N]: " -n 1 lock_user
                    echo
                    
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
    if [[ "${ENABLE_SERVICE_HARDENING:-true}" != "true" ]]; then
        log_info "Service hardening disabled in config"
        return 0
    fi

    log_info "Securing services"
    echo -e "${BLUE}[3] Securing Services${NC}"
    
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
        systemctl restart sshd
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
            systemctl stop "$service" >/dev/null 2>&1 || true
            log_info "Disabled service: $service"
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
        
        systemctl enable auditd
        systemctl restart auditd
    fi
}

# Enhanced forensic checks
forensic_checks() {
    if [[ "${ENABLE_FORENSICS:-true}" != "true" ]]; then
        log_info "Forensic checks disabled in config"
        return 0
    fi

    log_info "Running forensic analysis"
    echo -e "${BLUE}[4] Forensic Analysis${NC}"
    
    # Find SUID/SGID files
    echo -e "${CYAN}Searching for SUID/SGID files...${NC}"
    find / -type f \( -perm -4000 -o -perm -2000 \) ! -path "/proc/*" ! -path "/sys/*" \
        -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/suid_sgid.log"
    
    # Find world-writable files
    echo -e "${CYAN}Searching for world-writable files...${NC}"
    find / -xdev -type f -perm -o+w ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" \
        -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/world_writable.log"
    
    # Check for files with no owner
    echo -e "${CYAN}Searching for files with no owner...${NC}"
    find / -xdev \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" \
        -exec ls -ld {} \+ 2>/dev/null > "$SCAN_DIR/no_owner.log"
    
    # Check network connections
    echo -e "${CYAN}Checking network connections...${NC}"
    if command_exists ss; then
        ss -tulpn > "$SCAN_DIR/open_ports.log"
    elif command_exists netstat; then
        netstat -tulpn > "$SCAN_DIR/open_ports.log"
    fi
    
    # Check running processes
    echo -e "${CYAN}Checking running processes...${NC}"
    ps aux > "$SCAN_DIR/running_processes.log"
    
    # Check crontabs
    echo -e "${CYAN}Checking scheduled tasks...${NC}"
    {
        echo "=== System Crontab ==="
        cat /etc/crontab 2>/dev/null || echo "No system crontab"
        echo -e "\n=== User Crontabs ==="
        for user in $(cut -f1 -d: /etc/passwd); do
            crontab -u "$user" -l 2>/dev/null && echo "--- End of $user crontab ---" || true
        done
    } > "$SCAN_DIR/crontabs.log"
    
    # Check startup scripts
    echo -e "${CYAN}Checking startup scripts...${NC}"
    ls -la /etc/init.d/ > "$SCAN_DIR/init_scripts.log" 2>/dev/null || true
    systemctl list-unit-files --type=service > "$SCAN_DIR/systemd_services.log" 2>/dev/null || true
    
    log_info "Forensic analysis completed"
}

# Enhanced system scans
system_scans() {
    if [[ "${ENABLE_SCANS:-true}" != "true" ]]; then
        log_info "System scans disabled in config"
        return 0
    fi

    log_info "Running security scans"
    echo -e "${BLUE}[5] Running Security Scans${NC}"
    
    # ClamAV scan
    if command_exists clamscan; then
        echo -e "${CYAN}Running ClamAV scan...${NC}"
        clamscan -r --infected --exclude-dir="^/(sys|proc|dev)" / > "$SCAN_DIR/clamav.log" 2>&1 &
        local clam_pid=$!
    fi
    
    # Rootkit Hunter scan
    if command_exists rkhunter; then
        echo -e "${CYAN}Running Rootkit Hunter scan...${NC}"
        rkhunter --check --skip-keypress --report-warnings-only > "$SCAN_DIR/rkhunter.log" 2>&1
    fi
    
    # Lynis security audit
    if command_exists lynis; then
        echo -e "${CYAN}Running Lynis security audit...${NC}"
        lynis audit system --quick --no-colors > "$SCAN_DIR/lynis.log" 2>&1
    fi
    
    # chkrootkit scan
    if command_exists chkrootkit; then
        echo -e "${CYAN}Running chkrootkit scan...${NC}"
        chkrootkit > "$SCAN_DIR/chkrootkit.log" 2>&1
    fi
    
    # Wait for ClamAV to complete if it was started
    if [[ -n "${clam_pid:-}" ]]; then
        echo -e "${CYAN}Waiting for ClamAV scan to complete...${NC}"
        wait "$clam_pid" || true
    fi
    
    log_info "Security scans completed"
}

# Enhanced backup with better encryption
secure_backup() {
    log_info "Creating secure backup"
    echo -e "${BLUE}[6] Creating Secure Backup${NC}"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/system_backup_$timestamp.tar.gz.gpg"
    local passphrase_file="$BACKUP_DIR/.passphrase_$timestamp"
    
    # Generate strong passphrase
    local passphrase
    passphrase=$(openssl rand -base64 32)
    echo "$passphrase" > "$passphrase_file"
    chmod 600 "$passphrase_file"
    
    echo -e "${CYAN}Creating encrypted backup...${NC}"
    
    # Create backup with exclusions
    {
        tar --exclude='/proc/*' --exclude='/sys/*' --exclude='/dev/*' \
            --exclude='/tmp/*' --exclude='/var/tmp/*' --exclude='/run/*' \
            --exclude='/mnt/*' --exclude='/media/*' --exclude='/lost+found' \
            --exclude='/home/*/Downloads/*' --exclude='/home/*/.cache/*' \
            --exclude="$BACKUP_DIR/*" \
            -czf - /etc /home /var/log /root 2>/dev/null
    } | gpg --batch --symmetric --cipher-algo AES256 \
            --passphrase "$passphrase" -o "$backup_file"
    
    if [[ $? -eq 0 ]]; then
        chmod 600 "$backup_file"
        echo -e "${GREEN}Backup created: $backup_file${NC}"
        echo -e "${YELLOW}Passphrase stored in: $passphrase_file${NC}"
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
    if [[ "${ENABLE_REPORTING:-true}" != "true" ]]; then
        log_info "Report generation disabled in config"
        return 0
    fi

    log_info "Generating comprehensive report"
    echo -e "${BLUE}[7] Generating Report${NC}"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="$REPORT_DIR/cyberpatriot_report_$timestamp"
    
    # Generate text report
    generate_text_report "$report_file.txt"
    
    # Generate HTML report
    generate_html_report "$report_file.html"
    
    echo -e "${GREEN}Reports generated in: $REPORT_DIR${NC}"
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

# Generate HTML report
generate_html_report() {
    local report_file="$1"
    
    cat > "$report_file" <<-'EOF'
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
        <h2>Security Status</h2>
        <p class="success">✓ System hardening completed</p>
        <p class="success">✓ Security scans executed</p>
        <p class="info">ℹ Check detailed logs in $SCAN_DIR</p>
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

    echo -e "${GREEN}=== CyberPatriot Competition Resources ===${NC}"
    for i in "${!resources[@]}"; do
        local title="${resources[i]%%:*}"
        echo "$((i+1)). $title"
    done
    echo "0. Cancel"

    while true; do
        read -rp "Select resource (0-${#resources[@]}): " res
        
        if [[ "$res" =~ ^[0-9]+$ ]]; then
            if [[ $res -eq 0 ]]; then
                return 0
            elif [[ $res -ge 1 && $res -le ${#resources[@]} ]]; then
                local url="${resources[$((res-1))]#*:}"
                echo -e "${BLUE}Opening: $url${NC}"
                
                if command_exists xdg-open; then
                    xdg-open "$url" 2>/dev/null || echo -e "${YELLOW}Please visit: $url${NC}"
                else
                    echo -e "${YELLOW}Please visit: $url${NC}"
                fi
                break
            else
                echo -e "${RED}Invalid selection. Please choose 0-${#resources[@]}${NC}"
            fi
        else
            echo -e "${RED}Please enter a valid number${NC}"
        fi
    done
}

# Run all features with progress tracking
run_all_features() {
    log_info "Starting comprehensive security hardening"
    echo -e "${GREEN}=== Running All Security Features ===${NC}"
    
    local features=(
        "firewall_hardening:Firewall Configuration"
        "user_security:User Security Hardening"
        "service_hardening:Service Hardening"
        "forensic_checks:Forensic Analysis"
        "system_scans:Security Scans"
        "secure_backup:Secure Backup"
        "generate_report:Report Generation"
    )
    
    local total=${#features[@]}
    local current=0
    
    for feature in "${features[@]}"; do
        local func_name="${feature%%:*}"
        local display_name="${feature#*:}"
        
        ((current++))
        echo -e "${CYAN}[$current/$total] $display_name${NC}"
        
        if "$func_name"; then
            echo -e "${GREEN}✓ $display_name completed${NC}"
        else
            echo -e "${RED}✗ $display_name failed${NC}"
            log_error "$display_name failed"
        fi
        
        echo "---"
    done
    
    echo -e "${GREEN}=== All features completed ===${NC}"
    log_info "Comprehensive security hardening completed"
}

# Enhanced menu with better formatting
feature_menu() {
    # Clear screen if possible
    command_exists clear && clear || printf '\033[2J\033[H'
    
    echo -e "${GREEN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${GREEN}┃        CyberPatriot Toolkit          ┃${NC}"
    echo -e "${GREEN}┃     Enhanced Security Suite v8.2    ┃${NC}"
    echo -e "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┗${NC}"
    echo
    echo -e "${BLUE}Security Features:${NC}"
    echo "  1.  🛡️ Firewall Setup & Configuration"
    echo "  2.  🔒 User Security Hardening"
    echo "  3.  ⚙️  Service Hardening"
    echo "  4.  🔍 Forensic Analysis"
    echo "  5.  🛡  Security Scans"
    echo "  6.  💾 Secure Backup"
    echo "  7.  📄 Generate Reports"
    echo
    echo -e "${BLUE}Utilities:${NC}"
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
    echo -e "${BLUE}=== System Status ===${NC}"
    
    # Firewall status
    if command_exists ufw; then
        echo -e "${CYAN}Firewall Status:${NC}"
        ufw status | head -5
        echo
    fi
    
    # Service status
    echo -e "${CYAN}Critical Services:${NC}"
    local services=("ssh" "ufw" "fail2ban" "auditd")
    for service in "${services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            echo -e "  ✓ $service: ${GREEN}Active${NC}"
        else
            echo -e "  ✗ $service: ${RED}Inactive${NC}"
        fi
    done
    echo
    
    # Disk usage
    echo -e "${CYAN}Disk Usage:${NC}"
    df -h / | tail -1
    echo
    
    # Memory usage
    echo -e "${CYAN}Memory Usage:${NC}"
    free -h | grep "Mem:"
    echo
    
    # Recent logins
    echo -e "${CYAN}Recent Logins (last 5):${NC}"
    last -5 | head -5
}

# View logs function
view_logs() {
    echo -e "${BLUE}=== Available Logs ===${NC}"
    echo "1. Main Log"
    echo "2. Scan Results"
    echo "3. System Log (auth)"
    echo "4. Firewall Log"
    echo "0. Back"
    
    read -rp "Select log to view: " log_choice
    
    case $log_choice in
        1)
            if [[ -f "$LOG_DIR/cyberpatriot.log" ]]; then
                echo -e "${CYAN}=== Main Log (last 50 lines) ===${NC}"
                tail -50 "$LOG_DIR/cyberpatriot.log"
            else
                echo -e "${YELLOW}No main log found${NC}"
            fi
            ;;
        2)
            echo -e "${CYAN}=== Available Scan Results ===${NC}"
            ls -la "$SCAN_DIR/" 2>/dev/null || echo "No scan results found"
            ;;
        3)
            if [[ -f /var/log/auth.log ]]; then
                echo -e "${CYAN}=== Authentication Log (last 20 lines) ===${NC}"
                tail -20 /var/log/auth.log
            else
                echo -e "${YELLOW}No auth log found${NC}"
            fi
            ;;
        4)
            if [[ -f /var/log/ufw.log ]]; then
                echo -e "${CYAN}=== Firewall Log (last 20 lines) ===${NC}"
                tail -20 /var/log/ufw.log
            else
                echo -e "${YELLOW}No firewall log found${NC}"
            fi
            ;;
        0)
            return 0
            ;;
        *)
            echo -e "${RED}Invalid selection${NC}"
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
        read -rp "Enter choice (1-13): " choice
        
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
                echo -e "${GREEN}Thank you for using CyberPatriot Toolkit!${NC}"
                log_info "CyberPatriot toolkit session ended"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please choose 1-13.${NC}" >&2
                ;;
        esac
        
        echo
        read -rp "Press Enter to continue..." -t 30 || true
        echo
    done
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi