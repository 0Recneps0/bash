#!/usr/bin/env bash
# ^always use because its portable

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Exit on any error
set -e

# Exit on undefined variable
set -u

echo "Starting system maintenance and security setup..."

# Function to handle yes/no prompts
ask_yes_no() {
    while true; do
        read -rp "$1 (Y/n): " yn
        case $yn in
            [Yy]* ) return 0;;  # Yes
            [Nn]* ) return 1;;  # No
            "" ) return 0;;     # Default to yes
            * ) echo "Please answer Y or n.";;
        esac
    done
}

# 1. Update the machine
echo "Updating system..."
apt-get update
apt-get upgrade -y
apt-get dist-upgrade -y

# 2. Install and run ClamAV
echo "ClamAV Configuration"
if ask_yes_no "Would you like to install ClamAV antivirus?"; then
    echo "Installing ClamTK..."
    apt-get install clamtk -y
    
    if ask_yes_no "Would you like to update virus definitions with freshclam?"; then
        echo "Updating virus definitions..."
        freshclam
    fi
    
    if ask_yes_no "Would you like to run a quick system scan now?"; then
        echo "Running quick scan..."
        clamscan --recursive --infected /home
    fi
fi

# 3. Configure firewall
echo "Firewall Configuration"
if ask_yes_no "Would you like to install and configure the firewall?"; then
    echo "Installing UFW..."
    apt-get install ufw -y
    
    if ask_yes_no "Would you like to configure basic firewall rules?"; then
        echo "Setting up basic firewall rules..."
        ufw default deny incoming
        ufw default allow outgoing
        
        if ask_yes_no "Allow SSH connections?"; then
            ufw allow ssh
        fi
        
        if ask_yes_no "Enable UFW now?"; then
            ufw enable
        fi
        
        if ask_yes_no "Show firewall status?"; then
            ufw status verbose
        fi
    fi
fi

# Function to change user password
change_password() {
    local user=$1
    echo "Changing password for user: $user"
    if echo "$user:Cyb3rPatr\!0t$" | chpasswd; then
        echo "Password successfully changed for $user"
    else
        echo "Failed to change password for $user"
    fi

}

echo "User Password Management Script"
echo "------------------------------"

if ask_yes_no "Would you like to see a list of all users first?"; then
    echo "User list:"
    echo "----------"
    cut -d: -f1 /etc/passwd
    echo "----------"
fi

if ask_yes_no "Would you like to change ALL user passwords?"; then
    # Get all regular users (UID >= 1000) and safely iterate
    awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd | while IFS= read -r user; do
	if ask_yes_no "Change password for $user?"; then
	    change_password "$user"
	fi
    done	
else
    # Change specific user password
    read -rp "Enter username to change password: " username
    if id "$username" >/dev/null 2>&1; then
        change_password "$username"
    else
        echo "User $username does not exist"
    fi
fi

echo "Password change operations completed."




# Check if root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Function to install package
install_package() {
    local package="$1"
    if ! dpkg -l | grep -q "^ii\s\+${package}\s"; then
        echo "Installing ${package}..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"
    fi
}

# Function to remove package
remove_package() {
    local package="$1"
    if dpkg -l | grep -q "^ii\s\+${package}\s"; then
        echo "Removing ${package}..."
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "$package"
        DEBIAN_FRONTEND=noninteractive apt-get purge -y "$package"
    fi
}

# Function to prompt for yes/no
prompt_yn() {
    local prompt="$1"
    local yn
    while true; do
        read -r -p "$prompt (y/n) " yn
        case "${yn,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

# Update package list
apt-get update

# Ensure UFW is installed first
install_package "ufw"

# Samba
if prompt_yn "Install Samba?"; then
    install_package "samba"
    install_package "samba-common"
    if ! systemctl is-enabled smbd &>/dev/null; then
        systemctl enable smbd
    fi
    systemctl start smbd
    ufw allow samba
else
    systemctl stop smbd &>/dev/null || true
    systemctl disable smbd &>/dev/null || true
    remove_package "samba"
    remove_package "samba-common"
    ufw deny samba
fi

# FTP
if prompt_yn "Install FTP?"; then
    install_package "vsftpd"
    if ! systemctl is-enabled vsftpd &>/dev/null; then
        systemctl enable vsftpd
    fi
    systemctl start vsftpd
    ufw allow ftp
else
    systemctl stop vsftpd &>/dev/null || true
    systemctl disable vsftpd &>/dev/null || true
    remove_package "vsftpd"
    ufw deny ftp
fi

# SSH
if prompt_yn "Install SSH?"; then
    install_package "openssh-server"
    if ! systemctl is-enabled ssh &>/dev/null; then
        systemctl enable ssh
    fi
    systemctl start ssh
    ufw allow ssh
else
    systemctl stop ssh &>/dev/null || true
    systemctl disable ssh &>/dev/null || true
    remove_package "openssh-server"
    ufw deny ssh
fi

# Telnet (with extra warning)
if prompt_yn "Install Telnet? (WARNING: INSECURE)"; then
    echo "WARNING: Telnet sends passwords in plain text. SSH is strongly recommended instead."
    if prompt_yn "Are you sure you want to continue?"; then
        install_package "telnetd"
        if ! systemctl is-enabled inetd &>/dev/null; then
            systemctl enable inetd
        fi
        systemctl start inetd
        ufw allow telnet
    fi
else
    systemctl stop inetd &>/dev/null || true
    systemctl disable inetd &>/dev/null || true
    remove_package "telnetd"
    ufw deny telnet
fi

# Mail
if prompt_yn "Install Mail server?"; then
    install_package "postfix"
    install_package "dovecot-imapd"
    install_package "dovecot-pop3d"
    if ! systemctl is-enabled postfix &>/dev/null; then
        systemctl enable postfix
    fi
    systemctl start postfix
    ufw allow smtp
    ufw allow pop3
    ufw allow imap
else
    systemctl stop postfix &>/dev/null || true
    systemctl stop dovecot &>/dev/null || true
    systemctl disable postfix &>/dev/null || true
    systemctl disable dovecot &>/dev/null || true
    remove_package "postfix"
    remove_package "dovecot-imapd"
    remove_package "dovecot-pop3d"
    ufw deny smtp
    ufw deny pop3
    ufw deny imap
fi

# Print
if prompt_yn "Install Print server?"; then
    install_package "cups"
    if ! systemctl is-enabled cups &>/dev/null; then
        systemctl enable cups
    fi
    systemctl start cups
    ufw allow 631/tcp
    ufw allow 631/udp
else
    systemctl stop cups &>/dev/null || true
    systemctl disable cups &>/dev/null || true
    remove_package "cups"
    ufw deny 631/tcp
    ufw deny 631/udp
fi

# MySQL
if prompt_yn "Install MySQL?"; then
    install_package "mysql-server"
    if ! systemctl is-enabled mysql &>/dev/null; then
        systemctl enable mysql
    fi
    systemctl start mysql
    ufw allow 3306/tcp
    echo "IMPORTANT: Run 'mysql_secure_installation' after this script completes"
else
    systemctl stop mysql &>/dev/null || true
    systemctl disable mysql &>/dev/null || true
    remove_package "mysql-server"
    ufw deny 3306/tcp
fi

# Web Server
if prompt_yn "Install Web Server?"; then
    install_package "apache2"
    if ! systemctl is-enabled apache2 &>/dev/null; then
        systemctl enable apache2
    fi
    systemctl start apache2
    ufw allow http
    ufw allow https
else
    systemctl stop apache2 &>/dev/null || true
    systemctl disable apache2 &>/dev/null || true
    remove_package "apache2"
    ufw deny http
    ufw deny https
fi

# DNS
if prompt_yn "Install DNS server?"; then
    install_package "bind9"
    if ! systemctl is-enabled bind9 &>/dev/null; then
        systemctl enable bind9
    fi
    systemctl start bind9
    ufw allow dns
else
    systemctl stop bind9 &>/dev/null || true
    systemctl disable bind9 &>/dev/null || true
    remove_package "bind9"
    ufw deny dns
fi

# Media Files
if prompt_yn "Install Media tools?"; then
    install_package "ubuntu-restricted-extras"
    install_package "vlc"
    install_package "ffmpeg"
else
    remove_package "ubuntu-restricted-extras"
    remove_package "vlc"
    remove_package "ffmpeg"
fi

# Enable UFW if not already enabled
if ! ufw status | grep -q "Status: active"; then
    echo "Enabling UFW firewall..."
    ufw --force enable
fi

# Display status
echo -e "\nConfiguration complete! Please check:"
echo "1. Review any error messages above"
echo "2. Verify firewall rules: ufw status"
echo "3. Set up proper authentication and access controls"
echo "4. Review service configurations as needed"
echo "5. If MySQL was installed, run mysql_secure_installation"

echo -e "\nActive services:"
systemctl list-units --type=service --state=active | grep -E "smbd|vsftpd|ssh|telnet|postfix|cups|mysql|apache2|bind9"

echo -e "\nBlocked/Removed services:"
for service in smbd vsftpd ssh inetd postfix cups mysql apache2 bind9; do
    if ! systemctl is-active --quiet "$service"; then
        echo "- $service"
    fi
done

echo -e "\nFirewall status:"
ufw status numbered

echo "Script completed."
