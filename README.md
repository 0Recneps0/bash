# CyberPatriot Hardening Script

## 🚀 Getting Started

### Prerequisites
- Linux system (Ubuntu/Debian recommended)
- Internet connection (for dependency installation)
- Root privileges

### 📥 Installation
1. **Download version**:
   

2. **Make the script executable**:
   ```bash
   chmod +x cyberpatriot.sh
   ```

---

## 🛠 Usage

### First-Time Setup
```bash
sudo ./cyberpatriot.sh
```
1. Select option **10** to install dependencies:  
   ```
   Enter choice (1-11): 10
   ```

### Key Features
| Option | Command              | Description                          |
|--------|----------------------|--------------------------------------|
| 1-7    | Individual hardening | Firewall, users, services, scans, etc |
| 8      | `cyber_resources`    | Open competition guides/checklists   |
| 9      | `run_all_features`   | Full system hardening                |
| 10     | `install_dependencies` | Install required tools             |
| 11     | -                    | Exit the script                     |

### 🔄 Example Workflow
```bash
# First run
sudo ./cyberpatriot.sh
10  # Install dependencies
9   # Run all features
7   # Generate report
11  # Exit

# Subsequent runs
sudo ./cyberpatriot.sh
9   # Run all features
7   # Generate report
11  # Exit
```

---

## 📂 Post-Run Verification
Check these directories for outputs:
```bash
# Security scans and forensic results
ls /var/log/cyberpatriot/scans/

# Encrypted backups
ls /var/backups/cyberpatriot/

# PDF reports
ls /var/log/cyberpatriot/reports/
```

---

## 💡 Notes
- **Browser Required**: Resource links (option 8) open in your default browser
- **Auto-Cleanup**: Old logs older than 14 days are automatically deleted
- **Backup Security**: Backups use randomized encryption passphrases
- **Dependencies**: Python 3 and `reportlab` are required for PDF reports (auto-installed)

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
``` 

This README provides:  
- Clear installation/usage instructions  
- Table-based command reference  
- Directory structure for outputs  
- Badges for quick scanning  
- Responsive Markdown formatting
