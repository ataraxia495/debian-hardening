# 🛡️ Debian 12-13 Hardening Script

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Debian 12](https://img.shields.io/badge/Debian-12-blue?logo=debian)](https://www.debian.org/releases/bookworm/)
[![Debian 13](https://img.shields.io/badge/Debian-13-blue?logo=debian)](https://www.debian.org/releases/trixie/)

A comprehensive Bash script to automate security hardening for **Debian 12 (bookworm)** and **Debian 13 (trixie)** servers.  
It applies best security practices across multiple system components with interactive prompts, detailed logging, and a built‑in rollback mechanism.

## ✨ Features

- **Modular hardening** – choose exactly what to apply:
  - SSH – secure configuration, custom port, disable root login
  - Firewall – `nftables` with strict default‑deny policy
  - DNS – `systemd-resolved` with DNS‑over‑TLS and DNSSEC
  - GRUB – password protection for boot loader
  - Hardware – disable USB/Firewire, install integrity checkers
  - Kernel – `sysctl` hardening (BPF, network, ptrace, etc.)
  - Fail2ban – protect SSH from brute‑force attacks
  - Lynis suggestions – implement common Lynis recommendations
  - System audit – run a Lynis audit and generate an HTML report

- **Interactive confirmation** – each action requires explicit approval
- **Automatic backups** – original configuration files are saved before any changes, allowing safe restoration.
- **Comprehensive logging** – separate logs per module plus a master log in `/var/log/hardening/`.
- **Rollback menu** – restore previous configurations from backups if needed.
- **Cleanup** – optionally remove temporary packages (e.g., Lynis) on exit.

## ⚙️ Requirements

- **Debian 12 (bookworm)** or **Debian 13 (trixie)**
- **Root privileges** – the script must be run as root (or with `sudo`)
- **Internet connection** – for package downloads
- **Basic debian utilities**

## 🚀 Installation

1. **Clone the repository** (or download the script and configuration file):

   ```bash
   git clone https://github.com/ataraxia495/debian-hardening.git  
   cd debian-hardening
   ```

2. **Run the script as root**

   ```bash
   sudo chmod +x main.sh
   sudo ./main.sh
   ```

3. Or simply

   ```bash
   sudo bash main.sh
   ```

## 🧭 Usage

When launched, the script displays a menu of available hardening modules. You can select which ones to apply by entering the corresponding numbers.
Each module will prompt for confirmation before making any changes. After all selected modules are processed, you will have the option to run a system audit with Lynis and to clean up temporary packages.

All modifications are logged, and backups of original configuration files are stored. In case something goes wrong, you can use the built‑in rollback option to restore the previous state.

## ⚙️ Configuration
You can adjust the following variables in the configuration.conf:

- LOG_DIR="/var/log/hardening" – (do not change)
- MAIN_LOG="$LOG_DIR/hardening-main.log" – (do not change)
- PORT=2200 – custom SSH port (must be between 1024 and 65535)
- GRUBUSERNAME="grubadmin" – username for GRUB boot menu protection
- USER_HOME=$(eval echo ~${SUDO_USER:-$USER}) – (do not change)

## 📁 Log Structure
All logs are written to /var/log/hardening/:

```text
/var/log/hardening/
├── main.log
├── ssh-hardening.log
├── firewall-hardening.log
├── dns-hardening.log
├── grub-hardening.log
├── hardware-hardening.log
├── kernel-hardening.log
├── fail2ban-hardening.log
├── lynis-suggestions.log
├── system-audit.log
└── rollback.log
```
---
⚠️ **ALWAYS TEST IN ISOLATED ENVIRONMENT FIRST**
