#!/bin/bash
# shellcheck source=configuration.conf
export DEBIAN_FRONTEND=noninteractive

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration file
CONF_FILE="configuration.conf"

# Banner
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo -e "║           ${WHITE}Debian 12-13 Hardening Script${CYAN}                   ║"
    echo "║                                                           ║"
    echo -e "║      ${YELLOW}Minimal Installation Security Hardening${CYAN}              ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Load configuration
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
else
    echo "ERROR: Configuration file not found at: $CONF_FILE" >&2
    exit 1
fi

# ------------------------------------------------
# Logging configuration
# ------------------------------------------------
mkdir -p "$LOG_DIR" 2>/dev/null || { echo -e "${RED}Cannot create log directory: $LOG_DIR${NC}"; exit 1; }
chmod 700 "$LOG_DIR"
touch "$MAIN_LOG"
chmod 600 "$MAIN_LOG"
chown root:root "$MAIN_LOG"

log_summary() {
    local msg="$1"
    local ts; ts=$(date '+%d-%m-%Y %H:%M:%S')
    printf "[%s] %s\n" "$ts" "$msg" >> "$MAIN_LOG"
}

log_section() {
    local section_log="$1"
    local msg="$2"
    local ts; ts=$(date '+%d-%m-%Y %H:%M:%S')
    # Write to section-specific log
    printf "[%s] %s\n" "$ts" "$msg" >> "$section_log"
    # Also mirror important events to main log with section name
    case "$msg" in
        START*|END*|ERROR*|WARNING*|User*|backup*|Created*|Restored*)
            local section_name; section_name=$(basename "$section_log" .log)
            printf "[%s] [%s] %s\n" "$ts" "$section_name" "$msg" >> "$MAIN_LOG"
            ;;
    esac
}

log_section_and_echo() {
    local section_log="$1"
    local color="$2"
    local msg="$3"
    echo -e "${color}${msg}${NC}"
    log_section "$section_log" "$msg"
}

init_log() {
    local ts; ts=$(date '+%d-%m-%Y %H:%M:%S')
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "       Debian Hardening Script - Execution started"
        echo "═══════════════════════════════════════════════════════════════"
        echo "Start time: $ts"
        echo "User:       ${SUDO_USER:-root}"
        echo "Script:     $0"
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            echo "Distro:     $PRETTY_NAME"
        fi
        echo ""
    } >> "$MAIN_LOG"
    log_summary "Hardening script execution started."
}

# Check root privileges
check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${RED}${BOLD}ERROR: This script must be executed as root.${NC}" >&2
        echo -e "${YELLOW}Please run: sudo $0${NC}"
        exit 1
    fi
}

# Function for checking user's confirmation
confirm_action() {
    local action_name="$1"
    local description="$2"
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${WHITE}${BOLD}Action:${NC} ${YELLOW}$action_name${NC}"
    echo -e "${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${WHITE}${BOLD}Description:${NC}"
    # Multiline with wrapping
    echo -e "$description" | fold -s -w 50 | while IFS= read -r line; do
        echo -e "${CYAN}${BOLD}║${NC}   $line"
    done
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -rp "$(echo -e "${GREEN}${BOLD}Proceed?${NC} ${YELLOW}[Y/n]:${NC}") " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" && -n "$confirm" ]]; then
        log_summary "User cancelled: $action_name"
        echo -e "${RED}Action cancelled.${NC}"
        return 1
    fi
    log_summary "User confirmed: $action_name"
    return 0
}

# ------------------------------------------------
# SSH hardening: configuring
# ------------------------------------------------
ssh_hardening() {
    local SECTION_LOG="$LOG_DIR/ssh-hardening.log"
    local CONFIG_DIR="/etc/ssh/sshd_config.d"
    local CONFIG_FILE="$CONFIG_DIR/99-hardening.conf"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "SSH HARDENING - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started SSH hardening."

    if ! confirm_action "SSH Hardening" "This will create SSH hardening configuration in $CONFIG_DIR, change port to ${PORT}, disable root login, and apply security settings. SSH service will be reloaded."; then
        log_section "$SECTION_LOG" "User cancelled SSH hardening."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Applying SSH hardening."

    if [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup"
        log_section "$SECTION_LOG" "Created backup: ${CONFIG_FILE}.backup"
    fi

    cat > "$CONFIG_FILE" << EOF
# SSH Hardening Configuration - Applied $(date '+%d-%m-%Y %H:%M:%S')

# Change default SSH port
Port ${PORT}

# Disable root login
PermitRootLogin no

# Authentication settings
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# Security settings
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no

# Logging
LogLevel VERBOSE
EOF
    chmod 600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    log_section "$SECTION_LOG" "Created configuration file: $CONFIG_FILE"
    log_section "$SECTION_LOG" "Port -> ${PORT}"
    log_section "$SECTION_LOG" "PermitRootLogin -> no"
    log_section "$SECTION_LOG" "MaxAuthTries -> 3"
    log_section "$SECTION_LOG" "MaxSessions -> 2"
    log_section "$SECTION_LOG" "X11Forwarding -> no"
    log_section "$SECTION_LOG" "AllowAgentForwarding -> no"
    log_section "$SECTION_LOG" "AllowTcpForwarding -> no"
    log_section "$SECTION_LOG" "ClientAliveInterval -> 300"
    log_section "$SECTION_LOG" "ClientAliveCountMax -> 2"
    log_section "$SECTION_LOG" "TCPKeepAlive -> no"
    log_section "$SECTION_LOG" "LogLevel -> VERBOSE"

    # Test & reload
    if sshd -t 2>/dev/null; then
        log_section "$SECTION_LOG" "sshd -t -> configuration test PASSED."
        log_section_and_echo "$SECTION_LOG" "${GREEN}" "SSH configuration syntax check passed."
    else
        log_section "$SECTION_LOG" "ERROR: sshd -t configuration test FAILED."
        log_summary "ERROR: SSH configuration test failed."
        echo -e "${RED}ERROR: SSH configuration test failed - not reloading.${NC}"
        return 1
    fi

    if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
        log_section "$SECTION_LOG" "SSH service reloaded successfully."
        log_section_and_echo "$SECTION_LOG" "${GREEN}" "SSH service reloaded."
    else
        log_section "$SECTION_LOG" "WARNING: Failed to reload SSH service."
        echo -e "${YELLOW}WARNING: Could not reload SSH service.${NC}"
    fi

    echo ""
    echo "Port                    -> ${PORT}"
    echo "PermitRootLogin         -> no"
    echo "MaxAuthTries            -> 3"
    echo "MaxSessions             -> 2"
    echo "LoginGraceTime          -> 60"
    echo "ClientAliveInterval     -> 300"
    echo "ClientAliveCountMax     -> 2"
    echo "TCPKeepAlive            -> no"
    echo "X11Forwarding           -> no"
    echo "AllowAgentForwarding    -> no"
    echo "AllowTcpForwarding      -> no"
    echo "PermitEmptyPasswords    -> no"
    echo "IgnoreRhosts            -> yes"
    echo "HostbasedAuthentication -> no"
    echo "LogLevel                -> VERBOSE"
    echo ""

    log_section "$SECTION_LOG" "END: SSH hardening completed."
    log_summary "SSH hardening completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "SSH hardening completed successfully!"
}

# ---------------------------------------------------
# Firewall hardening: nftables installing/configuring
# ---------------------------------------------------
firewall_hardening() {
    local SECTION_LOG="$LOG_DIR/firewall-hardening.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "FIREWALL HARDENING - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started firewall hardening."

    if ! confirm_action "Firewall Hardening" "This will install nftables, reset rules, deny incoming by default, and allow SSH port ${PORT}."; then
        log_section "$SECTION_LOG" "User cancelled firewall hardening."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Applying firewall hardening."

    # Saving original config
    if [[ ! -f /etc/nftables.conf.old ]]; then
        cp /etc/nftables.conf /etc/nftables.conf.old
        log_section "$SECTION_LOG" "Saved original nftables configuration file: /etc/nftables.conf.old"
    fi

    # Backup
    if [[ ! -f /etc/nftables.conf.backup ]]; then
        cp /etc/nftables.conf /etc/nftables.conf.backup 2>/dev/null
        log_section "$SECTION_LOG" "Created backup: /etc/nftables.conf.backup"
    elif confirm_action "Overwrite nftables Backup" "Existing backup found - overwrite?"; then
        cp /etc/nftables.conf /etc/nftables.conf.backup
        log_section "$SECTION_LOG" "Overwrote backup: /etc/nftables.conf.backup"
    fi

    # Install
    if ! command -v nft >/dev/null 2>&1; then
        apt-get update && apt-get install -y nftables && log_section "$SECTION_LOG" "Installed nftables."
    fi
    systemctl enable --now nftables 2>/dev/null && log_section "$SECTION_LOG" "nftables service enabled and started."

    cat > /etc/nftables.conf << 'EOF'
flush ruleset
include "/etc/nftables.d/*.nft"
EOF

    # Create nftables configuration content
    mkdir -p /etc/nftables.d
    cat > /etc/nftables.d/99-hardening.nft << EOF
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        tcp dport ${PORT} ct state new accept
        icmp type echo-request limit rate 5/second accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
        oif lo accept
    }
}
EOF

    chmod 600 /etc/nftables.d/99-hardening.nft

    log_section "$SECTION_LOG" "Created nftables configuration: /etc/nftables.d/99-hardening.nft"

    # Apply the configuration
    nft -f /etc/nftables.conf && log_section "$SECTION_LOG" "Applied nftables configuration from file."
    systemctl restart nftables && log_section "$SECTION_LOG" "nftables service restarted."

    log_section "$SECTION_LOG" "END: Firewall hardening completed."
    log_summary "Firewall hardening completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "Firewall hardening completed successfully!"

    echo -e "${CYAN}Current ruleset:${NC}"
    nft list ruleset
}

# ------------------------------------------------------
# DNS hardening: systemd-resolved installing/configuring
# ------------------------------------------------------
dns_hardening() {
    local SECTION_LOG="$LOG_DIR/dns-hardening.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "DNS HARDENING - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started DNS hardening."

    if ! confirm_action "DNS Hardening" "This will download systemd-resolved, create/modify /etc/systemd/resolved.conf.d/00-dns.conf and update DNS configuration."; then
        log_section "$SECTION_LOG" "User cancelled DNS hardening."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Applying DNS hardening."

    # Install systemd-resolved if not present
    if ! dpkg -l | grep -q systemd-resolved; then
        apt-get install -y systemd-resolved && log_section "$SECTION_LOG" "Installed systemd-resolved."
    else
        log_section "$SECTION_LOG" "systemd-resolved is already installed."
    fi

    # Enable and start the service
    systemctl enable --now systemd-resolved && log_section "$SECTION_LOG" "Enabled systemd-resolved service."

    # Create configuration directory
    mkdir -p /etc/systemd/resolved.conf.d && log_section "$SECTION_LOG" "Created /etc/systemd/resolved.conf.d directory."

    # Create DNS configuration
    cat > /etc/systemd/resolved.conf.d/00-dns.conf << 'EOF'
[Resolve]
DNS=1.1.1.1 1.0.0.1
DNSOverTLS=yes
DNSSEC=yes
Cache=yes
EOF
    log_section "$SECTION_LOG" "Created DNS configuration file."

    # Update resolv.conf symlink
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf && log_section "$SECTION_LOG" "Updated /etc/resolv.conf symlink."
    systemctl restart systemd-resolved && log_section "$SECTION_LOG" "Restarted systemd-resolved service."

    echo ""
    echo "DNS        -> 1.1.1.1 1.0.0.1"
    echo "DNSOverTLS -> yes"
    echo "DNSSEC     -> yes"
    echo "Cache      -> yes"
    echo ""

    log_section "$SECTION_LOG" "END: DNS hardening completed."
    log_summary "DNS hardening completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "DNS hardening completed successfully!"
}

# --------------------------------------------------------
# GRUB hardening: create random generated password & apply
# --------------------------------------------------------
grub_hardening() {
    local SECTION_LOG="$LOG_DIR/grub-hardening.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "GRUB HARDENING - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started GRUB hardening."

    if ! confirm_action "GRUB Hardening" "This will set a GRUB password, modify /etc/grub.d/40_custom, and update GRUB configuration. You will need the GRUB password to boot the system."; then
        log_section "$SECTION_LOG" "User cancelled GRUB hardening."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Applying GRUB hardening."

    # Saving original config
    if [[ ! -f /etc/grub.d/40_custom.old ]]; then
        cp /etc/grub.d/40_custom /etc/grub.d/40_custom.old
        log_section "$SECTION_LOG" "Saved original GRUB configuration file: /etc/grub.d/40_custom.old"
    fi

    # Backup existing GRUB configuration
    if [[ ! -f /etc/grub.d/40_custom.backup ]]; then
        cp /etc/grub.d/40_custom /etc/grub.d/40_custom.backup
        log_section "$SECTION_LOG" "Created GRUB config backup: /etc/grub.d/40_custom.backup"
    else
        if confirm_action "Overwrite GRUB Backup" "This will overwrite your existing backup."; then
            cp /etc/grub.d/40_custom /etc/grub.d/40_custom.backup
            log_section "$SECTION_LOG" "Overwrote GRUB config backup: /etc/grub.d/40_custom.backup"
        else
            log_section "$SECTION_LOG" "Using existing GRUB backup without overwriting."
        fi
    fi

    # Check for existing GRUB password
    if [[ -f /etc/grub.d/40_custom ]] && grep -q "password_pbkdf2" /etc/grub.d/40_custom; then
        if ! confirm_action "GRUB Password Overwrite Warning" "Looks like you already have a GRUB password. If you continue, the existing password will be overwritten."; then
            log_section "$SECTION_LOG" "User cancelled due to existing GRUB password."
            return 1
        else
            log_section "$SECTION_LOG" "Proceeding to overwrite existing GRUB password."
        fi
    fi

    # Generate GRUB password
    local grub_gen; grub_gen=$(openssl rand -base64 12)
    log_section "$SECTION_LOG" "Generated random GRUB password."
    log_section "$SECTION_LOG" "Generating GRUB password hash."
    local grub_hash; grub_hash=$(printf "%s\n%s\n" "$grub_gen" "$grub_gen" | grub-mkpasswd-pbkdf2 2>/dev/null | awk '/grub.pbkdf2/{print $NF}')

    if [[ -z "$GRUBUSERNAME" ]]; then
        log_section "$SECTION_LOG" "ERROR: GRUB username is unset."
        echo -e "${RED}ERROR: GRUB username is unset.${NC}"
        return 1
    fi

    if [[ -z "$grub_hash" ]]; then
        log_section "$SECTION_LOG" "ERROR: Failed to generate GRUB password hash."
        echo -e "${RED}ERROR: Failed to generate GRUB password hash.${NC}"
        return 1
    fi

    log_section "$SECTION_LOG" "Successfully generated GRUB password hash."

    # Create GRUB configuration
    log_section "$SECTION_LOG" "Creating /etc/grub.d/40_custom with GRUB password."
    cat > /etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 \$0

set superusers="$GRUBUSERNAME"
password_pbkdf2 $GRUBUSERNAME $grub_hash
EOF
    chmod +x /etc/grub.d/40_custom
    log_section "$SECTION_LOG" "Set executable permissions on /etc/grub.d/40_custom."

    update-grub
    log_section "$SECTION_LOG" "GRUB configuration updated successfully."

    log_section "$SECTION_LOG" "Displaying GRUB credentials to user"
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${WHITE}${BOLD}GRUB Boot Credentials${NC}"
    echo -e "${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${WHITE}Username:${NC} ${YELLOW}${BOLD}$GRUBUSERNAME${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${WHITE}Password:${NC} ${YELLOW}${BOLD}$grub_gen${NC}"
    echo -e "${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${RED}${BOLD}SAVE THESE CREDENTIALS!${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Clean up
    unset grub_gen
    log_section "$SECTION_LOG" "Cleared GRUB password from memory."

    log_section "$SECTION_LOG" "END: GRUB hardening completed."
    log_summary "GRUB hardening completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "GRUB hardening completed successfully!"
}

# -------------------------------------------------------
# Hardware hardening: Installation & Configuration
# -------------------------------------------------------
hardware_hardening() {
    local SECTION_LOG="$LOG_DIR/hardware-hardening.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "HARDWARE HARDENING - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started hardware hardening."

    if ! confirm_action "Hardware hardening" "This will install and configure multiple security packages: debsums (integrity checker), rkhunter (rootkit scanner), auditd (auditing daemon), and perform hardware/package hardening (disable USB/FireWire, configure apt-listbugs)."; then
        log_section "$SECTION_LOG" "User cancelled hardware hardening."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Installing security packages."
    echo -e "${CYAN}Installing security packages: debsums, rkhunter, auditd...${NC}"
    apt-get install -y debsums rkhunter auditd
    log_section "$SECTION_LOG" "Installed packages: debsums, rkhunter, auditd."
    log_section "$SECTION_LOG" "END: Installing security packages."

    # --- Hardware & Package Hardening ---
    log_section "$SECTION_LOG" "START: Applying Hardware & Package Hardening."

    # Disabling USB storage driver
    if confirm_action "Disabling USB Storage" "This will add 'blacklist usb-storage' to /etc/modprobe.d/blacklist-usb.conf and update initramfs."; then
        log_section "$SECTION_LOG" "Checking/creating USB blacklist file."
        if [[ ! -f /etc/modprobe.d/blacklist-usb.conf ]]; then
            touch /etc/modprobe.d/blacklist-usb.conf
            chmod 600 /etc/modprobe.d/blacklist-usb.conf
            chown root:root /etc/modprobe.d/blacklist-usb.conf
            log_section "$SECTION_LOG" "Created /etc/modprobe.d/blacklist-usb.conf."
        fi
        if ! grep -q "blacklist usb-storage" /etc/modprobe.d/blacklist-usb.conf 2>/dev/null; then
            echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist-usb.conf
            log_section "$SECTION_LOG" "Added 'blacklist usb-storage' to /etc/modprobe.d/blacklist-usb.conf."
        else
             log_section "$SECTION_LOG" "USB storage was already blacklisted."
        fi
        log_section "$SECTION_LOG" "Updating initramfs after USB blacklist change."
        update-initramfs -u
    fi

    # Disabling firewire driver
    if confirm_action "Disabling Firewire" "This will create/update /etc/modprobe.d/blacklist-firewire.conf and update initramfs."; then
        log_section "$SECTION_LOG" "Checking/creating Firewire blacklist file."
        if [[ ! -f /etc/modprobe.d/blacklist-firewire.conf ]]; then
            cat > /etc/modprobe.d/blacklist-firewire.conf << 'EOF'
blacklist ohci1394
blacklist sbp2
blacklist dv1394
blacklist raw1394
blacklist video1394
blacklist firewire-ohci
blacklist firewire-sbp2
EOF
            chmod 600 /etc/modprobe.d/blacklist-firewire.conf
            chown root:root /etc/modprobe.d/blacklist-firewire.conf
            log_section "$SECTION_LOG" "Created /etc/modprobe.d/blacklist-firewire.conf."
        else
             log_section "$SECTION_LOG" "Firewire blacklist file already exists, skipping creation."
        fi
        log_section "$SECTION_LOG" "Updating initramfs after Firewire blacklist change."
        update-initramfs -u
    fi

    # apt-listbugs installation/configuration
    if confirm_action "Configure apt-listbugs" "This will install apt-listbugs and configure it to warn about critical bugs during package installation (currently set to manual mode via config file)."; then
        log_section "$SECTION_LOG" "Checking/installing apt-listbugs."
        if ! dpkg -l | grep -q apt-listbugs; then
            apt-get install -y apt-listbugs
            log_section "$SECTION_LOG" "Installed apt-listbugs package."
        else
             log_section "$SECTION_LOG" "apt-listbugs is already installed."
        fi

        log_section "$SECTION_LOG" "Creating/updating apt-listbugs configuration."
        cat > /etc/apt/apt.conf.d/10apt-listbugs << 'EOF'
// Before installing packages, check whether they have release-critical bugs.
// If you don't like it, comment it out.
// DPkg::Pre-Install-Pkgs {"/usr/bin/apt-listbugs apt";}; // Uncomment to enable automatic checks during apt install
DPkg::Tools::Options::/usr/bin/apt-listbugs "";
DPkg::Tools::Options::/usr/bin/apt-listbugs::Version "3";
DPkg::Tools::Options::/usr/bin/apt-listbugs::InfoFD "20";
AptListbugs::Severities "critical,grave,serious";
// AptListbugs::IgnoreRegexp "FTBFS"; // Example: Ignore 'fails to build from source' bugs
EOF
        chmod 600 /etc/apt/apt.conf.d/10apt-listbugs
        chown root:root /etc/apt/apt.conf.d/10apt-listbugs
        log_section "$SECTION_LOG" "Created/updated /etc/apt/apt.conf.d/10apt-listbugs."
    fi
    log_section "$SECTION_LOG" "END: Hardware & Package Hardening completed."

    # --- Debsums Configuration ---
    log_section "$SECTION_LOG" "START: Configuring debsums."
    echo -e "${CYAN}Configuring debsums...${NC}"
    log_section "$SECTION_LOG" "debsums is installed and ready to use. Run 'debsums -c' for checksum verification."
    log_section "$SECTION_LOG" "END: Configuring debsums completed."

    # --- Rkhunter Scan ---
    log_section "$SECTION_LOG" "START: rkhunter scan."
    echo -e "${CYAN}Starting rkhunter scan...${NC}"
    if command -v rkhunter >/dev/null 2>&1; then
        rkhunter --check --skip-keypress
    else
        log_section "$SECTION_LOG" "WARNING: rkhunter command not found after installation."
        echo -e "${YELLOW}WARNING: rkhunter command not found after installation.${NC}"
    fi
    log_section "$SECTION_LOG" "END: rkhunter scan."

    # --- Auditd Configuration ---
    log_section "$SECTION_LOG" "START: Configuring auditd."
    echo -e "${CYAN}Configuring auditd...${NC}"
    # Enable and start the service
    systemctl enable --now auditd 2>/dev/null && log_section "$SECTION_LOG" "auditd service enabled and started."
    if [[ ! -f /etc/audit/rules.d/99-hardening.rules ]]; then
        log_section "$SECTION_LOG" "Creating basic audit rules file: /etc/audit/rules.d/99-hardening.rules"
        cat > /etc/audit/rules.d/99-hardening.rules << 'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/hosts -p wa -k hosts_access
-w /etc/hostname -p wa -k hostname_change
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
EOF
        chmod 600 /etc/audit/rules.d/99-hardening.rules
        chown root:root /etc/audit/rules.d/99-hardening.rules
        log_section "$SECTION_LOG" "Created basic audit rules file."
        # Reload rules
        systemctl reload auditd 2>/dev/null && log_section "$SECTION_LOG" "Reloaded auditd rules."
    else
        log_section "$SECTION_LOG" "Basic audit rules file already exists: /etc/audit/rules.d/99-hardening.rules"
    fi
    log_section "$SECTION_LOG" "END: Configuring auditd completed."

    log_section "$SECTION_LOG" "END: Security packages installation & configuration completed."
    log_summary "Security packages installation & configuration completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "Security packages installed and configured successfully!"

    # Stricter rights

    chmod 600 /etc/crontab

    chmod 600 /etc/ssh/sshd_config
    systemctl restart ssh

    chmod 700 /etc/cron.d
    chmod 700 /etc/cron.daily
    chmod 700 /etc/cron.hourly
    chmod 700 /etc/cron.weekly
    chmod 700 /etc/cron.monthly

    chmod 700 /etc/sudoers.d

    #chmod 700 /etc/bin/as
    #chmod 700 /etc/bin/ld
    #chmod 700 /etc/bin/make

    cat > /etc/security/limits.d/10-coredump-debian.conf << EOF
*               soft    core            0
root            soft    core            0
*               hard    core            0
root            hard    core            0
EOF
}


# -------------------------------------------------------
# Kernel hardening: configuring
# -------------------------------------------------------
kernel_hardening() {
    local SECTION_LOG="$LOG_DIR/kernel-hardening.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "KERNEL HARDENING - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started kernel hardening."

    if ! confirm_action "Kernel Hardening" "This will modify kernel parameters in /etc/sysctl.d/99-custom.conf, including network security, BPF restrictions, and other kernel security settings."; then
        log_section "$SECTION_LOG" "User cancelled kernel hardening."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Applying kernel hardening changes."

    # Check for existing custom config, create if not
    if [[ ! -f /etc/sysctl.d/99-custom.conf ]]; then
        touch /etc/sysctl.d/99-custom.conf
        log_section "$SECTION_LOG" "Created /etc/sysctl.d/99-custom.conf"
    else
        log_section "$SECTION_LOG" "Custom kernel config already exists at /etc/sysctl.d/99-custom.conf."
    fi

    # Backup existing configuration
    if [[ ! -f /etc/sysctl.d/99-custom.conf.backup ]]; then
        cp /etc/sysctl.d/99-custom.conf /etc/sysctl.d/99-custom.conf.backup
        log_section "$SECTION_LOG" "Created kernel config backup: /etc/sysctl.d/99-custom.conf.backup"
    else
        if confirm_action "Overwrite Kernel Backup" "This will overwrite your existing backup."; then
            cp /etc/sysctl.d/99-custom.conf /etc/sysctl.d/99-custom.conf.backup
            log_section "$SECTION_LOG" "Overwrote kernel config backup: /etc/sysctl.d/99-custom.conf.backup"
        else
            log_section "$SECTION_LOG" "Using existing kernel backup without overwriting."
        fi
    fi

    # Creating file with kernel hardening parameters
    log_section "$SECTION_LOG" "Applying kernel hardening parameters to /etc/sysctl.d/99-custom.conf."
    cat > /etc/sysctl.d/99-custom.conf << EOF
# Kernel hardening parameters - Applied $(date '+%d-%m-%Y %H:%M:%S')

# TTY security
dev.tty.ldisc_autoload = 0

# Filesystem protection
fs.protected_fifos = 2

# Kernel pointer restrictions
kernel.kptr_restrict = 2

# SysRq key disable
kernel.sysrq = 0

# Unprivileged BPF disable
kernel.unprivileged_bpf_disabled = 1

# YAMA ptrace scope
kernel.yama.ptrace_scope = 1

# BPF JIT hardening
net.core.bpf_jit_harden = 2

# IPv4 security
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_redirects = 0

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    log_section "$SECTION_LOG" "Created /etc/sysctl.d/99-custom.conf with kernel hardening parameters."

    # Apply the settings
    if sysctl -p /etc/sysctl.d/99-custom.conf > /dev/null 2>&1; then
        log_section "$SECTION_LOG" "Successfully applied kernel hardening parameters."
    else
        log_section "$SECTION_LOG" "WARNING: Some kernel parameters failed to apply (check dmesg for details)."
    fi

    grep -v '^#' /etc/sysctl.d/99-custom.conf | grep -v '^$' | while read -r param; do
        log_section "$SECTION_LOG" "  $param"
    done

    echo ""
    echo "dev.tty.ldisc_autoload                 -> 0"
    echo "fs.protected_fifos                     -> 2"
    echo "kernel.kptr_restrict                   -> 2"
    echo "kernel.sysrq                           -> 0"
    echo "kernel.unprivileged_bpf_disabled       -> 1"
    echo "kernel.yama.ptrace_scope               -> 1"
    echo "net.core.bpf_jit_harden                -> 2"
    echo "net.ipv4.conf.default.log_martians     -> 1"
    echo "net.ipv4.conf.all.rp_filter            -> 1"
    echo "net.ipv4.conf.default.rp_filter        -> 1"
    echo "net.ipv4.conf.all.accept_redirects     -> 0"
    echo "net.ipv4.conf.all.send_redirects       -> 0"
    echo "net.ipv4.conf.all.accept_source_route  -> 0"
    echo "net.ipv4.tcp_syncookies                -> 1"
    echo "net.ipv4.conf.all.log_martians         -> 1"
    echo "net.ipv4.conf.default.accept_redirects -> 0"
    echo "net.ipv6.conf.all.accept_redirects     -> 0"
    echo "net.ipv6.conf.all.accept_source_route  -> 0"
    echo "net.ipv6.conf.default.accept_redirects -> 0"
    echo ""

    log_section "$SECTION_LOG" "END: Kernel hardening completed."
    log_summary "Kernel hardening completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "Kernel hardening completed successfully!"
}

# -------------------------------------------------------
# Fail2ban hardening: installing/configuring
# -------------------------------------------------------
fail2ban_hardening() {
    local SECTION_LOG="$LOG_DIR/fail2ban-hardening.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "FAIL2BAN HARDENING - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started fail2ban hardening."

    if ! confirm_action "Fail2ban Hardening" "This will install fail2ban, create jail.local configuration, and enable/start the fail2ban service."; then
        log_section "$SECTION_LOG" "User cancelled fail2ban hardening."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Applying fail2ban hardening changes."

    # Check and install fail2ban
    log_section "$SECTION_LOG" "Checking if fail2ban is installed."
    if ! dpkg -l | grep -q fail2ban; then
        log_section "$SECTION_LOG" "Installing fail2ban package."
        echo -e "${CYAN}Installing fail2ban...${NC}"
        apt-get install -y fail2ban
        log_section "$SECTION_LOG" "Installed fail2ban."
    else
        log_section "$SECTION_LOG" "fail2ban is already installed."
        echo -e "${CYAN}fail2ban is already installed.${NC}"
    fi

    # Create jail.local if it doesn't exist
    log_section "$SECTION_LOG" "Checking for /etc/fail2ban/jail.local configuration."
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        log_section "$SECTION_LOG" "Created /etc/fail2ban/jail.local from jail.conf."
    else
        log_section "$SECTION_LOG" "jail.local already exists, using existing configuration."
    fi

    if [[ ! -f /etc/fail2ban/jail.local.old ]]; then
        cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.old
        log_section "$SECTION_LOG" "Saved original fail2ban configuration file: /etc/fail2ban/jail.local.old"
    fi

    # Backup existing configuration
    log_section "$SECTION_LOG" "Creating backup of fail2ban configuration."
    if [[ ! -f /etc/fail2ban/jail.local.backup ]]; then
        cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.backup
        log_section "$SECTION_LOG" "Created fail2ban config backup: /etc/fail2ban/jail.local.backup"
    else
        if confirm_action "Overwrite Fail2ban Backup" "This will overwrite your existing backup."; then
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.backup
            log_section "$SECTION_LOG" "Overwrote fail2ban config backup: /etc/fail2ban/jail.local.backup"
        else
            log_section "$SECTION_LOG" "Using existing fail2ban backup without overwriting."
        fi
    fi

    # Create hardened fail2ban configuration
    log_section "$SECTION_LOG" "Creating hardened fail2ban configuration."
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 300
maxretry = 5

[sshd]
enabled = true
port = ${PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 300
EOF
    log_section "$SECTION_LOG" "Created /etc/fail2ban/jail.local with hardened configuration."

    log_section "$SECTION_LOG" "Enabling fail2ban service to start on boot."
    systemctl enable fail2ban
    log_section "$SECTION_LOG" "Enabled fail2ban service."

    log_section "$SECTION_LOG" "Restarting fail2ban service to apply configuration."
    if systemctl restart fail2ban; then
        log_section "$SECTION_LOG" "Successfully restarted fail2ban service."
        echo -e "${GREEN}Fail2ban service started successfully.${NC}"
    else
        log_section "$SECTION_LOG" "WARNING: Failed to restart fail2ban service."
        echo -e "${YELLOW}Warning: Failed to restart fail2ban service.${NC}"
    fi

    # Verify fail2ban is running
    log_section "$SECTION_LOG" "Verifying fail2ban service status."
    if systemctl is-active --quiet fail2ban; then
        log_section "$SECTION_LOG" "fail2ban service is actively running."
        echo -e "${GREEN}fail2ban service is running.${NC}"
    else
        log_section "$SECTION_LOG" "ERROR: fail2ban service is not running."
        echo -e "${RED}ERROR: fail2ban service is not running.${NC}"
    fi

    log_section "$SECTION_LOG" "Fail2ban configuration summary:"
    log_section "$SECTION_LOG" "  SSH Port: $PORT"
    log_section "$SECTION_LOG" "  Ban time: 3600 seconds (1 hour)"
    log_section "$SECTION_LOG" "  Find time: 300 seconds (5 minutes)"
    log_section "$SECTION_LOG" "  Max retries: 3 for SSH"

    echo ""
    echo "[DEFAULT]"
    echo "bantime  -> 3600"
    echo "findtime -> 300"
    echo "maxretry -> 5"
    #echo ""
    echo "[sshd]"
    echo "enabled  -> true"
    echo "port     -> ${PORT}"
    echo "filter   -> sshd"
    echo "logpath  -> /var/log/auth.log"
    echo "maxretry -> 3"
    echo "bantime  -> 3600"
    echo "findtime -> 300"
    echo ""

    log_section "$SECTION_LOG" "END: Fail2ban hardening completed."
    log_summary "Fail2ban hardening completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "Fail2ban hardening completed successfully!"
}

# -------------------------------------------------------
# Lynis suggestions: installing packages/configuring some
# -------------------------------------------------------
lynis_suggestions() {
    local SECTION_LOG="$LOG_DIR/lynis-suggestions.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "LYNIS SUGGESTIONS IMPLEMENTATION - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started Lynis suggestions implementation."

    if ! confirm_action "Lynis Suggestions Implementation" "This will install multiple packages (libpam-tmpdir, apt-show-versions, unattended-upgrades, aide), modify PAM configuration, configure automatic upgrades, and initialize AIDE database."; then
        log_section "$SECTION_LOG" "User cancelled Lynis suggestions implementation."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Implementing Lynis security suggestions."

    # Install libpam-tmpdir
    log_section "$SECTION_LOG" "Checking and installing libpam-tmpdir."
    echo -e "${CYAN}Installing libpam-tmpdir...${NC}"
    if ! dpkg -l | grep -q libpam-tmpdir; then
        apt-get install -y libpam-tmpdir
        log_section "$SECTION_LOG" "Installed libpam-tmpdir package."
    else
        log_section "$SECTION_LOG" "libpam-tmpdir is already installed."
    fi

    # Configure PAM tmpdir
    log_section "$SECTION_LOG" "Configuring PAM tmpdir in /etc/pam.d/common-session."
    if grep -q "tmpdir" /etc/pam.d/common-session 2>/dev/null; then
        log_section "$SECTION_LOG" "tmpdir already configured in PAM common-session."
    else
        echo "session optional pam_tmpdir.so" >> /etc/pam.d/common-session
        log_section "$SECTION_LOG" "Added tmpdir configuration to /etc/pam.d/common-session."
    fi

    # Install apt-show-versions
    log_section "$SECTION_LOG" "Checking and installing apt-show-versions."
    echo -e "${CYAN}Installing apt-show-versions...${NC}"
    if ! dpkg -l | grep -q apt-show-versions; then
        apt-get install -y apt-show-versions
        log_section "$SECTION_LOG" "Installed apt-show-versions package."
    else
        log_section "$SECTION_LOG" "apt-show-versions is already installed."
    fi

    # Install unattended-upgrades
    log_section "$SECTION_LOG" "Checking and installing unattended-upgrades."
    echo -e "${CYAN}Installing unattended-upgrades...${NC}"
    if ! dpkg -l | grep -q unattended-upgrades; then
        apt-get install -y unattended-upgrades
        log_section "$SECTION_LOG" "Installed unattended-upgrades package."
    else
        log_section "$SECTION_LOG" "unattended-upgrades is already installed."
    fi

    # Configure unattended-upgrades
    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
    echo "unattended-upgrades unattended-upgrades/automatic_reboot boolean false" | debconf-set-selections
    echo "unattended-upgrades unattended-upgrades/remove_unused_dependencies boolean false" | debconf-set-selections

    # Apply the configuration
    dpkg-reconfigure -f noninteractive unattended-upgrades

    # Creating config file for auto security updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    # Configure which updates to install
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
"${distro_id}:${distro_codename}";
"${distro_id}:${distro_codename}-security";
"${distro_id}ESMApps:${distro_codename}-apps-security";
"${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
// List packages to exclude from automatic updates
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
    log_section "$SECTION_LOG" "Configured unattended-upgrades automatically."

    # Install AIDE
    log_section "$SECTION_LOG" "Installing AIDE (Advanced Intrusion Detection Environment)."
    echo -e "${CYAN}Installing AIDE...${NC}"
    if ! dpkg -l | grep -q aide; then
        apt-get install -y aide aide-common
        log_section "$SECTION_LOG" "Installed AIDE and aide-common packages."
    else
        log_section "$SECTION_LOG" "AIDE is already installed."
    fi

    # Initialize AIDE database
    log_section "$SECTION_LOG" "Checking AIDE database status."
    if [[ ! -f /var/lib/aide/aide.db.new ]] && [[ ! -f /var/lib/aide/aide.db ]]; then
        if aide --init --config=/etc/aide/aide.conf; then
            log_section "$SECTION_LOG" "Successfully initialized AIDE database."
            log_section "$SECTION_LOG" "New AIDE database created at: /var/lib/aide/aide.db.new"
            echo -e "${YELLOW}AIDE database initialized. aide.db.new will be moved to /var/lib/aide/aide.db for activation.${NC}"
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        else
            log_section "$SECTION_LOG" "WARNING: AIDE database initialization may have encountered issues."
            echo -e "${YELLOW}AIDE database initialization completed with warnings. Check logs for details.${NC}"
        fi
    elif [[ -f /var/lib/aide/aide.db.new ]]; then
        log_section "$SECTION_LOG" "AIDE database already initialized (aide.db.new exists)."
        echo -e "${YELLOW}AIDE database already initialized. aide.db.new will be moved to /var/lib/aide/aide.db for activation.${NC}"
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    else
        log_section "$SECTION_LOG" "AIDE database already exists and is active (/var/lib/aide/aide.db)."
        echo -e "${CYAN}AIDE database is already active.${NC}"
    fi

    # Display summary of installed packages
    log_section "$SECTION_LOG" "Summary of installed packages:"
    for pkg in libpam-tmpdir apt-show-versions unattended-upgrades aide; do
        if dpkg -l | grep -q "^ii.*$pkg"; then
            log_section "$SECTION_LOG" "  $pkg: Installed"
        else
            log_section "$SECTION_LOG" "  $pkg: Not installed"
        fi
    done

    # Verify PAM configuration
    log_section "$SECTION_LOG" "Verifying PAM tmpdir configuration."
    if grep -q "pam_tmpdir.so" /etc/pam.d/common-session 2>/dev/null; then
        log_section "$SECTION_LOG" "PAM tmpdir is configured in /etc/pam.d/common-session."
    else
        log_section "$SECTION_LOG" "WARNING: PAM tmpdir is not configured in /etc/pam.d/common-session."
    fi

    log_section "$SECTION_LOG" "END: Lynis suggestions implementation completed."
    log_summary "Lynis suggestions implementation completed."
    log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "Lynis suggestions implementation completed successfully!"
}

# -----------------------------------------------------------
# Backups Rollback: return config files to previous versions
# -----------------------------------------------------------
backups_rollback() {
    local SECTION_LOG="$LOG_DIR/rollback.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "BACKUP ROLLBACK MENU - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started backup rollback menu."

    while true; do
        print_banner
        echo ""
        echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}${BOLD}║${NC} ${WHITE}${BOLD}Rollback Menu${NC}"
        echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Rollback SSH configuration"
        echo -e "${WHITE}2.${NC} Rollback nftables configuration"
        echo -e "${WHITE}3.${NC} Rollback GRUB configuration"
        echo -e "${WHITE}4.${NC} Rollback kernel configuration"
        echo -e "${WHITE}5.${NC} Rollback fail2ban configuration"
        echo -e "${WHITE}0.${NC} Back to main menu"
        echo ""
        read -rp "$(echo -e "${GREEN}Option:${NC}" ) " rollOpt

        case $rollOpt in
            1)
                log_section "$SECTION_LOG" "User selected: Rollback SSH configuration."
                # Check ssh config backup for existing
                if [[ ! -f /etc/ssh/sshd_config.backup ]]; then
                    log_section "$SECTION_LOG" "ERROR: No SSH backup found at /etc/ssh/sshd_config.backup."
                    echo -e "${RED}No SSH backup found.${NC}"
                    read -rp "Press enter to continue."
                    continue
                fi
                if ! confirm_action "Rollback SSH Configuration" "This will restore SSH configuration to previous version."; then
                    log_section "$SECTION_LOG" "User cancelled SSH rollback."
                    continue
                fi
                # Return ssh config from backup
                log_section "$SECTION_LOG" "START: Restoring SSH configuration from backup."
                cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
                log_section "$SECTION_LOG" "Restored SSH configuration from /etc/ssh/sshd_config.backup."
                log_section "$SECTION_LOG" "Reloading SSH service."
                systemctl reload ssh
                log_section "$SECTION_LOG" "SSH service reloaded."
                log_section "$SECTION_LOG" "END: SSH configuration rollback completed."
                log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "SSH configuration restored successfully!"
            ;;
            2)
                log_section "$SECTION_LOG" "User selected: Rollback nftables configuration."
                # Check nftables config backup for existing
                if [[ ! -f /etc/nftables.conf.backup ]]; then
                    log_section "$SECTION_LOG" "ERROR: No nftables backup found at /etc/nftables.conf.backup."
                    echo -e "${RED}No nftables backup found.${NC}"
                    read -rp "Press enter to continue."
                    continue
                fi
                if ! confirm_action "Rollback nftables Configuration" "This will restore nftables configuration to previous version."; then
                    log_section "$SECTION_LOG" "User cancelled nftables rollback."
                    continue
                fi
                # Return nftables config from backup
                log_section "$SECTION_LOG" "START: Restoring nftables configuration from backup."
                cp /etc/nftables.conf.backup /etc/nftables.conf
                log_section "$SECTION_LOG" "Restored nftables configuration from /etc/nftables.conf.backup."
                log_section "$SECTION_LOG" "Restarting nftables service."
                systemctl restart nftables
                log_section "$SECTION_LOG" "Restarted nftables service."
                log_section "$SECTION_LOG" "END: nftables configuration rollback completed."
                log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "nftables configuration restored successfully!"
            ;;
            3)
                log_section "$SECTION_LOG" "User selected: Rollback GRUB configuration."
                # Check GRUB config backup for existing
                if [[ ! -f /etc/grub.d/40_custom.backup ]]; then
                    log_section "$SECTION_LOG" "ERROR: No GRUB backup found at /etc/grub.d/40_custom.backup."
                    echo -e "${RED}No GRUB backup found.${NC}"
                    read -rp "Press enter to continue."
                    continue
                fi
                if ! confirm_action "Rollback GRUB Configuration" "This will restore GRUB configuration to previous version."; then
                    log_section "$SECTION_LOG" "User cancelled GRUB rollback."
                    continue
                fi
                # Return GRUB config from backup & give rights to execute
                log_section "$SECTION_LOG" "START: Restoring GRUB configuration from backup."
                cp /etc/grub.d/40_custom.backup /etc/grub.d/40_custom
                chmod +x /etc/grub.d/40_custom
                log_section "$SECTION_LOG" "Restored GRUB configuration from /etc/grub.d/40_custom.backup."
                log_section "$SECTION_LOG" "Updating GRUB configuration."
                update-grub
                log_section "$SECTION_LOG" "GRUB configuration updated."
                log_section "$SECTION_LOG" "END: GRUB configuration rollback completed."
                log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "GRUB configuration restored successfully!"
            ;;
            4)
                log_section "$SECTION_LOG" "User selected: Rollback kernel configuration."
                # Check kernel config backup for existing
                if [[ ! -f /etc/sysctl.d/99-custom.conf.backup ]]; then
                    log_section "$SECTION_LOG" "ERROR: No kernel configuration backup found at /etc/sysctl.d/99-custom.conf.backup."
                    echo -e "${RED}No kernel configuration backup found.${NC}"
                    read -rp "Press enter to continue."
                    continue
                fi
                if ! confirm_action "Rollback Kernel Configuration" "This will restore kernel configuration to previous version."; then
                    log_section "$SECTION_LOG" "User cancelled kernel rollback."
                    continue
                fi
                # Return kernel config from backup
                log_section "$SECTION_LOG" "START: Restoring kernel configuration from backup."
                cp /etc/sysctl.d/99-custom.conf.backup /etc/sysctl.d/99-custom.conf
                log_section "$SECTION_LOG" "Restored kernel configuration from /etc/sysctl.d/99-custom.conf.backup."
                log_section "$SECTION_LOG" "Applying kernel parameters."
                sysctl -p /etc/sysctl.d/99-custom.conf
                log_section "$SECTION_LOG" "Kernel parameters applied."
                log_section "$SECTION_LOG" "END: Kernel configuration rollback completed."
                log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "Kernel configuration restored successfully!"
            ;;
            5)
                log_section "$SECTION_LOG" "User selected: Rollback fail2ban configuration."
                # Check fail2ban config backup for existing
                if [[ ! -f /etc/fail2ban/jail.local.backup ]]; then
                    log_section "$SECTION_LOG" "ERROR: No fail2ban configuration backup found at /etc/fail2ban/jail.local.backup."
                    echo -e "${RED}No fail2ban configuration backup found.${NC}"
                    read -rp "Press enter to continue."
                    continue
                fi
                if ! confirm_action "Rollback Fail2ban Configuration" "This will restore fail2ban configuration to previous version."; then
                    log_section "$SECTION_LOG" "User cancelled fail2ban rollback."
                    continue
                fi
                # Return fail2ban config from backup
                log_section "$SECTION_LOG" "START: Restoring fail2ban configuration from backup."
                cp /etc/fail2ban/jail.local.backup /etc/fail2ban/jail.local
                log_section "$SECTION_LOG" "Restored fail2ban configuration from /etc/fail2ban/jail.local.backup."
                log_section "$SECTION_LOG" "Restarting fail2ban service."
                systemctl restart fail2ban
                log_section "$SECTION_LOG" "Restarted fail2ban service."
                log_section "$SECTION_LOG" "END: Fail2ban configuration rollback completed."
                log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "Fail2ban configuration restored successfully!"
            ;;
            0)
                log_section "$SECTION_LOG" "User selected: Back to main menu."
                log_section "$SECTION_LOG" "END: Rollback menu session completed."
                log_summary "Rollback menu session completed."
                return 0
            ;;
            *)
                log_section "$SECTION_LOG" "Invalid menu option selected: $rollOpt"
                echo -e "${RED}Invalid option.${NC}"
            ;;
        esac
        echo ""
        read -rp "Press enter to continue."
    done
}

# -----------------------------------------------------------
# System audit: installing lynis run audit then remove lynis
# -----------------------------------------------------------
system_audit() {
    local SECTION_LOG="$LOG_DIR/system-audit.log"

    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "SYSTEM AUDIT - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Started system audit."

    if ! confirm_action "System Audit" "This will install lynis, run a system audit, generate an HTML report, and then remove lynis."; then
        log_section "$SECTION_LOG" "User cancelled system audit."
        return 1
    fi

    log_section "$SECTION_LOG" "START: Performing system audit with Lynis."

    # Install lynis
    log_section "$SECTION_LOG" "Installing lynis package."
    echo -e "${CYAN}Installing lynis...${NC}"
    apt-get install -y lynis
    log_section "$SECTION_LOG" "Installed lynis package."

    # Install colorized-logs for HTML output
    log_section "$SECTION_LOG" "Installing colorized-logs for HTML conversion."
    apt-get install -y colorized-logs
    log_section "$SECTION_LOG" "Installed colorized-logs package."

    log_section "$SECTION_LOG" "Starting Lynis system audit."
    echo -e "${CYAN}Running system audit...${NC}"
    local REPORT_FILE="$USER_HOME/lynis-report.html"
    log_section "$SECTION_LOG" "Report will be saved to: $REPORT_FILE"

    # Run lynis audit and convert to HTML
    if lynis audit system | ansi2html -l > "$REPORT_FILE"; then
        log_section "$SECTION_LOG" "Lynis audit completed successfully."
        log_section "$SECTION_LOG" "Generated HTML report at: $REPORT_FILE"
        # Check report file size
        local REPORT_SIZE; REPORT_SIZE=$(wc -c < "$REPORT_FILE")
        log_section "$SECTION_LOG" "Report file size: $REPORT_SIZE bytes"
        if [[ $REPORT_SIZE -lt 100 ]]; then
            log_section "$SECTION_LOG" "WARNING: Report file is very small, conversion may have failed."
            echo -e "${YELLOW}Warning: Generated report file is very small. Check if conversion was successful.${NC}"
        fi
    else
        log_section "$SECTION_LOG" "ERROR: Lynis audit or HTML conversion failed."
        echo -e "${RED}ERROR: Audit or report generation failed.${NC}"
    fi

    # Display report location
    echo -e "${GREEN}${BOLD}System audit completed!${NC}"
    echo -e "${CYAN}Report saved to: $REPORT_FILE${NC}"
    log_section "$SECTION_LOG" "Displayed report location to user."

    # Verify report exists
    log_section "$SECTION_LOG" "Verifying report file exists."
    if [[ -f "$REPORT_FILE" ]]; then
        log_section "$SECTION_LOG" " Report file confirmed: $REPORT_FILE"
        log_section "$SECTION_LOG" "  File size: $(du -h "$REPORT_FILE" | cut -f1)"
        log_section "$SECTION_LOG" "  File permissions: $(stat -c "%A %U %G" "$REPORT_FILE")"
        chmod 644 "$REPORT_FILE"
        chown "$SUDO_USER:$SUDO_USER" "$REPORT_FILE"
        log_section "$SECTION_LOG" "Set proper ownership and permissions on report file."
    else
        log_section "$SECTION_LOG" " ERROR: Report file not found at $REPORT_FILE"
        echo -e "${RED}ERROR: Report file was not created.${NC}"
    fi

    log_section "$SECTION_LOG" "END: System audit completed."
    log_summary "System audit completed."
    if [[ -f "$REPORT_FILE" ]]; then
        log_section_and_echo "$SECTION_LOG" "${GREEN}${BOLD}" "System audit completed successfully! Report saved to: $REPORT_FILE"
    else
        log_section_and_echo "$SECTION_LOG" "${YELLOW}${BOLD}" "System audit completed with warnings. Report may not have been generated."
    fi
}

# -----------------------------------------------------------
# Cleanup function for temporary packages
# -----------------------------------------------------------
cleanup_temp_packages() {
    local SECTION_LOG="$LOG_DIR/cleanup.log"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_section "$SECTION_LOG" "CLEANUP ON EXIT - $(date '+%d-%m-%Y %H:%M:%S')"
    log_section "$SECTION_LOG" "═══════════════════════════════════════════════════════════════"
    log_summary "Starting cleanup of temporary packages."

    echo -e "${CYAN}Performing final cleanup of temporary packages...${NC}"

    # Check if lynis is installed and purge it
    if dpkg-query -W -f='${Status}' lynis 2>/dev/null | grep -q "install ok installed"; then
        log_section "$SECTION_LOG" "Found lynis installed, purging..."
        apt-get purge --auto-remove -y lynis
        log_section "$SECTION_LOG" "Purged lynis package."
        echo -e "${YELLOW}Purged lynis.${NC}"
    else
        log_section "$SECTION_LOG" "lynis not found, skipping purge."
    fi

    # Check if colorized-logs is installed and purge it
    if dpkg-query -W -f='${Status}' colorized-logs 2>/dev/null | grep -q "install ok installed"; then
        log_section "$SECTION_LOG" "Found colorized-logs installed, purging..."
        apt-get purge --auto-remove -y colorized-logs
        log_section "$SECTION_LOG" "Purged colorized-logs package."
        echo -e "${YELLOW}Purged colorized-logs.${NC}"
    else
        log_section "$SECTION_LOG" "colorized-logs not found, skipping purge."
    fi

    # Check if rkhunter is installed and purge it
    if dpkg-query -W -f='${Status}' rkhunter 2>/dev/null | grep -q "install ok installed"; then
        log_section "$SECTION_LOG" "Found rkhunter installed, purging..."
        apt-get purge --auto-remove -y rkhunter
        log_section "$SECTION_LOG" "Purged rkhunter package."
        echo -e "${YELLOW}Purged rkhunter.${NC}"
    else
        log_section "$SECTION_LOG" "rkhunter not found, skipping purge."
    fi

    log_section "$SECTION_LOG" "END: Cleanup completed."
    log_summary "Cleanup of temporary packages completed."
    echo -e "${GREEN}Final cleanup completed.${NC}"
}

show_menu() {
    print_banner
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${WHITE}${BOLD}Main Menu${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}1.${NC}  SSH Hardening"
    echo -e "${WHITE}2.${NC}  Firewall Hardening"
    echo -e "${WHITE}3.${NC}  DNS Hardening"
    echo -e "${WHITE}4.${NC}  GRUB Hardening"
    echo -e "${WHITE}5.${NC}  Hardware Hardening"
    echo -e "${WHITE}6.${NC}  Kernel Hardening"
    echo -e "${WHITE}7.${NC}  Fail2ban Hardening"
    echo -e "${WHITE}8.${NC}  Lynis Suggestions"
    echo -e "${WHITE}9.${NC}  Backups & Rollback"
    echo -e "${WHITE}10.${NC} System Audit"
    echo -e "${WHITE}0.${NC}  Exit"
    echo ""
    read -rp "$(echo -e "${GREEN}${BOLD}Option:${NC}" ) " option
}

main() {
    check_root
    init_log
    echo ""
    echo -e "${GREEN}${BOLD}Script initialized successfully!${NC}"
    echo -e "${CYAN}${BOLD}Distribution: $PRETTY_NAME${NC}"
    echo -e "${CYAN}Log file: $MAIN_LOG${NC}"
    echo ""
    read -rp "Press enter to continue."
    while true; do
        show_menu
        case $option in
            1) ssh_hardening ;;
            2) firewall_hardening ;;
            3) dns_hardening ;;
            4) grub_hardening ;;
            5) hardware_hardening ;;
            6) kernel_hardening ;;
            7) fail2ban_hardening ;;
            8) lynis_suggestions ;;
            9) backups_rollback ;;
            10) system_audit ;;
            0)
                cleanup_temp_packages
                log_summary "Hardening script execution ended."
                clear
                echo ""
                echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}${BOLD}║${NC} ${GREEN}${BOLD}Script completed successfully!${NC}"
                echo -e "${CYAN}${BOLD}║${NC}"
                echo -e "${CYAN}${BOLD}║${NC} ${YELLOW}Please reboot the system to apply all changes.${NC}"
                echo -e "${CYAN}${BOLD}║${NC}"
                echo -e "${CYAN}${BOLD}║${NC} ${CYAN}Log file location: $MAIN_LOG${NC}"
                echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
                echo ""
                exit 0
            ;;
            *)
                log_summary "Invalid menu option selected: $option"
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 1
            ;;
        esac
        echo ""
        read -rp "Press enter to continue."
    done
}

main
