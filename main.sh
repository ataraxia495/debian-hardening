#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/hardening_script.log"

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

init_log() {
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    chown root:root "$LOG_FILE"
    log_message "=== Hardening Script Started ==="
    log_message "Date: $(date)"
    log_message "User: $(whoami)"
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        log_message "Distribution: $PRETTY_NAME"
    fi
}

log_message() {
    local message="$1"
    local timestamp=$(date '+%d-%m-%Y %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Check root privileges
check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${RED}${BOLD}ERROR: This script must be executed as root${NC}" >&2
        echo -e "${YELLOW}Please run: sudo $0${NC}"
        exit 1
    fi
}

check_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo -e "${GREEN}${NC} Distribution: ${BOLD}$PRETTY_NAME${NC}"
    fi
}

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
    read -p "$(echo -e ${GREEN}${BOLD}Proceed?${NC} ${YELLOW}[Y/n]:${NC} ) " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" && -n "$confirm" ]]; then
        log_message "User cancelled: $action_name"
        echo -e "${RED}Action cancelled.${NC}"
        return 1
    fi
    log_message "User confirmed: $action_name"
    return 0
}

ssh_hardening() {
    if ! confirm_action "SSH Hardening" "This will modify SSH configuration, change port to ${PORT}, disable root login, and apply security settings. SSH service will be reloaded."; then
        return 1
    fi

    echo ""
    log_message "Started SSH hardening"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    log_message "Created SSH config backup: /etc/ssh/sshd_config.backup"

    sed -i "s/^#\?Port.*/Port ${PORT}/" /etc/ssh/sshd_config
    log_message "Changed SSH port to ${PORT}"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    log_message "Disabled root login via SSH"
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    log_message "Set MaxAuthTries to 3"
    sed -i 's/^#\?MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config
    log_message "Set MaxSessions to 2"
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    log_message "Disabled X11Forwarding"
    sed -i 's/^#\?AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
    log_message "Disabled AllowAgentForwarding"
    sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
    log_message "Disabled AllowTcpForwarding"
    sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    log_message "Set ClientAliveInterval to 300"
    sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    log_message "Set ClientAliveCountMax to 2"
    sed -i 's/^#\?TCPKeepAlive.*/TCPKeepAlive no/' /etc/ssh/sshd_config
    log_message "Disabled TCPKeepAlive"
    sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    log_message "Set LogLevel to VERBOSE"

    if sshd -t 2>/dev/null; then
        log_message "SSH config test passed"
        echo -e "${GREEN}${NC} SSH configuration test passed"
    else
        log_message "ERROR: SSH config test failed"
        echo -e "${RED}ERROR: SSH config test failed${NC}"
        return 1
    fi

    if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
        log_message "SSH service reloaded"
        echo -e "${GREEN}${NC} SSH service reloaded successfully"
    else
        log_message "WARNING: SSH service reload failed (may not be running)"
        echo -e "${YELLOW}WARNING: SSH service reload failed${NC}"
    fi

    log_message "SSH hardening completed successfully"
    echo -e "${GREEN}${BOLD}SSH hardening completed successfully!${NC}"
}

firewall_hardening() {
    if ! confirm_action "Firewall Hardening" "This will install nftables, reset all firewall rules, deny incoming by default, allow SSH port ${PORT}, and enable the firewall. Existing firewall rules will be lost."; then
        return 1
    fi

    cp /etc/nftables.conf /etc/nftables.conf.backup
    log_message "Created nftables config backup: /etc/nftables.conf.backup"
    log_message "Started firewall hardening"

    echo -e "${CYAN}Installing nftables...${NC}"
    apt install nftables -y
    log_message "Installed nftables"

    systemctl enable nftables
    systemctl start nftables
    nft flush ruleset
    log_message "Flushed existing nftables ruleset"
    nft add table inet filter
    nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
    nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
    nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
    log_message "Created base chains with default policies"

    nft add rule inet filter input iif lo accept
    nft add rule inet filter output oif lo accept

    nft add rule inet filter input ct state established,related accept

    nft add rule inet filter output udp dport 53 ct state new accept
    nft add rule inet filter output tcp dport 53 ct state new accept

    nft add rule inet filter input tcp dport 443 ct state new accept

    nft add rule inet filter input tcp dport ${PORT} ct state new accept
    log_message "Allowed SSH port ${PORT}/tcp"
    nft add rule inet filter input limit rate 5/minute log prefix \"NFT DROP: \" flags all counter
    log_message "Enabled logging for dropped packets"
    nft list ruleset > /etc/nftables.conf
    log_message "Saved nftables configuration"
    systemctl restart nftables
    log_message "Restarted nftables service"

    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║${NC} ${WHITE}${BOLD}Nftables Ruleset${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    nft list ruleset
    echo ""
    log_message "Firewall hardening completed successfully"
    echo -e "${GREEN}${BOLD}Firewall hardening completed successfully!${NC}"
}

dns_hardening() {
    if ! confirm_action "DNS Hardening" "This will download systemd-resolved, create/modify /etc/systemd/resolved.conf.d/00-dns.conf and update DNS configuration"; then
    return 1
    fi

    sudo apt install systemd-resolved
    log_message "Installed systemd-resolved"
    systemctl enable --now systemd-resolved
    log_message "Enabled systemd-resolved service"
    mkdir /etc/systemd/resolved.conf.d
    if [[ ! -f /etc/systemd/resolved.conf.d/00-dns.conf ]]; then
    touch /etc/systemd/resolved.conf.d/00-dns.conf
    fi

    cat > /etc/systemd/resolved.conf.d/00-dns.conf << 'EOF'
[Resolve]
DNS=1.1.1.1 1.0.0.1
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
Cache=yes
EOF

    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
    log_message "Restarted systemd-resolved service"
    log_message "DNS hardening completed successfuly"
    echo -e "${GREEN}${BOLD}DNS hardneing completed successfuly!${NC}"
}

grub_hardening() {
    if ! confirm_action "GRUB Hardening" "This will set a GRUB password, modify /etc/grub.d/40_custom, and update GRUB configuration. You will need the GRUB password to boot the system."; then
        return 1
    fi

    cp /etc/grub.d/40_custom /etc/grub.d/40_custom.backup
    log_message "Created GRUB config backup: /etc/grub.d/40_custom.backup"

    if [[ -f /etc/grub.d/40_custom ]] && grep -q "password_pbkdf2" /etc/grub.d/40_custom; then
        if ! confirm_action "GRUB password overwrite warning" "Looks like you already have grub password. If you continue password would be overwritten"; then
            return 1
        fi
    fi

    log_message "Started GRUB hardening"

    local grub_gen=$(openssl rand -base64 12)
    log_message "Generated random GRUB password"

    local grub_hash=$(printf "%s\n%s\n" "$grub_gen" "$grub_gen" | grub-mkpasswd-pbkdf2 2>/dev/null | awk '/grub.pbkdf2/{print $NF}')

    if [[ -z "$GRUBUSERNAME" ]]; then
        log_message "ERROR: Grub username is unset"
        echo -e "${RED}ERROR: Grub username is unset${NC}"
        return 1
    fi

    if [[ -z "$grub_hash" ]]; then
        log_message "ERROR: Failed to generate GRUB password hash"
        echo -e "${RED}ERROR: Failed to generate GRUB password hash${NC}"
        return 1
    fi

    log_message "Generated GRUB password hash"
    cat > /etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 \$0

set superusers="$GRUBUSERNAME"
password_pbkdf2 $GRUBUSERNAME $grub_hash
EOF

    chmod +x /etc/grub.d/40_custom
    log_message "Created /etc/grub.d/40_custom with GRUB password"
    update-grub
    log_message "Updated GRUB configuration"

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

    unset grub_gen
    log_message "GRUB hardening completed successfully"
    echo -e "${GREEN}${BOLD}GRUB hardening completed successfully!${NC}"
}

security_packages() {
    if ! confirm_action "Security Packages Installation" "This will install multiple security packages: debsums, needrestart, rkhunter, and auditd."; then
        return 1
    fi

    log_message "Started security packages installation"

    echo -e "${CYAN}Updating package lists...${NC}"
    apt update
    echo -e "${CYAN}Installing security packages...${NC}"
    apt install debsums needrestart rkhunter auditd -y

    log_message "Installed security packages: debsums, needrestart, rkhunter, auditd"
    log_message "Security packages installation completed"
    echo -e "${GREEN}${BOLD}Security packages installed successfully!${NC}"
}

kernel_hardening() {
    if ! confirm_action "Kernel Hardening" "This will modify kernel parameters in /etc/sysctl.d/99-custom.conf, including network security, BPF restrictions, and other kernel security settings."; then
        return 1
    fi

    if [[ ! -f /etc/sysctl.d/99-custom.conf ]]; then
        touch /etc/sysctl.d/99-custom.conf
        log_message "Created /etc/sysctl.d/99-custom.conf"
    else
        log_message "Custom config already exists"
    fi

    cp /etc/sysctl.d/99-custom.conf /etc/sysctl.d/99-custom.conf.backup
    log_message "Created kernel config backup: /etc/sysctl.d/99-custom.conf.backup"

    log_message "Started kernel hardening"
    cat > /etc/sysctl.d/99-custom.conf << EOF
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
kernel.kptr_restrict = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
net.core.bpf_jit_harden = 2
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
EOF

    log_message "Created /etc/sysctl.d/99-custom.conf with kernel hardening parameters"
    sysctl -p /etc/sysctl.d/99-custom.conf
    log_message "Applied kernel hardening parameters"
    echo -e "${GREEN}${NC} Kernel hardening parameters applied"
    log_message "Kernel hardening completed successfully"
    echo -e "${GREEN}${BOLD}Kernel hardening completed successfully!${NC}"
}

fail2ban_hardening() {
    if ! confirm_action "Fail2ban Hardening" "This will install fail2ban, create jail.local configuration, and enable/start the fail2ban service."; then
        return 1
    fi

    log_message "Started fail2ban hardening"

    echo -e "${CYAN}Installing fail2ban...${NC}"
    apt update && apt install fail2ban -y
    log_message "Installed fail2ban"

    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        log_message "Created /etc/fail2ban/jail.local from jail.conf"
    else
        log_message "jail.local already exists, skipping copy"
    fi

    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.backup
    log_message "Created fail2ban config backup: /etc/fail2ban.jail.local.backup"

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

    systemctl enable fail2ban
    log_message "Enabled fail2ban service"
    systemctl restart fail2ban
    log_message "Started fail2ban service"
    echo -e "${GREEN}${NC}Fail2ban service started"
    log_message "Fail2ban hardening completed successfully"
    echo -e "${GREEN}${BOLD}Fail2ban hardening completed successfully!${NC}"
}

lynis_suggestions() {
    if ! confirm_action "Lynis Suggestions Implementation" "This will install multiple packages (libpam-tmpdir, apt-show-versions, unattended-upgrades, aide), modify PAM configuration, configure automatic upgrades, and initialize AIDE database."; then
        return 1
    fi

    log_message "Started lynis suggestions implementation"

    echo -e "${CYAN}Installing libpam-tmpdir...${NC}"
    apt update && apt install libpam-tmpdir -y
    log_message "Installed libpam-tmpdir"

    if grep -q "tmpdir" /etc/pam.d/common-session 2>/dev/null; then
        log_message "tmpdir already configured in PAM"
    else
        echo "session optional pam_tmpdir.so" >> /etc/pam.d/common-session
        log_message "Added tmpdir to /etc/pam.d/common-session"
    fi

    echo -e "${CYAN}Installing apt-show-versions...${NC}"
    apt install apt-show-versions -y
    log_message "Installed apt-show-versions"

    echo -e "${CYAN}Installing unattended-upgrades...${NC}"
    apt install unattended-upgrades -y
    log_message "Installed unattended-upgrades"
    dpkg-reconfigure -plow unattended-upgrades
    log_message "Configured unattended-upgrades"

    echo -e "${CYAN}Installing AIDE...${NC}"
    apt install aide aide-common -y
    log_message "Installed AIDE"

    if [[ ! -f /var/lib/aide/aide.db.new ]]; then
        aide --init --config=/etc/aide/aide.conf
        log_message "Initialized AIDE database"
        echo -e "${YELLOW}AIDE database initialized. Move /var/lib/aide/aide.db.new to /var/lib/aide/aide.db after review.${NC}"
    else
        log_message "AIDE database already exists"
    fi

    log_message "Lynis suggestions implementation completed"
    echo -e "${GREEN}${BOLD}Lynis suggestions implementation completed!${NC}"
}

backups_rollback() {
    while true; do
        print_banner
        echo ""
        echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}${BOLD}║${NC} ${WHITE}${BOLD}Rollback Menu${NC}"
        echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Rollback SSH config"
        echo -e "${WHITE}2.${NC} Rollback nftables config"
        echo -e "${WHITE}3.${NC} Rollback GRUB config"
        echo -e "${WHITE}4.${NC} Rollback kernel config"
        echo -e "${WHITE}0.${NC} Back to main menu"
        echo ""
        read -p "$(echo -e ${GREEN}Option:${NC} ) " rollOpt

        case $rollOpt in
            1)
                if [[ ! -f /etc/ssh/sshd_config.backup ]]; then
                    echo -e "${RED}No SSH backup found${NC}"
                    read -p "Press enter to continue.."
                    continue
                fi

                if ! confirm_action "Rollback SSH config" "This will restore SSH config to previous version"; then
                    continue
                fi

                cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
                log_message "Restored SSH config from backup"
                systemctl reload ssh
                log_message "SSH service reloaded"
                echo -e "${GREEN}SSH config restored${NC}"
                ;;
            2)
                if [[ ! -f /etc/nftables.conf.backup ]]; then
                    echo -e "${RED}No nftables backup found${NC}"
                    read -p "Press enter to continue.."
                    continue
                fi

                if ! confirm_action "Rollback nftables config" "This will restore nftables config to previous version"; then
                    continue
                fi

                cp /etc/nftables.conf.backup /etc/nftables.conf
                log_message "Restored nftables config from backup"
                systemctl restart nftables
                log_message "Restarted nftables service"
                echo -e "${GREEN}nftables config restored${NC}"
                ;;
            3)
                if [[ ! -f /etc/grub.d/40_custom.backup ]]; then
                    echo -e "${RED}No GRUB backup found${NC}"
                    read -p "Press enter to continue.."
                    continue
                fi

                if ! confirm_action "Rollback GRUB config" "This will restore GRUB config to previous version"; then
                    continue
                fi

                cp /etc/grub.d/40_custom.backup /etc/grub.d/40_custom
                log_message "Restored GRUB config from backup"
                update-grub
                log_message "Updated GRUB configuration"
                echo -e "${GREEN}GRUB config restored${NC}"
                ;;
            4)
                if [[ ! -f /etc/sysctl.d/99-custom.conf.backup ]]; then
                    echo -e "${RED}No kernel config backup found${NC}"
                    read -p "Press enter to continue.."
                    continue
                fi

                if ! confirm_action "Rollback kernel config" "This will restore kernel config to previous version"; then
                    continue
                fi

                cp /etc/sysctl.d/99-custom.conf.backup /etc/sysctl.d/99-custom.conf
                log_message "Restored kernel config from backup"
                sysctl -p /etc/sysctl.d/99-custom.conf
                log_message "Applied kernel hardening parameters"
                echo -e "${GREEN}Kernel config restored${NC}"
                ;;
            0)
                return 0
                ;;
            *)
                log_message "Invalid menu option selected: $rollOpt"
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
        echo ""
        read -p "Press enter to continue.."
    done
}

system_audit() {
    if ! confirm_action "System Audit" "This will install lynis, run a system audit, generate an HTML report, and then remove lynis."; then
        return 1
    fi

    log_message "Started system audit"

    echo -e "${CYAN}Installing lynis...${NC}"
    apt install lynis -y
    apt install colorized-logs -y
    log_message "Installed lynis package"
    log_message "Installed colorized-logs package"

    echo -e "${CYAN}Running system audit...${NC}"
    lynis audit system | ansi2html -l > "$USER_HOME/lynis-report.html"
    log_message "Lynis report created at $USER_HOME/lynis-report.html"

    echo -e "${GREEN}${BOLD}System audit completed!${NC}"
    echo -e "${CYAN}Report saved to: $USER_HOME/lynis-report.html${NC}"

    apt purge --auto-remove lynis -y
    apt purge --auto-remove colorized-logs -y
    log_message "Removed lynis package"
    log_message "Removed colorized-logs package"
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
    echo -e "${WHITE}5.${NC}  Security Packages"
    echo -e "${WHITE}6.${NC}  Kernel Hardening"
    echo -e "${WHITE}7.${NC}  Fail2ban Hardening"
    echo -e "${WHITE}8.${NC}  Lynis Suggestions"
    echo -e "${WHITE}9.${NC}  Backups & Rollback"
    echo -e "${WHITE}10.${NC} System Audit"
    echo -e "${WHITE}0.${NC}  Exit"
    echo ""
    read -p "$(echo -e ${GREEN}${BOLD}Option:${NC} ) " option
}

main() {
    check_root
    init_log

    echo ""
    echo -e "${GREEN}${BOLD}Script initialized successfully!${NC}"
    echo -e "${CYAN}Log file: $LOG_FILE${NC}"
    echo ""
    read -p "Press enter to continue.."

    # Load configuration
    if [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
        log_message "Taken variables from configuration file"
    else
        log_message "ERROR: Configuration file not found"
        echo -e "${RED}${BOLD}ERROR: Configuration file not found at: $CONF_FILE${NC}" >&2
        exit 1
    fi

    while true; do
        show_menu
        case $option in
            1) ssh_hardening ;;
            2) firewall_hardening ;;
            3) dns_hardening ;;
            4) grub_hardening ;;
            5) security_packages ;;
            6) kernel_hardening ;;
            7) fail2ban_hardening ;;
            8) lynis_suggestions ;;
            9) backups_rollback ;;
            10) system_audit ;;
            0)
                log_message "=== Hardening Script Exited ==="
                echo ""
                echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}${BOLD}║${NC} ${GREEN}${BOLD}Script completed successfully!${NC}"
                echo -e "${CYAN}${BOLD}║${NC}"
                echo -e "${CYAN}${BOLD}║${NC} ${YELLOW}Please reboot the system to apply all changes${NC}"
                echo -e "${CYAN}${BOLD}║${NC}"
                echo -e "${CYAN}${BOLD}║${NC} ${CYAN}Log file location: $LOG_FILE${NC}"
                echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
                echo ""
                exit 0
                ;;
            *)
                log_message "Invalid menu option selected: $option"
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 1
                ;;
        esac

        echo ""
        read -p "Press enter to continue.."
    done
}

main
