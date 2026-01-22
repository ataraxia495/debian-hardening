#!/bin/bash

set -euo pipefail

#===Configuration===

#SSH Port
port=2200

#Grub configuration
grubusername="grubadmin"
grubpasswd="debian1313"

#Log file
LOG_FILE="/var/log/hardening_script.log"

#===================

init_log() {
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
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
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

confirm_action() {
    local action_name="$1"
    local description="$2"
    echo ""
    echo "=========================================="
    echo "Action: $action_name"
    echo "Description: $description"
    echo "=========================================="
    read -p "Do you want to proceed? (Y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_message "User cancelled: $action_name"
        echo "Action cancelled."
        return 1
    fi
    log_message "User confirmed: $action_name"
    return 0
}

check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "Must execute with root"
        exit 1
    fi
}

check_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "Distribution: $PRETTY_NAME"
    fi
}
ssh_hardening() {
    if ! confirm_action "SSH Hardening" "This will modify SSH configuration, change port to ${port}, disable root login, and apply security settings. SSH service will be reloaded."; then
        return 1
    fi

    echo ""
    log_message "Started SSH hardening"
    echo "Started SSH hardening.."
    echo "Creating backup.. backup file - /etc/ssh/sshd_config.backup"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    log_message "Created SSH config backup: /etc/ssh/sshd_config.backup"

    sed -i "s/^#\?Port.*/Port ${port}/" /etc/ssh/sshd_config
    log_message "Changed SSH port to ${port}"
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

    sshd -t
    if [[ $? -eq 0 ]]; then
        log_message "SSH config test passed"
    else
        log_message "ERROR: SSH config test failed"
        echo "ERROR: SSH configuration test failed. Changes not applied."
        return 1
    fi

    systemctl reload ssh
    log_message "SSH service reloaded"
    echo ""
    echo "Completed SSH hardening.. SSH port - ${port}"
    echo "Check /etc/ssh/sshd_config for other changes"
    log_message "SSH hardening completed successfully"
}

firewall_hardening() {
    if ! confirm_action "Firewall Hardening" "This will install UFW, reset all firewall rules, deny incoming by default, allow SSH port ${port}, and enable the firewall. Existing firewall rules will be lost."; then
        return 1
    fi

    echo ""
    log_message "Started firewall hardening"
    echo "Started firewall hardening.."
    apt install ufw -y
    log_message "Installed UFW"
    ufw --force reset
    log_message "Reset UFW rules"
    ufw default deny incoming
    log_message "Set default deny incoming"
    ufw default allow outgoing
    log_message "Set default allow outgoing"
    ufw allow ${port}/tcp
    log_message "Allowed SSH port ${port}/tcp"
    ufw logging on
    log_message "Enabled UFW logging"
    ufw --force enable
    log_message "Enabled UFW firewall"
    systemctl enable ufw
    log_message "Enabled UFW service"
    systemctl restart ufw 2>/dev/null || true
    log_message "Restarted UFW service"
    echo ""
    echo "===== UFW Status ====="
    ufw status verbose
    echo "Completed firewall hardening"
    log_message "Firewall hardening completed successfully"
}

dns_hardening() {
    echo "wip"
}

grub_hardening() {
    if ! confirm_action "GRUB Hardening" "This will set a GRUB password, modify /etc/grub.d/40_custom, and update GRUB configuration. You will need the GRUB password to boot the system."; then
        return 1
    fi

    log_message "Started GRUB hardening"
    echo "Started grub hardening.."

    # Generate PBKDF2 password hash
    local grub_hash=$(echo -e "$grubpasswd\n$grubpasswd" | grub-mkpasswd-pbkdf2 2>/dev/null | awk '/grub.pbkdf2/{print $NF}')

    if [[ -z "$grub_hash" ]]; then
        log_message "ERROR: Failed to generate GRUB password hash"
        echo "Error: Failed to generate GRUB password hash"
        return 1
    fi

    log_message "Generated GRUB password hash"
    cat > /etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 \$0

set superusers="$grubusername"
password_pbkdf2 $grubusername $grub_hash
EOF

    chmod +x /etc/grub.d/40_custom
    log_message "Created /etc/grub.d/40_custom with GRUB password"
    update-grub
    log_message "Updated GRUB configuration"
    echo ""
    echo "Completed grub hardening"
    echo "Your grub username - ${grubusername}, your grub password - ${grubpasswd}"
    log_message "GRUB hardening completed successfully"
}

security_packages() {
    if ! confirm_action "Security Packages Installation" "This will install multiple security packages: fail2ban, debsums, apt-listbugs, needrestart, rkhunter, and auditd."; then
        return 1
    fi

    log_message "Started security packages installation"
    echo "Installing security packages.."
    apt update && apt install fail2ban debsums apt-listbugs needrestart rkhunter auditd -y
    log_message "Installed security packages: fail2ban, debsums, apt-listbugs, needrestart, rkhunter, auditd"
    echo "Security packages installed successfully"
    log_message "Security packages installation completed"
}

kernel_hardening() {
    if ! confirm_action "Kernel Hardening" "This will modify kernel parameters in /etc/sysctl.d/99-custom.conf, including network security, BPF restrictions, and other kernel security settings."; then
        return 1
    fi

    log_message "Started kernel hardening"
    echo "Started kernel hardening.."
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
    echo ""
    echo "Completed kernel hardening"
    log_message "Kernel hardening completed successfully"
}

fail2ban_hardening() {
    if ! confirm_action "Fail2ban Hardening" "This will install fail2ban, create jail.local configuration, and enable/start the fail2ban service."; then
        return 1
    fi

    log_message "Started fail2ban hardening"
    echo "Started fail2ban hardening.."
    apt update && apt install fail2ban -y
    log_message "Installed fail2ban"
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        log_message "Created /etc/fail2ban/jail.local from jail.conf"
    else
        log_message "jail.local already exists, skipping copy"
    fi
    systemctl enable fail2ban
    log_message "Enabled fail2ban service"
    systemctl restart fail2ban
    log_message "Started fail2ban service"
    echo ""
    echo "Completed fail2ban hardening"
    log_message "Fail2ban hardening completed successfully"
}

lynis_suggestions() {
    if ! confirm_action "Lynis Suggestions Implementation" "This will install multiple packages (libpam-tmpdir, apt-show-versions, unattended-upgrades, aide), modify PAM configuration, configure automatic upgrades, and initialize AIDE database."; then
        return 1
    fi

    log_message "Started lynis suggestions implementation"
    echo "Installing libpam-tmpdir.."
    apt update && apt install libpam-tmpdir -y
    log_message "Installed libpam-tmpdir"
    if grep -q "tmpdir" /etc/pam.d/common-session 2>/dev/null; then
        echo "tmpdir already configured in /etc/pam.d/common-session"
        log_message "tmpdir already configured in PAM"
    else
        echo "session optional pam_tmpdir.so" >> /etc/pam.d/common-session
        echo "Added tmpdir to /etc/pam.d/common-session"
        log_message "Added tmpdir to /etc/pam.d/common-session"
    fi
    echo ""
    echo "Installed libpam-tmpdir"

    apt install apt-show-versions -y
    log_message "Installed apt-show-versions"

    apt install unattended-upgrades -y
    log_message "Installed unattended-upgrades"
    dpkg-reconfigure -plow unattended-upgrades
    log_message "Configured unattended-upgrades"

    apt install aide aide-common -y
    log_message "Installed AIDE"
    if [[ ! -f /var/lib/aide/aide.db.new ]]; then
        aide --init --config=/etc/aide/aide.conf
        log_message "Initialized AIDE database"
        echo "AIDE database initialized. Move /var/lib/aide/aide.db.new to /var/lib/aide/aide.db after review."
    else
        echo "AIDE database already exists"
        log_message "AIDE database already exists"
    fi
#    chown root:root /usr/bin/python3 /usr/bin/perl
#    chmod 700 /usr/bin/python3 /usr/bin/perl
    log_message "Lynis suggestions implementation completed"
}

show_menu() {
    clear
    echo -e "#=================================#"
    echo -e "       Test Hardening Script       "
    echo -e "#=================================#"
    echo ""
    check_version
    echo ""
    echo "1. ssh_hardening"
    echo "2. firewall_hardening"
    echo "3. dns_hardening"
    echo "4. grub_hardening"
    echo "5. security_packages"
    echo "6. kernel_hardening"
    echo "7. fail2ban_hardening"
    echo "8. lynis_suggestions"
    echo "0. Exit"

    echo ""
    read -p "Option: " option
}

main() {
    check_root
    init_log

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
            0)
                log_message "=== Hardening Script Exited ==="
                echo "Exiting. Please reboot"
                echo "Log file location: $LOG_FILE"
                exit 0
                ;;
            *)
                echo "Invalid option"
                log_message "Invalid menu option selected: $option"
                ;;
        esac

        echo ""
        read -p "Press enter to continue.."
    done
}

main