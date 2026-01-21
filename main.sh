#!/bin/bash

set -e

#===Configuration===

#SSH Port
port=2200

#Grub configuration
grubusername="grubadmin"
grubpasswd="debian1313"

#===================

check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "Must execute with root"
        exit 1
    fi
}

check_version() {
    local version=
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "Distribution: $PRETTY_NAME"
    fi
}
ssh_hardening() {
    echo ""
    echo "Started SSH hardening.."
    echo "Creating backup.. backup file - /etc/ssh/sshd_config.backup"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

    sed -i "s/^#\?Port.*/Port ${port}/" /etc/ssh/sshd_config
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/^#\?MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#\?AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    sed -i 's/^#\?TCPKeepAlive.*/TCPKeepAlive no/' /etc/ssh/sshd_config
    sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config

    sshd -t

    systemctl reload ssh
    echo ""
    echo "Completed SSH hardening.. SSH port - ${port}"
    echo "Check /etc/ssh/sshd_config for other changes"
}

firewall_hardening() {
    echo ""
    echo "Started firewall hardening.."
    apt install ufw -y
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ${port}/tcp
    ufw logging on
    ufw --force enable
    systemctl restart ufw
    echo ""
    echo "===== UFW Status ====="
    ufw status verbose
    echo "Completed firewall hardening"
}

dns_hardening() {
    echo "wip"
}

grub_hardening() {
    echo "Started grub hardening.."
    cat > /etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 \$0

set superusers="$grubusername"
password_pbkdf2 grubadmin $(echo -e "$grubpasswd\n$grubpasswd" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/{print $NF}')
EOF

    chmod +x /etc/grub.d/40_custom
    update-grub
    echo ""
    echo "Completed grub hardening"
    echo "Your grub username - ${grubusername}, your grub password - ${grubpasswd}"
}

security_packages() {
    apt update && apt install fail2ban debsums apt-listbugs needrestart rkhunter auditd -y
}

kernel_hardening() {
    echo "Started kernel hardening.."
    cat > /etc/sysctl.d/99-custom.conf << EOF
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
kernel.kptr_restrict = 2
kernel.modules_disabled = 1
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

    sysctl -p /etc/sysctl.d/99-custom.conf
    echo ""
    echo "Completed kernel hardening"
}

fail2ban_hardening() {
    echo "Started fail2ban hardening.."
    apt update && apt install fail2ban
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    echo ""
    echo "Completed fail2ban hardening"
}

lynis_suggestions() {
    echo "Installing libpam-tmpdir.."
    apt update && apt install libpam-tmpdir -y
    grep tmpdir /etc/pam.d/common-session
    echo ""
    echo "Installed libpam-tmpdir"

    apt install apt-show-versions -y

    apt install unattended-upgrades -y
    dpkg-reconfigure -plow unattended-upgrades

    apt install aide aide-common -y
    aide --init --config=/etc/aide/aide.conf
#    chown root:root /usr/bin/python3 /usr/bin/perl
#    chmod 700 /usr/bin/python3 /usr/bin/perl
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
                echo "Exiting. Please reboot"
                exit 0
                ;;
            *)
                echo "Invalid option"
                ;;
        esac

        echo ""
        read -p "Press enter to continue.."
    done
}

main