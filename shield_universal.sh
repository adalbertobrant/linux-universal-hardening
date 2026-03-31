#!/usr/bin/env bash
# ==============================================================================
#  Universal Linux Shield (Debian, Fedora, Arch)
#  Author: Adalberto Caldeira & Community
#  Description: Automated Security Hardening (MAC, Firewall, Sysctl, Sudoers)
#  Usage: sudo ./shield_universal.sh
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'
info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
ok()   { echo -e "${GREEN}[OK]${RESET}   $1"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Erro: Este script precisa ser executado como root (use sudo).${RESET}"
    exit 1
fi

info "Detectando Sistema Operacional..."
source /etc/os-release
OS_FAMILY=""

if [[ "$ID" == "arch" || "${ID_LIKE:-}" == *"arch"* ]]; then
    OS_FAMILY="arch"
    info "Arch Linux detectado."
elif [[ "$ID" == "debian" || "$ID" == "ubuntu" || "${ID_LIKE:-}" == *"debian"* ]]; then
    OS_FAMILY="debian"
    info "Debian/Ubuntu detectado."
elif [[ "$ID" == "fedora" || "${ID_LIKE:-}" == *"rhel"* || "${ID_LIKE:-}" == *"fedora"* ]]; then
    OS_FAMILY="fedora"
    info "Fedora/RHEL detectado."
else
    echo -e "${RED}OS não suportado oficialmente por este script: $ID${RESET}"
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. Instalação de Pacotes Base
# ------------------------------------------------------------------------------
info "Sincronizando pacotes de segurança vitais..."
case $OS_FAMILY in
    arch)
        pacman -Syu --needed --noconfirm ufw apparmor audit sqlite >/dev/null 2>&1
        ;;
    debian)
        apt-get update >/dev/null 2>&1
        apt-get install -y ufw apparmor apparmor-utils auditd sqlite3 >/dev/null 2>&1
        ;;
    fedora)
        dnf install -y firewalld audit sqlite >/dev/null 2>&1
        ;;
esac
ok "Pacotes instalados."

# ------------------------------------------------------------------------------
# 2. Configuração de MAC (Mandatory Access Control)
# ------------------------------------------------------------------------------
info "Configurando Mandatory Access Control..."
if [[ "$OS_FAMILY" == "fedora" ]]; then
    # Fedora usa SELinux
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1 2>/dev/null || true
    ok "SELinux configurado para Enforcing."
else
    # Debian e Arch usam AppArmor
    systemctl enable --now apparmor.service >/dev/null 2>&1 || true
    aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
    
    # Injeção no GRUB (segura)
    if [[ -f /etc/default/grub ]]; then
        if ! grep -q "apparmor=1" /etc/default/grub; then
            sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
            if [[ "$OS_FAMILY" == "debian" ]]; then
                update-grub >/dev/null 2>&1 || true
            else
                grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
            fi
        fi
    fi
    ok "AppArmor ativado e forçado (Enforce)."
fi

# ------------------------------------------------------------------------------
# 3. Firewall Base
# ------------------------------------------------------------------------------
info "Trancando portas de entrada..."
if [[ "$OS_FAMILY" == "fedora" ]]; then
    systemctl enable --now firewalld >/dev/null 2>&1
    firewall-cmd --set-default-zone=drop >/dev/null 2>&1
    ok "Firewalld ativado (Zone: drop)."
else
    systemctl enable --now ufw >/dev/null 2>&1 || true
    ufw --force enable >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw reload >/dev/null 2>&1
    ok "UFW ativado (Policy: deny)."
fi

# ------------------------------------------------------------------------------
# 4. Hardening de Kernel (Sysctl) & Core Dumps
# ------------------------------------------------------------------------------
info "Aplicando blindagem de Kernel e Memória..."
tee /etc/sysctl.d/99-hardening.conf > /dev/null <<'EOF'
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.perf_event_paranoid = 3
EOF
sysctl --system >/dev/null 2>&1

mkdir -p /etc/systemd/coredump.conf.d
tee /etc/systemd/coredump.conf.d/disable.conf > /dev/null <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sysctl -w kernel.core_pattern=/dev/null >/dev/null 2>&1
ok "Kernel hardening e restrição de Core Dumps aplicados."

# ------------------------------------------------------------------------------
# 5. Políticas de Sudoers
# ------------------------------------------------------------------------------
info "Aplicando restrições de Sudo..."
grep -q "^#includedir /etc/sudoers.d" /etc/sudoers || echo "#includedir /etc/sudoers.d" >> /etc/sudoers
tee /etc/sudoers.d/99-hardening > /dev/null <<'EOF'
Defaults    timestamp_timeout=5
Defaults    passwd_tries=3
Defaults    passwd_timeout=30
Defaults    logfile=/var/log/sudo.log
Defaults    log_input,log_output
Defaults    requiretty
Defaults    use_pty
EOF
chmod 0440 /etc/sudoers.d/99-hardening
ok "Políticas de Sudoers aplicadas com sucesso."

echo -e "\n${GREEN}================================================================${RESET}"
echo -e "${GREEN}  Blindagem Universal Concluída! (${OS_FAMILY^^})${RESET}"
echo -e "${GREEN}  Recomenda-se reiniciar o sistema e executar o verify_universal.sh${RESET}"
echo -e "${GREEN}================================================================${RESET}\n"
