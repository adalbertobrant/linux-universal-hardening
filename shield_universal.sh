#!/usr/bin/env bash
# ==============================================================================
#  Universal Linux Shield v2.0 (Debian, Fedora, Arch)
#  Author: Adalberto Caldeira & Community
#  Description: Automated Security Hardening with Interactive Profiles
#  Usage: sudo ./shield_universal.sh
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
ok()   { echo -e "${GREEN}[OK]${RESET}   $1"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Erro: Este script precisa ser executado como root (use sudo).${RESET}"
    exit 1
fi

echo -e "${BOLD}${CYAN}🛡️  BEM-VINDO AO LINUX UNIVERSAL SHIELD 🛡️${RESET}\n"
echo -e "Escolha o nível de Hardening que deseja aplicar nesta máquina:\n"
echo -e "  ${BOLD}[1] PC Normal (Desktop / Uso Pessoal)${RESET}"
echo -e "      Proteção invisível. Mantém o sistema seguro, mas relaxa o controle de acesso"
echo -e "      (AppArmor em modo Complain) para garantir que navegadores (Firefox), interface"
echo -e "      gráfica (GNOME/Wayland) e jogos funcionem sem travamentos.\n"
echo -e "  ${BOLD}[2] Ambiente Dev (Workstation de Programação)${RESET}"
echo -e "      Segurança balanceada. Protege o Kernel e a rede, mas permite o uso de compiladores,"
echo -e "      depuradores (ptrace) e ferramentas de contêineres.\n"
echo -e "  ${BOLD}[3] Servidor Super Seguro (Fort Knox / Produção)${RESET}"
echo -e "      Paranoia total (Zero Trust). Bloqueia tudo. Vai quebrar interfaces gráficas e"
echo -e "      impedir debuggers. Feito exclusivamente para servidores isolados.\n"

read -p "Digite o número do perfil desejado [1, 2 ou 3]: " PROFILE_CHOICE

case $PROFILE_CHOICE in
    1) PROFILE_NAME="PC Normal"; MAC_MODE="complain"; PTRACE=1; PERF=2 ;;
    2) PROFILE_NAME="Ambiente Dev"; MAC_MODE="complain"; PTRACE=1; PERF=2 ;;
    3) PROFILE_NAME="Servidor Super Seguro"; MAC_MODE="enforce"; PTRACE=2; PERF=3 ;;
    *) echo -e "${RED}Opção inválida. Saindo.${RESET}"; exit 1 ;;
esac

echo -e "\n${YELLOW}Iniciando blindagem para o perfil: ${BOLD}${PROFILE_NAME}${RESET}...\n"

info "Detectando Sistema Operacional..."
source /etc/os-release
OS_FAMILY=""

if [[ "$ID" == "arch" || "${ID_LIKE:-}" == *"arch"* ]]; then
    OS_FAMILY="arch"
elif [[ "$ID" == "debian" || "$ID" == "ubuntu" || "${ID_LIKE:-}" == *"debian"* ]]; then
    OS_FAMILY="debian"
elif [[ "$ID" == "fedora" || "${ID_LIKE:-}" == *"rhel"* || "${ID_LIKE:-}" == *"fedora"* ]]; then
    OS_FAMILY="fedora"
else
    echo -e "${RED}OS não suportado: $ID${RESET}"; exit 1
fi
ok "Sistema detectado: ${OS_FAMILY^^}"

# ------------------------------------------------------------------------------
info "Sincronizando pacotes de segurança..."
case $OS_FAMILY in
    arch) pacman -Syu --needed --noconfirm ufw apparmor audit >/dev/null 2>&1 ;;
    debian) apt-get update >/dev/null 2>&1; apt-get install -y ufw apparmor apparmor-utils auditd >/dev/null 2>&1 ;;
    fedora) dnf install -y firewalld audit >/dev/null 2>&1 ;;
esac

# ------------------------------------------------------------------------------
info "Configurando Mandatory Access Control (MAC)..."
if [[ "$OS_FAMILY" == "fedora" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1 2>/dev/null || true
    ok "SELinux configurado."
else
    systemctl enable --now apparmor.service >/dev/null 2>&1 || true
    if [[ "$MAC_MODE" == "enforce" ]]; then
        aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
        ok "AppArmor: Modo ENFORCE (Máxima Restrição)."
    else
        aa-complain /etc/apparmor.d/* >/dev/null 2>&1 || true
        ok "AppArmor: Modo COMPLAIN (Monitoramento, sem quebrar GUI)."
    fi
    # Injeção no GRUB
    if [[ -f /etc/default/grub ]] && ! grep -q "apparmor=1" /etc/default/grub; then
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
        [[ "$OS_FAMILY" == "debian" ]] && update-grub >/dev/null 2>&1 || grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
    fi
fi

# ------------------------------------------------------------------------------
info "Configurando Firewall..."
if [[ "$OS_FAMILY" == "fedora" ]]; then
    systemctl enable --now firewalld >/dev/null 2>&1; firewall-cmd --set-default-zone=drop >/dev/null 2>&1
else
    systemctl enable --now ufw >/dev/null 2>&1 || true; ufw --force enable >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1; ufw reload >/dev/null 2>&1
fi
ok "Firewall trancado (Deny Incoming)."

# ------------------------------------------------------------------------------
info "Aplicando blindagem dinâmica de Kernel (Sysctl)..."
tee /etc/sysctl.d/99-hardening.conf > /dev/null <<EOF
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = $PTRACE
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
kernel.perf_event_paranoid = $PERF
EOF
sysctl --system >/dev/null 2>&1

mkdir -p /etc/systemd/coredump.conf.d
tee /etc/systemd/coredump.conf.d/disable.conf > /dev/null <<EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sysctl -w kernel.core_pattern=/dev/null >/dev/null 2>&1
ok "Kernel ajustado para o perfil: $PROFILE_NAME."

# ------------------------------------------------------------------------------
info "Aplicando restrições de Sudo..."
grep -q "^#includedir /etc/sudoers.d" /etc/sudoers || echo "#includedir /etc/sudoers.d" >> /etc/sudoers
tee /etc/sudoers.d/99-hardening > /dev/null <<EOF
Defaults    timestamp_timeout=5
Defaults    passwd_tries=3
Defaults    logfile=/var/log/sudo.log
Defaults    requiretty
EOF
chmod 0440 /etc/sudoers.d/99-hardening
ok "Políticas de Sudoers aplicadas."

echo -e "\n${GREEN}================================================================${RESET}"
echo -e "${GREEN}  Blindagem [${PROFILE_NAME}] Concluída!${RESET}"
echo -e "${GREEN}  Por favor, reinicie a máquina antes de rodar a verificação.${RESET}"
echo -e "${GREEN}================================================================${RESET}\n"
