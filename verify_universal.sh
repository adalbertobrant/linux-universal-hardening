#!/usr/bin/env bash
# ==============================================================================
#  Universal Linux Security Verifier v2.0
#  Author: Adalberto Caldeira & Community
#  Usage: ./verify_universal.sh
# ==============================================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
PASS=0; FAIL=0; MAX=0

pass() { echo -e "  ${GREEN}[PASS]${RESET} $1"; ((PASS++)); ((MAX++)); }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1"; ((FAIL++)); ((MAX++)); }
section() { echo -e "\n${BOLD}${CYAN}━━━  $1  ━━━${RESET}"; }

echo -e "${BOLD}${CYAN}🔍 AUDITORIA DE SEGURANÇA UNIVERSAL 🔍${RESET}\n"
echo -e "Qual perfil de segurança devemos usar como gabarito para esta auditoria?"
echo -e "  [1] PC Normal\n  [2] Ambiente Dev\n  [3] Servidor Super Seguro"
read -p "Opção [1, 2 ou 3]: " AUDIT_PROFILE

case $AUDIT_PROFILE in
    1|2) EXPECT_MAC="complain"; EXPECT_PTRACE=1; EXPECT_PERF=2 ;;
    3) EXPECT_MAC="enforce"; EXPECT_PTRACE=2; EXPECT_PERF=3 ;;
    *) echo -e "${RED}Opção inválida.${RESET}"; exit 1 ;;
esac

source /etc/os-release
OS_FAMILY="debian"
[[ "$ID" == "arch" || "${ID_LIKE:-}" == *"arch"* ]] && OS_FAMILY="arch"
[[ "$ID" == "fedora" || "${ID_LIKE:-}" == *"rhel"* || "${ID_LIKE:-}" == *"fedora"* ]] && OS_FAMILY="fedora"

echo -e "\n${BOLD}Iniciando varredura em: $PRETTY_NAME${RESET}"

# ------------------------------------------------------------------------------
section "T1 · Mandatory Access Control (MAC)"
if [[ "$OS_FAMILY" == "fedora" ]]; then
    if sestatus 2>/dev/null | grep -q "Current mode:.*enforcing"; then
        pass "SELinux is Enforcing"
    else
        fail "SELinux is NOT Enforcing"
    fi
else
    if systemctl is-active --quiet apparmor.service; then
        pass "AppArmor service is active"
    else
        fail "AppArmor service inactive"
    fi
    
    if [[ "$EXPECT_MAC" == "enforce" ]]; then
        if sudo aa-status 2>/dev/null | grep -q "profiles are in enforce mode"; then
            pass "AppArmor ENFORCE mode confirmed (Server Standard)"
        else
            fail "AppArmor is NOT in enforce mode"
        fi
    else
        if sudo aa-status 2>/dev/null | grep -q "profiles are in complain mode"; then
            pass "AppArmor COMPLAIN mode confirmed (Desktop/Dev Standard)"
        else
            fail "AppArmor complain mode not detected"
        fi
    fi
fi

# ------------------------------------------------------------------------------
section "T2 · Firewall Status"
if [[ "$OS_FAMILY" == "fedora" ]]; then
    if systemctl is-active --quiet firewalld; then
        pass "Firewalld is active"
        sudo firewall-cmd --get-default-zone 2>/dev/null | grep -q "drop" && pass "Firewalld default zone is DROP" || fail "Firewalld default zone is not drop"
    else
        fail "Firewalld is inactive"
    fi
else
    if systemctl is-active --quiet ufw; then
        pass "UFW is active"
        sudo ufw status verbose 2>/dev/null | grep -q "deny (incoming)" && pass "UFW default policy is deny incoming" || fail "UFW incoming policy is not deny"
    else
        fail "UFW is inactive"
    fi
fi

# ------------------------------------------------------------------------------
section "T3 · Kernel Sysctl Parameters (Dynamic Profile)"
check_sysctl() {
    local key="$1" expected="$2"
    local actual=$(sysctl -n "$key" 2>/dev/null || echo "MISSING")
    if [[ "$actual" == "$expected" ]]; then
        pass "sysctl $key = $actual"
    else
        fail "sysctl $key = $actual (expected $expected)"
    fi
}
check_sysctl "kernel.dmesg_restrict" "1"
check_sysctl "kernel.kptr_restrict" "2"
check_sysctl "kernel.yama.ptrace_scope" "$EXPECT_PTRACE"
check_sysctl "kernel.perf_event_paranoid" "$EXPECT_PERF"
check_sysctl "fs.suid_dumpable" "0"
check_sysctl "fs.protected_fifos" "2"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.conf.all.log_martians" "1"

# ------------------------------------------------------------------------------
section "T4 · Sudoers & Coredumps"
if sudo test -f /etc/sudoers.d/99-hardening; then
    pass "Sudoers hardening file exists"
    sudo grep -q "timestamp_timeout=5" /etc/sudoers.d/99-hardening && pass "Sudoers timeout securely set" || fail "Sudoers timeout not enforced"
else
    fail "Sudoers hardening file missing"
fi

[[ "$(sysctl -n kernel.core_pattern 2>/dev/null)" == "/dev/null" ]] && pass "Core dumps routed to /dev/null" || fail "Core dumps are active"

# ------------------------------------------------------------------------------
section "FINAL SCORE"
SCORE=$(( (PASS * 100) / MAX ))
echo -e "\n══════════════════════════════════════════════"
echo -e "  Perfil Auditado: Nível $AUDIT_PROFILE"
echo -e "  PASS: $PASS  |  FAIL: $FAIL"
echo -e "  Security score: ${BOLD}${SCORE}%${RESET} ($PASS/$MAX checks passed)"
echo -e "══════════════════════════════════════════════\n"
