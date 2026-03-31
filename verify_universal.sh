#!/usr/bin/env bash
# ==============================================================================
#  Universal Linux Security Verifier (Debian, Fedora, Arch)
#  Author: Adalberto Caldeira & Community
#  Usage: ./verify_universal.sh
# ==============================================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
PASS=0; FAIL=0; MAX=0

pass() { echo -e "  ${GREEN}[PASS]${RESET} $1"; ((PASS++)); ((MAX++)); }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1"; ((FAIL++)); ((MAX++)); }
section() { echo -e "\n${BOLD}${CYAN}━━━  $1  ━━━${RESET}"; }

source /etc/os-release
OS_FAMILY="debian"
[[ "$ID" == "arch" || "${ID_LIKE:-}" == *"arch"* ]] && OS_FAMILY="arch"
[[ "$ID" == "fedora" || "${ID_LIKE:-}" == *"rhel"* || "${ID_LIKE:-}" == *"fedora"* ]] && OS_FAMILY="fedora"

echo -e "${BOLD}Universal Security Verification Suite${RESET}"
echo -e "OS: $PRETTY_NAME | Kernel: $(uname -r)"

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
    if sudo aa-status 2>/dev/null | grep -q "profiles are in enforce mode"; then
        pass "AppArmor has profiles in enforce mode"
    else
        fail "No AppArmor profiles in enforce mode"
    fi
fi

# ------------------------------------------------------------------------------
section "T2 · Firewall Status"
if [[ "$OS_FAMILY" == "fedora" ]]; then
    if systemctl is-active --quiet firewalld; then
        pass "Firewalld is active"
        if sudo firewall-cmd --get-default-zone 2>/dev/null | grep -q "drop"; then
            pass "Firewalld default zone is DROP"
        else
            fail "Firewalld default zone is not drop"
        fi
    else
        fail "Firewalld is inactive"
    fi
else
    if systemctl is-active --quiet ufw; then
        pass "UFW is active"
        if sudo ufw status verbose 2>/dev/null | grep -q "deny (incoming)"; then
            pass "UFW default policy is deny incoming"
        else
            fail "UFW incoming policy is not deny"
        fi
    else
        fail "UFW is inactive"
    fi
fi

# ------------------------------------------------------------------------------
section "T3 · Kernel Sysctl Parameters"
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
check_sysctl "kernel.yama.ptrace_scope" "1"
check_sysctl "kernel.sysrq" "0"
check_sysctl "fs.suid_dumpable" "0"
check_sysctl "fs.protected_hardlinks" "1"
check_sysctl "fs.protected_fifos" "2"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.conf.all.log_martians" "1"

# ------------------------------------------------------------------------------
section "T4 · Sudoers & Coredumps"
if sudo test -f /etc/sudoers.d/99-hardening; then
    pass "Sudoers hardening file exists"
    if sudo grep -q "timestamp_timeout=5" /etc/sudoers.d/99-hardening; then
        pass "Sudoers timeout securely set"
    else
        fail "Sudoers timeout not enforced"
    fi
else
    fail "Sudoers hardening file missing"
fi

if [[ "$(sysctl -n kernel.core_pattern 2>/dev/null)" == "/dev/null" ]]; then
    pass "Core dumps routed to /dev/null"
else
    fail "Core dumps are not properly disabled in sysctl"
fi

# ------------------------------------------------------------------------------
section "FINAL SCORE"
SCORE=$(( (PASS * 100) / MAX ))
echo -e "\n══════════════════════════════════════════════"
echo -e "  PASS: $PASS  |  FAIL: $FAIL"
echo -e "  Security score: ${BOLD}${SCORE}%${RESET} ($PASS/$MAX checks passed)"
echo -e "══════════════════════════════════════════════\n"
