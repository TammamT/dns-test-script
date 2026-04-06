#!/bin/bash
# ============================================================
# dns-audit.sh — Full DNS Audit for Restricted Networks
#
# Usage:
#   ./dns-audit.sh          # run all tests
#   ./dns-audit.sh udp      # run only UDP tests
#   ./dns-audit.sh doh dot  # run only DoH and DoT
#
# Available modules: detect udp tcp dot doh doq dnscrypt ipv6
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTS_DIR="$SCRIPT_DIR/tests"

# Setup shared env
export TIMEOUT="${TIMEOUT:-1}"
export TEST_DOMAIN="${TEST_DOMAIN:-example.com}"
export REPORT_FILE="${REPORT_FILE:-$SCRIPT_DIR/dns_report_$(date +%Y%m%d_%H%M%S).txt}"
export RANKING_FILE="/tmp/dns_ranking_$$.tmp"
export COUNTER_DIR="/tmp/dns_audit_$$"

# Init
source "$TESTS_DIR/common.sh"
init_counters
> "$REPORT_FILE"

ALL_MODULES="detect udp tcp dot doh doq dnscrypt ipv6"
MODULES="${@:-$ALL_MODULES}"

header "DNS Audit v3 — Full Network Analysis"
log "  Host:     $(hostname)"
log "  Date:     $(date)"
log "  Timeout:  ${TIMEOUT}s"
log "  Report:   ${REPORT_FILE}"
log "  Modules:  ${MODULES}"

# Check and install dependencies
section "DEPENDENCY CHECK"

# cmd -> apt package mapping
apt_pkg() {
    case "$1" in
        dig)    echo "dnsutils" ;;
        kdig)   echo "knot-dnsutils" ;;
        ping6)  echo "iputils-ping" ;;
        ip)     echo "iproute2" ;;
        *)      echo "$1" ;;
    esac
}

MISSING_REQUIRED=()
for cmd in dig curl openssl ip ping6; do
    if command -v $cmd >/dev/null 2>&1; then
        log "  ${G}✓${N} $cmd"
    else
        log "  ${R}✗${N} $cmd — missing"
        MISSING_REQUIRED+=("$(apt_pkg $cmd)")
    fi
done

if [ ${#MISSING_REQUIRED[@]} -gt 0 ]; then
    log ""
    log "  ${Y}Installing missing packages: ${MISSING_REQUIRED[*]}${N}"
    if sudo apt-get install -y "${MISSING_REQUIRED[@]}"; then
        log "  ${G}✓ Installed successfully${N}"
    else
        log "  ${R}✗ Install failed. Run manually: sudo apt install ${MISSING_REQUIRED[*]}${N}"
        exit 1
    fi
fi

if command -v kdig >/dev/null 2>&1; then
    log "  ${G}✓${N} kdig (accurate DoT/DoQ testing)"
else
    log "  ${Y}○${N} kdig not found — installing for accurate DoT/DoQ testing..."
    if sudo apt-get install -y knot-dnsutils; then
        log "  ${G}✓ kdig installed${N}"
    else
        log "  ${Y}○${N} Could not install kdig — DoT will use TLS handshake fallback, DoQ will use port check"
    fi
fi

# Resolve trusted reference IP via DoT (needs kdig, so runs after dependency check)
section "REFERENCE IP RESOLUTION"
TRUSTED_IP=$(resolve_trusted_ip "$TEST_DOMAIN")
if [ -n "$TRUSTED_IP" ]; then
    export EXPECTED_IP="$TRUSTED_IP"
    log "  ${G}✓${N} Resolved ${B}${TEST_DOMAIN}${N} via DoT: ${B}${EXPECTED_IP}${N}"
    log "  ${C}  (tamper detection will compare against this)${N}"
else
    log "  ${Y}⚠${N} Could not resolve via DoT — tamper detection disabled"
    log "  ${Y}  (all responses will be marked OK if they resolve)${N}"
    export EXPECTED_IP=""
fi

# Run selected modules
for mod in $MODULES; do
    if [ -f "$TESTS_DIR/${mod}.sh" ]; then
        source "$TESTS_DIR/${mod}.sh"
    else
        log ""
        log "  ${R}Unknown module: $mod${N}"
        log "  ${W}Available: $ALL_MODULES${N}"
    fi
done

# ====================================================================
# SUMMARY
# ====================================================================
header "RESULTS"
log ""
log "  Total tested:    ${B}$(get total)${N}"
log "  ${G}Accessible:      $(get pass)${N}"
log "  ${R}Blocked:         $(get fail)${N}"
log "  ${Y}Tampered:        $(get tampered)${N}"
log ""

p=$(get pass)
if [ "$p" -eq 0 ]; then
    log "  ${R}${B}Everything blocked!${N}"
    log "  ${Y}Options: VPN, Cloudflare WARP, DNS tunneling (iodine/dnstt)${N}"
elif [ "$p" -lt 5 ]; then
    log "  ${Y}${B}Heavy blocking detected.${N}"
else
    log "  ${G}${B}Multiple servers accessible.${N}"
fi

t=$(get tampered)
if [ "$t" -gt 0 ]; then
    log ""
    log "  ${Y}${B}⚠ $t server(s) returned tampered/different IPs${N}"
    log "  ${Y}  These may be ISP-hijacked — responses cannot be trusted${N}"
fi

# ====================================================================
# LATENCY RANKING (top 20 fastest working servers)
# ====================================================================
if [ -f "$RANKING_FILE" ] && [ -s "$RANKING_FILE" ]; then
    header "TOP 20 FASTEST SERVERS"
    log ""
    printf "  ${B}%-4s  %-8s  %-6s  %-33s %s${N}\n" "#" "PROTO" "SPEED" "NAME" "ADDRESS" | tee -a "$REPORT_FILE"
    log "  ────  ────────  ──────  ─────────────────────────────────  ───────────────────"

    # Sort by ms (field 3), only OK entries
    rank=0
    grep "^OK|" "$RANKING_FILE" | sort -t'|' -k3 -n | head -20 | \
    while IFS='|' read -r status proto ms name addr extra; do
        printf "  ${G}%-4s${N}  %-8s  ${Y}%4d ms${N}  %-33s %s\n" "$((++rank))" "$proto" "$ms" "$name" "$addr" | tee -a "$REPORT_FILE"
    done

    # Show tampered separately
    tampered_count=$(grep -c "^TAMPER|" "$RANKING_FILE" 2>/dev/null)
    if [ "${tampered_count:-0}" -gt 0 ]; then
        log ""
        log "  ${Y}${B}TAMPERED RESPONSES (ISP may be injecting fake answers):${N}"
        grep "^TAMPER|" "$RANKING_FILE" | sort -t'|' -k3 -n | \
        while IFS='|' read -r status proto ms name addr fake_ip; do
            printf "  ${Y}⚠${N}     %-8s  %4d ms  %-33s %s ${R}→ %s${N}\n" "$proto" "$ms" "$name" "$addr" "$fake_ip" | tee -a "$REPORT_FILE"
        done
    fi
fi

# ====================================================================
# AGH CONFIG SUGGESTION
# ====================================================================
if [ -f "$RANKING_FILE" ] && [ -s "$RANKING_FILE" ]; then
    header "SUGGESTED AGH UPSTREAM CONFIG"
    log ""
    log "  Based on fastest working servers:"
    log ""

    # Get top 5 unique IPs from OK results
    grep "^OK|" "$RANKING_FILE" | sort -t'|' -k3 -n | head -10 | \
    while IFS='|' read -r status proto ms name addr extra; do
        case "$proto" in
            UDP|TCP) log "  $addr" ;;
            DoT)     log "  tls://$addr" ;;
            DoH)     log "  https://${addr}" ;;
            DoQ)     log "  quic://$addr" ;;
        esac
    done
fi

log ""
log "  ${C}Full report saved to: ${REPORT_FILE}${N}"
log ""

# Cleanup
rm -f "$RANKING_FILE"
rm -rf "$COUNTER_DIR"
