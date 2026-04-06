#!/bin/bash
# common.sh — shared functions. Source this, don't run it.

TIMEOUT="${TIMEOUT:-1}"
TEST_DOMAIN="${TEST_DOMAIN:-example.com}"
# Verify with: dig +short example.com A — update if it changes
EXPECTED_IP="${EXPECTED_IP:-93.184.215.14}"
REPORT_FILE="${REPORT_FILE:-dns_report_$(date +%Y%m%d_%H%M%S).txt}"
RANKING_FILE="${RANKING_FILE:-/tmp/dns_ranking_$$.tmp}"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m';    M='\033[0;35m'; W='\033[1;37m'; N='\033[0m'

COUNTER_DIR="${COUNTER_DIR:-/tmp/dns_audit_$$}"
init_counters() {
    mkdir -p "$COUNTER_DIR"
    for f in pass fail total tampered; do echo 0 > "$COUNTER_DIR/$f"; done
    > "$RANKING_FILE"
}
inc() { local v=$(cat "$COUNTER_DIR/$1"); echo $((v+1)) > "$COUNTER_DIR/$1"; }
get() { cat "$COUNTER_DIR/$1"; }

log()     { echo -e "$1" | tee -a "$REPORT_FILE"; }
log_raw() { echo "$1" >> "$REPORT_FILE"; }
section() { log ""; log "${C}── $1 ──${N}"; log ""; }
header()  {
    log ""
    log "${B}═══════════════════════════════════════════════════════════════════${N}"
    log "${B}  $1${N}"
    log "${B}═══════════════════════════════════════════════════════════════════${N}"
}

test_udp() {
    local name="$1" ip="$2"; inc total
    local output ms answer
    output=$(dig +timeout=$TIMEOUT +tries=1 +stats @"$ip" "$TEST_DOMAIN" A 2>/dev/null)
    ms=$(echo "$output" | grep -oP 'Query time: \K[0-9]+')
    answer=$(echo "$output" | awk '/IN[[:space:]]+A[[:space:]]+/{print $NF}' | head -1)
    if echo "$output" | grep -q "NOERROR" && [ -n "$ms" ]; then
        inc pass
        if [ -n "$answer" ] && [ "$answer" != "$EXPECTED_IP" ]; then
            inc tampered
            printf "  ${Y}⚠ TAMPER${N}  %-33s %-20s ${Y}%4d ms${N}  ${R}→ %s${N}\n" "$name" "$ip" "$ms" "$answer" | tee -a "$REPORT_FILE"
            echo "TAMPER|UDP|$ms|$name|$ip|$answer" >> "$RANKING_FILE"
        else
            printf "  ${G}✓ OPEN${N}    %-33s %-20s ${Y}%4d ms${N}\n" "$name" "$ip" "$ms" | tee -a "$REPORT_FILE"
            echo "OK|UDP|$ms|$name|$ip" >> "$RANKING_FILE"
        fi
    else
        inc fail
        printf "  ${R}✗ BLOCKED${N} %-33s %s\n" "$name" "$ip" | tee -a "$REPORT_FILE"
    fi
}

test_tcp() {
    local name="$1" ip="$2"; inc total
    local output ms answer
    output=$(dig +timeout=$TIMEOUT +tries=1 +tcp +stats @"$ip" "$TEST_DOMAIN" A 2>/dev/null)
    ms=$(echo "$output" | grep -oP 'Query time: \K[0-9]+')
    answer=$(echo "$output" | awk '/IN[[:space:]]+A[[:space:]]+/{print $NF}' | head -1)
    if echo "$output" | grep -q "NOERROR" && [ -n "$ms" ]; then
        inc pass
        if [ -n "$answer" ] && [ "$answer" != "$EXPECTED_IP" ]; then
            inc tampered
            printf "  ${Y}⚠ TAMPER${N}  %-33s %-20s ${Y}%4d ms${N}  ${C}(TCP)${N}  ${R}→ %s${N}\n" "$name" "$ip" "$ms" "$answer" | tee -a "$REPORT_FILE"
            echo "TAMPER|TCP|$ms|$name|$ip|$answer" >> "$RANKING_FILE"
        else
            printf "  ${G}✓ OPEN${N}    %-33s %-20s ${Y}%4d ms${N}  ${C}(TCP)${N}\n" "$name" "$ip" "$ms" | tee -a "$REPORT_FILE"
            echo "OK|TCP|$ms|$name|$ip" >> "$RANKING_FILE"
        fi
    else
        inc fail
        printf "  ${R}✗ BLOCKED${N} %-33s %s  ${C}(TCP)${N}\n" "$name" "$ip" | tee -a "$REPORT_FILE"
    fi
}

test_dot() {
    local name="$1" ip="$2" hostname="${3:-$ip}"; inc total
    local start end ms result
    if command -v kdig >/dev/null 2>&1; then
        start=$(date +%s%N)
        result=$(kdig +tls-ca +tls-hostname="$hostname" +timeout=$TIMEOUT +retry=0 @"$ip" "$TEST_DOMAIN" A 2>/dev/null)
        end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
        if echo "$result" | grep -q "NOERROR"; then
            inc pass
            printf "  ${G}✓ OPEN${N}    %-33s %-20s ${Y}%4d ms${N}  ${M}(DoT)${N}\n" "$name" "$ip" "$ms" | tee -a "$REPORT_FILE"
            echo "OK|DoT|$ms|$name|$ip" >> "$RANKING_FILE"; return
        fi
    fi
    start=$(date +%s%N)
    result=$(timeout 2 bash -c "echo | openssl s_client -connect $ip:853 -servername $hostname 2>/dev/null" | grep -c "BEGIN CERTIFICATE")
    end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
    if [ "${result:-0}" -gt 0 ] 2>/dev/null; then
        inc pass
        printf "  ${G}✓ OPEN${N}    %-33s %-20s ${Y}%4d ms${N}  ${M}(DoT TLS✓)${N}\n" "$name" "$ip" "$ms" | tee -a "$REPORT_FILE"
        echo "OK|DoT|$ms|$name|$ip" >> "$RANKING_FILE"
    else
        inc fail
        printf "  ${R}✗ BLOCKED${N} %-33s %s  ${M}(DoT)${N}\n" "$name" "$ip" | tee -a "$REPORT_FILE"
    fi
}

test_doh() {
    local name="$1" hostname="$2" ip="$3" path="$4"; inc total
    local start end ms result answer
    start=$(date +%s%N)
    result=$(curl -s --max-time 2 --resolve "${hostname}:443:${ip}" \
        -H "accept: application/dns-json" \
        "https://${hostname}${path}?name=${TEST_DOMAIN}&type=A" 2>/dev/null)
    end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
    answer=$(echo "$result" | grep -oP '"data"\s*:\s*"\K[0-9.]+' | head -1)
    if [ -n "$answer" ]; then
        inc pass
        if [ "$answer" != "$EXPECTED_IP" ]; then
            inc tampered
            printf "  ${Y}⚠ TAMPER${N}  %-18s %-24s → %-15s ${Y}%4d ms${N}  ${R}→ %s${N}\n" "$name" "$hostname" "$ip" "$ms" "$answer" | tee -a "$REPORT_FILE"
            echo "TAMPER|DoH|$ms|$name|$hostname>$ip|$answer" >> "$RANKING_FILE"
        else
            printf "  ${G}✓ OPEN${N}    %-18s %-24s → %-15s ${Y}%4d ms${N}\n" "$name" "$hostname" "$ip" "$ms" | tee -a "$REPORT_FILE"
            echo "OK|DoH|$ms|$name|$hostname>$ip" >> "$RANKING_FILE"
        fi
    else
        inc fail
        printf "  ${R}✗ BLOCKED${N} %-18s %-24s → %s\n" "$name" "$hostname" "$ip" | tee -a "$REPORT_FILE"
    fi
}

test_doq() {
    local name="$1" ip="$2" port="${3:-853}"; inc total
    local start end ms rc result
    if command -v kdig >/dev/null 2>&1; then
        start=$(date +%s%N)
        result=$(kdig +quic @"$ip" -p "$port" +timeout=$TIMEOUT +retry=0 "$TEST_DOMAIN" A 2>/dev/null)
        end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
        if echo "$result" | grep -q "NOERROR"; then
            inc pass
            printf "  ${G}✓ OPEN${N}    %-33s %-15s:%-5s ${Y}%4d ms${N}  ${C}(QUIC)${N}\n" "$name" "$ip" "$port" "$ms" | tee -a "$REPORT_FILE"
            echo "OK|DoQ|$ms|$name|$ip:$port" >> "$RANKING_FILE"
            return
        fi
    fi
    # Fallback: UDP port reachability (not a real DoQ test)
    start=$(date +%s%N)
    timeout $TIMEOUT bash -c "echo >/dev/udp/$ip/$port" 2>/dev/null; rc=$?
    end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
    if [ $rc -eq 0 ]; then
        inc pass
        printf "  ${G}~ MAYBE${N}   %-33s %-15s:%-5s ${Y}%4d ms${N}  ${C}(QUIC port open)${N}\n" "$name" "$ip" "$port" "$ms" | tee -a "$REPORT_FILE"
        echo "OK|DoQ|$ms|$name|$ip:$port" >> "$RANKING_FILE"
    else
        inc fail
        printf "  ${R}✗ BLOCKED${N} %-33s %s:%s  ${C}(QUIC)${N}\n" "$name" "$ip" "$port" | tee -a "$REPORT_FILE"
    fi
}

test_dnscrypt() {
    local name="$1" ip="$2" port="${3:-443}"; inc total
    local start end ms
    start=$(date +%s%N)
    timeout $TIMEOUT bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; local rc=$?
    end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
    if [ $rc -eq 0 ]; then
        inc pass
        printf "  ${G}✓ OPEN${N}    %-33s %-15s:%-5s ${Y}%4d ms${N}  ${M}(DNSCrypt)${N}\n" "$name" "$ip" "$port" "$ms" | tee -a "$REPORT_FILE"
        echo "OK|DNSCrypt|$ms|$name|$ip:$port" >> "$RANKING_FILE"
    else
        inc fail
        printf "  ${R}✗ BLOCKED${N} %-33s %s:%s  ${M}(DNSCrypt)${N}\n" "$name" "$ip" "$port" | tee -a "$REPORT_FILE"
    fi
}
