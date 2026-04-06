#!/bin/bash
# common.sh — shared functions. Source this, don't run it.

TIMEOUT="${TIMEOUT:-1}"
TEST_DOMAIN="${TEST_DOMAIN:-example.com}"
REPORT_FILE="${REPORT_FILE:-dns_report_$(date +%Y%m%d_%H%M%S).txt}"
RANKING_FILE="${RANKING_FILE:-/tmp/dns_ranking_$$.tmp}"

# --- Tamper detection via multi-domain DoT reference resolution ---
#
# Domains chosen for tamper detection:
#   - Mix of CDN, well-known, porn (ISP-blocked), and obscure infrastructure
#   - Porn sites are the best canary: filtering ISPs *will* tamper with them
#   - Obscure infra sites catch blanket hijacking without ISP whitelisting
#
TAMPER_DOMAINS="example.com dns.google eporner.com txxx.com hdzog.com ftp.afrinic.net lacnic.net ftp.isc.org"
TAMPER_DIR="${TAMPER_DIR:-/tmp/dns_tamper_$$}"
DOT_SERVERS="1.0.0.1:cloudflare-dns.com 8.8.8.8:dns.google 9.9.9.9:dns.quad9.net 94.140.14.14:dns.adguard-dns.com"

# --- Trusted IP resolution and lookup ---

resolve_all_trusted_ips() {
    mkdir -p "$TAMPER_DIR"
    local domain entry ip host

    for domain in $TAMPER_DOMAINS; do
        local trust_file="$TAMPER_DIR/${domain//./_}.ips"
        > "$trust_file"

        for entry in $DOT_SERVERS; do
            ip="${entry%%:*}"
            host="${entry##*:}"
            if command -v kdig >/dev/null 2>&1; then
                kdig +tls-ca +tls-hostname="$host" +timeout=3 +retry=0 @"$ip" "$domain" A 2>/dev/null \
                    | awk '/IN[[:space:]]+A[[:space:]]+/{print $NF}' >> "$trust_file"
            fi
        done

        [ -s "$trust_file" ] && sort -u "$trust_file" -o "$trust_file"
    done
}

_trust_file_for() { echo "$TAMPER_DIR/${1//./_}.ips"; }

is_trusted_ip_for() {
    local tf="$TAMPER_DIR/${1//./_}.ips"
    [ -s "$tf" ] && grep -qxF "$2" "$tf"
}

tamper_enabled_for() { [ -s "$TAMPER_DIR/${1//./_}.ips" ]; }

# --- Colors and counters ---

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

# --- Logging ---

log()     { echo -e "$1" | tee -a "$REPORT_FILE"; }
log_raw() { echo "$1" >> "$REPORT_FILE"; }
section() { log ""; log "${C}── $1 ──${N}"; log ""; }
header()  {
    log ""
    log "${B}═══════════════════════════════════════════════════════════════════${N}"
    log "${B}  $1${N}"
    log "${B}═══════════════════════════════════════════════════════════════════${N}"
}

# --- Core tamper check ---
#
# _check_tamper <query_func> [extra_args...]
#
# Loops over TAMPER_DOMAINS, calls query_func for each, compares answers.
# query_func signature: query_func <domain> [extra_args...]
#   Must set: _Q_ANSWER (IP or empty), _Q_MS (latency)
#   Return 0 = got answer, non-zero = failed
#
# Sets on return:
#   _TAMPER_RESULT  = clean | tampered | blocked
#   _TAMPER_MS      = latency of first successful query
#   _TAMPER_COUNT   = "N/M" (tampered/checked)
#   _TAMPER_DETAILS = "domain→fake_ip domain→fake_ip ..."
#
_check_tamper() {
    local query_func="$1"; shift
    local tampered_count=0 checked_count=0
    _TAMPER_MS="" ; _TAMPER_DETAILS=""

    for domain in $TAMPER_DOMAINS; do
        tamper_enabled_for "$domain" || continue

        _Q_ANSWER="" ; _Q_MS=""
        if "$query_func" "$domain" "$@"; then
            [ -z "$_TAMPER_MS" ] && _TAMPER_MS="$_Q_MS"
            checked_count=$((checked_count + 1))

            if [ -n "$_Q_ANSWER" ] && ! is_trusted_ip_for "$domain" "$_Q_ANSWER"; then
                tampered_count=$((tampered_count + 1))
                _TAMPER_DETAILS="${_TAMPER_DETAILS}${domain}→${_Q_ANSWER} "
            fi
        else
            # Query failed — if first domain fails, server is likely blocked; bail early
            [ "$checked_count" -eq 0 ] && break
        fi
    done

    if [ "$checked_count" -eq 0 ]; then
        _TAMPER_RESULT="blocked"; _TAMPER_MS=0; return 2
    fi

    _TAMPER_COUNT="$tampered_count/$checked_count"
    if [ "$tampered_count" -gt 0 ]; then
        _TAMPER_RESULT="tampered"; return 1
    else
        _TAMPER_RESULT="clean"; return 0
    fi
}

# --- Result reporting ---
#
# _report_result <name> <addr> <proto> <label>
#   Reads _TAMPER_RESULT, _TAMPER_MS, _TAMPER_COUNT, _TAMPER_DETAILS
#
_report_result() {
    local name="$1" addr="$2" proto="$3" label="$4"
    case "$_TAMPER_RESULT" in
        clean)
            inc pass
            printf "  ${G}✓ OPEN${N}    %-33s %-20s ${Y}%4d ms${N}  %b\n" "$name" "$addr" "$_TAMPER_MS" "$label" | tee -a "$REPORT_FILE"
            echo "OK|$proto|$_TAMPER_MS|$name|$addr" >> "$RANKING_FILE"
            ;;
        tampered)
            inc pass; inc tampered
            printf "  ${Y}⚠ TAMPER${N}  %-33s %-20s ${Y}%4d ms${N}  %b  ${R}(%s) %s${N}\n" "$name" "$addr" "$_TAMPER_MS" "$label" "$_TAMPER_COUNT" "$_TAMPER_DETAILS" | tee -a "$REPORT_FILE"
            echo "TAMPER|$proto|$_TAMPER_MS|$name|$addr|$_TAMPER_DETAILS" >> "$RANKING_FILE"
            ;;
        blocked)
            inc fail
            printf "  ${R}✗ BLOCKED${N} %-33s %s  %b\n" "$name" "$addr" "$label" | tee -a "$REPORT_FILE"
            ;;
    esac
}

# --- DoH result reporting (different column layout) ---

_report_result_doh() {
    local name="$1" hostname="$2" ip="$3"
    case "$_TAMPER_RESULT" in
        clean)
            inc pass
            printf "  ${G}✓ OPEN${N}    %-18s %-24s → %-15s ${Y}%4d ms${N}\n" "$name" "$hostname" "$ip" "$_TAMPER_MS" | tee -a "$REPORT_FILE"
            echo "OK|DoH|$_TAMPER_MS|$name|$hostname>$ip" >> "$RANKING_FILE"
            ;;
        tampered)
            inc pass; inc tampered
            printf "  ${Y}⚠ TAMPER${N}  %-18s %-24s → %-15s ${Y}%4d ms${N}  ${R}(%s) %s${N}\n" "$name" "$hostname" "$ip" "$_TAMPER_MS" "$_TAMPER_COUNT" "$_TAMPER_DETAILS" | tee -a "$REPORT_FILE"
            echo "TAMPER|DoH|$_TAMPER_MS|$name|$hostname>$ip|$_TAMPER_DETAILS" >> "$RANKING_FILE"
            ;;
        blocked)
            inc fail
            printf "  ${R}✗ BLOCKED${N} %-18s %-24s → %s\n" "$name" "$hostname" "$ip" | tee -a "$REPORT_FILE"
            ;;
    esac
}

# --- Query functions (called by _check_tamper) ---

_query_udp() {
    local domain="$1" ip="$2"
    local output
    output=$(dig +timeout=$TIMEOUT +tries=1 +stats @"$ip" "$domain" A 2>/dev/null)
    _Q_MS=$(echo "$output" | grep -oP 'Query time: \K[0-9]+')
    _Q_ANSWER=$(echo "$output" | awk '/IN[[:space:]]+A[[:space:]]+/{print $NF}' | head -1)
    echo "$output" | grep -q "NOERROR" && [ -n "$_Q_MS" ]
}

_query_tcp() {
    local domain="$1" ip="$2"
    local output
    output=$(dig +timeout=$TIMEOUT +tries=1 +tcp +stats @"$ip" "$domain" A 2>/dev/null)
    _Q_MS=$(echo "$output" | grep -oP 'Query time: \K[0-9]+')
    _Q_ANSWER=$(echo "$output" | awk '/IN[[:space:]]+A[[:space:]]+/{print $NF}' | head -1)
    echo "$output" | grep -q "NOERROR" && [ -n "$_Q_MS" ]
}

_query_dot() {
    local domain="$1" ip="$2" hostname="$3"
    local start end result
    start=$(date +%s%N)
    result=$(kdig +tls-ca +tls-hostname="$hostname" +timeout=$TIMEOUT +retry=0 @"$ip" "$domain" A 2>/dev/null)
    end=$(date +%s%N)
    _Q_MS=$(( (end - start) / 1000000 ))
    _Q_ANSWER=$(echo "$result" | awk '/IN[[:space:]]+A[[:space:]]+/{print $NF}' | head -1)
    echo "$result" | grep -q "NOERROR"
}

_query_doh() {
    local domain="$1" hostname="$2" ip="$3" path="$4"
    local start end
    start=$(date +%s%N)
    _Q_ANSWER=$(curl -s --max-time 2 --resolve "${hostname}:443:${ip}" \
        -H "accept: application/dns-json" \
        "https://${hostname}${path}?name=${domain}&type=A" 2>/dev/null | \
        tr -d '\0' | grep -oP '"data"\s*:\s*"\K[0-9.]+' | head -1)
    end=$(date +%s%N)
    _Q_MS=$(( (end - start) / 1000000 ))
    [ -n "$_Q_ANSWER" ]
}

# --- Public test functions ---

test_udp() {
    local name="$1" ip="$2"; inc total
    _check_tamper _query_udp "$ip"
    _report_result "$name" "$ip" "UDP" ""
}

test_tcp() {
    local name="$1" ip="$2"; inc total
    _check_tamper _query_tcp "$ip"
    _report_result "$name" "$ip" "TCP" "${C}(TCP)${N}"
}

test_dot() {
    local name="$1" ip="$2" hostname="${3:-$ip}"; inc total

    if command -v kdig >/dev/null 2>&1; then
        _check_tamper _query_dot "$ip" "$hostname"
        _report_result "$name" "$ip" "DoT" "${M}(DoT)${N}"
        return
    fi

    # Fallback: TLS handshake check only (no tamper detection possible)
    local start end ms result
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
    _check_tamper _query_doh "$hostname" "$ip" "$path"
    _report_result_doh "$name" "$hostname" "$ip"
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
