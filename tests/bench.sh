#!/bin/bash
# bench.sh — benchmark clean (non-tampered, non-blocked) servers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

BENCH_ROUNDS="${BENCH_ROUNDS:-10}"
BENCH_DOMAIN="example.com"
BENCH_FILE="${BENCH_FILE:-/tmp/dns_bench_$$.tmp}"

section "LATENCY BENCHMARK (${BENCH_ROUNDS} rounds per server)"

if [ ! -s "$RANKING_FILE" ]; then
    log "  ${Y}No servers to benchmark — run other modules first${N}"
    return 0 2>/dev/null || exit 0
fi

ok_count=$(grep -c "^OK|" "$RANKING_FILE" 2>/dev/null)
if [ "${ok_count:-0}" -eq 0 ]; then
    log "  ${Y}No clean servers found — all tampered or blocked${N}"
    return 0 2>/dev/null || exit 0
fi

log "  Benchmarking ${B}${ok_count}${N} clean servers, ${B}${BENCH_ROUNDS}${N} queries each..."
log "  ${C}(this will take a while)${N}"
log ""

> "$BENCH_FILE"

# --- DNSCrypt proxy management for benchmarking ---
DCPROXY_PORT=15354
DCPROXY_PID=""
DCBENCH_DIR="/tmp/dnscrypt_bench_$$"

# Known stamps (same as dnscrypt-verify.sh)
declare -A DCSTAMPS
DCSTAMPS["208.67.222.222:443"]="sdns://AQAAAAAAAAAADjIwOC42Ny4yMjIuMjIyILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ"
DCSTAMPS["208.67.220.220:443"]="sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ"
DCSTAMPS["94.140.14.14:443"]="sdns://AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
DCSTAMPS["94.140.14.14:5443"]="sdns://AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
DCSTAMPS["185.228.168.168:443"]="sdns://AQMAAAAAAAAAFDE4NS4yMjguMTY4LjE2ODo4NDQzILysMvrVQ2kXHwgy1gdQJ8MgjO7w6OmflBjcd2Bl1I8pEWNsZWFuYnJvd3Npbmcub3Jn"
DCSTAMPS["185.228.168.168:8443"]="sdns://AQMAAAAAAAAAFDE4NS4yMjguMTY4LjE2ODo4NDQzILysMvrVQ2kXHwgy1gdQJ8MgjO7w6OmflBjcd2Bl1I8pEWNsZWFuYnJvd3Npbmcub3Jn"
DCSTAMPS["9.9.9.9:443"]="sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"
DCSTAMPS["1.0.0.1:443"]="sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5"
DCSTAMPS["1.1.1.1:443"]="sdns://AgcAAAAAAAAABzEuMS4xLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5"

_dc_start_proxy() {
    local addr="$1" stamp="${DCSTAMPS[$addr]}"
    [ -z "$stamp" ] && return 1

    mkdir -p "$DCBENCH_DIR"
    local config="$DCBENCH_DIR/bench.toml"

    cat > "$config" <<TOML
listen_addresses = ['127.0.0.1:${DCPROXY_PORT}']
max_clients = 10
timeout = 2000
server_names = ['bench-server']
[static]
  [static.'bench-server']
  stamp = '${stamp}'
TOML

    dnscrypt-proxy -config "$config" >/dev/null 2>&1 &
    DCPROXY_PID=$!

    # Wait for ready
    for i in 1 2 3 4 5 6; do
        sleep 0.5
        if dig +timeout=1 +tries=1 @127.0.0.1 -p $DCPROXY_PORT example.com A >/dev/null 2>&1; then
            return 0
        fi
    done
    # Failed to start
    kill $DCPROXY_PID 2>/dev/null
    wait $DCPROXY_PID 2>/dev/null
    DCPROXY_PID=""
    return 1
}

_dc_stop_proxy() {
    if [ -n "$DCPROXY_PID" ]; then
        kill $DCPROXY_PID 2>/dev/null
        wait $DCPROXY_PID 2>/dev/null
        DCPROXY_PID=""
    fi
}

# --- Single query benchmark functions ---

_bench_single() {
    local proto="$1" addr="$2" ms=""

    case "$proto" in
        UDP)
            ms=$(dig +timeout=$TIMEOUT +tries=1 +stats @"$addr" "$BENCH_DOMAIN" A 2>/dev/null \
                | grep -oP 'Query time: \K[0-9]+')
            ;;
        TCP)
            ms=$(dig +timeout=$TIMEOUT +tries=1 +tcp +stats @"$addr" "$BENCH_DOMAIN" A 2>/dev/null \
                | grep -oP 'Query time: \K[0-9]+')
            ;;
        DoT)
            local start end
            start=$(date +%s%N)
            kdig +tls +timeout=$TIMEOUT +retry=0 @"$addr" "$BENCH_DOMAIN" A >/dev/null 2>&1
            end=$(date +%s%N)
            ms=$(( (end - start) / 1000000 ))
            ;;
        DoQ)
            local ip="${addr%%:*}" port="${addr##*:}" start end
            start=$(date +%s%N)
            kdig +quic @"$ip" -p "$port" +timeout=$TIMEOUT +retry=0 "$BENCH_DOMAIN" A >/dev/null 2>&1
            end=$(date +%s%N)
            ms=$(( (end - start) / 1000000 ))
            ;;
        DNSCrypt)
            # Query through already-running dnscrypt-proxy
            local start end
            start=$(date +%s%N)
            dig +timeout=2 +tries=1 +stats @127.0.0.1 -p $DCPROXY_PORT "$BENCH_DOMAIN" A >/dev/null 2>&1
            end=$(date +%s%N)
            ms=$(( (end - start) / 1000000 ))
            ;;
        DoH)
            return 1
            ;;
    esac

    [ -n "$ms" ] && echo "$ms" && return 0
    return 1
}

# _calc_stats — read times from stdin, output median|avg|min|max|count
_calc_stats() {
    local times=()
    while read -r t; do
        [ -n "$t" ] && times+=("$t")
    done

    local count=${#times[@]}
    [ "$count" -eq 0 ] && return 1

    local sorted
    sorted=$(printf '%s\n' "${times[@]}" | sort -n)
    local min=$(echo "$sorted" | head -1)
    local max=$(echo "$sorted" | tail -1)
    local median=$(echo "$sorted" | sed -n "$(( (count + 1) / 2 ))p")
    local sum=0
    for t in "${times[@]}"; do sum=$((sum + t)); done
    local avg=$((sum / count))

    echo "$median|$avg|$min|$max|$count"
}

# --- Main benchmark loop ---

while IFS='|' read -r status proto ms name addr extra; do
    # Skip DoH — can't bench without path info
    [ "$proto" = "DoH" ] && continue
    # Skip protocols that need kdig if not available
    [[ "$proto" =~ ^(DoT|DoQ)$ ]] && ! command -v kdig >/dev/null 2>&1 && continue

    printf "  ${C}Benchmarking:${N} %-33s ${C}(%s)${N}\n" "$name" "$proto" | tee -a "$REPORT_FILE"

    # DNSCrypt: start proxy for this server, run rounds, stop
    if [ "$proto" = "DNSCrypt" ]; then
        if ! command -v dnscrypt-proxy >/dev/null 2>&1; then
            log "    ${Y}→ skipped (dnscrypt-proxy not installed)${N}"
            continue
        fi
        if ! _dc_start_proxy "$addr"; then
            log "    ${R}→ failed to start proxy${N}"
            continue
        fi
    fi

    results=""
    for ((i=1; i<=BENCH_ROUNDS; i++)); do
        t=$(_bench_single "$proto" "$addr")
        [ -n "$t" ] && results="${results}${t}\n"
    done

    # Stop DNSCrypt proxy after rounds
    [ "$proto" = "DNSCrypt" ] && _dc_stop_proxy

    stats=$(echo -e "$results" | _calc_stats)
    if [ -n "$stats" ]; then
        median="${stats%%|*}"
        echo "${stats}|${proto}|${name}|${addr}" >> "$BENCH_FILE"
        log "    ${G}→ median ${median} ms${N}"
    else
        log "    ${R}→ failed${N}"
    fi
done < <(grep "^OK|" "$RANKING_FILE" | sort -t'|' -k3 -n)

# --- Display results ---

if [ ! -s "$BENCH_FILE" ]; then
    log ""
    log "  ${Y}No servers responded during benchmark${N}"
    return 0 2>/dev/null || exit 0
fi

log ""
header "BENCHMARK RESULTS (sorted by median latency)"
log ""
printf "  ${B}%-4s  %-8s  %6s  %6s  %6s  %6s  %-33s %s${N}\n" \
    "#" "PROTO" "MEDIAN" "AVG" "MIN" "MAX" "NAME" "ADDRESS" | tee -a "$REPORT_FILE"
log "  ────  ────────  ──────  ──────  ──────  ──────  ─────────────────────────────────  ───────────────────"

rank=0
sort -t'|' -k1 -n "$BENCH_FILE" | \
while IFS='|' read -r median avg min max count proto name addr; do
    rank=$((rank + 1))
    printf "  ${G}%-4s${N}  %-8s  ${Y}%4d ms${N}  %4d ms  %4d ms  %4d ms  %-33s %s\n" \
        "$rank" "$proto" "$median" "$avg" "$min" "$max" "$name" "$addr" | tee -a "$REPORT_FILE"
done

# Cleanup
rm -rf "$DCBENCH_DIR"

# BENCH_FILE is kept for AGH config suggestion — cleaned up by dns-audit.sh
