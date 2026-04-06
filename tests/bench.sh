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

# _bench_single — run one query, return ms via stdout
# Usage: _bench_single <proto> <addr>
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
            local ip="${addr%%:*}" port="${addr##*:}" start end
            start=$(date +%s%N)
            timeout $TIMEOUT bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
            end=$(date +%s%N)
            ms=$(( (end - start) / 1000000 ))
            ;;
        DoH)
            # Skip DoH in bench — path info not available from ranking file
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

# Benchmark each clean server (no pipe — avoid subshell)
while IFS='|' read -r status proto ms name addr extra; do
    # Skip DoH — can't bench without path info
    [ "$proto" = "DoH" ] && continue
    # Skip protocols that need kdig if not available
    [[ "$proto" =~ ^(DoT|DoQ)$ ]] && ! command -v kdig >/dev/null 2>&1 && continue

    printf "  ${C}Benchmarking:${N} %-33s ${C}(%s)${N}\n" "$name" "$proto" | tee -a "$REPORT_FILE"

    results=""
    for ((i=1; i<=BENCH_ROUNDS; i++)); do
        t=$(_bench_single "$proto" "$addr")
        [ -n "$t" ] && results="${results}${t}\n"
    done

    stats=$(echo -e "$results" | _calc_stats)
    if [ -n "$stats" ]; then
        median="${stats%%|*}"
        echo "${stats}|${proto}|${name}|${addr}" >> "$BENCH_FILE"
        log "    ${G}→ median ${median} ms${N}"
    else
        log "    ${R}→ failed${N}"
    fi
done < <(grep "^OK|" "$RANKING_FILE" | sort -t'|' -k3 -n)

# Display results
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

# BENCH_FILE is kept for AGH config suggestion — cleaned up by dns-audit.sh
