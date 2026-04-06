#!/bin/bash
# dnscrypt-verify.sh — verify DNSCrypt servers with real queries via dnscrypt-proxy
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

section "DNSCrypt — verification (real queries)"

# Check if any MAYBE DNSCrypt entries exist to verify
maybe_count=$(grep -c "^MAYBE|DNSCrypt|" "$RANKING_FILE" 2>/dev/null)
if [ "${maybe_count:-0}" -eq 0 ]; then
    log "  ${Y}No DNSCrypt servers to verify — skipping${N}"
    return 0 2>/dev/null || exit 0
fi

# Install dnscrypt-proxy if needed
if ! command -v dnscrypt-proxy >/dev/null 2>&1; then
    log "  ${Y}○${N} dnscrypt-proxy not found — installing..."
    if sudo apt-get install -y dnscrypt-proxy >/dev/null 2>&1; then
        # Stop the system service — we'll run our own instances
        sudo systemctl stop dnscrypt-proxy 2>/dev/null
        sudo systemctl disable dnscrypt-proxy 2>/dev/null
        log "  ${G}✓ dnscrypt-proxy installed${N}"
    else
        log "  ${R}✗ Could not install dnscrypt-proxy — skipping verification${N}"
        return 0 2>/dev/null || exit 0
    fi
fi

DCPROXY=$(command -v dnscrypt-proxy)
DCTEMP_DIR="/tmp/dnscrypt_verify_$$"
mkdir -p "$DCTEMP_DIR"
DCPROXY_PORT=15353  # temp port for verification queries

# Known DNSCrypt stamps (IPv4, protocol 0x01 = DNSCrypt)
# Source: dnscrypt.info/public-servers, adguard-dns.io/kb/general/dns-providers
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

log "  Verifying ${B}${maybe_count}${N} servers with real DNSCrypt queries..."
log ""

# _verify_dnscrypt — start dnscrypt-proxy with a single server, do a real query
# Usage: _verify_dnscrypt <name> <addr> <stamp>
# Sets: _DC_MS (latency), returns 0 on success
_verify_dnscrypt() {
    local name="$1" addr="$2" stamp="$3"
    local config="$DCTEMP_DIR/config_$$.toml"
    local pidfile="$DCTEMP_DIR/pid_$$"
    _DC_MS=""

    # Write minimal config
    cat > "$config" <<TOML
listen_addresses = ['127.0.0.1:${DCPROXY_PORT}']
max_clients = 10
timeout = 2000
server_names = ['test-server']
[static]
  [static.'test-server']
  stamp = '${stamp}'
TOML

    # Start dnscrypt-proxy in background
    $DCPROXY -config "$config" -pidfile "$pidfile" >/dev/null 2>&1 &
    local proxy_pid=$!

    # Wait for it to be ready (up to 3 seconds)
    local ready=0
    for i in 1 2 3 4 5 6; do
        sleep 0.5
        if dig +timeout=1 +tries=1 @127.0.0.1 -p $DCPROXY_PORT example.com A >/dev/null 2>&1; then
            ready=1
            break
        fi
    done

    local result=1
    if [ "$ready" -eq 1 ]; then
        # Real benchmark query
        local start end output ms
        start=$(date +%s%N)
        output=$(dig +timeout=2 +tries=1 +stats @127.0.0.1 -p $DCPROXY_PORT "$TEST_DOMAIN" A 2>/dev/null)
        end=$(date +%s%N)
        _DC_MS=$(( (end - start) / 1000000 ))

        if echo "$output" | grep -q "NOERROR"; then
            result=0
        fi
    fi

    # Cleanup
    kill $proxy_pid 2>/dev/null
    wait $proxy_pid 2>/dev/null
    rm -f "$config" "$pidfile"

    return $result
}

# Process each MAYBE DNSCrypt entry
verified=0
failed=0

while IFS='|' read -r status proto ms name addr extra; do
    stamp="${DCSTAMPS[$addr]}"

    if [ -z "$stamp" ]; then
        printf "  ${Y}○${N} %-33s %-20s ${Y}no stamp — skipped${N}\n" "$name" "$addr" | tee -a "$REPORT_FILE"
        continue
    fi

    printf "  ${C}…${N} %-33s %-20s verifying..." "$name" "$addr" >&2

    if _verify_dnscrypt "$name" "$addr" "$stamp"; then
        verified=$((verified + 1))
        printf "\r  ${G}✓ VERIFIED${N} %-33s %-20s ${Y}%4d ms${N}  ${M}(DNSCrypt)${N}\n" "$name" "$addr" "$_DC_MS" | tee -a "$REPORT_FILE"
        # Upgrade from MAYBE to OK in ranking
        # Remove old MAYBE entry, add verified OK entry
        sed -i "/^MAYBE|DNSCrypt|.*|${name}|/d" "$RANKING_FILE"
        echo "OK|DNSCrypt|$_DC_MS|$name|$addr" >> "$RANKING_FILE"
    else
        failed=$((failed + 1))
        printf "\r  ${R}✗ FAILED${N}   %-33s %-20s ${M}(DNSCrypt)${N}\n" "$name" "$addr" | tee -a "$REPORT_FILE"
    fi

done < <(grep "^MAYBE|DNSCrypt|" "$RANKING_FILE" | sort -t'|' -k3 -n)

log ""
log "  ${G}Verified: $verified${N}  ${R}Failed: $failed${N}  ${Y}No stamp: $((maybe_count - verified - failed))${N}"

# Cleanup temp dir
rm -rf "$DCTEMP_DIR"
