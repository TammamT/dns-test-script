#!/bin/bash
# detect.sh — hijack detection, port 53 interception, SNI/DPI inspection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

section "HIJACK DETECTION"
log "  Checking if ISP intercepts DNS traffic..."
log ""

hijack_result=$(dig +short +timeout=2 +tries=1 @8.8.8.8 o-o.myaddr.l.google.com TXT 2>/dev/null | head -1)
if [ -n "$hijack_result" ] && ! echo "$hijack_result" | grep -q "timed out"; then
    log "  Response from 8.8.8.8: $hijack_result"
    if echo "$hijack_result" | grep -qiE "google|216\.239|2001:4860"; then
        log "  ${G}${B}✓ No hijacking — traffic reaches Google directly${N}"
    else
        log "  ${R}${B}⚠ DNS HIJACKING — response is NOT from Google${N}"
        log "  ${Y}  ISP is intercepting port 53 traffic${N}"
    fi
else
    log "  ${R}${B}⚠ No response from 8.8.8.8 — DNS blocked or hijacked${N}"
fi

# Compare resolver IPs from different servers
ans1=$(dig +short +timeout=2 +tries=1 @8.8.8.8 whoami.akamai.net A 2>/dev/null | head -1)
ans2=$(dig +short +timeout=2 +tries=1 @9.9.9.9 whoami.akamai.net A 2>/dev/null | head -1)
if [ -n "$ans1" ] && [ -n "$ans2" ]; then
    if [ "$ans1" = "$ans2" ]; then
        log "  ${Y}  8.8.8.8 and 9.9.9.9 return same resolver IP: $ans1${N}"
        log "  ${Y}  ISP likely redirecting all DNS to one server${N}"
    else
        log "  ${G}  Different resolver IPs ($ans1 vs $ans2) — looks legit${N}"
    fi
fi

section "PORT 53 TRANSPARENT PROXY"
log "  Sending DNS query to a non-DNS server on port 53..."
log "  If we get a response, ISP is proxying ALL :53 traffic"
log ""

PORT53_INTERCEPTED=0
intercept=$(dig +short +timeout=2 +tries=1 @93.184.215.14 google.com A 2>/dev/null | head -1)
if [ -n "$intercept" ] && ! echo "$intercept" | grep -q "timed out"; then
    PORT53_INTERCEPTED=1
    log "  ${R}${B}⚠ PORT 53 INTERCEPTION CONFIRMED${N}"
    log "  ${R}  Got DNS response from 93.184.215.14 (not a DNS server): $intercept${N}"
    log "  ${Y}  ISP redirects ALL port 53 traffic — plain DNS cannot be trusted${N}"
else
    log "  ${G}✓ No transparent proxy — port 53 reaches real destinations${N}"
fi

section "SNI / DPI INSPECTION"
log "  Testing if ISP inspects TLS SNI to block DNS hostnames..."
log ""

# Google: real SNI vs fake SNI
sni_real=$(timeout 2 bash -c "echo | openssl s_client -connect 8.8.8.8:443 -servername dns.google 2>/dev/null" | grep -c "BEGIN CERTIFICATE" 2>/dev/null)
sni_fake=$(timeout 2 bash -c "echo | openssl s_client -connect 8.8.8.8:443 -servername www.example.com 2>/dev/null" | grep -c "BEGIN CERTIFICATE" 2>/dev/null)

if [ "${sni_real:-0}" -gt 0 ] && [ "${sni_fake:-0}" -gt 0 ]; then
    log "  ${G}✓ 8.8.8.8:443 — both real+fake SNI work — no SNI blocking${N}"
elif [ "${sni_real:-0}" -eq 0 ] && [ "${sni_fake:-0}" -gt 0 ]; then
    log "  ${R}${B}⚠ SNI INSPECTION on 8.8.8.8:443${N}"
    log "  ${R}  'dns.google' SNI blocked, but fake SNI works${N}"
    log "  ${Y}  ISP uses DPI to block DNS hostnames in TLS handshake${N}"
elif [ "${sni_real:-0}" -eq 0 ] && [ "${sni_fake:-0}" -eq 0 ]; then
    log "  ${Y}  8.8.8.8:443 — both SNIs failed — IP may be blocked entirely${N}"
else
    log "  ${G}✓ 8.8.8.8:443 — real SNI works — no DPI detected${N}"
fi

# Cloudflare
for ip in 1.1.1.1 1.0.0.1; do
    sni=$(timeout 2 bash -c "echo | openssl s_client -connect $ip:443 -servername cloudflare-dns.com 2>/dev/null" | grep -c "BEGIN CERTIFICATE" 2>/dev/null)
    if [ "${sni:-0}" -gt 0 ]; then
        log "  ${G}✓ $ip:443 with 'cloudflare-dns.com' SNI — OPEN${N}"
    else
        log "  ${R}✗ $ip:443 with 'cloudflare-dns.com' SNI — BLOCKED${N}"
    fi
done

# AdGuard
sni_ag=$(timeout 2 bash -c "echo | openssl s_client -connect 94.140.14.14:443 -servername dns.adguard-dns.com 2>/dev/null" | grep -c "BEGIN CERTIFICATE" 2>/dev/null)
if [ "${sni_ag:-0}" -gt 0 ]; then
    log "  ${G}✓ 94.140.14.14:443 with 'dns.adguard-dns.com' SNI — OPEN${N}"
else
    log "  ${R}✗ 94.140.14.14:443 with 'dns.adguard-dns.com' SNI — BLOCKED${N}"
fi

# Quad9
sni_q9=$(timeout 2 bash -c "echo | openssl s_client -connect 9.9.9.9:443 -servername dns.quad9.net 2>/dev/null" | grep -c "BEGIN CERTIFICATE" 2>/dev/null)
if [ "${sni_q9:-0}" -gt 0 ]; then
    log "  ${G}✓ 9.9.9.9:443 with 'dns.quad9.net' SNI — OPEN${N}"
else
    log "  ${R}✗ 9.9.9.9:443 with 'dns.quad9.net' SNI — BLOCKED${N}"
fi
