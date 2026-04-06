#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

section "IPv6 CONNECTIVITY CHECK"

ipv6_works=0

ipv6_addr=$(ip -6 addr show scope global 2>/dev/null | grep -oP 'inet6 \K[^ ]+' | head -1)
if [ -n "$ipv6_addr" ]; then
    log "  ${G}✓ Global IPv6 address: $ipv6_addr${N}"
    ipv6_works=1
else
    log "  ${Y}  No global IPv6 address found${N}"
fi

if [ $ipv6_works -eq 1 ]; then
    if ping6 -c 1 -W 2 2001:4860:4860::8888 >/dev/null 2>&1; then
        log "  ${G}✓ IPv6 internet reachable${N}"
    else
        log "  ${R}✗ IPv6 internet NOT reachable${N}"
        ipv6_works=0
    fi
fi

if [ $ipv6_works -eq 0 ]; then
    log ""
    log "  ${Y}No IPv6 connectivity — skipping IPv6 DNS tests${N}"
    return 0
fi

section "IPv6 DNS (UDP :53)"

test_udp "Google IPv6"                   "2001:4860:4860::8888"
test_udp "Google IPv6 Secondary"         "2001:4860:4860::8844"
test_udp "Cloudflare IPv6"               "2606:4700:4700::1111"
test_udp "Cloudflare IPv6 Secondary"     "2606:4700:4700::1001"
test_udp "Quad9 IPv6"                    "2620:fe::fe"
test_udp "Quad9 IPv6 Secondary"          "2620:fe::9"
test_udp "OpenDNS IPv6"                  "2620:119:35::35"
test_udp "OpenDNS IPv6 Secondary"        "2620:119:53::53"
test_udp "AdGuard IPv6"                  "2a10:50c0::ad1:ff"
test_udp "AdGuard IPv6 Secondary"        "2a10:50c0::ad2:ff"
test_udp "Mullvad IPv6"                  "2a07:e340::2"
test_udp "CleanBrowsing IPv6 Sec"        "2a0d:2a00:1::2"
test_udp "CleanBrowsing IPv6 Family"     "2a0d:2a00:1::"
test_udp "NextDNS IPv6"                  "2a07:a8c0::"
test_udp "NextDNS IPv6 Secondary"        "2a07:a8c1::"
test_udp "Yandex IPv6"                   "2a02:6b8::feed:0ff"
test_udp "Yandex IPv6 Safe"              "2a02:6b8::feed:bad"
test_udp "Yandex IPv6 Family"            "2a02:6b8::feed:a11"
test_udp "UncensoredDNS IPv6"            "2001:67c:28a4::"
test_udp "Neustar IPv6"                  "2610:a1:1018::1"
test_udp "Neustar IPv6 Secondary"        "2610:a1:1019::1"
test_udp "CIRA IPv6"                     "2620:10A:80BB::10"
test_udp "CIRA IPv6 Secondary"           "2620:10A:80BC::10"
test_udp "DNS.SB IPv6"                   "2a09::"
test_udp "DNS.SB IPv6 Secondary"         "2a11::"
test_udp "Alternate DNS IPv6"            "2602:fcbc::ad"
test_udp "Alternate DNS IPv6 Sec"        "2602:fcbc:2::ad"
test_udp "TWNIC IPv6"                    "2001:de4::101"
test_udp "TWNIC IPv6 Secondary"          "2001:de4::102"
test_udp "Applied Privacy IPv6"          "2a02:1b8:10:234::2"
test_udp "Digitalcourage IPv6"           "2a02:2970:1002::18"
test_udp "French Data Network IPv6"      "2001:910:800::40"
test_udp "Control D IPv6"               "2606:1a40::"
test_udp "Control D IPv6 Uncensored"    "2606:1a40::5"
test_udp "DNS for Family IPv6"          "2a01:4f8:1c0c:40db::1"
test_udp "DNS for Family IPv6 2"        "2a01:4f8:1c17:4df8::1"
