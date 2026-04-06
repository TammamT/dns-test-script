#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

section "DNSCrypt — port reachability (TCP)"
log "  Testing TCP connectivity to known DNSCrypt servers"
log ""

test_dnscrypt "Cisco/OpenDNS :443"       "208.67.222.222"   443
test_dnscrypt "Cisco/OpenDNS :5443"      "208.67.222.222"   5443
test_dnscrypt "Cisco/OpenDNS 2 :443"     "208.67.220.220"   443
test_dnscrypt "AdGuard :443"             "94.140.14.14"     443
test_dnscrypt "AdGuard :5443"            "94.140.14.14"     5443
test_dnscrypt "CleanBrowsing :443"       "185.228.168.168"  443
test_dnscrypt "CleanBrowsing :8443"      "185.228.168.168"  8443
test_dnscrypt "Quad9 :443"               "9.9.9.9"          443
test_dnscrypt "Quad9 :5443"              "9.9.9.9"          5443
test_dnscrypt "Cloudflare :443"          "1.1.1.1"          443
test_dnscrypt "Cloudflare Alt :443"      "1.0.0.1"          443
test_dnscrypt "Scaleway FR :443"         "163.172.180.125"  443
test_dnscrypt "DNSCrypt.ca :443"         "167.114.220.125"  443
test_dnscrypt "DNSCrypt.ca 2 :443"       "149.56.228.45"    443
test_dnscrypt "AhaDNS NL :443"           "5.2.75.75"        443
test_dnscrypt "LibreDNS :443"            "116.202.176.26"   443

log ""
log "  ${C}Tip: If ports are open, install dnscrypt-proxy${N}"
log "  ${C}     and point AGH upstream to 127.0.0.1:5353${N}"
