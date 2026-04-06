#!/bin/bash
# doq.sh — DNS-over-QUIC (port 853 or 8853, UDP-based)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

section "DNS-over-QUIC (DoQ) — UDP port reachability"

log "  QUIC runs over UDP. Testing if ports are reachable."
log "  Port open ≠ full DoQ working, but blocked port = definitely won't work"
log ""

test_doq "AdGuard DoQ"               "94.140.14.14"     853
test_doq "AdGuard DoQ 2"             "94.140.15.15"     853
test_doq "NextDNS DoQ"               "45.90.28.0"       853
test_doq "NextDNS DoQ 2"             "45.90.30.0"       853
test_doq "Mullvad DoQ"               "194.242.2.2"      853
test_doq "Control D DoQ"             "76.76.2.0"        853
test_doq "DNS.SB DoQ"                "185.222.222.222"  853
test_doq "AliDNS DoQ"                "223.5.5.5"        853
test_doq "Quad9 DoQ"                 "9.9.9.9"          853
test_doq "AdGuard 8853"              "94.140.14.14"     8853
test_doq "Mullvad 8853"              "194.242.2.2"      8853
