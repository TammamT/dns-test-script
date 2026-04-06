# DNS Audit Toolkit

A comprehensive DNS reachability and security testing tool designed for networks with heavy DNS restrictions (e.g. Iraq, Iran, China). Tests 200+ DNS servers across 8 protocols to find what works from your location.

Built for **Debian-based** systems (Ubuntu, Debian, etc.).

## What It Does

- **Detects DNS hijacking** — checks if your ISP is intercepting and redirecting DNS traffic
- **Detects transparent proxying** — sends DNS queries to non-DNS servers to see if your ISP intercepts all port 53 traffic
- **Detects SNI/DPI inspection** — tests if your ISP uses deep packet inspection to block DNS hostnames in TLS handshakes
- **Tests 200+ public DNS servers** across UDP, TCP, DoT, DoH, DoQ, DNSCrypt, and IPv6
- **Validates responses** — flags servers returning wrong IPs (ISP tampering)
- **Ranks servers by latency** — shows the top 20 fastest working servers
- **Recommends AGH config** — outputs ready-to-paste upstream servers for AdGuard Home
- **Saves a full report** to a timestamped file for comparison between ISPs/locations

## Requirements

- Debian-based Linux (Ubuntu, Debian, etc.)
- `sudo` access

Dependencies are **auto-installed** on first run via `apt`:
- `dnsutils` (dig), `curl`, `openssl`, `iproute2` (ip), `iputils-ping` (ping6)
- `knot-dnsutils` (kdig) for accurate DoT/DoQ testing

## Setup

```bash
git clone https://github.com/TammamT/dns-test-script.git
cd dns-test-script
chmod +x dns-audit.sh tests/*.sh
./dns-audit.sh
```

## Usage

Run everything:
```bash
./dns-audit.sh
```

Run specific modules:
```bash
./dns-audit.sh detect      # hijack + interception + DPI detection
./dns-audit.sh udp         # plain DNS over UDP :53
./dns-audit.sh tcp         # plain DNS over TCP :53
./dns-audit.sh dot         # DNS-over-TLS :853
./dns-audit.sh doh         # DNS-over-HTTPS :443 (bypasses DNS dependency)
./dns-audit.sh doq         # DNS-over-QUIC
./dns-audit.sh dnscrypt    # DNSCrypt port reachability
./dns-audit.sh ipv6        # IPv6 DNS servers
./dns-audit.sh doh dot     # combine multiple modules
```

### Environment variables

```bash
TIMEOUT=2 ./dns-audit.sh              # custom timeout (default: 1s)
TEST_DOMAIN=google.com ./dns-audit.sh  # custom test domain (default: example.com)
```

## File Structure

```
dns-test-script/
├── dns-audit.sh           Main runner + summary + ranking
└── tests/
    ├── common.sh          Shared functions, colors, counters
    ├── detect.sh          Hijack, port 53 proxy, SNI/DPI
    ├── udp.sh             85 servers — UDP :53
    ├── tcp.sh             28 servers — TCP :53
    ├── dot.sh             26 servers — DoT :853
    ├── doh.sh             29 servers — DoH :443 (with --resolve IP bypass)
    ├── doq.sh             14 servers — DNS-over-QUIC
    ├── dnscrypt.sh        16 servers — DNSCrypt ports
    └── ipv6.sh            35 servers — IPv6 DNS
```

## Output

Each server is marked as:

| Symbol | Meaning |
|--------|---------|
| ✓ OPEN | Server is accessible, response is correct |
| ✗ BLOCKED | Server is unreachable (blocked by ISP) |
| ⚠ TAMPER | Server responds but returns a wrong IP (ISP injecting fake answers) |
| ~ MAYBE | UDP port appears open but full protocol test unavailable (DoQ without kdig) |

A full report is saved to `dns_report_YYYYMMDD_HHMMSS.txt` in the script directory.

## DoH IP Bypass

Most DoH tests fail in restricted networks because the system needs DNS to resolve the DoH server's hostname — a chicken-and-egg problem. This toolkit solves it by using `curl --resolve` to hardcode the server IP, bypassing system DNS entirely.

## Tips

- **DoH on port 443** is the hardest for ISPs to block since it looks like normal HTTPS traffic
- **DoQ (QUIC)** is very new — most ISPs don't know to block it yet
- **DNSCrypt on port 443** often slips through since ISPs can't distinguish it from HTTPS
- If everything is blocked, consider Cloudflare WARP, a VPN, or DNS tunneling (iodine/dnstt)
