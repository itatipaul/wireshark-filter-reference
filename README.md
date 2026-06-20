# Wireshark Filter Reference Plugin

A Wireshark Lua plugin that adds a categorised, searchable filter reference directly into the Tools menu — so you can find and apply the right display filter in seconds, without memorising syntax.

---

## What it does

Every filter lives under **Tools → Filter Reference → [Category] → [Filter Name]**. Click a filter and it's instantly applied to your current capture. No typing, no syntax errors.

```
Tools
 └── Filter Reference
      ├── — Tools —
      │    ├── Guided troubleshooting (I want to...)
      │    ├── Explain this filter
      │    └── Filter history
      ├── IP
      │    ├── Match any IP address
      │    ├── Source IP only
      │    ├── Destination IP only
      │    └── ...
      ├── TCP
      │    ├── SYN — connection start
      │    ├── RST — connection reset
      │    ├── Retransmissions
      │    └── ...
      ├── DNS
      ├── HTTP
      ├── TLS
      ├── UDP
      ├── ARP
      ├── ICMP
      ├── QUIC
      ├── HTTP2
      ├── VLAN
      ├── VoIP
      └── Operators
```

---

## Features

### Categorised menu dropdown
70+ filters organised into 14 protocol categories. Click any entry to apply it immediately. Capture filters show a warning dialog (since they must be set before a capture starts) instead of silently applying.

### Guided troubleshooting
Six step-by-step walkthroughs for common problems:
- Why is my internet slow?
- Connection being refused or dropped?
- DNS not resolving?
- Who is this device talking to?
- Is there an ARP problem on the LAN?
- Debug an HTTPS / TLS connection

Each step auto-applies a filter and tells you exactly what to look for in the results.

### Filter explainer
Paste any Wireshark display filter string and get a plain-English breakdown of every token in it — useful when you inherit a capture file with filters you didn't write.

### Filter history
The last 10 filters you applied in the current session, with one-click re-apply buttons.

---

## Installation

1. Copy `filter_reference_menu.lua` to your Wireshark plugins folder:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Wireshark\plugins\` |
| macOS | `~/.local/lib/wireshark/plugins/` |
| Linux | `~/.local/lib/wireshark/plugins/` |

2. Restart Wireshark, or go to **Analyze → Reload Lua Plugins**
3. Open via **Tools → Filter Reference**

---

## Filter categories

| Category | What's covered |
|---|---|
| **IP** | Address matching, TTL, IPv4/IPv6, capture filters |
| **TCP** | Flags (SYN, RST, FIN, ACK), retransmissions, zero window, lost segments, stream follow |
| **UDP** | DNS, DHCP, NTP, mDNS, SNMP, large packets, bad checksums |
| **HTTP** | GET/POST, status codes (200, 3xx, 4xx/5xx), hostname filter, cleartext credentials |
| **DNS** | Queries, responses, NXDOMAIN, record types (A, AAAA, MX, TXT), errors |
| **TLS** | Handshake types, certificates, alerts, SNI hostname filter |
| **QUIC** | All QUIC, QUIC on port 443 (HTTP/3) |
| **HTTP2** | DATA frames, HEADERS frames, stream end |
| **ARP** | Requests, replies, duplicate IP detection, gratuitous ARP |
| **ICMP** | Ping, destination unreachable, port unreachable, TTL exceeded, redirects, ICMPv6 |
| **VLAN** | 802.1Q tagged frames, VLAN ID filter, QoS marking |
| **VoIP** | SIP INVITE/BYE, RTP audio/video, RTCP quality stats |
| **Operators** | AND/OR/NOT, payload search, regex, frame size, inter-packet gap, MAC address, broadcasts |

---

## Requirements

- Wireshark **3.0 or later** with Lua scripting enabled
- No external dependencies — pure Lua, uses only Wireshark's built-in API

---

## Compatibility

| Platform | Supported |
|---|---|
| Windows |
| macOS |
| Linux |

---

## Contributing

Pull requests are welcome. To add a new filter, add an entry to the `filters` table in `filter_reference_menu.lua`:

```lua
{ cat="CATEGORY", code="your.filter == value",
  name="Display name in the menu",
  type="display",   -- or "capture"
  desc="Plain-English description of what this filter does." },
```

The menu entry is registered automatically — no other changes needed.

---

## Acknowledgements

Built on Wireshark's Lua scripting API. Filter descriptions are written to be useful to both beginners learning packet analysis and experienced analysts who just want a quick reference.
