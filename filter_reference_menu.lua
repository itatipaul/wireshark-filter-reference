-- ============================================================
-- Wireshark Filter Reference Plugin  —  Menu Edition
-- Version: 3.0
--
-- What's new in v3.0:
--   * Every filter is now a nested menu entry under Tools,
--     giving you a true categorised dropdown:
--       Tools > Filter Reference > TCP > SYN — connection start
--   * Clicking any filter entry instantly applies it.
--   * Capture filters show a warning dialog instead of
--     silently applying (they must be set before capture).
--   * Guided troubleshooting, Explain this filter, and
--     Filter history are still available at the top of the menu.
--   * Filter history (last 10) is kept per session.
--
-- Installation:
--   1. Copy this file to your Wireshark plugins folder:
--        Windows : %APPDATA%\Wireshark\plugins\
--        macOS   : ~/.local/lib/wireshark/plugins/
--        Linux   : ~/.local/lib/wireshark/plugins/
--   2. Restart Wireshark  (or Analyze > Reload Lua Plugins)
--   3. Open via  Tools > Filter Reference > ...
-- ============================================================


-- ============================================================
-- SECTION 1 — FILTER DATA
-- ============================================================

local filters = {

  -- ── IP ────────────────────────────────────────────────────
  { cat="IP", code="ip.addr == X.X.X.X",
    name="Match any IP address",
    type="display",
    desc="Show ALL traffic to or from a specific IP. Replace X.X.X.X with the address you want." },

  { cat="IP", code="ip.src == X.X.X.X",
    name="Source IP only",
    type="display",
    desc="Show only packets SENT FROM a specific IP address." },

  { cat="IP", code="ip.dst == X.X.X.X",
    name="Destination IP only",
    type="display",
    desc="Show only packets going TO a specific IP address." },

  { cat="IP", code="!(ip.addr == X.X.X.X)",
    name="Exclude an IP",
    type="display",
    desc="HIDE all traffic to or from a specific IP." },

  { cat="IP", code="ip.ttl < 10",
    name="Low TTL (< 10)",
    type="display",
    desc="Packets close to expiring — useful for spotting routing loops or traceroute probes." },

  { cat="IP", code="ip.ttl == 1",
    name="TTL = 1 (traceroute)",
    type="display",
    desc="Packets that will expire at the very next hop. Traceroute sends these deliberately." },

  { cat="IP", code="ip.version == 6",
    name="IPv6 only",
    type="display",
    desc="Show only IPv6 traffic. Useful when troubleshooting dual-stack networks." },

  { cat="IP", code="ip.version == 4",
    name="IPv4 only",
    type="display",
    desc="Show only IPv4 traffic — the most common type." },

  { cat="IP", code="host X.X.X.X",
    name="Host — capture filter",
    type="capture",
    desc="CAPTURE FILTER: record only traffic to or from the specified host. Set before starting capture." },

  { cat="IP", code="net X.X.X.X/24",
    name="Subnet — capture filter",
    type="capture",
    desc="CAPTURE FILTER: record only traffic within a specific subnet, e.g. 192.168.1.0/24." },

  -- ── TCP ───────────────────────────────────────────────────
  { cat="TCP", code="tcp.port == 443",
    name="TCP port (e.g. 443)",
    type="display",
    desc="Traffic on a specific TCP port. Common: 80=HTTP, 443=HTTPS, 22=SSH, 3306=MySQL." },

  { cat="TCP", code="tcp.flags.syn == 1 && tcp.flags.ack == 0",
    name="SYN — connection start",
    type="display",
    desc="Pure SYN packets — a device is trying to open a new connection. High numbers may indicate a SYN flood." },

  { cat="TCP", code="tcp.flags.syn == 1 && tcp.flags.ack == 1",
    name="SYN-ACK — server reply",
    type="display",
    desc="SYN-ACK packets — the server accepting a connection. Part of the TCP three-way handshake." },

  { cat="TCP", code="tcp.flags.rst == 1",
    name="RST — connection reset",
    type="display",
    desc="TCP RST packets — a connection was abruptly refused or terminated. Can indicate a closed port or firewall block." },

  { cat="TCP", code="tcp.flags.fin == 1",
    name="FIN — graceful close",
    type="display",
    desc="TCP FIN packets — one side is politely closing the connection. Normal at the end of a session." },

  { cat="TCP", code="tcp.analysis.retransmission",
    name="Retransmissions",
    type="display",
    desc="Packets Wireshark detected as retransmissions — a sign of packet loss or network congestion." },

  { cat="TCP", code="tcp.analysis.duplicate_ack",
    name="Duplicate ACKs",
    type="display",
    desc="The receiver is sending the same ACK repeatedly — usually because packets arrived out of order." },

  { cat="TCP", code="tcp.analysis.zero_window",
    name="Zero window",
    type="display",
    desc="The receiver's buffer is full — it's telling the sender to stop. A sign of a slow application or bottleneck." },

  { cat="TCP", code="tcp.analysis.lost_segment",
    name="Lost segment",
    type="display",
    desc="Wireshark believes a segment was lost — a gap in the sequence numbers. Strong indicator of packet loss." },

  { cat="TCP", code="tcp.stream eq 0",
    name="Follow one stream (index 0)",
    type="display",
    desc="Isolate a single TCP conversation by its stream index. Change 0 to any stream index number." },

  { cat="TCP", code="tcp.analysis.flags",
    name="All TCP problems",
    type="display",
    desc="Any packet Wireshark flagged as having a TCP issue — great first filter for troubleshooting." },

  -- ── UDP ───────────────────────────────────────────────────
  { cat="UDP", code="udp",
    name="All UDP traffic",
    type="display",
    desc="Show all UDP traffic — DNS, streaming, gaming, VoIP, and anything that prioritises speed over reliability." },

  { cat="UDP", code="udp.port == 53",
    name="DNS (port 53)",
    type="display",
    desc="DNS traffic on port 53. Both queries and responses." },

  { cat="UDP", code="udp.port == 67 || udp.port == 68",
    name="DHCP traffic",
    type="display",
    desc="DHCP traffic — the protocol that assigns IP addresses. Useful for debugging 'no IP address' problems." },

  { cat="UDP", code="udp.port == 123",
    name="NTP — time sync",
    type="display",
    desc="Network Time Protocol on port 123. Used by devices to synchronise clocks." },

  { cat="UDP", code="udp.port == 5353",
    name="mDNS / Bonjour",
    type="display",
    desc="Multicast DNS on port 5353 — used by Apple Bonjour, Avahi, and Windows mDNS for device discovery." },

  { cat="UDP", code="udp.port == 161 || udp.port == 162",
    name="SNMP monitoring",
    type="display",
    desc="Simple Network Management Protocol — used to monitor routers, switches, and servers." },

  { cat="UDP", code="udp.length > 1000",
    name="Large UDP packets",
    type="display",
    desc="UDP packets with payloads over 1000 bytes — useful for spotting large transfers or fragmentation issues." },

  { cat="UDP", code="udp.checksum_bad == 1",
    name="Bad UDP checksum",
    type="display",
    desc="UDP packets with a failed checksum — may indicate data corruption or NIC checksum offloading issues." },

  -- ── HTTP ──────────────────────────────────────────────────
  { cat="HTTP", code="http",
    name="All HTTP traffic",
    type="display",
    desc="All unencrypted HTTP traffic, typically on port 80. HTTPS traffic won't appear here (it's under TLS)." },

  { cat="HTTP", code='http.request.method == "GET"',
    name="HTTP GET requests",
    type="display",
    desc="HTTP GET requests — the most common type, used when a browser fetches a page or resource." },

  { cat="HTTP", code='http.request.method == "POST"',
    name="HTTP POST requests",
    type="display",
    desc="HTTP POST requests — used to submit forms, upload files, or send data to an API." },

  { cat="HTTP", code="http.response.code == 200",
    name="HTTP 200 OK",
    type="display",
    desc="Successful HTTP responses — the server returned what was asked for." },

  { cat="HTTP", code="http.response.code >= 400",
    name="HTTP errors (4xx / 5xx)",
    type="display",
    desc="HTTP error responses. 4xx = client errors (404, 403), 5xx = server errors (500, 503)." },

  { cat="HTTP", code="http.response.code >= 300 && http.response.code < 400",
    name="HTTP redirects (3xx)",
    type="display",
    desc="HTTP redirects — the server is telling the client to go somewhere else. 301 = permanent, 302 = temporary." },

  { cat="HTTP", code='http.host contains "example.com"',
    name="Filter by hostname",
    type="display",
    desc="Show HTTP requests to a specific domain. Replace example.com with the hostname you want to watch." },

  { cat="HTTP", code='frame contains "password"',
    name="Cleartext credentials",
    type="display",
    desc="Find packets whose payload contains the word 'password'. Also try 'username', 'login', 'passwd'." },

  -- ── DNS ───────────────────────────────────────────────────
  { cat="DNS", code="dns",
    name="All DNS traffic",
    type="display",
    desc="All DNS traffic — both queries (questions) and responses (answers)." },

  { cat="DNS", code="dns.flags.response == 0",
    name="DNS queries only",
    type="display",
    desc="Only DNS questions (outgoing lookups). Your device is asking 'what is the IP of this domain?'" },

  { cat="DNS", code="dns.flags.response == 1",
    name="DNS responses only",
    type="display",
    desc="Only DNS answers (incoming). The server is replying with an IP address (or an error)." },

  { cat="DNS", code='dns.qry.name contains "google"',
    name="DNS queries for a domain",
    type="display",
    desc="DNS queries mentioning a specific word or domain. Replace 'google' with any domain you want to track." },

  { cat="DNS", code="dns.flags.rcode != 0",
    name="DNS errors (any)",
    type="display",
    desc="DNS responses with any non-zero return code — covers NXDOMAIN, SERVFAIL, REFUSED, and others." },

  { cat="DNS", code="dns.flags.rcode == 3",
    name="NXDOMAIN — domain not found",
    type="display",
    desc="NXDOMAIN responses — the domain does not exist. Useful for finding typos, misconfigs, or malware beaconing." },

  { cat="DNS", code="dns.qry.type == 1",
    name="A record lookups (IPv4)",
    type="display",
    desc="DNS queries for A records — converting a hostname to an IPv4 address. The most common DNS query type." },

  { cat="DNS", code="dns.qry.type == 28",
    name="AAAA record lookups (IPv6)",
    type="display",
    desc="DNS queries for AAAA records — converting a hostname to an IPv6 address." },

  { cat="DNS", code="dns.qry.type == 15",
    name="MX record lookups (mail)",
    type="display",
    desc="DNS queries for MX records — finding the mail server for a domain." },

  { cat="DNS", code="dns.qry.type == 16",
    name="TXT record lookups",
    type="display",
    desc="DNS queries for TXT records — used for SPF, DKIM, domain verification, and other metadata." },

  -- ── TLS ───────────────────────────────────────────────────
  { cat="TLS", code="tls",
    name="All TLS / SSL traffic",
    type="display",
    desc="All TLS encrypted traffic. The content is encrypted, but you can still analyse handshakes and metadata." },

  { cat="TLS", code="tls.handshake.type == 1",
    name="Client Hello",
    type="display",
    desc="The client is starting a TLS handshake — it sends a ClientHello listing the TLS versions and ciphers it supports." },

  { cat="TLS", code="tls.handshake.type == 2",
    name="Server Hello",
    type="display",
    desc="The server's response to a ClientHello — it picks a cipher suite and TLS version." },

  { cat="TLS", code="tls.handshake.type == 11",
    name="Certificate exchange",
    type="display",
    desc="The server is sending its TLS certificate during the handshake. Useful for inspecting certificate chains." },

  { cat="TLS", code="tls.record.content_type == 21",
    name="TLS alerts",
    type="display",
    desc="TLS alert messages — certificate rejection, handshake failure, or decryption errors." },

  { cat="TLS", code='tls.handshake.extensions_server_name contains "example.com"',
    name="SNI — filter by hostname",
    type="display",
    desc="Filter TLS traffic by the SNI field — the target hostname, visible even in encrypted traffic. Replace example.com." },

  -- ── QUIC ──────────────────────────────────────────────────
  { cat="QUIC", code="quic",
    name="All QUIC traffic",
    type="display",
    desc="All QUIC traffic — the UDP-based transport used by HTTP/3 and modern Google services. Encrypted by design." },

  { cat="QUIC", code="quic && udp.port == 443",
    name="QUIC on port 443",
    type="display",
    desc="QUIC traffic on port 443 — the standard port for HTTPS over QUIC / HTTP/3." },

  -- ── HTTP/2 ────────────────────────────────────────────────
  { cat="HTTP2", code="http2",
    name="All HTTP/2 traffic",
    type="display",
    desc="All HTTP/2 traffic. HTTP/2 runs over TLS and multiplexes multiple requests over a single connection." },

  { cat="HTTP2", code="http2.type == 0",
    name="HTTP/2 DATA frames",
    type="display",
    desc="HTTP/2 DATA frames — the actual content being transferred (HTML, JSON, images, etc.)." },

  { cat="HTTP2", code="http2.type == 1",
    name="HTTP/2 HEADERS frames",
    type="display",
    desc="HTTP/2 HEADERS frames — request and response headers, including method, path, and status code." },

  { cat="HTTP2", code="http2.flags.end_stream == 1",
    name="HTTP/2 stream end",
    type="display",
    desc="HTTP/2 frames that mark the end of a stream (request or response complete)." },

  -- ── ARP ───────────────────────────────────────────────────
  { cat="ARP", code="arp",
    name="All ARP traffic",
    type="display",
    desc="All ARP traffic — ARP maps IP addresses to MAC addresses on a local network. Normal on any LAN." },

  { cat="ARP", code="arp.opcode == 1",
    name="ARP requests",
    type="display",
    desc="ARP 'Who has this IP?' questions. A device is looking up the MAC address of another device." },

  { cat="ARP", code="arp.opcode == 2",
    name="ARP replies",
    type="display",
    desc="ARP replies — 'That IP belongs to this MAC address'." },

  { cat="ARP", code="arp.duplicate-address-detected",
    name="Duplicate IP detected",
    type="display",
    desc="Wireshark spotted two devices claiming the same IP. A sign of ARP spoofing or a static IP conflict." },

  { cat="ARP", code="arp.src.proto_ipv4 == 0.0.0.0",
    name="Gratuitous ARP probe",
    type="display",
    desc="ARP probes from 0.0.0.0 — sent by devices when they first connect to check if their IP is already in use." },

  -- ── ICMP ──────────────────────────────────────────────────
  { cat="ICMP", code="icmp",
    name="All ICMP traffic",
    type="display",
    desc="All ICMP traffic — pings, traceroute probes, and network error messages." },

  { cat="ICMP", code="icmp.type == 8",
    name="Ping requests",
    type="display",
    desc="ICMP echo requests — outgoing pings. Checking whether a host is reachable." },

  { cat="ICMP", code="icmp.type == 0",
    name="Ping replies",
    type="display",
    desc="ICMP echo replies — the response to a ping. The remote host confirms it is reachable." },

  { cat="ICMP", code="icmp.type == 3",
    name="Destination unreachable",
    type="display",
    desc="ICMP 'destination unreachable' — the target host, port, or network could not be reached." },

  { cat="ICMP", code="icmp.type == 3 && icmp.code == 3",
    name="Port unreachable",
    type="display",
    desc="A UDP packet arrived at a port with no listener. The OS sent back this ICMP error." },

  { cat="ICMP", code="icmp.type == 11",
    name="TTL exceeded (traceroute)",
    type="display",
    desc="A packet's TTL hit zero and was dropped by a router. This is the mechanism traceroute relies on." },

  { cat="ICMP", code="icmp.type == 5",
    name="ICMP redirect",
    type="display",
    desc="A router is telling a host to use a different gateway. Can be legitimate or a sign of a routing attack." },

  { cat="ICMP", code="icmpv6",
    name="All ICMPv6 traffic",
    type="display",
    desc="All ICMPv6 — the IPv6 equivalent of ICMP. Includes neighbour discovery, router advertisements, and ping6." },

  { cat="ICMP", code="icmpv6.type == 135",
    name="Neighbour solicitation (IPv6)",
    type="display",
    desc="IPv6 Neighbour Solicitation — the IPv6 equivalent of an ARP request." },

  { cat="ICMP", code="icmpv6.type == 134",
    name="Router advertisement (IPv6)",
    type="display",
    desc="IPv6 Router Advertisements — routers announcing themselves and providing gateway and prefix info." },

  -- ── VLAN ──────────────────────────────────────────────────
  { cat="VLAN", code="vlan",
    name="All VLAN traffic",
    type="display",
    desc="Show all 802.1Q VLAN-tagged frames. Useful on trunk ports or when analysing segmented networks." },

  { cat="VLAN", code="vlan.id == 10",
    name="Filter by VLAN ID",
    type="display",
    desc="Show traffic on a specific VLAN. Replace 10 with your VLAN number." },

  { cat="VLAN", code="vlan.priority > 0",
    name="VLAN QoS marked",
    type="display",
    desc="VLAN frames with a non-zero priority (QoS marking) — useful for checking voice/video traffic prioritisation." },

  -- ── VoIP / SIP ────────────────────────────────────────────
  { cat="VoIP", code="sip",
    name="All SIP traffic",
    type="display",
    desc="All SIP traffic — used to set up, manage, and tear down voice and video calls." },

  { cat="VoIP", code='sip.Method == "INVITE"',
    name="SIP INVITE — call start",
    type="display",
    desc="SIP INVITE messages — someone is initiating a call. The first message in a VoIP call setup." },

  { cat="VoIP", code='sip.Method == "BYE"',
    name="SIP BYE — call end",
    type="display",
    desc="SIP BYE messages — a party is ending an active call." },

  { cat="VoIP", code="rtp",
    name="All RTP (audio / video)",
    type="display",
    desc="Real-time Transport Protocol — carries the actual voice or video data during a call." },

  { cat="VoIP", code="rtcp",
    name="RTCP — call quality stats",
    type="display",
    desc="RTP Control Protocol — carries quality statistics about an active RTP stream (jitter, packet loss, delay)." },

  -- ── Operators & Techniques ────────────────────────────────
  { cat="Operators", code="ip.addr == X.X.X.X && tcp.port == 80",
    name="AND (&&) — combine conditions",
    type="display",
    desc="Both conditions must be true. This example shows HTTP traffic from a specific IP." },

  { cat="Operators", code="http || dns",
    name="OR (||) — either matches",
    type="display",
    desc="Either condition can match. This shows HTTP or DNS traffic." },

  { cat="Operators", code="!arp",
    name="NOT (!) — exclude traffic",
    type="display",
    desc="Exclude matching traffic. Put ! in front of any filter to hide that type." },

  { cat="Operators", code="!(arp or icmp or dns)",
    name="Hide background noise",
    type="display",
    desc="Hide the most common background chatter — ARP, ping, and DNS — so you can focus on what matters." },

  { cat="Operators", code='frame contains "password"',
    name="Payload keyword search",
    type="display",
    desc="Search the raw packet payload for any string. Case-sensitive. Change 'password' to any keyword." },

  { cat="Operators", code='tcp matches "(?i)password"',
    name="Regex search (case-insensitive)",
    type="display",
    desc="Use a regular expression to search packet content. (?i) makes it case-insensitive." },

  { cat="Operators", code="frame.len > 1400",
    name="Large frames (> 1400 bytes)",
    type="display",
    desc="Packets larger than 1400 bytes — useful for spotting jumbo frames or packets close to the MTU limit." },

  { cat="Operators", code="frame.time_delta > 1",
    name="Slow inter-packet gap (> 1 s)",
    type="display",
    desc="Packets where more than 1 second elapsed since the previous packet — useful for finding latency spikes." },

  { cat="Operators", code="eth.dst == ff:ff:ff:ff:ff:ff",
    name="Ethernet broadcasts",
    type="display",
    desc="All Ethernet broadcast frames — sent to every device on the segment. High rates can indicate a storm." },

  { cat="Operators", code="eth.addr == XX:XX:XX:XX:XX:XX",
    name="Filter by MAC address",
    type="display",
    desc="Show traffic to or from a specific MAC address. Replace XX:XX:XX:XX:XX:XX with the MAC you want." },

  { cat="Operators", code="frame.number == 1",
    name="Jump to frame number",
    type="display",
    desc="Show a specific frame by its number. Change 1 to any frame number in your capture." },

}


-- ============================================================
-- SECTION 2 — GUIDED SCENARIOS  (unchanged from v2.0)
-- ============================================================

local scenarios = {

  {
    name = "Why is my internet slow?",
    desc = "Step through filters to find retransmissions, zero windows, and congestion.",
    steps = {
      { label="1. All TCP problems",  code="tcp.analysis.flags",          hint="Look for red/yellow rows — these are Wireshark's expert alerts. Lots of them = congestion." },
      { label="2. Retransmissions",   code="tcp.analysis.retransmission", hint="Retransmits mean data had to be re-sent. Many = packet loss on the path." },
      { label="3. Zero windows",      code="tcp.analysis.zero_window",    hint="Zero window = receiver is overwhelmed. Could be slow disk, slow app, or overloaded server." },
      { label="4. Slow packet gaps",  code="frame.time_delta > 0.5",      hint="Large gaps between packets = latency. Right-click > Follow TCP Stream to see the full conversation." },
    }
  },

  {
    name = "Connection being refused or dropped?",
    desc = "Find RST packets and diagnose why connections are failing.",
    steps = {
      { label="1. All RST packets",   code="tcp.flags.rst == 1",                          hint="RST = abrupt close. Could be a firewall, closed port, or crashing service." },
      { label="2. Connection starts", code="tcp.flags.syn == 1 && tcp.flags.ack == 0",    hint="See which connections are being attempted." },
      { label="3. No SYN-ACK reply?", code="tcp.flags.syn == 1",                          hint="If you see SYN but no SYN-ACK, the server isn't responding — check firewall rules." },
      { label="4. ICMP unreachable",  code="icmp.type == 3",                              hint="Unreachable messages tell you WHY packets couldn't get through." },
    }
  },

  {
    name = "DNS not resolving?",
    desc = "Verify DNS queries are leaving your machine and answers are returning.",
    steps = {
      { label="1. All DNS traffic",   code="dns",                     hint="Do you see ANY DNS traffic? If not, DNS isn't reaching the network." },
      { label="2. Queries only",      code="dns.flags.response == 0", hint="Are your queries going out? Check qry.name for correct domain names." },
      { label="3. Responses only",    code="dns.flags.response == 1", hint="Are answers coming back? Check dns.a for the returned IP." },
      { label="4. DNS errors",        code="dns.flags.rcode != 0",    hint="Non-zero rcode = error. rcode 3 = NXDOMAIN. rcode 2 = SERVFAIL." },
    }
  },

  {
    name = "Who is this device talking to?",
    desc = "Pick out one IP and see everything it is doing.",
    steps = {
      { label="1. All traffic from IP", code="ip.src == X.X.X.X",        hint="Replace X.X.X.X. See all outgoing connections from this device." },
      { label="2. All traffic to IP",   code="ip.dst == X.X.X.X",        hint="See what is being sent TO this device." },
      { label="3. Both directions",     code="ip.addr == X.X.X.X",       hint="See all traffic in either direction — the full picture." },
      { label="4. DNS lookups it made", code="ip.src == X.X.X.X && dns", hint="What domains is this device resolving? Suspicious names stand out." },
    }
  },

  {
    name = "Is there an ARP problem on the LAN?",
    desc = "Check for IP conflicts, spoofing, or DHCP issues.",
    steps = {
      { label="1. All ARP",         code="arp",                               hint="Get a baseline — how much ARP traffic is there? A little is normal." },
      { label="2. ARP requests",    code="arp.opcode == 1",                   hint="Who is asking for what? High rates from one device can mean a misconfiguration." },
      { label="3. Duplicate IPs",   code="arp.duplicate-address-detected",    hint="Any results here = IP conflict. Two devices claiming the same address." },
      { label="4. DHCP traffic",    code="udp.port == 67 || udp.port == 68", hint="Check DHCP is assigning addresses correctly — look for DISCOVER, OFFER, REQUEST, ACK." },
    }
  },

  {
    name = "Debug an HTTPS / TLS connection",
    desc = "Inspect the TLS handshake even though the payload is encrypted.",
    steps = {
      { label="1. All TLS",       code="tls",                         hint="Get a feel for how much TLS traffic there is." },
      { label="2. Client Hello",  code="tls.handshake.type == 1",     hint="The client is offering its supported TLS versions and ciphers." },
      { label="3. Server Hello",  code="tls.handshake.type == 2",     hint="The server picks a cipher. If missing, the handshake failed early." },
      { label="4. TLS alerts",    code="tls.record.content_type == 21", hint="Alert packets = something went wrong. Expand the TLS layer to see the alert description." },
    }
  },

}


-- ============================================================
-- SECTION 3 — TOKEN EXPLANATIONS  (for "Explain this filter")
-- ============================================================

local token_explanations = {
  ["ip.addr"]                               = "any IP address (source or destination)",
  ["ip.src"]                                = "source IP address (who sent it)",
  ["ip.dst"]                                = "destination IP address (who it's going to)",
  ["ip.ttl"]                                = "IP Time-To-Live (how many hops remain)",
  ["ip.version"]                            = "IP version (4 = IPv4, 6 = IPv6)",
  ["tcp"]                                   = "TCP protocol",
  ["tcp.port"]                              = "TCP port (source or destination)",
  ["tcp.srcport"]                           = "TCP source port",
  ["tcp.dstport"]                           = "TCP destination port",
  ["tcp.flags.syn"]                         = "TCP SYN flag (connection start)",
  ["tcp.flags.ack"]                         = "TCP ACK flag (acknowledgement)",
  ["tcp.flags.rst"]                         = "TCP RST flag (connection reset/refused)",
  ["tcp.flags.fin"]                         = "TCP FIN flag (graceful close)",
  ["tcp.flags.push"]                        = "TCP PSH flag (push data now)",
  ["tcp.analysis.retransmission"]           = "Wireshark detected a retransmission (packet loss)",
  ["tcp.analysis.zero_window"]              = "TCP zero window (receiver buffer full)",
  ["tcp.analysis.duplicate_ack"]            = "duplicate ACK (out-of-order or lost packet)",
  ["tcp.analysis.lost_segment"]             = "lost segment (gap in sequence numbers)",
  ["tcp.analysis.flags"]                    = "any Wireshark TCP expert flag (problems detected)",
  ["tcp.stream"]                            = "TCP stream index (identifies one conversation)",
  ["udp"]                                   = "UDP protocol",
  ["udp.port"]                              = "UDP port (source or destination)",
  ["udp.length"]                            = "UDP datagram length in bytes",
  ["udp.checksum_bad"]                      = "bad UDP checksum (possible corruption)",
  ["http"]                                  = "HTTP protocol (unencrypted web traffic)",
  ["http.request.method"]                   = "HTTP request method (GET, POST, etc.)",
  ["http.response.code"]                    = "HTTP response status code (200, 404, 500, etc.)",
  ["http.host"]                             = "HTTP Host header (which website was requested)",
  ["dns"]                                   = "DNS protocol (domain name lookups)",
  ["dns.qry.name"]                          = "DNS query name (the domain being looked up)",
  ["dns.flags.response"]                    = "DNS message type (0 = query, 1 = response)",
  ["dns.flags.rcode"]                       = "DNS response code (0 = ok, 3 = NXDOMAIN, etc.)",
  ["dns.qry.type"]                          = "DNS record type (1=A, 28=AAAA, 15=MX, 16=TXT)",
  ["tls"]                                   = "TLS/SSL encrypted traffic",
  ["tls.handshake.type"]                    = "TLS handshake message type (1=ClientHello, 2=ServerHello, 11=Certificate)",
  ["tls.record.content_type"]               = "TLS record type (21=Alert, 22=Handshake, 23=ApplicationData)",
  ["tls.handshake.extensions_server_name"]  = "TLS SNI extension (target hostname, visible even in encrypted traffic)",
  ["arp"]                                   = "ARP protocol (maps IP addresses to MAC addresses)",
  ["arp.opcode"]                            = "ARP operation (1 = request, 2 = reply)",
  ["arp.duplicate-address-detected"]        = "Wireshark detected a duplicate IP address on the network",
  ["icmp"]                                  = "ICMP protocol (ping and network error messages)",
  ["icmp.type"]                             = "ICMP message type (8=ping request, 0=ping reply, 3=unreachable, 11=TTL exceeded)",
  ["icmp.code"]                             = "ICMP sub-code (detail within the type, e.g. code 3 = port unreachable)",
  ["icmpv6"]                                = "ICMPv6 (IPv6 control messages including neighbour discovery)",
  ["icmpv6.type"]                           = "ICMPv6 message type (134=Router Advertisement, 135=Neighbour Solicitation)",
  ["frame"]                                 = "any frame / raw packet",
  ["frame.len"]                             = "total frame length in bytes",
  ["frame.time_delta"]                      = "time since previous packet (seconds)",
  ["frame.number"]                          = "frame number in the capture file",
  ["frame contains"]                        = "search the raw payload for a text string",
  ["eth.addr"]                              = "Ethernet MAC address (source or destination)",
  ["eth.src"]                               = "source MAC address",
  ["eth.dst"]                               = "destination MAC address",
  ["eth.dst == ff:ff:ff:ff:ff:ff"]          = "Ethernet broadcast (sent to all devices)",
  ["vlan"]                                  = "802.1Q VLAN-tagged frame",
  ["vlan.id"]                               = "VLAN ID number",
  ["quic"]                                  = "QUIC protocol (UDP-based, used by HTTP/3)",
  ["http2"]                                 = "HTTP/2 protocol",
  ["sip"]                                   = "SIP protocol (VoIP call setup)",
  ["rtp"]                                   = "RTP protocol (real-time audio/video stream)",
  ["rtcp"]                                  = "RTCP protocol (RTP quality control statistics)",
  ["&&"]                                    = "AND — both conditions must be true",
  ["||"]                                    = "OR — either condition can be true",
  ["!"]                                     = "NOT — exclude / hide matching packets",
  ["=="]                                    = "equals",
  ["!="]                                    = "does not equal",
  [">="]                                    = "greater than or equal to",
  ["<="]                                    = "less than or equal to",
  [">"]                                     = "greater than",
  ["<"]                                     = "less than",
  ["contains"]                              = "payload contains this text string",
  ["matches"]                               = "payload matches this regular expression",
  ["eq"]                                    = "equals (alternative syntax)",
}


-- ============================================================
-- SECTION 4 — HELPERS
-- ============================================================

local filter_history = {}

local function add_to_history(code)
  for i, v in ipairs(filter_history) do
    if v == code then table.remove(filter_history, i); break end
  end
  table.insert(filter_history, 1, code)
  if #filter_history > 10 then table.remove(filter_history) end
end

local function apply_display_filter(code)
  add_to_history(code)
  set_filter(code)
  apply_filter()
end

local function show_capture_warning(name, code)
  local win = TextWindow.new("Capture filter — read me first")
  win:set(string.format(
    "  '%s' is a CAPTURE filter.\n\n"
    .. "  IMPORTANT: capture filters are set BEFORE you start\n"
    .. "  recording. They cannot be applied to an existing capture file.\n\n"
    .. "  To use it:\n"
    .. "    1. Go to  Capture > Options\n"
    .. "    2. Paste this into the Capture Filter box:\n\n"
    .. "         %s\n\n"
    .. "    3. Start a new capture.\n\n"
    .. "  Display filters (the majority of entries) work on open captures.",
    name, code))
end

-- Plain-English explainer for a filter string
local function explain_filter(code)
  if not code or code == "" then
    return "  (nothing to explain — enter a filter string above)"
  end
  local lines = {}
  lines[#lines+1] = "  Filter : " .. code
  lines[#lines+1] = ""
  lines[#lines+1] = "  Plain-English breakdown:"
  lines[#lines+1] = ""

  local sorted_tokens = {}
  for k in pairs(token_explanations) do sorted_tokens[#sorted_tokens+1] = k end
  table.sort(sorted_tokens, function(a, b) return #a > #b end)

  local matched = {}
  local lower_code = code:lower()
  for _, token in ipairs(sorted_tokens) do
    if lower_code:find(token:lower(), 1, true) then
      matched[#matched+1] = { token = token, explanation = token_explanations[token] }
    end
  end

  if #matched == 0 then
    lines[#lines+1] = "  No known tokens recognised. Try a simpler filter or check the spelling."
  else
    for _, m in ipairs(matched) do
      lines[#lines+1] = string.format("  %-44s  =>  %s", m.token, m.explanation)
    end
  end

  lines[#lines+1] = ""
  lines[#lines+1] = "  Note: display filters are case-sensitive for string values."
  lines[#lines+1] = "  Combine with && (AND), || (OR), or ! (NOT) to build complex filters."
  return table.concat(lines, "\n")
end


-- ============================================================
-- SECTION 5 — GUIDED SCENARIO WINDOW  (unchanged from v2.0)
-- ============================================================

local function open_scenarios()
  local win           = TextWindow.new("Wireshark — I want to...")
  local current_scene = nil
  local current_step  = 0

  local function render_menu()
    local lines = {}
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = "  GUIDED TROUBLESHOOTING — pick a goal below"
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = ""
    for i, s in ipairs(scenarios) do
      lines[#lines+1] = string.format("  [%d]  %s", i, s.name)
      lines[#lines+1] = string.format("       %s", s.desc)
      lines[#lines+1] = ""
    end
    lines[#lines+1] = "  Use the numbered buttons below to pick a scenario."
    lines[#lines+1] = "========================================================"
    win:set(table.concat(lines, "\n"))
  end

  local function render_scenario()
    local s = current_scene
    local lines = {}
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = "  " .. s.name
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = ""
    for i, step in ipairs(s.steps) do
      local marker = (i == current_step) and "  >>> " or "      "
      lines[#lines+1] = marker .. step.label
      lines[#lines+1] = "          Filter : " .. step.code
      if i == current_step then
        lines[#lines+1] = ""
        lines[#lines+1] = "  APPLIED ^^"
        lines[#lines+1] = ""
        lines[#lines+1] = "  What to look for:"
        lines[#lines+1] = "  " .. step.hint
      end
      lines[#lines+1] = ""
    end
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = "  Use  << Back  /  Next step >>  to work through this."
    lines[#lines+1] = "  Use  Back to menu  to pick a different scenario."
    lines[#lines+1] = "========================================================"
    win:set(table.concat(lines, "\n"))
  end

  local function apply_step(n)
    if current_scene and n >= 1 and n <= #current_scene.steps then
      current_step = n
      apply_display_filter(current_scene.steps[n].code)
      render_scenario()
    end
  end

  for i = 1, math.min(#scenarios, 6) do
    local idx = i
    win:add_button(string.format("%d", idx), function()
      current_scene = scenarios[idx]
      current_step  = 1
      apply_display_filter(current_scene.steps[1].code)
      render_scenario()
    end)
  end

  win:add_button("<< Back", function()
    if current_scene and current_step > 1 then apply_step(current_step - 1) end
  end)

  win:add_button("Next step >>", function()
    if current_scene and current_step < #current_scene.steps then apply_step(current_step + 1) end
  end)

  win:add_button("Back to menu", function()
    current_scene = nil
    current_step  = 0
    render_menu()
  end)

  win:add_button("Clear filter", function()
    set_filter("") ; apply_filter()
  end)

  render_menu()
end


-- ============================================================
-- SECTION 6 — EXPLAIN THIS FILTER WINDOW  (unchanged from v2.0)
-- ============================================================

local function open_explainer()
  local win        = TextWindow.new("Wireshark — Explain this filter")
  local last_input = ""

  local function render(explanation)
    local lines = {}
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = "  FILTER EXPLAINER"
    lines[#lines+1] = "  Paste any Wireshark display filter to get a"
    lines[#lines+1] = "  plain-English breakdown of what it does."
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = ""
    if explanation then
      lines[#lines+1] = explanation
    else
      lines[#lines+1] = "  Click  'Enter filter...'  to paste or type a filter."
      lines[#lines+1] = ""
      lines[#lines+1] = "  Examples to try:"
      lines[#lines+1] = "    tcp.flags.syn == 1 && ip.src == 192.168.1.5"
      lines[#lines+1] = "    http.response.code >= 400"
      lines[#lines+1] = "    !(arp or icmp or dns)"
      lines[#lines+1] = "    dns.flags.rcode == 3"
    end
    lines[#lines+1] = ""
    lines[#lines+1] = "========================================================"
    win:set(table.concat(lines, "\n"))
  end

  win:add_button("Enter filter...", function()
    local input = gui_edit_dialog and
                  gui_edit_dialog("Explain this filter",
                    "Paste or type a Wireshark display filter:", last_input)
    if input ~= nil then
      last_input = input
      render(explain_filter(input))
    end
  end)

  win:add_button("Also apply it", function()
    if last_input and last_input ~= "" then
      apply_display_filter(last_input)
    end
  end)

  win:add_button("Clear", function()
    last_input = ""
    render(nil)
  end)

  render(nil)
end


-- ============================================================
-- SECTION 7 — HISTORY WINDOW  (unchanged from v2.0)
-- ============================================================

local function open_history()
  local win = TextWindow.new("Wireshark — Filter History")
  local hist_page_results = {}

  local function render()
    local lines = {}
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = "  FILTER HISTORY  (last 10 applied this session)"
    lines[#lines+1] = "========================================================"
    lines[#lines+1] = ""
    hist_page_results = {}
    if #filter_history == 0 then
      lines[#lines+1] = "  No filters applied yet this session."
    else
      for i, code in ipairs(filter_history) do
        hist_page_results[i] = code
        lines[#lines+1] = string.format("  [%d]  %s", i, code)
      end
    end
    lines[#lines+1] = ""
    lines[#lines+1] = "  Use Re-apply 1-10 to apply a previous filter again."
    lines[#lines+1] = "========================================================"
    win:set(table.concat(lines, "\n"))
  end

  for n = 1, 10 do
    local idx = n
    win:add_button(string.format("Re-apply %d", idx), function()
      local code = hist_page_results[idx]
      if code then apply_display_filter(code) ; render() end
    end)
  end

  win:add_button("Clear history", function()
    filter_history = {}
    render()
  end)

  render()
end


-- ============================================================
-- SECTION 8 — REGISTER ALL MENU ENTRIES
--
-- Structure:
--   Tools
--    └── Filter Reference
--         ├── 🔍 Guided troubleshooting (I want to...)
--         ├── 💬 Explain this filter
--         ├── 📋 Filter history
--         ├── ── (separator via naming convention) ──
--         ├── IP
--         │    ├── Match any IP address
--         │    └── ...
--         ├── TCP
--         │    └── ...
--         └── ...
-- ============================================================

-- Utility tools at the top
register_menu("Filter Reference/\xE2\x80\x94 Tools \xE2\x80\x94/Guided troubleshooting (I want to...)", open_scenarios,  MENU_TOOLS_UNSORTED)
register_menu("Filter Reference/\xE2\x80\x94 Tools \xE2\x80\x94/Explain this filter",                  open_explainer,  MENU_TOOLS_UNSORTED)
register_menu("Filter Reference/\xE2\x80\x94 Tools \xE2\x80\x94/Filter history",                       open_history,    MENU_TOOLS_UNSORTED)

-- One menu entry per filter, nested under its category
for _, f in ipairs(filters) do
  local entry_name = f.name
  -- Mark capture filters so users know before clicking
  if f.type == "capture" then
    entry_name = entry_name .. "  [CAPTURE]"
  end

  local menu_path = string.format("Filter Reference/%s/%s", f.cat, entry_name)
  local filter    = f   -- capture loop variable for closure

  register_menu(menu_path, function()
    if filter.type == "capture" then
      show_capture_warning(filter.name, filter.code)
    else
      apply_display_filter(filter.code)
    end
  end, MENU_TOOLS_UNSORTED)
end
