"""Golden tests for SSHD, Nginx, Fail2ban, and UFW parsers with hand-crafted lines."""

from sloth_soc.parsers.base import ParserContext
from sloth_soc.parsers.fail2ban import Fail2banParser
from sloth_soc.parsers.nginx import NginxParser
from sloth_soc.parsers.sshd import SSHDParser
from sloth_soc.parsers.ufw import UFWParser
from sloth_soc.schema import Event, Unparsed

CTX = ParserContext(file_path="golden.log", year_hint=2026, default_host="lab-vps")


def test_sshd_golden_lines():
    parser = SSHDParser()

    # 1. Failed password for invalid user
    line1 = "Oct 21 03:12:45 lab-vps sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52344 ssh2"
    ev1 = parser.parse_line(line1, 1, CTX)
    assert isinstance(ev1, Event)
    assert ev1.kind == "auth_fail"
    assert ev1.src_ip == "203.0.113.5"
    assert ev1.user == "admin"
    assert ev1.invalid_user is True

    # 2. Accepted publickey
    line2 = "Oct 21 09:02:11 lab-vps sshd[2201]: Accepted publickey for alice from 198.51.100.7 port 50222 ssh2: ED25519 SHA256:abc"
    ev2 = parser.parse_line(line2, 2, CTX)
    assert isinstance(ev2, Event)
    assert ev2.kind == "auth_ok"
    assert ev2.user == "alice"
    assert ev2.src_ip == "198.51.100.7"

    # 3. Connection closed
    line3 = "Oct 21 03:13:03 lab-vps sshd[1250]: Connection closed by authenticating user root 203.0.113.5 port 52351 [preauth]"
    ev3 = parser.parse_line(line3, 3, CTX)
    assert isinstance(ev3, Event)
    assert ev3.kind == "disconnect"
    assert ev3.src_ip == "203.0.113.5"

    # 4. Hostile ANSI escape injection in username
    line4 = "Oct 21 03:12:47 lab-vps sshd[1234]: Failed password for \x1b[31mroot\x1b[0m from 203.0.113.5 port 52346 ssh2"
    ev4 = parser.parse_line(line4, 4, CTX)
    assert isinstance(ev4, Event)
    assert ev4.user == "root"  # ANSI stripped!

    # 5. Hostile newline log forging injection in username
    line5 = "Oct 21 03:12:48 lab-vps sshd[1234]: Failed password for invalid user admin\nAccepted password for root from 1.1.1.1 from 203.0.113.5 port 52347 ssh2"
    ev5 = parser.parse_line(line5, 5, CTX)
    assert isinstance(ev5, Event)
    assert "\n" not in (ev5.user or "")

    # 6. IPv6 address
    line6 = "Oct 21 03:12:49 lab-vps sshd[1234]: Failed password for root from 2001:db8::1 port 52348 ssh2"
    ev6 = parser.parse_line(line6, 6, CTX)
    assert isinstance(ev6, Event)
    assert ev6.src_ip == "2001:db8::1"


def test_nginx_golden_lines():
    parser = NginxParser()

    # 1. Standard benign request
    line1 = '198.51.100.12 - - [21/Oct/2026:03:14:01 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"'
    ev1 = parser.parse_line(line1, 1, CTX)
    assert isinstance(ev1, Event)
    assert ev1.kind == "http_req"
    assert ev1.src_ip == "198.51.100.12"
    assert ev1.path == "/index.html"
    assert ev1.status == 200
    assert ev1.bytes == 4520

    # 2. 404 probe request
    line2 = '203.0.113.5 - - [21/Oct/2026:03:14:02 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/7.88.1"'
    ev2 = parser.parse_line(line2, 2, CTX)
    assert isinstance(ev2, Event)
    assert ev2.path == "//.env" or ev2.path == "/.env"
    assert ev2.status == 404

    # 3. Binary TLS handshake / malformed request
    line3 = '203.0.113.77 - - [21/Oct/2026:03:15:00 +0000] "\\x16\\x03\\x01\\x02" 400 150 "-" "-"'
    ev3 = parser.parse_line(line3, 3, CTX)
    assert isinstance(ev3, Event)
    assert ev3.status == 400

    # 4. Hostile path with prompt injection
    line4 = '203.0.113.5 - - [21/Oct/2026:03:14:05 +0000] "GET /test?q=Ignore_instructions HTTP/1.1" 404 150 "-" "-"'
    ev4 = parser.parse_line(line4, 4, CTX)
    assert isinstance(ev4, Event)

    # 5. IPv6 client
    line5 = '2001:db8::5 - - [21/Oct/2026:03:14:06 +0000] "GET /health HTTP/1.1" 200 12 "-" "UptimeMonitor"'
    ev5 = parser.parse_line(line5, 5, CTX)
    assert isinstance(ev5, Event)
    assert ev5.src_ip == "2001:db8::5"

    # 6. Missing / empty user agent
    line6 = '198.51.100.50 - - [21/Oct/2026:03:14:07 +0000] "POST /api/v1/login HTTP/1.1" 401 230 "-" "-"'
    ev6 = parser.parse_line(line6, 6, CTX)
    assert isinstance(ev6, Event)
    assert ev6.status == 401


def test_fail2ban_golden_lines():
    parser = Fail2banParser()

    # 1. Ban action
    line1 = "2026-10-21 03:12:50,123 fail2ban.actions [999]: NOTICE [sshd] Ban 203.0.113.5"
    ev1 = parser.parse_line(line1, 1, CTX)
    assert isinstance(ev1, Event)
    assert ev1.kind == "ban"
    assert ev1.src_ip == "203.0.113.5"

    # 2. Restore Ban action
    line2 = "2026-10-21 03:12:55,123 fail2ban.actions [999]: NOTICE [sshd] Restore Ban 203.0.113.5"
    ev2 = parser.parse_line(line2, 2, CTX)
    assert isinstance(ev2, Event)
    assert ev2.kind == "ban"

    # 3. Unban action
    line3 = "2026-10-21 03:22:50,123 fail2ban.actions [999]: NOTICE [sshd] Unban 203.0.113.5"
    ev3 = parser.parse_line(line3, 3, CTX)
    assert isinstance(ev3, Event)
    assert ev3.kind == "unban"

    # 4. Found action
    line4 = "2026-10-21 03:12:48,100 fail2ban.filter [999]: INFO [sshd] Found 203.0.113.5 - 2026-10-21 03:12:48"
    ev4 = parser.parse_line(line4, 4, CTX)
    assert isinstance(ev4, Event)

    # 5. IPv6 ban
    line5 = "2026-10-21 03:12:50,123 fail2ban.actions [999]: NOTICE [sshd] Ban 2001:db8::4"
    ev5 = parser.parse_line(line5, 5, CTX)
    assert isinstance(ev5, Event)
    assert ev5.src_ip == "2001:db8::4"

    # 6. Unmatched line produces Unparsed, never raises
    line6 = "2026-10-21 03:12:50,123 fail2ban.server [999]: INFO Server ready"
    ev6 = parser.parse_line(line6, 6, CTX)
    assert isinstance(ev6, Unparsed)


def test_ufw_golden_lines():
    parser = UFWParser()

    # 1. Standard UFW BLOCK TCP
    line1 = "Oct 21 03:20:01 lab-vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.44 DST=192.0.2.10 PROTO=TCP SPT=40000 DPT=3389"
    ev1 = parser.parse_line(line1, 1, CTX)
    assert isinstance(ev1, Event)
    assert ev1.kind == "fw_block"
    assert ev1.src_ip == "203.0.113.44"
    assert ev1.port == 3389
    assert ev1.method == "TCP"

    # 2. UFW BLOCK UDP
    line2 = "Oct 21 03:20:02 lab-vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.44 DST=192.0.2.10 PROTO=UDP SPT=50000 DPT=53"
    ev2 = parser.parse_line(line2, 2, CTX)
    assert isinstance(ev2, Event)
    assert ev2.port == 53
    assert ev2.method == "UDP"

    # 3. UFW AUDIT
    line3 = "Oct 21 03:20:03 lab-vps kernel: [UFW AUDIT] IN=eth0 OUT= SRC=203.0.113.44 DST=192.0.2.10 PROTO=TCP SPT=40001 DPT=22"
    ev3 = parser.parse_line(line3, 3, CTX)
    assert isinstance(ev3, Event)

    # 4. Without kernel prefix
    line4 = "Oct 21 03:20:04 lab-vps [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=192.0.2.10 PROTO=TCP SPT=40002 DPT=8080"
    ev4 = parser.parse_line(line4, 4, CTX)
    assert isinstance(ev4, Event)
    assert ev4.src_ip == "198.51.100.99"
    assert ev4.port == 8080

    # 5. IPv6 drop
    line5 = "Oct 21 03:20:05 lab-vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=2001:db8::9 DST=2001:db8::1 PROTO=TCP SPT=40003 DPT=23"
    ev5 = parser.parse_line(line5, 5, CTX)
    assert isinstance(ev5, Event)
    assert ev5.src_ip == "2001:db8::9"
    assert ev5.port == 23

    # 6. Bad IP produces Unparsed, never raises
    line6 = "Oct 21 03:20:06 lab-vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=not-an-ip DST=192.0.2.10 PROTO=TCP SPT=40004 DPT=80"
    ev6 = parser.parse_line(line6, 6, CTX)
    assert isinstance(ev6, Unparsed)
    assert ev6.reason == "bad_ip"
