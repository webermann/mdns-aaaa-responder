#!/usr/bin/env python3
"""Workaround for Fire OS devices that flood the LAN with mDNS AAAA queries for unicast-DNS names (*.fritz.box).

Background:
  Fire TV devices query names like 'fritz-boxoben.fritz.box' via mDNS. FRITZ!Box routers answer with the name
  'fritz-boxoben.local' instead, the Fire TV discards the non-matching answer and immediately re-queries without
  backoff (thousands of packets per second). An answer with the exactly matching name stops the loop.

This daemon listens for mDNS AAAA queries, resolves the queried name via regular unicast DNS (e.g. the FRITZ!Box)
and answers with the exact queried name, a long TTL and the cache-flush bit set.
Only names below the configured domains are answered, so normal '.local' mDNS traffic is not touched.

Standard library only, Python >= 3.9.
"""
import argparse
import logging
import random
import socket
import struct
import time

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
DNS_PORT = 53
TYPE_AAAA = 28
CLASS_IN = 0x0001
CLASS_IN_FLUSH = 0x8001
FLAG_RESPONSE = 0x8000
FLAG_RESPONSE_AA = 0x8400
FLAG_QUERY_RD = 0x0100

log = logging.getLogger("mdns-aaaa-responder")


# ----------------------------------------------------------------------------------------------------------------------
# DNS wire format helpers
# ----------------------------------------------------------------------------------------------------------------------
def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name (with compression) and return (name, offset after the name)."""
    labels = []
    end = None
    jumps = 0
    while True:
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if (end is None):
                end = offset + 2
            jumps += 1
            if (jumps > 32):
                raise ValueError("compression loop")
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if (length == 0):
            if (end is None):
                end = offset + 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode(errors="replace"))
        offset += 1 + length
    return ".".join(labels), end


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def aaaa_questions(data: bytes) -> list[str]:
    """Return all names asked for with type AAAA in an mDNS query (empty list for responses)."""
    if (len(data) < 12):
        return []
    _, flags, qdcount = struct.unpack("!HHH", data[:6])
    if (flags & FLAG_RESPONSE):
        return []
    names = []
    offset = 12
    for _ in range(qdcount):
        name, offset = parse_name(data, offset)
        qtype, _ = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        if (qtype == TYPE_AAAA):
            names.append(name)
    return names


def build_aaaa_response(name: str, addrs: list[str], ttl_s: int) -> bytes:
    """mDNS response with one AAAA record per address, all using the exact queried name."""
    enc = encode_name(name)
    header = struct.pack("!HHHHHH", 0, FLAG_RESPONSE_AA, 0, len(addrs), 0, 0)
    records = b""
    for i, addr in enumerate(addrs):
        # first record carries the full name, the following ones use a compression pointer to offset 12
        rr_name = enc if (i == 0) else b"\xc0\x0c"
        rdata = socket.inet_pton(socket.AF_INET6, addr)
        records += rr_name + struct.pack("!HHIH", TYPE_AAAA, CLASS_IN_FLUSH, ttl_s, len(rdata)) + rdata
    return header + records


def build_dns_query(name: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, FLAG_QUERY_RD, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", TYPE_AAAA, CLASS_IN)


def parse_dns_aaaa(data: bytes, qid: int) -> list[str]:
    """Extract all AAAA addresses from a unicast DNS response."""
    rid, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    if (rid != qid) or not (flags & FLAG_RESPONSE):
        return []
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4
    addrs = []
    for _ in range(ancount):
        _, offset = parse_name(data, offset)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if (rtype == TYPE_AAAA) and (rdlen == 16):
            addrs.append(socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16]))
        offset += rdlen
    return addrs


# ----------------------------------------------------------------------------------------------------------------------
# Unicast DNS resolver with cache
# ----------------------------------------------------------------------------------------------------------------------
class Resolver:
    def __init__(self, server: str, timeout_s: float, cache_s: float, neg_cache_s: float):
        self.server = server
        self.timeout_s = timeout_s
        self.cache_s = cache_s
        self.neg_cache_s = neg_cache_s
        self.cache: dict[str, tuple[float, list[str]]] = {}

    def lookup(self, name: str) -> list[str]:
        now = time.monotonic()
        hit = self.cache.get(name)
        if (hit is not None) and (now < hit[0]):
            return hit[1]
        addrs = self._query(name)
        self.cache[name] = (now + (self.cache_s if addrs else self.neg_cache_s), addrs)
        return addrs

    def _query(self, name: str) -> list[str]:
        qid = random.randint(0, 0xFFFF)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout_s)
            try:
                sock.sendto(build_dns_query(name, qid), (self.server, DNS_PORT))
                data, _ = sock.recvfrom(4096)
                return parse_dns_aaaa(data, qid)
            except (OSError, ValueError, IndexError, struct.error) as exc:
                log.warning("DNS lookup for %s failed: %s", name, exc)
                return []


# ----------------------------------------------------------------------------------------------------------------------
# mDNS daemon
# ----------------------------------------------------------------------------------------------------------------------
def open_mdns_socket(iface_ip: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", MDNS_PORT))
    mreq = struct.pack("4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton(iface_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    if (iface_ip != "0.0.0.0"):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
    return sock


def name_in_domains(name: str, domains: list[str]) -> bool:
    name = name.lower().rstrip(".")
    return any((name == dom) or name.endswith("." + dom) for dom in domains)


def run(args: argparse.Namespace) -> None:
    domains = [dom.lower().strip(".") for dom in args.domain]
    sources = set(args.source)
    resolver = Resolver(args.dns_server, args.dns_timeout, args.dns_cache, args.neg_cache)
    sock = open_mdns_socket(args.iface_ip)

    last_sent: dict[str, float] = {}
    sent_count: dict[str, int] = {}
    last_log: dict[str, float] = {}

    log.info("listening on %s:%d, domains=%s, dns=%s, ttl=%ds, sources=%s",
             MDNS_ADDR, MDNS_PORT, domains, args.dns_server, args.ttl, sorted(sources) or "any")

    while True:
        data, (src, _) = sock.recvfrom(9000)
        if sources and (src not in sources):
            continue
        try:
            names = aaaa_questions(data)
        except (ValueError, IndexError, struct.error):
            continue

        now = time.monotonic()
        for name in names:
            key = name.lower().rstrip(".")
            if not name_in_domains(key, domains):
                continue
            # rate limit per name, so we never amplify a storm
            if ((now - last_sent.get(key, 0.0)) < args.min_interval):
                continue
            last_sent[key] = now

            addrs = resolver.lookup(key)
            if not addrs:
                log.debug("%s asked AAAA %s, no AAAA in unicast DNS", src, name)
                continue
            sock.sendto(build_aaaa_response(name, addrs, args.ttl), (MDNS_ADDR, MDNS_PORT))

            # log at most once per minute per name with a counter, keeps the journal readable during a storm
            sent_count[key] = sent_count.get(key, 0) + 1
            if ((now - last_log.get(key, 0.0)) >= 60.0):
                log.info("%s asked AAAA %s -> answered %s (%d answers since last log)",
                         src, name, ", ".join(addrs), sent_count[key])
                sent_count[key] = 0
                last_log[key] = now


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dns-server", default="192.168.1.1", help="unicast DNS server (default: %(default)s)")
    parser.add_argument("--domain", action="append", default=None,
                        help="answer only names below this domain, repeatable (default: fritz.box)")
    parser.add_argument("--source", action="append", default=[],
                        help="only answer queries from this IPv4 address, repeatable (default: any)")
    parser.add_argument("--iface-ip", default="0.0.0.0", help="IPv4 of the LAN interface (default: kernel choice)")
    parser.add_argument("--ttl", type=int, default=3600, help="TTL of the answer in seconds (default: %(default)s)")
    parser.add_argument("--min-interval", type=float, default=1.0,
                        help="min. seconds between answers per name (default: %(default)s)")
    parser.add_argument("--dns-timeout", type=float, default=1.0, help="DNS timeout in s (default: %(default)s)")
    parser.add_argument("--dns-cache", type=float, default=300.0, help="DNS cache in s (default: %(default)s)")
    parser.add_argument("--neg-cache", type=float, default=60.0, help="negative DNS cache in s (default: %(default)s)")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    args = parser.parse_args()
    if (args.domain is None):
        args.domain = ["fritz.box"]

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    run(args)


if __name__ == "__main__":
    main()
