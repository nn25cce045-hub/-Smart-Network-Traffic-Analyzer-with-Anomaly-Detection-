"""Tests for safe packet field extraction and classification."""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from capture.packet_parser import parse_packet


def test_parses_tcp_packet_fields():
    packet = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=51515, dport=443)
    result = parse_packet(packet, captured_at=1_700_000_000)

    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "93.184.216.34"
    assert result["source_port"] == 51515
    assert result["destination_port"] == 443
    assert result["transport_protocol"] == "TCP"
    assert result["tcp_flags"] == "S"
    assert result["protocol"] == "TCP"
    assert result["size"] == len(packet)


def test_dns_takes_precedence_over_udp():
    packet = IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(qd=DNSQR(qname="example.com"))
    result = parse_packet(packet, captured_at=1_700_000_000)

    assert result["transport_protocol"] == "UDP"
    assert result["protocol"] == "DNS"


def test_identifies_clear_text_http_payload():
    packet = IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=50100, dport=9000) / Raw(b"GET /status HTTP/1.1\r\n\r\n")
    result = parse_packet(packet, captured_at=1_700_000_000)

    assert result["protocol"] == "HTTP"


def test_parses_icmp_without_assuming_ports():
    result = parse_packet(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), captured_at=1_700_000_000)

    assert result["protocol"] == "ICMP"
    assert result["source_port"] is None
    assert result["destination_port"] is None


def test_supports_ipv6_and_non_ip_packets():
    ipv6 = parse_packet(IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=10, dport=11), captured_at=1_700_000_000)
    ethernet = parse_packet(Ether(), captured_at=1_700_000_000)

    assert ipv6["source_ip"] == "2001:db8::1"
    assert ipv6["protocol"] == "UDP"
    assert ethernet["source_ip"] is None
    assert ethernet["protocol"] == "Other"
