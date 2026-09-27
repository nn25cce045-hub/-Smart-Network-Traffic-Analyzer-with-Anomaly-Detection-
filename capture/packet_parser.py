"""Convert Scapy packets into small, JSON-friendly records."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw


HTTP_PORTS = {80, 8000, 8080, 8888}
HTTP_PREFIXES = (
    b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ",
    b"OPTIONS ", b"HTTP/",
)


def _is_http(packet: Any, source_port: int | None, destination_port: int | None) -> bool:
    """Identify clear-text HTTP by its common ports or payload signature."""
    if source_port in HTTP_PORTS or destination_port in HTTP_PORTS:
        return True
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load).lstrip()
            return payload.startswith(HTTP_PREFIXES)
        except (AttributeError, TypeError, ValueError):
            return False
    return False


def parse_packet(packet: Any, captured_at: float | None = None) -> dict[str, Any]:
    """Safely extract the fields used by the web interface.

    Missing IP addresses and ports are represented by ``None``. Classification is
    intentionally conservative: DNS and clear-text HTTP take precedence over the
    underlying TCP/UDP transport protocol.
    """
    timestamp = captured_at
    if timestamp is None:
        try:
            timestamp = float(packet.time)
        except (AttributeError, TypeError, ValueError):
            timestamp = datetime.now().timestamp()

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None
    transport_protocol = "Other"

    try:
        if packet.haslayer(IP):
            source_ip = str(packet[IP].src)
            destination_ip = str(packet[IP].dst)
        elif packet.haslayer(IPv6):
            source_ip = str(packet[IPv6].src)
            destination_ip = str(packet[IPv6].dst)

        if packet.haslayer(TCP):
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)
            transport_protocol = "TCP"
        elif packet.haslayer(UDP):
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)
            transport_protocol = "UDP"

        if packet.haslayer(DNS) or source_port == 53 or destination_port == 53:
            protocol = "DNS"
        elif transport_protocol == "TCP" and _is_http(packet, source_port, destination_port):
            protocol = "HTTP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            transport_protocol = "ICMP"
        else:
            protocol = transport_protocol
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        protocol = "Other"

    try:
        packet_size = int(len(packet))
    except (TypeError, ValueError):
        packet_size = 0

    captured_datetime = datetime.fromtimestamp(timestamp).astimezone()
    return {
        "timestamp": captured_datetime.isoformat(timespec="milliseconds"),
        "time": captured_datetime.strftime("%H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "transport_protocol": transport_protocol,
        "protocol": protocol,
        "size": packet_size,
    }
