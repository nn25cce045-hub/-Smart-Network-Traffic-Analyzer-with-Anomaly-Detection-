"""Background Scapy capture controller."""

from __future__ import annotations

from threading import Event, RLock, Thread
from typing import Callable, Any

from scapy.all import get_if_addr, get_if_list, sniff

from capture.packet_parser import parse_packet


class PacketCapture:
    """Start and stop passive packet capture without blocking Flask."""

    def __init__(self, packet_callback: Callable[[dict[str, Any]], None]) -> None:
        self._packet_callback = packet_callback
        self._thread: Thread | None = None
        self._stop_event = Event()
        self._lock = RLock()
        self._running = False
        self._interface: str | None = None
        self._last_error: str | None = None

    @staticmethod
    def available_interfaces() -> list[dict[str, str | None]]:
        """Return capture interface names and any discoverable IPv4 address."""
        interfaces = []
        try:
            names = get_if_list()
        except Exception as exc:  # Scapy uses OS-specific exception types.
            raise RuntimeError(f"Could not list network interfaces: {exc}") from exc

        for name in names:
            address = None
            try:
                detected = get_if_addr(name)
                if detected and detected != "0.0.0.0":
                    address = detected
            except Exception:
                pass
            interfaces.append({"name": name, "address": address})
        return interfaces

    def start(self, interface: str) -> tuple[bool, str]:
        """Start capture on a validated interface."""
        with self._lock:
            if self._running:
                return False, "Packet capture is already running."
            if not interface:
                return False, "A network interface is required."
            try:
                valid_interfaces = {item["name"] for item in self.available_interfaces()}
            except RuntimeError as exc:
                return False, str(exc)
            if interface not in valid_interfaces:
                return False, "The selected network interface is not available."

            self._stop_event.clear()
            self._last_error = None
            self._interface = interface
            self._running = True
            self._thread = Thread(
                target=self._capture_loop,
                name="packet-capture",
                daemon=True,
            )
            self._thread.start()
            return True, f"Capture started on {interface}."

    def stop(self) -> tuple[bool, str]:
        """Signal the capture worker to stop."""
        with self._lock:
            if not self._running:
                return False, "Packet capture is already stopped."
            self._stop_event.set()
            return True, "Capture is stopping."

    def _capture_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                # A short timeout lets STOP CAPTURE take effect even when traffic is idle.
                sniff(
                    iface=self._interface,
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                    stop_filter=lambda _packet: self._stop_event.is_set(),
                )
        except PermissionError:
            self._last_error = (
                "Permission denied. Run the application with packet-capture privileges "
                "or grant the Python interpreter the required capabilities."
            )
        except OSError as exc:
            self._last_error = f"Packet capture failed: {exc}"
        except Exception as exc:
            self._last_error = f"Unexpected capture error: {exc}"
        finally:
            with self._lock:
                self._running = False
                self._interface = None

    def _handle_packet(self, packet: Any) -> None:
        try:
            self._packet_callback(parse_packet(packet))
        except Exception:
            # A malformed packet must not terminate the long-running capture worker.
            return

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "capturing": self._running,
                "interface": self._interface,
                "last_error": self._last_error,
            }
