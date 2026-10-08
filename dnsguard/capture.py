"""Packet sources: PCAP replay and live sniffing.

Both yield raw scapy packets; parsing happens in :mod:`dnsguard.parser`. Live
capture requires administrator/root privileges and raises a clear error otherwise.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterator

from scapy.packet import Packet


class CaptureError(Exception):
    """Raised for capture problems (missing file, no privileges, bad interface)."""


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """Yield packets from a PCAP/PCAPNG file in capture order.

    Uses ``PcapReader`` so large files are streamed rather than loaded at once.
    """
    p = Path(path)
    if not p.is_file():
        raise CaptureError(f"PCAP file not found: {p}")
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:  # pragma: no cover
        raise CaptureError(f"scapy PcapReader unavailable: {exc}") from exc
    try:
        with PcapReader(str(p)) as reader:
            for pkt in reader:
                yield pkt
    except Exception as exc:  # scapy raises various errors on malformed files
        raise CaptureError(f"Failed to read {p}: {exc}") from exc


def sniff_live(iface: str | None, bpf_filter: str,
               on_packet: Callable[[Packet], None],
               stop_filter: Callable[[Packet], bool] | None = None) -> None:
    """Sniff DNS packets live, calling ``on_packet`` for each.

    Raises :class:`CaptureError` with a friendly message if privileges are missing
    or the interface is invalid.
    """
    try:
        from scapy.sendrecv import sniff
    except ImportError as exc:  # pragma: no cover
        raise CaptureError(f"scapy sniff unavailable: {exc}") from exc

    try:
        sniff(iface=iface, filter=bpf_filter, prn=on_packet, store=False,
              stop_filter=stop_filter)
    except PermissionError as exc:
        raise CaptureError(
            "Live capture needs administrator/root privileges. "
            "On Windows run the terminal as Administrator (and install Npcap); "
            "on Linux/macOS use sudo or grant CAP_NET_RAW.") from exc
    except OSError as exc:
        msg = str(exc).lower()
        if "permission" in msg or "operation not permitted" in msg:
            raise CaptureError(
                "Live capture needs administrator/root privileges. "
                "On Windows run as Administrator with Npcap installed; "
                "on Linux/macOS use sudo.") from exc
        raise CaptureError(
            f"Could not start live capture on interface {iface!r}: {exc}. "
            "Check the interface name (list them with scapy's get_if_list()).") from exc
    except Exception as exc:  # pragma: no cover - last-resort friendly message
        raise CaptureError(f"Live capture failed: {exc}") from exc
