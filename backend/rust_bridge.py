"""
rust_bridge.py — Graceful bridge between Python and the native core_sniffer_rs module.

If core_sniffer_rs has been compiled with `maturin develop` inside core_sniffer_rs/,
this bridge will use it as the packet capture engine (faster, zero-copy).
If not available, the system silently falls back to the existing Scapy path.

Build instructions:
    cd core_sniffer_rs
    pip install maturin
    maturin develop --release
"""

import json
import logging
import sys
import os

logger = logging.getLogger('packet_peeper')

RUST_AVAILABLE = False
_RustSniffer = None

try:
    # The compiled .so is placed in the venv site-packages by `maturin develop`
    # or next to app.py if built manually.
    import core_sniffer_rs  # noqa: F401
    _RustSniffer = core_sniffer_rs.RustSniffer
    RUST_AVAILABLE = True
    logger.info("[RustBridge] ✅ core_sniffer_rs loaded — native packet capture available")
except ImportError:
    logger.info("[RustBridge] core_sniffer_rs not built — using Scapy fallback (run `maturin develop` in core_sniffer_rs/ to enable)")
except Exception as e:
    logger.warning(f"[RustBridge] Unexpected error loading core_sniffer_rs: {e} — using Scapy fallback")


class RustBridge:
    """
    Thin adapter that wraps RustSniffer and normalises its JSON packet dicts
    into the same format that the Scapy handle_packet() path produces.
    """

    def __init__(self, callback):
        """
        Args:
            callback: callable(packet_info: dict) — same signature as
                      PacketSniffer.handle_packet's output path.
        """
        self._callback = callback
        self._sniffer = _RustSniffer() if RUST_AVAILABLE else None
        self._running = False

    # ------------------------------------------------------------------
    # Public API (mirrors the Scapy sniff loop interface)
    # ------------------------------------------------------------------

    def start(self, interface: str, bpf_filter: str = "") -> bool:
        """
        Start native capture. Returns True if Rust core was used, False if
        unavailable (caller should fall back to Scapy).
        """
        if not self._sniffer:
            return False

        self._running = True
        logger.info(f"[RustBridge] Starting native capture on '{interface}' bpf='{bpf_filter}'")

        try:
            self._sniffer.start_capture(interface, bpf_filter, self._on_packet_json)
            return True
        except Exception as e:
            logger.error(f"[RustBridge] start_capture failed: {e} — falling back to Scapy")
            self._running = False
            return False

    def stop(self):
        """Signal the Rust capture thread to stop."""
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop_capture()
                logger.info("[RustBridge] Native capture stopped")
            except Exception as e:
                logger.warning(f"[RustBridge] Error stopping capture: {e}")

    # ------------------------------------------------------------------
    # Internal callback — called from the Rust thread via PyO3 GIL acquire
    # ------------------------------------------------------------------

    def _on_packet_json(self, json_str: str):
        """Parse Rust JSON payload and forward to the Python callback."""
        try:
            pkt = json.loads(json_str)

            # Normalise field names to match Scapy handle_packet output
            normalised = {
                'timestamp':  pkt.get('timestamp'),
                'length':     pkt.get('length', 0),
                'protocol':   pkt.get('protocol', 'OTHER').upper(),
                'src_ip':     pkt.get('src_ip', ''),
                'dst_ip':     pkt.get('dst_ip', ''),
                'src_port':   pkt.get('src_port'),
                'dst_port':   pkt.get('dst_port'),
                'tcp_flags':  pkt.get('tcp_flags'),
                'src_mac':    pkt.get('src_mac', ''),
                'dst_mac':    pkt.get('dst_mac', ''),
                # Rust core doesn't do service classification yet — leave for Python layer
                'service':    'Unknown',
                'category':   'other',
                'capture_engine': 'rust',
            }

            self._callback(normalised)

        except json.JSONDecodeError as e:
            logger.debug(f"[RustBridge] JSON parse error (dropped packet): {e}")
        except Exception as e:
            logger.error(f"[RustBridge] callback error: {e}")
