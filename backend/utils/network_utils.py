"""
Network utility functions — shared across modules.
"""

import ipaddress


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is RFC 1918 private, loopback, or link-local.

    Returns True for:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.0/8
      - 169.254.0.0/16 (link-local)

    Returns False for all other addresses, including multicast, broadcast,
    documentation ranges, and public IPs.
    """
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def is_reserved_ip(ip: str) -> bool:
    """Check if an IP is private, reserved, multicast, or link-local.

    Suitable for GeoIP skip logic — these IPs have no geographic location.
    """
    if not ip:
        return True
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_reserved or obj.is_multicast or obj.is_link_local
    except (ValueError, TypeError):
        return True
