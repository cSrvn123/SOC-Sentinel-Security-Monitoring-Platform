"""Indicator type identification using syntax only."""

from __future__ import annotations

import ipaddress
import re
from enum import Enum


class IndicatorType(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "domain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    UNKNOWN = "unknown"


_HASH_TYPES = {32: IndicatorType.MD5, 40: IndicatorType.SHA1, 64: IndicatorType.SHA256}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def identify_type(value: str) -> IndicatorType:
    """Identify likely IOC type; this does not establish validity or reputation."""
    if not isinstance(value, str) or not value.strip():
        return IndicatorType.UNKNOWN
    candidate = value.strip()
    if candidate.lower().startswith(("http://", "https://")):
        return IndicatorType.URL
    try:
        address = ipaddress.ip_address(candidate)
        return IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6
    except ValueError:
        pass
    if _HEX_RE.fullmatch(candidate):
        hash_type = _HASH_TYPES.get(len(candidate))
        if hash_type:
            return hash_type
    return IndicatorType.DOMAIN
