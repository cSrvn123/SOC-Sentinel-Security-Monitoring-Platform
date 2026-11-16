"""Syntax validation and conservative normalization for supported IOCs."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .classification import IndicatorType, identify_type


_HASH_LENGTHS = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOTTED_NUMERIC_RE = re.compile(r"^[0-9.]+$")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    indicator: str
    indicator_type: IndicatorType
    reason: str


def _valid_domain(host: str) -> tuple[bool, str]:
    if not host or len(host) > 253 or host.endswith("."):
        return False, "Domain must be a non-empty name of at most 253 characters without a trailing dot."
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False, "Domain could not be converted to valid IDNA form."
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return False, "Domain must contain at least two valid DNS labels."
    if any(len(label) > 63 for label in labels):
        return False, "Each DNS label must be 63 characters or fewer."
    return True, ascii_host


def _valid_host(host: str) -> tuple[bool, str]:
    try:
        address = ipaddress.ip_address(host)
        return True, address.compressed
    except ValueError:
        return _valid_domain(host)


def validate_indicator(value: str) -> ValidationResult:
    """Validate and normalize an IPv4/IPv6, domain, HTTP(S) URL, or hash IOC."""
    if not isinstance(value, str):
        return ValidationResult(False, str(value), IndicatorType.UNKNOWN, "Indicator must be text.")
    candidate = value.strip()
    kind = identify_type(candidate)
    if not candidate:
        return ValidationResult(False, candidate, IndicatorType.UNKNOWN, "Indicator is empty.")

    if kind in (IndicatorType.IPV4, IndicatorType.IPV6):
        try:
            parsed = ipaddress.ip_address(candidate)
            return ValidationResult(True, parsed.compressed, kind, "Valid IP address syntax.")
        except ValueError:
            return ValidationResult(False, candidate, kind, "Invalid IP address syntax.")

    if kind in _HASH_LENGTHS:
        expected = _HASH_LENGTHS[kind]
        valid = len(candidate) == expected and bool(_HEX_RE.fullmatch(candidate))
        reason = f"Valid {kind.value} hexadecimal digest." if valid else f"Expected exactly {expected} hexadecimal characters."
        return ValidationResult(valid, candidate.lower() if valid else candidate, kind, reason)

    if kind == IndicatorType.URL:
        try:
            parts = urlsplit(candidate)
            if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
                raise ValueError("URL must use http or https and include a host.")
            if parts.username is not None or parts.password is not None:
                raise ValueError("URLs containing embedded credentials are not accepted.")
            host = parts.hostname
            if host is None:
                raise ValueError("URL host is missing.")
            _ = parts.port  # Access validates port syntax and range.
            valid_host, _normalized_host = _valid_host(host)
            if not valid_host:
                raise ValueError("URL host is not a valid IP address or domain.")
            return ValidationResult(True, candidate, kind, "Valid HTTP(S) URL syntax.")
        except ValueError as exc:
            return ValidationResult(False, candidate, kind, str(exc))

    if kind == IndicatorType.DOMAIN:
        if _DOTTED_NUMERIC_RE.fullmatch(candidate):
            return ValidationResult(False, candidate, kind, "Dotted numeric value is not a valid IPv4 address.")
        valid, normalized = _valid_domain(candidate)
        return ValidationResult(valid, normalized if valid else candidate, kind,
                                "Valid domain syntax." if valid else normalized)

    return ValidationResult(False, candidate, IndicatorType.UNKNOWN, "Indicator type is not supported.")
