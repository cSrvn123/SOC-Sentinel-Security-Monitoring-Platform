"""Offline synthetic reputation and opt-in VirusTotal metadata lookups."""

from __future__ import annotations

import base64
import json
import os
from typing import Callable, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .classification import IndicatorType
from .models import Indicator, ReputationResult


class LookupErrorSafe(Exception):
    """Safe-to-display lookup error with no request headers or credentials."""


class OfflineReputationProvider:
    """Returns synthetic examples only; never makes a network request."""

    _FIXTURES: Mapping[str, ReputationResult] = {
        "198.51.100.10": ReputationResult("synthetic_benign", "low", "Synthetic offline fixture",
            "Synthetic example only: validate context before closing an alert.", 0, 0, 3),
        "benign.example": ReputationResult("synthetic_benign", "low", "Synthetic offline fixture",
            "Synthetic example only: validate context before closing an alert.", 0, 0, 3),
        "203.0.113.66": ReputationResult("synthetic_suspicious", "elevated", "Synthetic offline fixture",
            "Synthetic example only: investigate related activity and corroborate evidence.", 0, 2, 0),
        "suspicious.example": ReputationResult("synthetic_suspicious", "elevated", "Synthetic offline fixture",
            "Synthetic example only: investigate related activity and corroborate evidence.", 0, 2, 0),
        "192.0.2.44": ReputationResult("synthetic_unknown", "unknown", "Synthetic offline fixture",
            "No synthetic fixture is available; investigate using authorized internal context.", 0, 0, 0),
        "unknown.example": ReputationResult("synthetic_unknown", "unknown", "Synthetic offline fixture",
            "No synthetic fixture is available; investigate using authorized internal context.", 0, 0, 0),
    }

    def lookup(self, indicator: Indicator) -> ReputationResult:
        result = self._FIXTURES.get(indicator.value.lower())
        if result:
            return result
        return ReputationResult("synthetic_unknown", "unknown", "Synthetic offline fallback",
            "No synthetic result is available; no real threat-intelligence lookup was performed.", 0, 0, 0)


def _vt_endpoint(indicator: Indicator) -> str:
    value = indicator.value
    if indicator.indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
        return "ip_addresses/" + quote(value, safe=":.")
    if indicator.indicator_type == IndicatorType.DOMAIN:
        return "domains/" + quote(value, safe=".-")
    if indicator.indicator_type == IndicatorType.URL:
        url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        return "urls/" + url_id
    if indicator.indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
        return "files/" + quote(value, safe="")
    raise LookupErrorSafe("Unsupported indicator type for VirusTotal lookup.")


def _reputation_from_stats(stats: object) -> ReputationResult:
    if not isinstance(stats, dict):
        raise LookupErrorSafe("VirusTotal response did not contain analysis statistics.")
    values = {}
    for name in ("malicious", "suspicious", "harmless"):
        raw = stats.get(name, 0)
        if not isinstance(raw, int) or raw < 0:
            raise LookupErrorSafe("VirusTotal returned invalid analysis statistics.")
        values[name] = raw
    malicious, suspicious, harmless = values["malicious"], values["suspicious"], values["harmless"]
    if malicious:
        status, risk, recommendation = "malicious", "high", "Prioritize investigation; validate detections and correlate endpoint evidence."
    elif suspicious:
        status, risk, recommendation = "suspicious", "elevated", "Investigate context and corroborate with independent telemetry."
    elif harmless:
        status, risk, recommendation = "benign_votes_present", "low", "Review context; harmless votes are not proof that the indicator is safe."
    else:
        status, risk, recommendation = "unknown", "unknown", "No decisive analysis votes; investigate using authorized internal context."
    return ReputationResult(status, risk, "VirusTotal API v3", recommendation,
                            malicious, suspicious, harmless)


class VirusTotalProvider:
    """Read-only VirusTotal object lookups. No file upload/sample submission exists."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 10.0,
                 opener: Optional[Callable[..., object]] = None) -> None:
        self._api_key = api_key if api_key is not None else os.environ.get("VIRUSTOTAL_API_KEY")
        self._timeout = timeout
        self._opener = opener or urlopen

    def lookup(self, indicator: Indicator) -> ReputationResult:
        if not self._api_key:
            return ReputationResult("not_checked", "unknown", "VirusTotal API (not configured)",
                "Set VIRUSTOTAL_API_KEY privately and explicitly enable live lookup, or use offline mode.",
                error="API key is not configured.")
        try:
            request = Request("https://www.virustotal.com/api/v3/" + _vt_endpoint(indicator),
                              headers={"x-apikey": self._api_key, "accept": "application/json"}, method="GET")
            with self._opener(request, timeout=self._timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            data = payload.get("data") if isinstance(payload, dict) else None
            attributes = data.get("attributes") if isinstance(data, dict) else None
            stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
            return _reputation_from_stats(stats)
        except HTTPError as exc:
            if exc.code == 429:
                message = "VirusTotal rate limit reached; retry later according to your account limits."
            elif exc.code == 401:
                message = "VirusTotal rejected the API key (HTTP 401); check the local environment variable."
            elif exc.code == 403:
                message = "VirusTotal denied this lookup (HTTP 403); check API access and account limits."
            elif exc.code == 404:
                return ReputationResult("not_found", "unknown", "VirusTotal API v3",
                    "No report was found; investigate using authorized internal context.", error="Indicator report not found (HTTP 404).")
            else:
                message = f"VirusTotal returned HTTP {exc.code}."
            return ReputationResult("lookup_error", "unknown", "VirusTotal API v3",
                "Resolve the lookup issue or continue with internal evidence.", error=message)
        except URLError as exc:
            reason = getattr(exc, "reason", None)
            message = "VirusTotal request timed out." if isinstance(reason, TimeoutError) else "VirusTotal connection failed."
            return ReputationResult("lookup_error", "unknown", "VirusTotal API v3",
                "Check connectivity and retry only if appropriate.", error=message)
        except TimeoutError:
            return ReputationResult("lookup_error", "unknown", "VirusTotal API v3",
                "Check connectivity and retry only if appropriate.", error="VirusTotal request timed out.")
        except OSError:
            return ReputationResult("lookup_error", "unknown", "VirusTotal API v3",
                "Check connectivity and retry only if appropriate.", error="VirusTotal connection failed.")
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError, LookupErrorSafe) as exc:
            message = str(exc) if isinstance(exc, LookupErrorSafe) else "VirusTotal returned an invalid response."
            return ReputationResult("lookup_error", "unknown", "VirusTotal API v3",
                "Check the API response format; do not treat this lookup as a verdict.", error=message)
