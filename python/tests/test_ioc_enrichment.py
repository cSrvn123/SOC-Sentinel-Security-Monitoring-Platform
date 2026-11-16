from __future__ import annotations

import io
import json
import contextlib
import unittest
from io import StringIO
from urllib.error import HTTPError

from ioc_enrichment.classification import IndicatorType, identify_type
from ioc_enrichment.cli import main
from ioc_enrichment.enrichment import enrich_indicator
from ioc_enrichment.formatting import format_text
from ioc_enrichment.models import Indicator
from ioc_enrichment.reputation import OfflineReputationProvider, VirusTotalProvider
from ioc_enrichment.validation import validate_indicator


class IndicatorValidationTests(unittest.TestCase):
    def test_valid_indicator_types(self) -> None:
        samples = {"203.0.113.5": IndicatorType.IPV4, "2001:db8::1": IndicatorType.IPV6,
            "analyst.example": IndicatorType.DOMAIN, "https://analyst.example/path": IndicatorType.URL,
            "a" * 32: IndicatorType.MD5, "b" * 40: IndicatorType.SHA1, "c" * 64: IndicatorType.SHA256}
        for value, expected in samples.items():
            with self.subTest(kind=expected.value):
                result = validate_indicator(value)
                self.assertTrue(result.valid, result.reason)
                self.assertEqual(result.indicator_type, expected)

    def test_invalid_values(self) -> None:
        for value in ("999.1.1.1", "2001:db8:::1", "-bad.example", "bad..example",
            "http:///missing-host", "ftp://analyst.example/path", "https://user:pass@analyst.example/",
            "g" * 32, "a" * 31, "a" * 41, "a" * 63, ""):
            with self.subTest(value=value[:20]):
                self.assertFalse(validate_indicator(value).valid)

    def test_identification_is_syntax_based(self) -> None:
        self.assertEqual(identify_type("https://example.invalid/a"), IndicatorType.URL)
        self.assertEqual(identify_type("203.0.113.5"), IndicatorType.IPV4)
        self.assertEqual(identify_type("f" * 64), IndicatorType.SHA256)


class OfflineModeTests(unittest.TestCase):
    def test_synthetic_benign_suspicious_unknown_fixtures(self) -> None:
        cases = (("198.51.100.10", "synthetic_benign", "low"),
            ("203.0.113.66", "synthetic_suspicious", "elevated"),
            ("192.0.2.44", "synthetic_unknown", "unknown"))
        for value, status, risk in cases:
            result = enrich_indicator(value, OfflineReputationProvider())
            self.assertEqual(result.reputation_status, status)
            self.assertEqual(result.risk_classification, risk)
            self.assertIn("Synthetic", result.source)

    def test_unmapped_valid_ioc_is_synthetic_unknown(self) -> None:
        result = enrich_indicator("new.example")
        self.assertEqual(result.reputation_status, "synthetic_unknown")
        self.assertIn("not real threat intelligence", format_text(result).lower())

    def test_invalid_ioc_is_not_queried(self) -> None:
        class MustNotLookup:
            def lookup(self, indicator: Indicator) -> object:
                raise AssertionError("provider should not be called for invalid input")
        result = enrich_indicator("not a valid domain", MustNotLookup())
        self.assertEqual(result.validation_status, "invalid")
        self.assertEqual(result.reputation_status, "not_checked")

    def test_live_cli_requires_indicator_sharing_acknowledgment(self) -> None:
        stderr = StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["analyst.example", "--live"])
        self.assertEqual(status, 2)
        self.assertIn("approved for disclosure", stderr.getvalue())

    def test_sharing_acknowledgment_requires_live_mode(self) -> None:
        stderr = StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["analyst.example", "--allow-indicator-sharing"])
        self.assertEqual(status, 2)
        self.assertIn("requires --live", stderr.getvalue())


class VirusTotalProviderTests(unittest.TestCase):
    @staticmethod
    def _response(stats: dict[str, int]) -> object:
        class Response:
            def __enter__(self) -> "Response": return self
            def __exit__(self, *args: object) -> None: return None
            def read(self) -> bytes: return json.dumps({"data": {"attributes": {"last_analysis_stats": stats}}}).encode()
        return Response()

    def test_missing_key_is_graceful_and_does_not_call_network(self) -> None:
        provider = VirusTotalProvider(api_key="", opener=lambda *args, **kwargs: self.fail("network called"))
        result = provider.lookup(Indicator("analyst.example", IndicatorType.DOMAIN))
        self.assertEqual(result.reputation_status, "not_checked")
        self.assertEqual(result.error, "API key is not configured.")

    def test_successful_lookup_uses_get_and_does_not_return_key(self) -> None:
        seen: list[object] = []
        def opener(request: object, timeout: float) -> object:
            seen.append(request)
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(timeout, 3)
            return self._response({"malicious": 2, "suspicious": 0, "harmless": 1})
        result = VirusTotalProvider("synthetic-test-key", timeout=3, opener=opener).lookup(
            Indicator("analyst.example", IndicatorType.DOMAIN))
        self.assertEqual(result.reputation_status, "malicious")
        self.assertEqual(result.risk_classification, "high")
        self.assertEqual(len(seen), 1)
        self.assertNotIn("synthetic-test-key", repr(result))

    def test_http_errors_and_rate_limit(self) -> None:
        for code, expected in ((429, "rate limit"), (401, "HTTP 401"), (403, "HTTP 403"), (500, "HTTP 500")):
            def opener(*args: object, _code: int = code, **kwargs: object) -> object:
                raise HTTPError("https://example.invalid", _code, "synthetic", {}, io.BytesIO(b""))
            result = VirusTotalProvider("synthetic-test-key", opener=opener).lookup(
                Indicator("analyst.example", IndicatorType.DOMAIN))
            self.assertEqual(result.reputation_status, "lookup_error")
            self.assertIn(expected, result.error or "")
            self.assertNotIn("synthetic-test-key", result.error or "")

    def test_not_found(self) -> None:
        def opener(*args: object, **kwargs: object) -> object:
            raise HTTPError("https://example.invalid", 404, "synthetic", {}, io.BytesIO(b""))
        result = VirusTotalProvider("synthetic-test-key", opener=opener).lookup(
            Indicator("analyst.example", IndicatorType.DOMAIN))
        self.assertEqual(result.reputation_status, "not_found")

    def test_timeout_and_connection_errors(self) -> None:
        for exc, expected in ((TimeoutError(), "timed out"), (OSError(), "connection failed")):
            def opener(*args: object, _exc: Exception = exc, **kwargs: object) -> object:
                raise _exc
            result = VirusTotalProvider("synthetic-test-key", opener=opener).lookup(
                Indicator("analyst.example", IndicatorType.DOMAIN))
            self.assertEqual(result.reputation_status, "lookup_error")
            self.assertIn(expected, result.error or "")

    def test_invalid_response(self) -> None:
        class Response:
            def __enter__(self) -> "Response": return self
            def __exit__(self, *args: object) -> None: return None
            def read(self) -> bytes: return b"not-json"
        result = VirusTotalProvider("synthetic-test-key", opener=lambda *args, **kwargs: Response()).lookup(
            Indicator("analyst.example", IndicatorType.DOMAIN))
        self.assertEqual(result.reputation_status, "lookup_error")

    def test_url_lookup_uses_get_metadata_endpoint(self) -> None:
        captured: list[object] = []
        def opener(request: object, timeout: float) -> object:
            captured.append(request)
            return self._response({"malicious": 0, "suspicious": 0, "harmless": 0})
        result = VirusTotalProvider("synthetic-test-key", opener=opener).lookup(
            Indicator("https://analyst.example/path", IndicatorType.URL))
        self.assertEqual(result.reputation_status, "unknown")
        self.assertEqual(captured[0].get_method(), "GET")
        self.assertIn("/urls/", captured[0].full_url)


if __name__ == "__main__":
    unittest.main()
