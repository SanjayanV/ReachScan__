"""Tests for the OSV provider using a fake transport."""

import json
import unittest

from providers.osv import OsvProvider
from utils.exceptions import ProviderUnavailableError

SAMPLE_ENTRY = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2020-14343"],
    "summary": "yaml.load() is unsafe",
    "details": "Affects `yaml.load()` calls.",
    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"severity": "CRITICAL"},
    "references": [{"url": "https://example.com/advisory"}],
}


def fake_post(body_dict, *, fail=False):
    """Build an ``http_post`` transport returning canned JSON bytes."""

    def _post(endpoint: str, payload: bytes):
        if fail:
            raise ProviderUnavailableError("boom")
        return json.dumps(body_dict).encode("utf-8")

    return _post


class OsvProviderTest(unittest.TestCase):
    def setUp(self):
        self.provider = OsvProvider(
            endpoint="https://example.test/v1/query",
            ecosystem="PyPI", request_timeout=1, max_retries=2,
        )

    def test_lookup_transforms_entry(self):
        self.provider._http_post = fake_post({"vulns": [SAMPLE_ENTRY]})
        vulns = self.provider.lookup("pyyaml", "5.3.1")
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v.cve_id, "CVE-2020-14343")
        self.assertEqual(v.osv_id, "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(v.severity, "CRITICAL")
        self.assertEqual(v.fixed_version, "5.4")
        self.assertIn("yaml.load", v.vulnerable_functions)

    def test_empty_vulns(self):
        self.provider._http_post = fake_post({"vulns": []})
        self.assertEqual(self.provider.lookup("requests", "2.0"), [])

    def test_unavailable_returns_empty_after_retries(self):
        self.provider._http_post = fake_post(None, fail=True)
        self.assertEqual(self.provider.lookup("foo", "1.0"), [])

    def test_unversioned_uses_none(self):
        captured = {}

        def _post(endpoint, payload):
            captured["payload"] = payload
            return b'{"vulns": []}'

        self.provider._http_post = _post
        self.provider.lookup("foo", "*")
        import json as _json
        body = _json.loads(captured["payload"])
        self.assertIsNone(body["version"])


if __name__ == "__main__":
    unittest.main()