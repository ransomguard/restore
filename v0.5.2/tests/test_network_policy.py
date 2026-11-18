import unittest
from ransomguard.network_policy import make_plan


class NetworkPolicyTests(unittest.TestCase):
    def test_host_plan_does_not_claim_actual_enforcement(self):
        plan = make_plan({"scope": "host_outbound", "jev_url": "https://api.typesafe.ai/v1/systemone"})
        self.assertTrue(plan["plan_only"])
        self.assertFalse(plan["network_changed"])
        self.assertFalse(plan["live_enforcement_ready"])
        self.assertEqual(plan["scope"], "host_outbound")
        self.assertEqual(plan["unrelated_process_policy"], "subject_to_same_host_outbound_rules")
        self.assertEqual(plan["control_plane_endpoints"][0]["hostname"], "api.typesafe.ai")
        self.assertIn("daemon_active_ack_not_wfp_enforcement_proof", plan["known_limitations_deferred"])

    def test_process_scope_is_rejected_and_host_scope_explicit(self):
        for value in ({}, {"scope": "process", "jev_url": "https://api.typesafe.ai"},
                      {"scope": "host", "jev_url": "https://api.typesafe.ai"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_plan(value)

    def test_jev_only_endpoint_and_optional_approved_extras(self):
        plan = make_plan({"scope": "host_outbound", "jev_url": "https://api.typesafe.ai",
                          "extra_https_targets": ["https://extra.example.org/api"]})
        self.assertEqual(plan["allowlist"], ["https://api.typesafe.ai", "https://extra.example.org/api"])
        self.assertEqual([x["role"] for x in plan["control_plane_endpoints"]], ["jev", "approved_extra"])

    def test_invalid_or_unbounded_exceptions_rejected(self):
        for bad in ("http://example.com", "https://user:pass@example.com", "https://*.example.com",
                    "https://example.com/#fragment", "https://example.com:0", "https://example.com:65536",
                    "*:443"):
            with self.subTest(endpoint=bad), self.assertRaises(ValueError):
                make_plan({"scope": "host_outbound", "jev_url": bad})


if __name__ == "__main__":
    unittest.main()
