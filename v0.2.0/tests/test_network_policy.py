import unittest
from ransomguard.network_policy import make_plan


class NetworkPolicyTests(unittest.TestCase):
    def test_plan_never_claims_enforcement(self):
        plan = make_plan({"scope": "process", "jev_url": "https://api.typesafe.ai/v1/systemone"})
        self.assertTrue(plan["plan_only"])
        self.assertFalse(plan["network_changed"])
        self.assertFalse(plan["live_enforcement_ready"])
        self.assertEqual(plan["scope"], "process")
        self.assertEqual(plan["unrelated_process_policy"], "unchanged")
        self.assertEqual(plan["control_plane_endpoints"][0]["hostname"], "api.typesafe.ai")
        self.assertNotIn("outbound_exceptions", plan)

    def test_process_scope_is_default_and_host_scope_is_rejected(self):
        self.assertEqual(make_plan({})["scope"], "process")
        with self.assertRaises(ValueError):
            make_plan({"scope": "host"})

    def test_plan_requires_process_generation_and_preserves_other_processes(self):
        plan = make_plan({})
        self.assertEqual(plan["process_identity_fields"], ["pid", "process_create_time"])
        self.assertIn("selected process instance", plan["target_process_policy"])
        self.assertEqual(plan["unrelated_process_policy"], "unchanged")

    def test_invalid_endpoint_rejected(self):
        for bad in ("http://example.com", "https://user:pass@example.com", "https://*.example.com",
                    "https://example.com/#fragment", "https://example.com:0", "https://example.com:65536"):
            with self.subTest(endpoint=bad):
                with self.assertRaises(ValueError):
                    make_plan({"scope": "process", "jev_url": bad})

    def test_shared_python_interpreter_not_an_allowlist_identity(self):
        with self.assertRaises(ValueError):
            make_plan({"scope": "process", "agent_executable": "C:\\Python312\\python.exe"})


if __name__ == "__main__":
    unittest.main()
