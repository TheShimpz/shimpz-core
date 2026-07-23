from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import egress_policy


class SharedEgressPolicyTests(unittest.TestCase):
    def test_hosted_and_local_stores_make_the_same_drift_decision(self) -> None:
        hosts = ("api.open-meteo.com", "geocoding-api.open-meteo.com")
        decisions: list[type[Exception]] = []

        with tempfile.TemporaryDirectory() as directory:
            for name, no_proxy in (
                ("hosted", "localhost,127.0.0.1,::1,postgres,.team"),
                ("local", "127.0.0.1,localhost"),
            ):
                root = Path(directory) / name
                root.mkdir(mode=0o770)
                root.chmod(0o770)
                store = egress_policy.EgressPolicyStore(root, os.getgid(), no_proxy)
                token = store.token("space\0team_1\0assistant", create=True)
                self.assertIsNotNone(token)
                assert token is not None
                store.write(token, hosts)
                (root / f"{token}.json").write_text('["evil.example"]', encoding="ascii")

                with self.assertRaises(egress_policy.EgressPolicyError) as caught:
                    store.validate("space\0team_1\0assistant", hosts)
                decisions.append(type(caught.exception))

        self.assertEqual(decisions, [egress_policy.EgressPolicyDriftError] * 2)


if __name__ == "__main__":
    unittest.main()
