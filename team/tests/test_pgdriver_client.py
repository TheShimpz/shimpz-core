from __future__ import annotations

import unittest
from unittest import mock

import pgdriver_client


class PgDriverClientTests(unittest.TestCase):
    def test_upstream_error_body_is_never_reflected(self) -> None:
        response = mock.Mock(status=502)
        response.read.return_value = b'{"error":"sql and password secret"}'
        connection = mock.Mock()
        connection.getresponse.return_value = response

        with (
            mock.patch.object(pgdriver_client.http.client, "HTTPConnection", return_value=connection),
            self.assertRaises(pgdriver_client.PgDriverError) as raised,
        ):
            pgdriver_client._call("/v1/teams/apps/create", {"team_id": "alpha"}, "a" * 64)

        self.assertEqual(
            str(raised.exception),
            "pg-driver /v1/teams/apps/create failed with status 502",
        )
        self.assertNotIn("sql", str(raised.exception))
        self.assertNotIn("password", str(raised.exception))
        connection.close.assert_called_once_with()

    def test_success_returns_only_a_json_object(self) -> None:
        response = mock.Mock(status=200)
        response.read.return_value = b'{"created":true}'
        connection = mock.Mock()
        connection.getresponse.return_value = response

        with mock.patch.object(pgdriver_client.http.client, "HTTPConnection", return_value=connection):
            result = pgdriver_client._call("/v1/teams/apps/create", {"team_id": "alpha"}, "a" * 64)

        self.assertEqual(result, {"created": True})


if __name__ == "__main__":
    unittest.main()
