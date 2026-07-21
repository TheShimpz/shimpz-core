from __future__ import annotations

import json
import unittest
from base64 import b64decode
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import oauth_http_client

CLIENT_ID = "cloudflare-client-id-123"
CLIENT_SECRET = "cloudflare-client-secret-123"
CODE = "authorization-code-123456789"
VERIFIER = "v" * 64
STATE = "s" * 43
CHALLENGE = "c" * 43
SCOPES = ("dns.read", "offline_access", "zone.read")
ACCESS = "access-token-123456789"
REFRESH = "refresh-token-123456789"


@dataclass
class FakeTransport:
    responses: list[oauth_http_client.OAuthHTTPResponse]
    requests: list[dict[str, object]] = field(default_factory=list)

    def request(self, **request: object) -> oauth_http_client.OAuthHTTPResponse:
        self.requests.append(request)
        return self.responses.pop(0)


def response(payload: object, *, status: int = 200, content_type: str = "application/json"):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return oauth_http_client.OAuthHTTPResponse(status, content_type, body)


def _assert_basic(request: dict[str, object]) -> None:
    headers = request["headers"]
    assert isinstance(headers, dict)
    scheme, encoded = headers["Authorization"].split(" ", 1)
    if scheme != "Basic" or b64decode(encoded).decode("ascii") != f"{CLIENT_ID}:{CLIENT_SECRET}":
        raise AssertionError("invalid confidential client authentication")


class OAuthHTTPClientTests(unittest.TestCase):
    def test_authorization_url_is_fixed_cloudflare_pkce_and_exact_redirect(self) -> None:
        url = oauth_http_client.authorization_url(
            provider_id="cloudflare",
            client_id=CLIENT_ID,
            redirect_uri=oauth_http_client.LOCAL_REDIRECT_URI,
            state=STATE,
            code_challenge=CHALLENGE,
            scopes=SCOPES,
        )
        parsed = urlsplit(url)
        self.assertEqual(
            (parsed.scheme, parsed.netloc, parsed.path),
            ("https", "dash.cloudflare.com", "/oauth2/auth"),
        )
        self.assertEqual(
            parse_qs(parsed.query),
            {
                "response_type": ["code"],
                "client_id": [CLIENT_ID],
                "redirect_uri": [oauth_http_client.LOCAL_REDIRECT_URI],
                "scope": ["dns.read offline_access zone.read"],
                "state": [STATE],
                "code_challenge": [CHALLENGE],
                "code_challenge_method": ["S256"],
            },
        )
        for redirect in (
            "http://localhost:7777/api/oauth/cloudflare/callback",
            "https://evil.test/callback",
        ):
            with self.subTest(redirect=redirect), self.assertRaises(oauth_http_client.OAuthHTTPError):
                oauth_http_client.authorization_url(
                    provider_id="cloudflare",
                    client_id=CLIENT_ID,
                    redirect_uri=redirect,
                    state=STATE,
                    code_challenge=CHALLENGE,
                    scopes=SCOPES,
                )

    def test_exchange_uses_basic_secret_fixed_endpoint_and_validates_tokens(self) -> None:
        transport = FakeTransport(
            [
                response(
                    {
                        "token_type": "bearer",
                        "access_token": ACCESS,
                        "refresh_token": REFRESH,
                        "expires_in": 7200,
                        "scope": "zone.read dns.read offline_access",
                    }
                )
            ]
        )
        tokens = oauth_http_client.OAuthHTTPClient(transport).exchange_code(
            provider_id="cloudflare",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=oauth_http_client.LOCAL_REDIRECT_URI,
            code=CODE,
            code_verifier=VERIFIER,
            scopes=SCOPES,
        )

        self.assertEqual(tokens.access_token, ACCESS)
        self.assertEqual(tokens.refresh_token, REFRESH)
        request = transport.requests[0]
        self.assertEqual(request["url"], "https://dash.cloudflare.com/oauth2/token")
        _assert_basic(request)
        fields = parse_qs(bytes(request["body"]).decode())
        self.assertNotIn("client_id", fields)
        self.assertNotIn("client_secret", fields)
        self.assertEqual(fields["code_verifier"], [VERIFIER])

    def test_refresh_and_revoke_reuse_confidential_fixed_provider_endpoints(self) -> None:
        transport = FakeTransport(
            [
                response(
                    {
                        "token_type": "Bearer",
                        "access_token": "new-access-token-123456789",
                        "expires_in": 3600,
                        "scope": " ".join(SCOPES),
                    }
                ),
                response(b"", content_type=""),
            ]
        )
        client = oauth_http_client.OAuthHTTPClient(transport)
        tokens = client.refresh(
            provider_id="cloudflare",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            refresh_token=REFRESH,
            scopes=SCOPES,
        )
        self.assertEqual(tokens.refresh_token, REFRESH)
        client.revoke(
            provider_id="cloudflare",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            token=tokens.refresh_token,
        )

        self.assertEqual(transport.requests[0]["url"], "https://dash.cloudflare.com/oauth2/token")
        self.assertEqual(transport.requests[1]["url"], "https://dash.cloudflare.com/oauth2/revoke")
        for request in transport.requests:
            _assert_basic(request)
            self.assertNotIn("client_secret", parse_qs(bytes(request["body"]).decode()))
        self.assertEqual(parse_qs(bytes(transport.requests[1]["body"]).decode()), {"token": [REFRESH]})

    def test_redirects_malformed_json_scope_widening_and_reflection_fail_closed(self) -> None:
        bad_responses = (
            response({"error": "do-not-reflect-this-secret"}, status=302),
            response(b'{"access_token":"one","access_token":"two"}'),
            response(
                {
                    "token_type": "bearer",
                    "access_token": ACCESS,
                    "refresh_token": REFRESH,
                    "expires_in": 7200,
                    "scope": "dns.read offline_access zone.read dns.write",
                }
            ),
            response(
                {
                    "token_type": "bearer",
                    "access_token": ACCESS,
                    "expires_in": 7200,
                    "scope": " ".join(SCOPES),
                }
            ),
        )
        for provider_response in bad_responses:
            transport = FakeTransport([provider_response])
            with (
                self.subTest(body=provider_response.body),
                self.assertRaises(oauth_http_client.OAuthHTTPError) as caught,
            ):
                oauth_http_client.OAuthHTTPClient(transport).exchange_code(
                    provider_id="cloudflare",
                    client_id=CLIENT_ID,
                    client_secret=CLIENT_SECRET,
                    redirect_uri=oauth_http_client.HOSTED_REDIRECT_URI,
                    code=CODE,
                    code_verifier=VERIFIER,
                    scopes=SCOPES,
                )
            for private in ("do-not-reflect", ACCESS, CLIENT_SECRET):
                self.assertNotIn(private, str(caught.exception))

    def test_inputs_and_response_size_are_bounded(self) -> None:
        transport = FakeTransport(
            [
                oauth_http_client.OAuthHTTPResponse(
                    200,
                    "application/json",
                    b"x" * (oauth_http_client.MAX_RESPONSE_BYTES + 1),
                )
            ]
        )
        with self.assertRaises(oauth_http_client.OAuthHTTPError):
            oauth_http_client.OAuthHTTPClient(transport).exchange_code(
                provider_id="cloudflare",
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                redirect_uri=oauth_http_client.LOCAL_REDIRECT_URI,
                code=CODE,
                code_verifier=VERIFIER,
                scopes=SCOPES,
            )
        for invalid_client in ("short", "secret value", "x" * 257):
            with self.subTest(client=invalid_client), self.assertRaises(oauth_http_client.OAuthHTTPError):
                oauth_http_client.authorization_url(
                    provider_id="cloudflare",
                    client_id=invalid_client,
                    redirect_uri=oauth_http_client.LOCAL_REDIRECT_URI,
                    state=STATE,
                    code_challenge=CHALLENGE,
                    scopes=SCOPES,
                )
        for invalid_secret in ("short", "secret value", "x" * 1025):
            with self.subTest(secret=invalid_secret), self.assertRaises(oauth_http_client.OAuthHTTPError):
                oauth_http_client.OAuthHTTPClient(FakeTransport([])).refresh(
                    provider_id="cloudflare",
                    client_id=CLIENT_ID,
                    client_secret=invalid_secret,
                    refresh_token=REFRESH,
                    scopes=SCOPES,
                )


if __name__ == "__main__":
    unittest.main()
