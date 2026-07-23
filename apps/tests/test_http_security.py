from __future__ import annotations

import ast
import unittest
from pathlib import Path

APP_SOURCE = Path(__file__).resolve().parents[1] / "app.py"


class HttpSecurityStaticTests(unittest.TestCase):
    def test_bearer_authorization_uses_constant_time_comparison(self) -> None:
        tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
        handler = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Handler")
        authorized = next(node for node in handler.body if isinstance(node, ast.FunctionDef) and node.name == "_authed")
        returned = next(node for node in authorized.body if isinstance(node, ast.Return))

        self.assertEqual(ast.unparse(returned.value), "hmac.compare_digest(auth, f'Bearer {_token}')")


if __name__ == "__main__":
    unittest.main()
