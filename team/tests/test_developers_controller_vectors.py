"""Validate every shared vector through the independent Controller consumer."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from hosted_install.developers_controller_contract import ContractValidationError, ContractValidator

CONTRACT = Path(__file__).resolve().parents[1] / "contracts" / "developers-controller" / "v1"
VECTORS = json.loads((CONTRACT / "vectors.json").read_bytes())


def mutate(value: object, mutation: object) -> object:
    result = copy.deepcopy(value)
    if mutation is None:
        return result
    if not isinstance(mutation, dict):
        raise AssertionError("invalid vector mutation")
    path = mutation["path"]
    parent = result
    for key in path[:-1]:
        if not isinstance(parent, dict):
            raise AssertionError("invalid vector path")
        parent = parent[key]
    if not isinstance(parent, dict):
        raise AssertionError("invalid vector target")
    if mutation["op"] == "remove":
        del parent[path[-1]]
    else:
        parent[path[-1]] = copy.deepcopy(mutation["value"])
    return result


class DevelopersControllerVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = ContractValidator()

    def test_every_golden_vector(self) -> None:
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                fixture = VECTORS["fixtures"][case["fixture"]]
                value = mutate(fixture["value"], case.get("mutation"))
                if case["valid"]:
                    self.validator.validate(fixture["schema"], value)
                else:
                    with self.assertRaises(ContractValidationError):
                        self.validator.validate(fixture["schema"], value)

    def test_validation_errors_do_not_echo_input(self) -> None:
        secret = "attacker-controlled-secret"
        with self.assertRaises(ContractValidationError) as raised:
            self.validator.validate("team-list-response.schema.json", {"unexpected": secret})
        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
