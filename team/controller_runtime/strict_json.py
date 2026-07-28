"""Decode JSON without duplicate fields or non-finite numbers."""

from __future__ import annotations

import json


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_non_finite(_value):
    raise ValueError("non-finite JSON number")


def loads(data):
    return json.loads(
        data,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )
