"""Unsafe deserialization examples beyond pickle."""

from __future__ import annotations

import io
import marshal

import dill
import jsonpickle


def read_marshaled_blob(blob: bytes) -> object:
    # insecure example for guardrail testing
    return marshal.loads(blob)


def read_dill_stream(blob: bytes) -> object:
    stream = io.BytesIO(blob)

    # insecure example for guardrail testing
    return dill.load(stream)


def decode_jsonpickle_payload(document: str) -> object:
    # insecure example for guardrail testing
    return jsonpickle.decode(document)
