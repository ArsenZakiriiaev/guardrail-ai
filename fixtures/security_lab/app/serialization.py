"""Unsafe deserialization samples for static analysis exercises."""

from __future__ import annotations

import io
import pickle
from dataclasses import dataclass


@dataclass(slots=True)
class SerializedEnvelope:
    source: str
    payload: bytes


def build_pickle_envelope(payload: bytes) -> SerializedEnvelope:
    return SerializedEnvelope(source="local-training-fixture", payload=payload)


def read_cached_object_from_stream(envelope: SerializedEnvelope) -> object:
    """Unsafe file-like pickle loading example."""
    stream = io.BytesIO(envelope.payload)

    # insecure example for guardrail testing
    return pickle.load(stream)


def read_cached_object_from_blob(envelope: SerializedEnvelope) -> object:
    """Unsafe bytes pickle loading example."""
    blob = envelope.payload

    # insecure example for guardrail testing
    return pickle.loads(blob)
