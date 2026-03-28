"""YAML parsing helpers with intentionally unsafe loader choices."""

from __future__ import annotations

from dataclasses import dataclass

import yaml


@dataclass(slots=True)
class YamlImportRequest:
    label: str
    raw_text: str


def build_yaml_request(label: str, raw_text: str) -> YamlImportRequest:
    return YamlImportRequest(label=label, raw_text=raw_text)


def parse_untrusted_yaml(request: YamlImportRequest) -> object:
    raw_text = request.raw_text

    # insecure example for guardrail testing
    return yaml.load(raw_text)


def parse_untrusted_yaml_full_loader(request: YamlImportRequest) -> object:
    raw_text = request.raw_text

    # insecure example for guardrail testing
    return yaml.load(raw_text, Loader=yaml.FullLoader)
