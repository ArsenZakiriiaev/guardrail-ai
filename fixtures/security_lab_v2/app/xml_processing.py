"""XML processing helpers with unsafe parser configuration."""

from __future__ import annotations

from lxml import etree


def build_parser_for_partner_feed() -> etree.XMLParser:
    # insecure example for guardrail testing
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    return parser


def parse_partner_xml(xml_payload: bytes) -> object:
    parser = build_parser_for_partner_feed()
    return etree.fromstring(xml_payload, parser=parser)
