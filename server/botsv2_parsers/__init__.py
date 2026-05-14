"""
Splunk BOTSv2 raw-event parsers.

Shared by:
  - server/ingest  (BOTSv2 mode: _raw → NormalizedEvent graph triple)
  - server/ml-edge-scorer  (feature re-extraction from _raw for model input)

Each parser takes (_raw: str, host: str | None) → ParsedRow.
ParsedRow carries the graph triple (subject/object/edge) plus a flat
`fields` dict of numeric and categorical content columns.

Dispatch entry-point:  get_parser(sourcetype) → parser callable
"""
from .parsers import (
    ParsedRow,
    EMPTY,
    get_parser,
    parse_stream,
    parse_suricata,
    parse_access_combined,
    parse_sysmon,
    parse_pan_traffic,
    parse_mysql_kv,
    parse_winhostmon,
    parse_winregistry,
    parse_audit,
    parse_stub,
)

__all__ = [
    "ParsedRow",
    "EMPTY",
    "get_parser",
    "parse_stream",
    "parse_suricata",
    "parse_access_combined",
    "parse_sysmon",
    "parse_pan_traffic",
    "parse_mysql_kv",
    "parse_winhostmon",
    "parse_winregistry",
    "parse_audit",
    "parse_stub",
]
