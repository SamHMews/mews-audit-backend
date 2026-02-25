"""Unit tests for pure helper functions in mews_full_audit_app."""

import pytest
from datetime import datetime, timezone

from mews_full_audit_app import (
    esc,
    pick_name,
    parse_bool,
    safe_float,
    parse_utc,
    chunk_list,
    _deduplicate_by_id,
    _count_by_field,
    money_from_extended_amount,
    parse_iso_duration,
    build_report,
)


class TestEsc:
    def test_none(self):
        assert esc(None) == ""

    def test_plain_string(self):
        assert esc("hello") == "hello"

    def test_html_entities(self):
        assert esc('<script>alert("xss")</script>') == (
            "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
        )

    def test_ampersand(self):
        assert esc("A & B") == "A &amp; B"

    def test_single_quote(self):
        assert esc("it's") == "it&#39;s"

    def test_integer(self):
        assert esc(42) == "42"


class TestPickName:
    def test_none(self):
        assert pick_name(None) == ""

    def test_non_dict(self):
        assert pick_name("string") == ""

    def test_name_field(self):
        assert pick_name({"Name": "Hotel A"}) == "Hotel A"

    def test_short_name(self):
        assert pick_name({"ShortName": "A"}) == "A"

    def test_names_dict(self):
        assert pick_name({"Names": {"en-US": "English Name"}}) == "English Name"

    def test_names_empty(self):
        assert pick_name({"Names": {}}) == ""

    def test_empty_dict(self):
        assert pick_name({}) == ""


class TestParseBool:
    @pytest.mark.parametrize("value,expected", [
        (None, False),
        (True, True),
        (False, False),
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("off", False),
        ("maybe", False),
    ])
    def test_parse_bool(self, value, expected):
        assert parse_bool(value) == expected

    def test_default_true(self):
        assert parse_bool(None, default=True) is True
        assert parse_bool("maybe", default=True) is True


class TestSafeFloat:
    def test_none(self):
        assert safe_float(None) is None

    def test_string(self):
        assert safe_float("3.14") == pytest.approx(3.14)

    def test_int(self):
        assert safe_float(42) == pytest.approx(42.0)

    def test_bad_string(self):
        assert safe_float("abc") is None

    def test_zero(self):
        assert safe_float(0) == pytest.approx(0.0)


class TestParseUtc:
    def test_none(self):
        assert parse_utc(None) is None

    def test_empty_string(self):
        assert parse_utc("") is None

    def test_non_string(self):
        assert parse_utc(123) is None

    def test_z_suffix(self):
        result = parse_utc("2024-01-15T10:30:00Z")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_iso_with_offset(self):
        result = parse_utc("2024-01-15T10:30:00+00:00")
        assert result is not None

    def test_bad_format(self):
        assert parse_utc("not-a-date") is None


class TestChunkList:
    def test_empty(self):
        assert chunk_list([], 3) == []

    def test_smaller_than_chunk(self):
        assert chunk_list([1, 2], 5) == [[1, 2]]

    def test_exact_chunks(self):
        assert chunk_list([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]

    def test_remainder(self):
        assert chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]

    def test_zero_size(self):
        assert chunk_list([1, 2, 3], 0) == [[1, 2, 3]]

    def test_negative_size(self):
        assert chunk_list([1, 2, 3], -1) == [[1, 2, 3]]


class TestDeduplicateById:
    def test_empty(self):
        assert _deduplicate_by_id([], set()) == []

    def test_no_duplicates(self):
        items = [{"Id": "a", "x": 1}, {"Id": "b", "x": 2}]
        seen = set()
        result = _deduplicate_by_id(items, seen)
        assert len(result) == 2
        assert seen == {"a", "b"}

    def test_with_duplicates(self):
        items = [{"Id": "a"}, {"Id": "b"}, {"Id": "a"}]
        seen = set()
        result = _deduplicate_by_id(items, seen)
        assert len(result) == 2

    def test_pre_seen(self):
        items = [{"Id": "a"}, {"Id": "b"}]
        seen = {"a"}
        result = _deduplicate_by_id(items, seen)
        assert len(result) == 1
        assert result[0]["Id"] == "b"

    def test_non_dict_items_skipped(self):
        items = [{"Id": "a"}, "bad", None, {"Id": "b"}]
        result = _deduplicate_by_id(items, set())
        assert len(result) == 2


class TestCountByField:
    def test_empty(self):
        assert _count_by_field([], "origin") == []

    def test_counts(self):
        records = [
            {"PaymentOrigin": "Terminal"},
            {"PaymentOrigin": "Terminal"},
            {"PaymentOrigin": "Online"},
        ]
        result = _count_by_field(records, "PaymentOrigin")
        assert len(result) == 2
        # Sorted by count desc, then name asc
        assert result[0]["PaymentOrigin"] == "Terminal"
        assert result[0]["Count"] == 2
        assert result[1]["PaymentOrigin"] == "Online"
        assert result[1]["Count"] == 1

    def test_none_values(self):
        records = [{"PaymentOrigin": None}, {}]
        result = _count_by_field(records, "PaymentOrigin")
        assert len(result) == 1
        assert result[0]["PaymentOrigin"] == "None"
        assert result[0]["Count"] == 2


class TestMoneyFromExtendedAmount:
    def test_none(self):
        assert money_from_extended_amount(None) == ""

    def test_not_dict(self):
        assert money_from_extended_amount("abc") == ""

    def test_gross_value(self):
        assert money_from_extended_amount({"GrossValue": 99.5}) == "99.50"

    def test_value(self):
        assert money_from_extended_amount({"Value": 10}) == "10.00"

    def test_empty_dict(self):
        assert money_from_extended_amount({}) == ""


class TestParseIsoDuration:
    def test_none(self):
        assert parse_iso_duration(None) == "Not set"

    def test_empty_string(self):
        assert parse_iso_duration("") == "Not set"

    def test_seven_days(self):
        assert parse_iso_duration("P0M7DT0H0M0S") == "7 Days"

    def test_one_day(self):
        assert parse_iso_duration("P1D") == "1 Day"

    def test_one_month(self):
        assert parse_iso_duration("P1M") == "1 Month"

    def test_one_month_seven_days(self):
        assert parse_iso_duration("P1M7D") == "1 Month, 7 Days"

    def test_zero_duration(self):
        assert parse_iso_duration("P0D") == "0 Days"

    def test_unrecognised_returns_raw(self):
        assert parse_iso_duration("not-a-duration") == "not-a-duration"


def _minimal_data(enterprise_extra=None):
    """Return a minimal collect_data-style dict suitable for build_report."""
    ent = {"Id": "ent-1", "Name": "Test Hotel"}
    if enterprise_extra:
        ent.update(enterprise_extra)
    return {
        "cfg": {"Enterprise": ent},
        "enterprises": ["ent-1"],
        "services": [],
        "service_ids": [],
        "rate_groups": [],
        "rates": [],
        "products": [],
        "accounting_categories": [],
        "resources": [],
        "resource_categories": [],
        "resource_category_assignments": [],
        "restrictions": [],
        "availability_blocks": [],
        "rules_bundle": {},
        "payments": [],
        "payment_origin_counts_charged_90d": [],
        "payment_origin_counts_failed_90d": [],
        "cancellation_policies": [],
        "rules": [],
        "tax_environments": [],
        "taxations": [],
        "counters": [],
        "cashiers": [],
        "errors": {},
        "api_calls": [],
    }


class TestBuildReportEHW:
    def _find_check(self, report, key):
        for _sec, items in report.sections:
            for it in items:
                if it.key == key:
                    return it
        return None

    def test_ehw_shown_when_set(self):
        data = _minimal_data({"EditableHistoryInterval": "P0M7DT0H0M0S"})
        report = build_report(data, "https://api.mews-demo.com", "Test")
        item = self._find_check(report, "Editable history window (EHW)")
        assert item is not None
        assert item.status == "PASS"
        assert "7 Days" in item.summary
        assert item.details.get("EditableHistoryWindowTable") == [{"Editable History Window": "7 Days"}]

    def test_ehw_warn_when_missing(self):
        data = _minimal_data()
        report = build_report(data, "https://api.mews-demo.com", "Test")
        item = self._find_check(report, "Editable history window (EHW)")
        assert item is not None
        assert item.status == "WARN"
        assert item.risk == "High"

    def test_ehw_fallback_to_top_level_cfg(self):
        """If EditableHistoryInterval is at the top-level cfg (not under Enterprise), it should still be picked up."""
        data = _minimal_data()
        data["cfg"]["EditableHistoryInterval"] = "P1M"
        report = build_report(data, "https://api.mews-demo.com", "Test")
        item = self._find_check(report, "Editable history window (EHW)")
        assert item is not None
        assert item.status == "PASS"
        assert "1 Month" in item.summary
