import io
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, request, send_file, render_template_string, redirect, url_for, flash
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from reportlab.graphics import renderPDF
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)
from svglib.svglib import svg2rlg


# =========================================================
# CONFIG
# =========================================================

DEFAULT_BASE_URL = os.environ.get(
    "MEWS_CONNECTOR_BASE_URL",
    "https://api.mews-demo.com/api/connector/v1",
).rstrip("/")

MEWS_LOGO_SVG = "https://www.mews.com/hubfs/_Project_Phoenix/images/logo/Mews%20Logo.svg"

# Connector limitation: Limitation.Count must be 1..1000
MAX_PAGE_SIZE = 1000

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "https://samhmews.github.io").split(",")
    if o.strip()
]


# =========================================================
# MODELS
# =========================================================

@dataclass
class ApiCallResult:
    operation: str
    ok: bool
    status_code: Optional[int]
    duration_ms: int
    error: Optional[str] = None


@dataclass
class CheckItem:
    key: str
    status: str  # PASS/WARN/FAIL/NEEDS_INPUT/NA
    summary: str
    source: str = ""
    remediation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    risk: str = "Medium"  # Low/Medium/High


@dataclass
class AuditReport:
    generated_utc: datetime
    base_url: str
    client_name: str
    enterprise_id: str = ""
    enterprise_name: str = ""
    sections: List[Tuple[str, List[CheckItem]]] = field(default_factory=list)
    api_calls: List[ApiCallResult] = field(default_factory=list)


# =========================================================
# CONNECTOR CLIENT
# =========================================================

class MewsConnectorClient:
    """
    POST {base}/<resource>/<operation>
    e.g. https://api.mews-demo.com/api/connector/v1/services/getAll
    """

    def __init__(
        self,
        base_url: str,
        client_token: str,
        access_token: str,
        client_name: str = "mews-audit",
        timeout_seconds: int = 35,
    ):
        self.base_url = base_url.rstrip("/")
        self.client_token = client_token
        self.access_token = access_token
        self.client_name = client_name or "mews-audit"
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    def _post(self, resource: str, operation: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], ApiCallResult]:
        url = f"{self.base_url}/{resource}/{operation}"
        body = dict(payload or {})
        body["ClientToken"] = self.client_token
        body["AccessToken"] = self.access_token
        body["Client"] = self.client_name

        started = time.time()
        try:
            r = self.session.post(url, data=json.dumps(body), timeout=self.timeout_seconds)
            ms = int((time.time() - started) * 1000)

            if r.status_code != 200:
                err = f"HTTP {r.status_code}"
                try:
                    j = r.json()
                    if isinstance(j, dict) and j.get("Message"):
                        err = f"HTTP {r.status_code}: {j.get('Message')}"
                except Exception:
                    pass
                return {}, ApiCallResult(f"{resource}/{operation}", False, r.status_code, ms, err)

            try:
                return r.json(), ApiCallResult(f"{resource}/{operation}", True, r.status_code, ms)
            except Exception:
                return {}, ApiCallResult(f"{resource}/{operation}", False, r.status_code, ms, "Invalid JSON response")

        except requests.RequestException:
            ms = int((time.time() - started) * 1000)
            return {}, ApiCallResult(f"{resource}/{operation}", False, None, ms, "Network error")

    def paged_get_all(
        self,
        resource: str,
        operation: str,
        base_payload: Dict[str, Any],
        list_key: str,
        max_pages: int = 250,
    ) -> Tuple[List[Dict[str, Any]], List[ApiCallResult]]:
        """
        Generic pagination using Cursor.
        Ensures Limitation.Count <= 1000.
        """
        calls: List[ApiCallResult] = []
        out: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        for _ in range(max_pages):
            payload = dict(base_payload or {})
            limitation = dict(payload.get("Limitation") or {})
            limitation["Count"] = min(int(limitation.get("Count") or MAX_PAGE_SIZE), MAX_PAGE_SIZE)
            if cursor:
                limitation["Cursor"] = cursor
            payload["Limitation"] = limitation

            data, res = self._post(resource, operation, payload)
            calls.append(res)
            if not res.ok:
                break

            batch = data.get(list_key) or []
            if isinstance(batch, list) and batch:
                out.extend([x for x in batch if isinstance(x, dict)])

            cursor = data.get("Cursor")
            if not cursor or not isinstance(batch, list) or len(batch) == 0:
                break

        return out, calls

    def post(self, resource: str, operation: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], ApiCallResult]:
        return self._post(resource, operation, payload)


# =========================================================
# HELPERS
# =========================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

def time_window(days: int) -> Dict[str, str]:
    end = utc_now()
    start = end - timedelta(days=days)
    return {"StartUtc": iso(start), "EndUtc": iso(end)}

def pick_name(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ""
    s = (obj.get("Name") or "").strip()
    if s:
        return s
    names = obj.get("Names")
    if isinstance(names, dict):
        for v in names.values():
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""

def esc(s: Any) -> str:
    s = str(s or "")
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def yn(v: Any) -> str:
    if v is True:
        return "Yes"
    if v is False:
        return "No"
    return ""

def fetch_logo(max_width_mm: float = 38):
    try:
        r = requests.get(MEWS_LOGO_SVG, timeout=10)
        if r.status_code != 200:
            return None
        drawing = svg2rlg(io.BytesIO(r.content))
        if not drawing:
            return None
        max_w = max_width_mm * mm
        if drawing.width and drawing.width > max_w:
            scale = max_w / float(drawing.width)
            drawing.scale(scale, scale)
            drawing.width *= scale
            drawing.height *= scale
        return drawing
    except Exception:
        return None

def status_colour(status: str):
    s = (status or "").upper()
    if s == "PASS":
        return colors.HexColor("#0f7b37")
    if s == "FAIL":
        return colors.HexColor("#b91c1c")
    if s == "WARN":
        return colors.HexColor("#b45309")
    if s == "NEEDS_INPUT":
        return colors.HexColor("#4f46e5")
    return colors.grey

def badge(status: str) -> str:
    col = status_colour(status).hexval()
    return f"<font color='{col}'><b>{esc(status)}</b></font>"

def chunk_list(rows: List[Any], chunk_size: int) -> List[List[Any]]:
    if chunk_size <= 0:
        return [rows]
    return [rows[i:i + chunk_size] for i in range(0, len(rows), chunk_size)]

def rate_flags(r: Dict[str, Any]) -> str:
    bits = []
    if r.get("Code"):
        bits.append(f"Code={r.get('Code')}")
    if r.get("Type"):
        bits.append(f"Type={r.get('Type')}")
    if r.get("IsPublic") is not None:
        bits.append(f"Public={yn(r.get('IsPublic'))}")
    if r.get("IsPrivate") is not None:
        bits.append(f"Private={yn(r.get('IsPrivate'))}")
    if r.get("IsActive") is not None:
        bits.append(f"Active={yn(r.get('IsActive'))}")
    if r.get("IsEnabled") is not None:
        bits.append(f"Enabled={yn(r.get('IsEnabled'))}")
    if r.get("IsDefault") is not None:
        bits.append(f"Default={yn(r.get('IsDefault'))}")
    if r.get("ExternalIdentifier"):
        bits.append(f"ExtId={r.get('ExternalIdentifier')}")
    return ", ".join(bits)


# =========================================================
# DATA COLLECTION
# =========================================================

def collect_data(mc: MewsConnectorClient, report: AuditReport) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    def add_calls(calls: List[ApiCallResult]):
        report.api_calls.extend(calls)

    def add_call(call: ApiCallResult):
        report.api_calls.append(call)

    # Configuration
    cfg, call = mc.post("Configuration", "Get", {})
    add_call(call)
    data["configuration"] = cfg if call.ok else {"_error": call.error, "_status": call.status_code}

    # Services
    services, calls = mc.paged_get_all("Services", "GetAll", {"Limitation": {"Count": 1000}}, "Services")
    add_calls(calls)
    data["services"] = services
    service_ids = [s.get("Id") for s in services if s.get("Id")]

    # Tax
    tax_envs, calls = mc.paged_get_all("TaxEnvironments", "GetAll", {"Limitation": {"Count": 1000}}, "TaxEnvironments")
    add_calls(calls)
    data["tax_environments"] = tax_envs

    taxations, calls = mc.paged_get_all("Taxations", "GetAll", {"Limitation": {"Count": 1000}}, "Taxations")
    add_calls(calls)
    data["taxations"] = taxations

    # Products + categories
    prod_payload = {"Limitation": {"Count": 1000}}
    cat_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        prod_payload["ServiceIds"] = service_ids[:1000]
        cat_payload["ServiceIds"] = service_ids[:1000]

    products, calls = mc.paged_get_all("Products", "GetAll", prod_payload, "Products")
    add_calls(calls)
    data["products"] = products

    product_categories, calls = mc.paged_get_all("ProductCategories", "GetAll", cat_payload, "ProductCategories")
    add_calls(calls)
    data["product_categories"] = product_categories

    # Rules
    rules_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        rules_payload["ServiceIds"] = service_ids[:1000]
    rules, calls = mc.paged_get_all("Rules", "GetAll", rules_payload, "Rules")
    add_calls(calls)
    data["rules"] = rules

    # Accounting
    acc_cats, calls = mc.paged_get_all("AccountingCategories", "GetAll", {"Limitation": {"Count": 1000}}, "AccountingCategories")
    add_calls(calls)
    data["accounting_categories"] = acc_cats

    cashiers, calls = mc.paged_get_all("Cashiers", "GetAll", {"Limitation": {"Count": 1000}}, "Cashiers")
    add_calls(calls)
    data["cashiers"] = cashiers

    counters, calls = mc.paged_get_all("Counters", "GetAll", {"Limitation": {"Count": 1000}}, "Counters")
    add_calls(calls)
    data["counters"] = counters

    # Payments (30d sample)
    payments, calls = mc.paged_get_all(
        "Payments",
        "GetAll",
        {"CreatedUtc": time_window(30), "Limitation": {"Count": 1000}},
        "Payments",
    )
    add_calls(calls)
    data["payments"] = payments

    # Inventory
    resources, calls = mc.paged_get_all("Resources", "GetAll", {"Limitation": {"Count": 1000}}, "Resources")
    add_calls(calls)
    data["resources"] = resources

    rc_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        rc_payload["ServiceIds"] = service_ids[:1000]
    resource_categories, calls = mc.paged_get_all("ResourceCategories", "GetAll", rc_payload, "ResourceCategories")
    add_calls(calls)
    data["resource_categories"] = resource_categories

    rca_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        rca_payload["ServiceIds"] = service_ids[:1000]
    rca, calls = mc.paged_get_all("ResourceCategoryAssignments", "GetAll", rca_payload, "ResourceCategoryAssignments")
    add_calls(calls)
    data["resource_category_assignments"] = rca

    # Rates + groups
    rates, calls = mc.paged_get_all("Rates", "GetAll", {"Limitation": {"Count": 1000}}, "Rates")
    add_calls(calls)
    data["rates"] = rates

    rg_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        rg_payload["ServiceIds"] = service_ids[:1000]
    rate_groups, calls = mc.paged_get_all("RateGroups", "GetAll", rg_payload, "RateGroups")
    add_calls(calls)
    data["rate_groups"] = rate_groups

    # Restrictions
    restr_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        restr_payload["ServiceIds"] = service_ids[:1000]
    restrictions, calls = mc.paged_get_all("Restrictions", "GetAll", restr_payload, "Restrictions")
    add_calls(calls)
    data["restrictions"] = restrictions

    # CancellationPolicies (restricted beta; may be empty)
    cp_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        cp_payload["ServiceIds"] = service_ids[:1000]
    cancellation_policies, calls = mc.paged_get_all("CancellationPolicies", "GetAll", cp_payload, "CancellationPolicies")
    add_calls(calls)
    data["cancellation_policies"] = cancellation_policies

    return data


# =========================================================
# DERIVATIONS
# =========================================================

def map_accounting_categories_to_products(
    accounting_categories: List[Dict[str, Any]],
    products: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    cat_by_id = {c.get("Id"): c for c in accounting_categories if c.get("Id")}
    buckets: Dict[str, List[Dict[str, Any]]] = {}

    for p in products:
        acc_id = p.get("AccountingCategoryId") or "UNMAPPED"
        buckets.setdefault(acc_id, []).append(p)

    out = []
    for acc_id, plist in buckets.items():
        cat = cat_by_id.get(acc_id)
        out.append(
            {
                "AccountingCategoryId": acc_id,
                "AccountingCategoryName": pick_name(cat) or ("UNMAPPED" if acc_id == "UNMAPPED" else acc_id),
                "Products": sorted(
                    [
                        {
                            "Id": p.get("Id"),
                            "Name": pick_name(p) or (p.get("Name") or ""),
                            "Code": p.get("Code") or "",
                            "IsActive": p.get("IsActive"),
                            "Type": p.get("Type") or "",
                            "ProductCategoryId": p.get("ProductCategoryId") or "",
                        }
                        for p in plist
                    ],
                    key=lambda x: x["Name"],
                ),
            }
        )
    out.sort(key=lambda x: x["AccountingCategoryName"])
    return out


def map_spaces_by_category(
    resources: List[Dict[str, Any]],
    resource_categories: List[Dict[str, Any]],
    assignments: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    cat_by_id = {c.get("Id"): c for c in resource_categories if c.get("Id")}
    res_by_id = {r.get("Id"): r for r in resources if r.get("Id")}

    res_to_cat: Dict[str, List[str]] = {}
    for a in assignments:
        rid = a.get("ResourceId")
        cid = a.get("ResourceCategoryId")
        if rid and cid:
            res_to_cat.setdefault(rid, []).append(cid)

    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for rid, r in res_by_id.items():
        cids = res_to_cat.get(rid) or ["UNASSIGNED"]
        for cid in cids:
            buckets.setdefault(cid, []).append(r)

    out = []
    for cid, rlist in buckets.items():
        cat = cat_by_id.get(cid)
        out.append(
            {
                "ResourceCategoryId": cid,
                "ResourceCategoryName": pick_name(cat) or ("UNASSIGNED" if cid == "UNASSIGNED" else cid),
                "Type": cat.get("Type") if isinstance(cat, dict) else "",
                "Resources": sorted(
                    [
                        {"Id": r.get("Id"), "Name": r.get("Name") or "", "IsActive": r.get("IsActive"), "State": r.get("State") or ""}
                        for r in rlist
                    ],
                    key=lambda x: x["Name"],
                ),
            }
        )
    out.sort(key=lambda x: x["ResourceCategoryName"])
    return out


def build_rate_index(rates: List[Dict[str, Any]], rate_groups: List[Dict[str, Any]]) -> Dict[str, Any]:
    rg_by_id = {g.get("Id"): g for g in rate_groups if g.get("Id")}
    rate_by_id = {r.get("Id"): r for r in rates if r.get("Id")}

    def rate_label(r: Dict[str, Any]) -> str:
        return pick_name(r) or (r.get("Code") or "") or (r.get("Id") or "")

    rates_by_group: Dict[str, List[Dict[str, Any]]] = {}
    for r in rates:
        gid = r.get("GroupId") or "NO_GROUP"
        rates_by_group.setdefault(gid, []).append(r)

    def rate_rich(r: Dict[str, Any]) -> Dict[str, Any]:
        gid = r.get("GroupId")
        return {
            "Id": r.get("Id"),
            "Name": rate_label(r),
            "Code": r.get("Code") or "",
            "GroupId": gid or "",
            "GroupName": pick_name(rg_by_id.get(gid)) if gid in rg_by_id else "",
            "BaseRateId": r.get("BaseRateId") or "",
            "IsBaseRate": r.get("IsBaseRate"),
            "IsActive": r.get("IsActive"),
            "IsEnabled": r.get("IsEnabled"),
            "IsPublic": r.get("IsPublic"),
            "IsPrivate": r.get("IsPrivate"),
            "IsDefault": r.get("IsDefault"),
            "Type": r.get("Type") or "",
            "ExternalIdentifier": r.get("ExternalIdentifier") or "",
            "ShortName": r.get("ShortName") or "",
        }

    groups_out = []
    for gid, group_rates in rates_by_group.items():
        gname = pick_name(rg_by_id.get(gid)) if gid in rg_by_id else ("NO_GROUP" if gid == "NO_GROUP" else gid)

        base_rates = [r for r in group_rates if r.get("IsBaseRate") or (r.get("Type") == "Base")]
        derived = [r for r in group_rates if r.get("BaseRateId")]

        derived_by_base: Dict[str, List[Dict[str, Any]]] = {}
        for r in derived:
            derived_by_base.setdefault(r.get("BaseRateId"), []).append(r)

        tree = []
        for br in sorted(base_rates, key=rate_label):
            br_id = br.get("Id")
            tree.append({"Base": rate_rich(br), "Derived": [rate_rich(x) for x in sorted(derived_by_base.get(br_id, []), key=rate_label)]})

        orphans = []
        for r in derived:
            if r.get("BaseRateId") not in rate_by_id:
                orphans.append(rate_rich(r))

        misc = []
        for r in group_rates:
            if (r not in base_rates) and (not r.get("BaseRateId")) and (r.get("Type") != "Base"):
                misc.append(rate_rich(r))

        groups_out.append(
            {"RateGroupId": gid, "RateGroupName": gname, "Tree": tree, "Orphans": sorted(orphans, key=lambda x: x["Name"]), "Misc": sorted(misc, key=lambda x: x["Name"]), "RateCount": len(group_rates)}
        )

    groups_out.sort(key=lambda x: x["RateGroupName"])
    return {"RateGroups": groups_out}


def map_cancellation_policies(cancellation_policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_group: Dict[str, List[Dict[str, Any]]] = {}
    for p in cancellation_policies:
        rg_ids = p.get("RateGroupIds") or p.get("RateGroups") or []
        if not isinstance(rg_ids, list) or not rg_ids:
            by_group.setdefault("UNMAPPED", []).append(p)
            continue
        for gid in rg_ids:
            if gid:
                by_group.setdefault(gid, []).append(p)

    def policy_brief(p: Dict[str, Any]) -> Dict[str, Any]:
        desc = p.get("Description") or ""
        descriptions = p.get("Descriptions")
        if isinstance(descriptions, dict):
            for v in descriptions.values():
                if isinstance(v, str) and v.strip():
                    desc = v.strip()
                    break
        return {"Id": p.get("Id") or "", "Name": pick_name(p) or (p.get("Name") or ""), "Type": p.get("Type") or "", "Description": desc or ""}

    return {gid: [policy_brief(p) for p in plist] for gid, plist in by_group.items()}


def describe_restrictions(restrictions: List[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for x in restrictions:
        cond = x.get("Conditions") or {}
        parts = [f"RestrictionId={x.get('Id')}"]
        start = x.get("StartUtc") or ""
        end = x.get("EndUtc") or ""
        if start or end:
            parts.append(f"Active={start} → {end}")
        if cond.get("ResourceCategoryId"):
            parts.append(f"ResourceCategoryId={cond.get('ResourceCategoryId')}")
        if cond.get("RateGroupId"):
            parts.append(f"RateGroupId={cond.get('RateGroupId')}")
        if cond.get("ExactRateId") or cond.get("RateId"):
            parts.append(f"RateId={cond.get('ExactRateId') or cond.get('RateId')}")
        if cond.get("BaseRateId"):
            parts.append(f"BaseRateId={cond.get('BaseRateId')}")

        rules = []
        for k in ("ClosedToArrival", "ClosedToDeparture", "IsClosed", "Closed"):
            if k in cond and cond.get(k) is not None:
                rules.append(f"{k}={cond.get(k)}")
        for k in ("MinimumLength", "MaximumLength", "MinLength", "MaxLength"):
            if k in cond and cond.get(k) is not None:
                rules.append(f"{k}={cond.get(k)}")
        if cond.get("Days"):
            rules.append(f"Days={cond.get('Days')}")
        if cond.get("ArrivalDays"):
            rules.append(f"ArrivalDays={cond.get('ArrivalDays')}")
        if rules:
            parts.append("Rules: " + "; ".join(rules))
        lines.append(" | ".join(parts))
    return lines


# =========================================================
# REPORT BUILD (ALL SECTIONS)
# =========================================================

SECTION_ORDER = [
    "Legal & property baseline",
    "Users, access & security",
    "Accounting configuration",
    "Payments setup & reconciliation",
    "Inventory, rates & revenue structure",
    "Guest journey & operations",
    "Reporting, BI & data quality",
    "Integrations & automations",
    "Training, governance & ownership",
]


def build_report(base_url: str, client_name: str, data: Dict[str, Any], api_calls: List[ApiCallResult]) -> AuditReport:
    report = AuditReport(generated_utc=utc_now(), base_url=base_url, client_name=client_name, api_calls=api_calls)

    cfg = data.get("configuration")
    if isinstance(cfg, dict) and "_error" not in cfg:
        ent = cfg.get("Enterprise") or {}
        report.enterprise_id = ent.get("Id") or ""
        report.enterprise_name = ent.get("Name") or ""

    products = data.get("products", [])
    accounting_categories = data.get("accounting_categories", [])
    payments = data.get("payments", [])
    rates = data.get("rates", [])
    rate_groups = data.get("rate_groups", [])
    restrictions = data.get("restrictions", [])
    cancellation_policies = data.get("cancellation_policies", [])
    resources = data.get("resources", [])
    resource_categories = data.get("resource_categories", [])
    rca = data.get("resource_category_assignments", [])
    rules = data.get("rules", [])
    tax_envs = data.get("tax_environments", [])
    taxations = data.get("taxations", [])
    counters = data.get("counters", [])
    cashiers = data.get("cashiers", [])

    acc_breakdown = map_accounting_categories_to_products(accounting_categories, products)
    spaces_by_cat = map_spaces_by_category(resources, resource_categories, rca)
    rate_index = build_rate_index(rates, rate_groups)
    cancellation_by_group = map_cancellation_policies(cancellation_policies) if cancellation_policies else {}
    restriction_lines = describe_restrictions(restrictions)

    # Legal
    legal_items: List[CheckItem] = []
    tz = (cfg.get("Enterprise") or {}).get("TimeZone") if isinstance(cfg, dict) else None
    currency = (cfg.get("Enterprise") or {}).get("DefaultCurrency") if isinstance(cfg, dict) else None
    pricing_mode = cfg.get("PricingMode") if isinstance(cfg, dict) else None

    legal_items.append(CheckItem("Time zone", "PASS" if tz else "WARN", str(tz or "Not identified"), "Connector: Configuration/Get", "Set enterprise/property time zone in Mews if missing.", {}, "High" if not tz else "Low"))
    legal_items.append(CheckItem("Default currency", "PASS" if currency else "WARN", str(currency or "Not identified"), "Connector: Configuration/Get", "Ensure a default currency is set at enterprise level.", {}, "High" if not currency else "Low"))
    legal_items.append(CheckItem("Pricing mode (gross/net)", "PASS" if pricing_mode else "NEEDS_INPUT", str(pricing_mode or "Not exposed; confirm in UI"), "Connector: Configuration/Get", "Confirm whether pricing is gross or net in Mews.", {}, "Medium"))
    legal_items.append(CheckItem("Tax environment + VAT/GST rates", "PASS" if (tax_envs or taxations) else "WARN", f"TaxEnvironments={len(tax_envs)}, Taxations={len(taxations)}", "Connector: TaxEnvironments/GetAll + Taxations/GetAll", "Validate tax environment selection and tax codes match jurisdiction.", {"TaxEnvironments": tax_envs[:200], "Taxations": taxations[:500]}, "High" if not tax_envs else "Medium"))

    city_like = [p for p in products if "city" in (pick_name(p) or "").lower() and "tax" in (pick_name(p) or "").lower()]
    legal_items.append(CheckItem("City tax product + rule", "WARN" if not city_like else "PASS", f"City-tax-like products found: {len(city_like)}; Rules: {len(rules)}", "Connector: Products/GetAll + Rules/GetAll", "If city tax is required, ensure a dedicated product exists and is applied consistently (often via rule).", {"CityTaxCandidates": [{"Id": p.get("Id"), "Name": pick_name(p), "Code": p.get("Code") or ""} for p in city_like[:200]]}, "Medium"))
    legal_items.append(CheckItem("Fiscalisation (where relevant)", "NEEDS_INPUT", "Connector cannot reliably confirm fiscalisation requirements; confirm in Mews UI / local compliance docs.", "Workaround: manual evidence", "Document the fiscalisation requirement for jurisdiction and confirm Mews settings/provider configuration.", {}, "High"))

    # Users
    users_items: List[CheckItem] = [
        CheckItem("User list & roles / departments", "NEEDS_INPUT", "Not exposed via Connector. Requires manual export from Mews UI.", "Not available via Connector", "Export users and review active staff, roles, generic/shared logins, department mapping.", {}, "High"),
        CheckItem("2FA / passkeys adoption", "NEEDS_INPUT", "Not exposed via Connector. Validate via IdP/Mews UI.", "Not available via Connector", "Verify MFA enforcement for admins and secure/disable accounts lacking strong auth.", {}, "High"),
        CheckItem("SSO / SCIM enforcement", "NEEDS_INPUT", "Not exposed via Connector. Validate in IdP + Mews settings.", "Not available via Connector", "Confirm SSO enforcement and SCIM provisioning state (where used).", {}, "Medium"),
        CheckItem("Auditability (permission/history windows)", "NEEDS_INPUT", "Not exposed via Connector. Confirm audit settings in UI.", "Not available via Connector", "Set history windows to support traceability and change audits.", {}, "Medium"),
    ]

    # Accounting
    accounting_items: List[CheckItem] = []
    accounting_items.append(CheckItem("Accounting categories (structure)", "PASS" if accounting_categories else "WARN", f"Accounting categories returned: {len(accounting_categories)}", "Connector: AccountingCategories/GetAll", "Confirm separation of revenue/payments/taxes/deposits/fees aligns with accounting design.", {}, "High" if not accounting_categories else "Medium"))
    accounting_items.append(CheckItem("Accounting categories → product mapping (full detail)", "PASS" if acc_breakdown else "WARN", f"Categories with mapped products: {len(acc_breakdown)}", "Connector: AccountingCategories/GetAll + Products/GetAll", "Validate product allocations per accounting category; correct mis-allocations.", {"AccountingCategoryBreakdown": acc_breakdown}, "High"))
    accounting_items.append(CheckItem("Cash / counters", "PASS" if (cashiers or counters) else "WARN", f"Cashiers={len(cashiers)}, Counters={len(counters)}", "Connector: Cashiers/GetAll + Counters/GetAll", "Ensure cashiers are assigned and counters/numbering comply with local rules.", {}, "Medium"))
    accounting_items.append(CheckItem("Payment types mapping (Mews + external)", "NEEDS_INPUT", "Connector provides payments but not full mapping of gateway/terminal types to accounting categories.", "Partial via Connector; mapping requires UI review", "Review payment methods and accounting mapping in Mews and downstream export tooling.", {}, "High"))
    accounting_items.append(CheckItem("Ledgers design (guest vs deposit vs AR/TA)", "NEEDS_INPUT", "Ledger design and export design are not fully exposed via Connector.", "Workaround: manual evidence", "Document ledger strategy and validate export mappings (Omniboost/Sun/Dynamics/Xero/etc.).", {}, "High"))

    # Payments
    payments_items: List[CheckItem] = []
    payments_items.append(CheckItem("Payments (last 30 days sample)", "PASS", f"Payments retrieved: {len(payments)}", "Connector: Payments/GetAll (CreatedUtc 30d window)", "If empty, verify token scope/permissions or adjust window.", {"Payments": payments}, "Low"))
    payments_items.append(CheckItem("KYC & Mews Payments onboarding", "NEEDS_INPUT", "Not exposed via Connector. Confirm in Mews Payments UI.", "Not available via Connector", "Provide evidence of KYC status, payout configuration and multi-currency accounts (where used).", {}, "High"))
    payments_items.append(CheckItem("Share of Wallet (SoW) + automation", "NEEDS_INPUT", "SoW and scheduled payment policies are not fully exposed via Connector.", "Partial via payments data; policy requires UI", "Use payments for indicative SoW; confirm scheduled payments and policies in Mews UI.", {}, "Medium"))
    payments_items.append(CheckItem("Reconciliation flows (payouts/fees into GL)", "NEEDS_INPUT", "Payouts/fees reconciliation not exposed via Connector. Requires statements + export review.", "Not available via Connector", "Upload payout/fee statements and document reconciliation steps; align with export mappings.", {}, "High"))

    # Inventory/Rates
    inv_items: List[CheckItem] = []
    inv_items.append(CheckItem("Space categories → spaces (full detail)", "PASS" if spaces_by_cat else "WARN", f"Space category groups: {len(spaces_by_cat)} (includes UNASSIGNED if mapping missing).", "Connector: Resources/GetAll + ResourceCategories/GetAll + ResourceCategoryAssignments/GetAll", "Ensure each space belongs to the correct category; investigate any UNASSIGNED spaces.", {"SpacesByCategory": spaces_by_cat}, "High"))
    inv_items.append(CheckItem("Rates (ALL) grouped by Rate Group and Base Rate", "PASS" if rates else "WARN", f"Rates={len(rates)}, RateGroups={len(rate_groups)}", "Connector: Rates/GetAll + RateGroups/GetAll", "Validate base/derived structure, group membership, and flags (public/private/active/enabled/default).", {"RateIndex": rate_index}, "High"))
    inv_items.append(CheckItem("Cancellation policy per Rate Group (best available)", "PASS" if cancellation_policies else "NEEDS_INPUT", (f"CancellationPolicies returned: {len(cancellation_policies)}" if cancellation_policies else "CancellationPolicies/GetAll not available for this token (restricted). Confirm in UI."), "Connector: CancellationPolicies/GetAll (restricted; may be empty)", "If unavailable, export/capture policies from Mews UI; ensure each Rate Group’s policy matches intent.", {"CancellationPoliciesByRateGroup": cancellation_by_group}, "High"))
    inv_items.append(CheckItem("Restrictions & seasonality (descriptive)", "PASS" if restrictions else "WARN", f"Restrictions returned: {len(restrictions)}", "Connector: Restrictions/GetAll", "Confirm restrictions are purposeful and applied to correct scope and periods; remove stale rules.", {"RestrictionLines": restriction_lines}, "Medium"))
    inv_items.append(CheckItem("Channel manager / CRS mapping", "NEEDS_INPUT", "CHM/CRS mappings are not exposed via Connector alone.", "Not available via Connector", "Validate mapping in channel manager and identify gaps/double posting.", {}, "High"))

    # Guest journey
    ops_items: List[CheckItem] = [
        CheckItem("Booking flows + booking engine config", "NEEDS_INPUT", "Booking engine config not exposed via Connector.", "Not available via Connector", "Review IBE settings, branding and rules in UI and distribution stack.", {}, "Medium"),
        CheckItem("Availability blocks / groups / events usage", "NEEDS_INPUT", "Event/group configuration not fully exposed via Connector in this audit scope.", "Workaround: manual evidence", "Review group blocks and event workflows; confirm integrations use correct identifiers.", {}, "Medium"),
        CheckItem("Online check-in / guest portal / comms templates", "NEEDS_INPUT", "OCI and messaging templates not exposed via Connector.", "Not available via Connector", "Audit templates and merge tags in UI; test end-to-end guest journey.", {}, "Medium"),
        CheckItem("Housekeeping & maintenance", "NEEDS_INPUT", "Housekeeping configuration/integrations not exposed via Connector for full audit.", "Not available via Connector", "Review housekeeping configuration and status-driven automations in UI.", {}, "Medium"),
    ]

    # Reporting
    reporting_items: List[CheckItem] = [
        CheckItem("Core reports usage (Reservations/Manager/Accounting)", "NEEDS_INPUT", "Report configuration not exposed via Connector.", "Not available via Connector", "Confirm filters, totals mode, and cut-off logic align with finance operations.", {}, "High"),
        CheckItem("BI & analytics (segments/channels/markets)", "NEEDS_INPUT", "BI dashboards/config not exposed via Connector.", "Not available via Connector", "Define segments/channels/markets cleanly; avoid misuse of accounting categories for analysis.", {}, "Medium"),
        CheckItem("Error patterns (rebates/manual corrections/write-offs)", "NEEDS_INPUT", "Requires exports + operational context; not derived solely via Connector in this script.", "Workaround: export + analysis", "Review patterns via exports; redesign configuration where systematic issues are found.", {}, "Medium"),
    ]

    # Integrations
    integrations_items: List[CheckItem] = [
        CheckItem("Marketplace stack (CHM/POS/RMS/key/CRM/vouchers/messaging)", "NEEDS_INPUT", "Integration mapping health not exposed via Connector alone.", "Workaround: integration config + logs", "Review mappings and identify double-posting, gaps, broken mappings.", {}, "High"),
        CheckItem("Accounting & data exports (Omniboost/Sun/Dynamics/Xero/custom)", "NEEDS_INPUT", "Export cadence and failure handling not exposed via Connector alone.", "Workaround: export tool logs", "Validate mapping correctness, cadence, failure alerts, recovery process.", {}, "High"),
        CheckItem("Automation tooling (Zapier/Power Automate/custom workflows)", "NEEDS_INPUT", "Automation governance/monitoring not exposed via Connector.", "Workaround: workflow inventory", "Create automation register, monitoring plan, alerting and ownership.", {}, "Medium"),
    ]

    # Governance
    governance_items: List[CheckItem] = [
        CheckItem("Training coverage (Mews University)", "NEEDS_INPUT", "Training completion not exposed via Connector.", "Not available via Connector", "Collect completion evidence for key personas; align training with responsibilities.", {}, "Medium"),
        CheckItem("Process ownership & change governance", "NEEDS_INPUT", "Governance practices are organisational; not exposed via Connector.", "Workaround: RACI / governance docs", "Nominate a champion; establish evaluation, rollout and review process.", {}, "Medium"),
        CheckItem("Artifacts (SOPs/finance playbooks/rate governance rules)", "NEEDS_INPUT", "Documents are external to Connector scope.", "Workaround: document review", "Compare SOPs to live configuration; update and version-control artefacts.", {}, "Medium"),
    ]

    section_map = {
        "Legal & property baseline": legal_items,
        "Users, access & security": users_items,
        "Accounting configuration": accounting_items,
        "Payments setup & reconciliation": payments_items,
        "Inventory, rates & revenue structure": inv_items,
        "Guest journey & operations": ops_items,
        "Reporting, BI & data quality": reporting_items,
        "Integrations & automations": integrations_items,
        "Training, governance & ownership": governance_items,
    }

    report.sections = [(name, section_map[name]) for name in SECTION_ORDER]
    return report


# =========================================================
# PDF GENERATION (SAFE TABLES)
# =========================================================

def build_pdf(report: AuditReport) -> bytes:
    buf = io.BytesIO()

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleX", parent=styles["Title"], fontSize=20, leading=24, alignment=TA_CENTER, spaceAfter=10))
    styles.add(ParagraphStyle(name="H1X", parent=styles["Heading1"], fontSize=15, leading=18, spaceBefore=10, spaceAfter=6))
    styles.add(ParagraphStyle(name="BodyX", parent=styles["BodyText"], fontSize=9.6, leading=12))
    styles.add(ParagraphStyle(name="SmallX", parent=styles["BodyText"], fontSize=8.6, leading=11))
    styles.add(ParagraphStyle(name="TinyX", parent=styles["BodyText"], fontSize=8.1, leading=10))

    logo = fetch_logo()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=14 * mm,
        title="Mews Configuration Audit Report",
        author="Mews Audit Web App",
    )

    def P(text: Any, style_name: str = "TinyX") -> Paragraph:
        return Paragraph(esc(text), styles[style_name])

    def make_long_table(header: List[str], rows: List[List[Any]], col_widths: List[float]) -> LongTable:
        table_data: List[List[Any]] = [[P(h, "SmallX") for h in header]]
        for r in rows:
            table_data.append([c if isinstance(c, Paragraph) else P(c, "TinyX") for c in r])

        t = LongTable(table_data, colWidths=col_widths, repeatRows=1)
        ts = TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
        # zebra only for existing rows
        row_count = len(table_data)
        for i in range(1, row_count):
            if i % 2 == 0:
                ts.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8fafc"))
        t.setStyle(ts)
        return t

    def header_footer(canvas, doc_):
        canvas.saveState()
        y = A4[1] - 12 * mm
        if logo:
            renderPDF.draw(logo, canvas, 16 * mm, y - (logo.height or 0))
            canvas.setFont("Helvetica-Bold", 12.5)
            canvas.drawString(16 * mm + 44 * mm, y - 3 * mm, "Mews Configuration Audit Report")
        else:
            canvas.setFont("Helvetica-Bold", 12.5)
            canvas.drawString(16 * mm, y - 3 * mm, "Mews Configuration Audit Report")

        canvas.setFont("Helvetica", 8.5)
        canvas.drawRightString(A4[0] - 16 * mm, y - 3 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    story: List[Any] = []
    story.append(Spacer(1, 16))
    story.append(Paragraph("Mews Configuration Audit Report", styles["TitleX"]))
    story.append(Paragraph(
        f"<b>Enterprise:</b> {esc(report.enterprise_name or 'Unknown')} &nbsp;&nbsp; "
        f"<b>EnterpriseId:</b> {esc(report.enterprise_id or 'Unknown')}<br/>"
        f"<b>Generated (UTC):</b> {esc(report.generated_utc.strftime('%d/%m/%Y %H:%M'))} &nbsp;&nbsp; "
        f"<b>Base URL:</b> {esc(report.base_url)} &nbsp;&nbsp; "
        f"<b>Client:</b> {esc(report.client_name)}",
        styles["BodyX"]
    ))
    story.append(Spacer(1, 10))

    # Summary counts
    total = 0
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "NEEDS_INPUT": 0, "NA": 0}
    for _, items in report.sections:
        for it in items:
            total += 1
            k = (it.status or "").upper()
            counts[k] = counts.get(k, 0) + 1

    story.append(Paragraph("Executive summary", styles["H1X"]))
    story.append(Paragraph(
        f"Total checks: <b>{total}</b> &nbsp;&nbsp; "
        f"PASS: <b>{counts['PASS']}</b> &nbsp;&nbsp; "
        f"WARN: <b>{counts['WARN']}</b> &nbsp;&nbsp; "
        f"FAIL: <b>{counts['FAIL']}</b> &nbsp;&nbsp; "
        f"NEEDS_INPUT: <b>{counts['NEEDS_INPUT']}</b> &nbsp;&nbsp; "
        f"NA: <b>{counts['NA']}</b>",
        styles["BodyX"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report is generated from the Mews Connector API. Items marked <b>NEEDS_INPUT</b> require manual confirmation where the API does not expose the relevant configuration.",
        styles["SmallX"]
    ))
    story.append(PageBreak())

    # Detailed sections
    for sec_name, items in report.sections:
        story.append(Paragraph(esc(sec_name), styles["H1X"]))
        story.append(Spacer(1, 6))

        for it in items:
            block: List[Any] = []
            block.append(Paragraph(f"<b>{esc(it.key)}</b> &nbsp;&nbsp; {badge(it.status)} &nbsp;&nbsp; <font color='#64748b'>Risk:</font> <b>{esc(it.risk)}</b>", styles["BodyX"]))
            block.append(Paragraph(esc(it.summary or "-"), styles["BodyX"]))
            block.append(Spacer(1, 4))

            details = it.details or {}

            # Accounting mapping table
            if "AccountingCategoryBreakdown" in details:
                cats = details.get("AccountingCategoryBreakdown") or []
                rows = []
                for cat in cats:
                    cname = cat.get("AccountingCategoryName") or ""
                    cid = cat.get("AccountingCategoryId") or ""
                    prods = cat.get("Products") or []
                    if not prods:
                        rows.append([P(f"{cname} ({cid})"), P("—"), P("—"), P("—"), P("—")])
                        continue
                    for p in prods:
                        rows.append([P(f"{cname} ({cid})"), P(p.get("Name") or ""), P(p.get("Code") or ""), P(yn(p.get("IsActive"))), P(p.get("Type") or "")])
                header = ["Accounting category", "Product", "Code", "Active", "Type"]
                colw = [52*mm, 72*mm, 18*mm, 14*mm, 24*mm]
                block.append(Paragraph("<b>Detail: Accounting category mappings</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 350):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Payments table
            if "Payments" in details:
                pays = details.get("Payments") or []
                rows = []
                for p in pays:
                    amt = p.get("Amount") or {}
                    rows.append([P(p.get("Id") or ""), P(p.get("Type") or ""), P(p.get("State") or ""), P(amt.get("Currency") or p.get("Currency") or ""), P(str(amt.get("NetValue") or "")), P(str(amt.get("GrossValue") or "")), P(p.get("CreatedUtc") or "")])
                header = ["PaymentId", "Type", "State", "Curr", "Net", "Gross", "CreatedUtc"]
                colw = [38*mm, 22*mm, 16*mm, 10*mm, 16*mm, 16*mm, 44*mm]
                block.append(Paragraph("<b>Detail: Payments (30-day sample)</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 300):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Spaces table
            if "SpacesByCategory" in details:
                cats = details.get("SpacesByCategory") or []
                rows = []
                for cat in cats:
                    cname = cat.get("ResourceCategoryName") or ""
                    cid = cat.get("ResourceCategoryId") or ""
                    ctype = cat.get("Type") or ""
                    res = cat.get("Resources") or []
                    if not res:
                        rows.append([P(f"{cname} ({cid})"), P(ctype), P("—"), P("—"), P("—")])
                        continue
                    for r in res:
                        rows.append([P(f"{cname} ({cid})"), P(ctype), P(r.get("Name") or ""), P(yn(r.get("IsActive"))), P(r.get("State") or "")])
                header = ["Space category", "Cat type", "Space", "Active", "State"]
                colw = [52*mm, 18*mm, 74*mm, 14*mm, 22*mm]
                block.append(Paragraph("<b>Detail: Space categories and spaces</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 350):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Rates table
            if "RateIndex" in details:
                rgroups = (details.get("RateIndex") or {}).get("RateGroups") or []
                rows = []
                for g in rgroups:
                    gname = g.get("RateGroupName") or ""
                    gid = g.get("RateGroupId") or ""
                    for node in (g.get("Tree") or []):
                        base = node.get("Base") or {}
                        rows.append([P(f"{gname} ({gid})"), P("Base"), P(base.get("Name") or ""), P(base.get("Id") or ""), P(""), P(rate_flags(base))])
                        for d in (node.get("Derived") or []):
                            rows.append([P(f"{gname} ({gid})"), P("Derived"), P(d.get("Name") or ""), P(d.get("Id") or ""), P(d.get("BaseRateId") or ""), P(rate_flags(d))])
                    for o in (g.get("Orphans") or []):
                        rows.append([P(f"{gname} ({gid})"), P("Derived (orphan)"), P(o.get("Name") or ""), P(o.get("Id") or ""), P(o.get("BaseRateId") or ""), P(rate_flags(o))])
                    for m in (g.get("Misc") or []):
                        rows.append([P(f"{gname} ({gid})"), P("Other"), P(m.get("Name") or ""), P(m.get("Id") or ""), P(m.get("BaseRateId") or ""), P(rate_flags(m))])

                header = ["Rate group", "Relation", "Rate name", "RateId", "BaseRateId", "Flags"]
                colw = [44*mm, 22*mm, 44*mm, 34*mm, 34*mm, 26*mm]
                block.append(Paragraph("<b>Detail: Rates (by Rate Group and Base Rate)</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 250):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Restrictions
            if "RestrictionLines" in details:
                lines = details.get("RestrictionLines") or []
                rows = [[P(line)] for line in lines]
                header = ["Restriction (descriptive)"]
                colw = [A4[0] - (32 * mm)]
                block.append(Paragraph("<b>Detail: Restrictions (descriptive)</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 350):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            if it.source:
                block.append(Paragraph(f"<font color='#64748b'><b>Source:</b> {esc(it.source)}</font>", styles["TinyX"]))
            if it.remediation:
                block.append(Paragraph(f"<b>Recommendation:</b> {esc(it.remediation)}", styles["SmallX"]))

            block.append(Spacer(1, 10))
            story.append(KeepTogether(block))

        story.append(PageBreak())

    # Appendix: API call log
    story.append(Paragraph("Appendix: API call log", styles["H1X"]))
    story.append(Spacer(1, 6))
    rows = []
    for c in report.api_calls:
        line = f"{c.operation} | ok={c.ok} | http={c.status_code or ''} | {c.duration_ms}ms"
        if c.error:
            line += f" | {c.error}"
        rows.append([P(line)])
    header = ["Call"]
    colw = [A4[0] - (32 * mm)]
    for ch in chunk_list(rows, 500):
        story.append(make_long_table(header, ch, colw))
        story.append(Spacer(1, 6))

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    return buf.getvalue()


# =========================================================
# FLASK APP
# =========================================================

HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mews Audit Backend</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin:0;background:#0b1220;color:#e8eefc}
    .wrap{max-width:920px;margin:0 auto;padding:24px}
    .card{background:#111a2e;border:1px solid #1f2b4a;border-radius:14px;padding:18px;margin:14px 0}
    label{display:block;font-weight:600;margin:10px 0 6px}
    input{width:100%;padding:10px;border-radius:10px;border:1px solid #2a3a63;background:#0c1426;color:#e8eefc}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    .btn{display:inline-block;padding:12px 14px;border-radius:12px;border:0;background:#3b82f6;color:#fff;font-weight:700;cursor:pointer}
    .muted{color:#a9b7d6;font-size:13px;line-height:1.35}
    .flash{padding:10px 12px;border-radius:12px;margin:10px 0}
    .flash.error{background:#3b1420;border:1px solid #7a2034}
    .flash.ok{background:#13311d;border:1px solid #1e5a35}
    code{background:#0c1426;padding:2px 6px;border-radius:8px;border:1px solid #1f2b4a}
  </style>
</head>
<body>
<div class="wrap">
  <h1>Mews Audit Backend</h1>
  <p class="muted">
    Generates a PDF audit report from the Mews Connector API. Credentials are used once and never stored.
  </p>
  <p class="muted">
    Base URL examples:
    <br/><code>https://api.mews-demo.com/api/connector/v1</code>
    <br/><code>https://api.mews.com/api/connector/v1</code>
  </p>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="flash {{ 'error' if category=='error' else 'ok' }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  <form action="{{ url_for('audit') }}" method="post" class="card">
    <div class="row">
      <div>
        <label>Client token</label>
        <input name="client_token" type="password" autocomplete="off" required>
      </div>
      <div>
        <label>Access token</label>
        <input name="access_token" type="password" autocomplete="off" required>
      </div>
    </div>
    <div class="row">
      <div>
        <label>Client name (optional)</label>
        <input name="client" placeholder="mews-audit">
      </div>
      <div>
        <label>Connector base URL</label>
        <input name="base_url" placeholder="https://api.mews-demo.com/api/connector/v1">
      </div>
    </div>
    <div style="margin-top:14px;">
      <button class="btn" type="submit">Generate PDF audit</button>
    </div>
  </form>
</div>
</body>
</html>
"""

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me")
CORS(app, resources={r"/audit": {"origins": ALLOWED_ORIGINS}})

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["30 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


@app.get("/")
def index():
    return render_template_string(HTML)


@app.post("/audit")
@limiter.limit("10 per hour")
def audit():
    client_token = (request.form.get("client_token") or "").strip()
    access_token = (request.form.get("access_token") or "").strip()
    client_name = (request.form.get("client") or "mews-audit").strip()
    base_url = (request.form.get("base_url") or DEFAULT_BASE_URL).strip().rstrip("/")

    if not client_token or not access_token:
        flash("Client token and access token are required.", "error")
        return redirect(url_for("index"))

    if not base_url.lower().startswith("https://"):
        flash("Base URL must start with https://", "error")
        return redirect(url_for("index"))

    report = AuditReport(generated_utc=utc_now(), base_url=base_url, client_name=client_name)

    mc = MewsConnectorClient(
        base_url=base_url,
        client_token=client_token,
        access_token=access_token,
        client_name=client_name,
        timeout_seconds=int(os.environ.get("HTTP_TIMEOUT_SECONDS", "35")),
    )

    data = collect_data(mc, report)
    final_report = build_report(base_url, client_name, data, report.api_calls)
    pdf = build_pdf(final_report)

    # best-effort clear
    client_token = None
    access_token = None

    filename = f"mews-audit-{final_report.generated_utc.strftime('%Y-%m-%dT%H%M%SZ')}.pdf"
    return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
