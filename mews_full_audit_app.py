import io
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, request, send_file, render_template_string, redirect, url_for, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_RIGHT, TA_CENTER
from reportlab.graphics import renderPDF
from svglib.svglib import svg2rlg


# =========================
# CONFIG
# =========================

DEFAULT_BASE_URL = os.environ.get("MEWS_CONNECTOR_BASE_URL", "https://api.mews-demo.com/api/connector/v1").rstrip("/")
MEWS_LOGO_SVG = "https://www.mews.com/hubfs/_Project_Phoenix/images/logo/Mews%20Logo.svg"
MAX_PAGE_SIZE = 1000  # IMPORTANT: API limitation (Count must be 1..1000) :contentReference[oaicite:2]{index=2}

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "https://samhmews.github.io").split(",") if o.strip()]


# =========================
# MODELS
# =========================

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


# =========================
# CLIENT
# =========================

class MewsConnectorClient:
    """
    Connector API:
    POST {base}/<resource>/<operation>
    e.g. https://api.mews-demo.com/api/connector/v1/services/getAll
    """

    def __init__(self, base_url: str, client_token: str, access_token: str, client_name: str = "mews-audit",
                 timeout_seconds: int = 35):
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

    def paged_get_all(self, resource: str, operation: str, base_payload: Dict[str, Any],
                     list_key: str) -> Tuple[List[Dict[str, Any]], List[ApiCallResult]]:
        """
        Generic pagination:
        - Limitation.Count <= 1000 (hard limit)
        - Cursor returned for next page (if present)
        """
        calls: List[ApiCallResult] = []
        out: List[Dict[str, Any]] = []

        cursor: Optional[str] = None
        for _ in range(250):  # hard stop safety
            payload = dict(base_payload or {})
            limitation = payload.get("Limitation") or {}
            limitation["Count"] = min(int(limitation.get("Count") or MAX_PAGE_SIZE), MAX_PAGE_SIZE)
            if cursor:
                limitation["Cursor"] = cursor
            payload["Limitation"] = limitation

            data, res = self._post(resource, operation, payload)
            calls.append(res)
            if not res.ok:
                break

            batch = data.get(list_key) or []
            if isinstance(batch, list):
                out.extend([x for x in batch if isinstance(x, dict)])

            cursor = data.get("Cursor")
            if not cursor or not batch:
                break

        return out, calls

    def post(self, resource: str, operation: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], ApiCallResult]:
        return self._post(resource, operation, payload)


# =========================
# HELPERS
# =========================

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

def truncate(s: Any, n: int = 220) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"

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


# =========================
# DATA COLLECTION
# =========================

def collect_data(mc: MewsConnectorClient, report: AuditReport) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    def add_calls(calls: List[ApiCallResult]):
        report.api_calls.extend(calls)

    def add_call(call: ApiCallResult):
        report.api_calls.append(call)

    # Configuration (single call)
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

    # Rules (packages etc.)
    rules_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        rules_payload["ServiceIds"] = service_ids[:1000]
    rules, calls = mc.paged_get_all("Rules", "GetAll", rules_payload, "Rules")
    add_calls(calls)
    data["rules"] = rules

    # Accounting categories
    acc_cats, calls = mc.paged_get_all("AccountingCategories", "GetAll", {"Limitation": {"Count": 1000}}, "AccountingCategories")
    add_calls(calls)
    data["accounting_categories"] = acc_cats

    # Cashiers + counters
    cashiers, calls = mc.paged_get_all("Cashiers", "GetAll", {"Limitation": {"Count": 1000}}, "Cashiers")
    add_calls(calls)
    data["cashiers"] = cashiers

    counters, calls = mc.paged_get_all("Counters", "GetAll", {"Limitation": {"Count": 1000}}, "Counters")
    add_calls(calls)
    data["counters"] = counters

    # Payments (sample window for readability)
    payments, calls = mc.paged_get_all(
        "Payments", "GetAll",
        {"CreatedUtc": time_window(30), "Limitation": {"Count": 1000}},
        "Payments"
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

    # ResourceCategoryAssignments (best mapping for spaces → category)
    rca_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        rca_payload["ServiceIds"] = service_ids[:1000]
    rca, calls = mc.paged_get_all("ResourceCategoryAssignments", "GetAll", rca_payload, "ResourceCategoryAssignments")
    add_calls(calls)
    data["resource_category_assignments"] = rca

    # Rates + Rate groups
    rates, calls = mc.paged_get_all("Rates", "GetAll", {"Limitation": {"Count": 1000}}, "Rates")
    add_calls(calls)
    data["rates"] = rates

    rg_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        rg_payload["ServiceIds"] = service_ids[:1000]
    rate_groups, calls = mc.paged_get_all("RateGroups", "GetAll", rg_payload, "RateGroups")
    add_calls(calls)
    data["rate_groups"] = rate_groups

    # Restrictions (descriptive)
    restr_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        restr_payload["ServiceIds"] = service_ids[:1000]
    restrictions, calls = mc.paged_get_all("Restrictions", "GetAll", restr_payload, "Restrictions")
    add_calls(calls)
    data["restrictions"] = restrictions

    # Cancellation policies (best available “policy” linkage to RateGroups)
    # Restricted beta endpoint – may fail depending on token permissions. :contentReference[oaicite:3]{index=3}
    cp_payload = {"Limitation": {"Count": 1000}}
    if service_ids:
        cp_payload["ServiceIds"] = service_ids[:1000]
    cancellation_policies, calls = mc.paged_get_all("CancellationPolicies", "GetAll", cp_payload, "CancellationPolicies")
    add_calls(calls)
    data["cancellation_policies"] = cancellation_policies  # may be empty if restricted

    return data


# =========================
# DERIVATIONS (READABILITY + DETAIL)
# =========================

def map_accounting_categories_to_products(accounting_categories: List[Dict[str, Any]], products: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cat_by_id = {c.get("Id"): c for c in accounting_categories if c.get("Id")}
    buckets: Dict[str, List[Dict[str, Any]]] = {}

    for p in products:
        acc_id = p.get("AccountingCategoryId") or "UNMAPPED"
        buckets.setdefault(acc_id, []).append(p)

    out = []
    for acc_id, plist in buckets.items():
        cat = cat_by_id.get(acc_id)
        out.append({
            "AccountingCategoryId": acc_id,
            "AccountingCategoryName": pick_name(cat) or ("UNMAPPED" if acc_id == "UNMAPPED" else acc_id),
            "Products": sorted([
                {
                    "Id": p.get("Id"),
                    "Name": pick_name(p) or p.get("Name") or "",
                    "Code": p.get("Code") or "",
                    "IsActive": p.get("IsActive"),
                    "Type": p.get("Type") or "",
                    "ProductCategoryId": p.get("ProductCategoryId") or "",
                }
                for p in plist
            ], key=lambda x: x["Name"]),
        })
    out.sort(key=lambda x: x["AccountingCategoryName"])
    return out


def map_spaces_by_category(resources: List[Dict[str, Any]], resource_categories: List[Dict[str, Any]], assignments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
        out.append({
            "ResourceCategoryId": cid,
            "ResourceCategoryName": pick_name(cat) or ("UNASSIGNED" if cid == "UNASSIGNED" else cid),
            "Type": cat.get("Type") if isinstance(cat, dict) else "",
            "Resources": sorted([
                {
                    "Id": r.get("Id"),
                    "Name": r.get("Name") or "",
                    "IsActive": r.get("IsActive"),
                    "State": r.get("State"),
                }
                for r in rlist
            ], key=lambda x: x["Name"]),
        })
    out.sort(key=lambda x: x["ResourceCategoryName"])
    return out


def build_rate_index(rates: List[Dict[str, Any]], rate_groups: List[Dict[str, Any]]) -> Dict[str, Any]:
    rg_by_id = {g.get("Id"): g for g in rate_groups if g.get("Id")}
    rate_by_id = {r.get("Id"): r for r in rates if r.get("Id")}

    def rate_label(r: Dict[str, Any]) -> str:
        return pick_name(r) or (r.get("Code") or "") or (r.get("Id") or "")

    # Group rates by rate group
    rates_by_group: Dict[str, List[Dict[str, Any]]] = {}
    for r in rates:
        gid = r.get("GroupId") or "NO_GROUP"
        rates_by_group.setdefault(gid, []).append(r)

    # Also build base -> derived tree (within each group, where possible)
    def rate_rich(r: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "Id": r.get("Id"),
            "Name": rate_label(r),
            "Code": r.get("Code") or "",
            "GroupId": r.get("GroupId") or "",
            "GroupName": pick_name(rg_by_id.get(r.get("GroupId"))) if r.get("GroupId") in rg_by_id else "",
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

        # Determine base rates (best effort)
        base_rates = [r for r in group_rates if r.get("IsBaseRate") or (r.get("Type") == "Base")]
        derived = [r for r in group_rates if r.get("BaseRateId")]

        derived_by_base: Dict[str, List[Dict[str, Any]]] = {}
        for r in derived:
            derived_by_base.setdefault(r.get("BaseRateId"), []).append(r)

        tree = []
        for br in sorted(base_rates, key=rate_label):
            br_id = br.get("Id")
            tree.append({
                "Base": rate_rich(br),
                "Derived": [rate_rich(x) for x in sorted(derived_by_base.get(br_id, []), key=rate_label)]
            })

        # Orphans (derived whose base isn't returned)
        orphans = []
        for r in derived:
            if r.get("BaseRateId") not in rate_by_id:
                orphans.append(rate_rich(r))

        # Ungrouped within group (neither base nor derived)
        misc = []
        for r in group_rates:
            if (r not in base_rates) and (not r.get("BaseRateId")) and (r.get("Type") != "Base"):
                misc.append(rate_rich(r))

        groups_out.append({
            "RateGroupId": gid,
            "RateGroupName": gname,
            "Tree": tree,
            "Orphans": sorted(orphans, key=lambda x: x["Name"]),
            "Misc": sorted(misc, key=lambda x: x["Name"]),
            "RateCount": len(group_rates),
        })

    groups_out.sort(key=lambda x: x["RateGroupName"])
    return {"RateGroups": groups_out}


def map_cancellation_policies(cancellation_policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Connector has CancellationPolicies/GetAll (restricted beta). :contentReference[oaicite:4]{index=4}
    We map policies -> RateGroupIds when present.
    """
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
        return {
            "Id": p.get("Id"),
            "Name": pick_name(p) or p.get("Name") or "",
            "Type": p.get("Type") or "",
            "Description": pick_name(p.get("Descriptions")) if isinstance(p.get("Descriptions"), dict) else (p.get("Description") or ""),
        }

    return {gid: [policy_brief(p) for p in plist] for gid, plist in by_group.items()}


def describe_restrictions(restrictions: List[Dict[str, Any]], rates: List[Dict[str, Any]], rate_groups: List[Dict[str, Any]], resource_categories: List[Dict[str, Any]]) -> List[str]:
    rate_by_id = {r.get("Id"): r for r in rates if r.get("Id")}
    rg_by_id = {g.get("Id"): g for g in rate_groups if g.get("Id")}
    rc_by_id = {c.get("Id"): c for c in resource_categories if c.get("Id")}

    def rate_name(rid: Optional[str]) -> str:
        r = rate_by_id.get(rid) if rid else None
        return pick_name(r) or (rid or "")

    def rg_name(gid: Optional[str]) -> str:
        g = rg_by_id.get(gid) if gid else None
        return pick_name(g) or (gid or "")

    def rc_name(cid: Optional[str]) -> str:
        c = rc_by_id.get(cid) if cid else None
        return pick_name(c) or (cid or "")

    lines: List[str] = []
    for x in restrictions:
        cond = x.get("Conditions") or {}
        parts = [f"RestrictionId={x.get('Id')}"]

        start = x.get("StartUtc") or ""
        end = x.get("EndUtc") or ""
        if start or end:
            parts.append(f"Active={start} → {end}")

        if cond.get("ResourceCategoryId"):
            parts.append(f"SpaceCategory={rc_name(cond.get('ResourceCategoryId'))}")
        if cond.get("RateGroupId"):
            parts.append(f"RateGroup={rg_name(cond.get('RateGroupId'))}")
        if cond.get("ExactRateId") or cond.get("RateId"):
            parts.append(f"Rate={rate_name(cond.get('ExactRateId') or cond.get('RateId'))}")
        if cond.get("BaseRateId"):
            parts.append(f"BaseRate={rate_name(cond.get('BaseRateId'))}")

        # Behaviour flags
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


# =========================
# REPORT BUILD (ALL SECTIONS)
# =========================

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

    # Enterprise identity
    cfg = data.get("configuration")
    if isinstance(cfg, dict) and "_error" not in cfg:
        ent = cfg.get("Enterprise") or {}
        report.enterprise_id = ent.get("Id") or ""
        report.enterprise_name = ent.get("Name") or ""

    services = data.get("services", [])
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

    # Derivations
    acc_breakdown = map_accounting_categories_to_products(accounting_categories, products)
    spaces_by_cat = map_spaces_by_category(resources, resource_categories, rca)
    rate_index = build_rate_index(rates, rate_groups)
    cancellation_by_group = map_cancellation_policies(cancellation_policies) if cancellation_policies else {}
    restriction_lines = describe_restrictions(restrictions, rates, rate_groups, resource_categories)

    # ---------- Section: Legal & property baseline ----------
    legal_items: List[CheckItem] = []
    tz = (cfg.get("Enterprise") or {}).get("TimeZone") if isinstance(cfg, dict) else None
    currency = (cfg.get("Enterprise") or {}).get("DefaultCurrency") if isinstance(cfg, dict) else None
    pricing_mode = cfg.get("PricingMode") if isinstance(cfg, dict) else None

    legal_items.append(CheckItem(
        key="Time zone",
        status="PASS" if tz else "WARN",
        summary=str(tz or "Not identified"),
        source="Connector: Configuration/Get",
        remediation="Set enterprise/property time zone in Mews if missing.",
        risk="High" if not tz else "Low",
    ))
    legal_items.append(CheckItem(
        key="Default currency",
        status="PASS" if currency else "WARN",
        summary=str(currency or "Not identified"),
        source="Connector: Configuration/Get",
        remediation="Ensure a default currency is set at enterprise level.",
        risk="High" if not currency else "Low",
    ))
    legal_items.append(CheckItem(
        key="Pricing mode (gross/net)",
        status="PASS" if pricing_mode else "NEEDS_INPUT",
        summary=str(pricing_mode or "Not exposed; confirm in UI"),
        source="Connector: Configuration/Get",
        remediation="Confirm whether pricing is gross or net in Mews.",
        risk="Medium",
    ))
    legal_items.append(CheckItem(
        key="Tax environment + VAT/GST rates",
        status="PASS" if tax_envs or taxations else "WARN",
        summary=f"TaxEnvironments={len(tax_envs)}, Taxations={len(taxations)}",
        source="Connector: TaxEnvironments/GetAll + Taxations/GetAll",
        remediation="Validate tax environment selection and tax codes match jurisdiction.",
        risk="High" if not tax_envs else "Medium",
        details={"TaxEnvironments": tax_envs[:50], "Taxations": taxations[:200]}
    ))
    # City tax heuristic
    city_like = [p for p in products if "city" in (pick_name(p) or "").lower() and "tax" in (pick_name(p) or "").lower()]
    legal_items.append(CheckItem(
        key="City tax product + rule",
        status="WARN" if not city_like else "PASS",
        summary=f"City-tax-like products found: {len(city_like)}; Rules: {len(rules)}",
        source="Connector: Products/GetAll + Rules/GetAll",
        remediation="If city tax is required, ensure a dedicated product exists and is applied consistently (often via rule).",
        risk="Medium",
        details={"CityTaxCandidates": [{"Id": p.get("Id"), "Name": pick_name(p)} for p in city_like[:50]]}
    ))
    legal_items.append(CheckItem(
        key="Fiscalisation (where relevant)",
        status="NEEDS_INPUT",
        summary="Connector cannot reliably confirm fiscalisation requirements; confirm in Mews UI / local compliance docs.",
        source="Workaround: manual evidence",
        remediation="Document the fiscalisation requirement for jurisdiction and confirm Mews settings/provider configuration.",
        risk="High",
    ))

    # ---------- Section: Users, access & security ----------
    users_items: List[CheckItem] = [
        CheckItem(
            key="User list & roles / departments",
            status="NEEDS_INPUT",
            summary="Not exposed via Connector. Requires manual export from Mews UI.",
            source="Not available via Connector",
            remediation="Export users from Mews and review active users, role assignments, shared logins and department mapping.",
            risk="High",
        ),
        CheckItem(
            key="2FA / passkeys adoption",
            status="NEEDS_INPUT",
            summary="Not exposed via Connector. Validate via IdP/Mews UI.",
            source="Not available via Connector",
            remediation="Verify MFA enforcement for admins and remove/secure accounts lacking strong auth.",
            risk="High",
        ),
        CheckItem(
            key="SSO / SCIM enforcement",
            status="NEEDS_INPUT",
            summary="Not exposed via Connector. Validate in IdP + Mews settings.",
            source="Not available via Connector",
            remediation="Confirm SSO enforcement and SCIM provisioning state (where used).",
            risk="Medium",
        ),
        CheckItem(
            key="Auditability (permission/history windows)",
            status="NEEDS_INPUT",
            summary="Not exposed via Connector. Confirm operational and audit history settings in UI.",
            source="Not available via Connector",
            remediation="Set history windows to support traceability and change audits.",
            risk="Medium",
        ),
    ]

    # ---------- Section: Accounting configuration ----------
    accounting_items: List[CheckItem] = []
    accounting_items.append(CheckItem(
        key="Accounting categories (structure)",
        status="PASS" if accounting_categories else "WARN",
        summary=f"Accounting categories returned: {len(accounting_categories)}",
        source="Connector: AccountingCategories/GetAll",
        remediation="Confirm separation of revenue/payments/taxes/deposits/fees aligns with accounting design.",
        risk="High" if not accounting_categories else "Medium",
    ))
    accounting_items.append(CheckItem(
        key="Accounting categories → product mapping (full detail)",
        status="PASS" if acc_breakdown else "WARN",
        summary=f"Categories with mapped products: {len(acc_breakdown)}",
        source="Connector: AccountingCategories/GetAll + Products/GetAll",
        remediation="Validate product allocations per accounting category; correct any mis-allocations.",
        risk="High",
        details={"AccountingCategoryBreakdown": acc_breakdown}
    ))
    accounting_items.append(CheckItem(
        key="Cash / counters",
        status="PASS" if (cashiers or counters) else "WARN",
        summary=f"Cashiers={len(cashiers)}, Counters={len(counters)}",
        source="Connector: Cashiers/GetAll + Counters/GetAll",
        remediation="Ensure cashiers are assigned and counters/numbering comply with local rules.",
        risk="Medium",
    ))
    accounting_items.append(CheckItem(
        key="Payment types mapping (Mews + external)",
        status="NEEDS_INPUT",
        summary="Connector shows payments but not full mapping of terminal/gateway types to accounting categories.",
        source="Partial via Connector; mapping requires UI review",
        remediation="Review payment methods and accounting category mappings in Mews and downstream export tool.",
        risk="High",
    ))
    accounting_items.append(CheckItem(
        key="Ledgers design (guest vs deposit vs AR/TA)",
        status="NEEDS_INPUT",
        summary="Ledger design and downstream export design are not fully exposed via Connector.",
        source="Workaround: manual evidence",
        remediation="Document ledgers strategy and validate export mappings (Omniboost/Sun/Dynamics/Xero/etc.).",
        risk="High",
    ))

    # ---------- Section: Payments setup & reconciliation ----------
    payments_items: List[CheckItem] = []
    payments_items.append(CheckItem(
        key="Payments (last 30 days sample)",
        status="PASS",
        summary=f"Payments retrieved: {len(payments)} (rendered as readable wrapped lines; no tables).",
        source="Connector: Payments/GetAll (CreatedUtc 30d window)",
        remediation="If unexpectedly empty, verify token scope/permissions or adjust window.",
        risk="Low",
        details={"Payments": payments[:400]}
    ))
    payments_items.append(CheckItem(
        key="KYC & Mews Payments onboarding",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Confirm in Mews Payments UI.",
        source="Not available via Connector",
        remediation="Provide evidence of KYC status, payout configuration and multi-currency accounts (where used).",
        risk="High",
    ))
    payments_items.append(CheckItem(
        key="Share of Wallet (SoW) + automation (scheduled payments / policies)",
        status="NEEDS_INPUT",
        summary="SoW and payment scheduling policies are not fully exposed via Connector.",
        source="Partial via payments data; policy requires UI",
        remediation="Use payments dataset for indicative SoW; confirm policies/schedules in Mews UI.",
        risk="Medium",
    ))
    payments_items.append(CheckItem(
        key="Reconciliation flows (payouts/fees into GL)",
        status="NEEDS_INPUT",
        summary="Payouts/fees reconciliation not exposed via Connector. Requires statements + accounting export review.",
        source="Not available via Connector",
        remediation="Upload payout/fee statements and document reconciliation steps; align with accounting export mappings.",
        risk="High",
    ))

    # ---------- Section: Inventory, rates & revenue structure ----------
    inv_items: List[CheckItem] = []
    inv_items.append(CheckItem(
        key="Space categories → spaces (full detail)",
        status="PASS" if spaces_by_cat else "WARN",
        summary=f"Space category groups: {len(spaces_by_cat)} (includes UNASSIGNED if mapping not available).",
        source="Connector: Resources/GetAll + ResourceCategories/GetAll + ResourceCategoryAssignments/GetAll",
        remediation="Ensure each space belongs to the correct category; investigate any UNASSIGNED spaces.",
        risk="High",
        details={"SpacesByCategory": spaces_by_cat}
    ))
    inv_items.append(CheckItem(
        key="Rates (ALL) grouped by Rate Group and Base Rate",
        status="PASS" if rates else "WARN",
        summary=f"Rates={len(rates)}, RateGroups={len(rate_groups)}. Output grouped by rate group, then base→derived.",
        source="Connector: Rates/GetAll + RateGroups/GetAll",
        remediation="Validate base/derived structure, group membership, and flags (public/private/active/enabled/default).",
        risk="High",
        details={"RateIndex": rate_index}
    ))
    # “Payment policies assigned to rates” – best available is CancellationPolicies by RateGroup (restricted)
    inv_items.append(CheckItem(
        key="Payment/cancellation policy per Rate Group (best available via Connector)",
        status="PASS" if cancellation_policies else "NEEDS_INPUT",
        summary=(
            f"CancellationPolicies returned: {len(cancellation_policies)} (mapped to rate groups where possible)."
            if cancellation_policies else
            "CancellationPolicies/GetAll is Restricted (beta). If your token lacks access, confirm in UI and provide evidence."
        ),
        source="Connector: CancellationPolicies/GetAll (Restricted) maps to rate groups. " ,
        remediation="If unavailable, export/capture policies from Mews UI; ensure each Rate Group’s policy matches intent.",
        risk="High",
        details={"CancellationPoliciesByRateGroup": cancellation_by_group}
    ))
    inv_items.append(CheckItem(
        key="Restrictions & seasonality (descriptive)",
        status="PASS" if restrictions else "WARN",
        summary=f"Restrictions returned: {len(restrictions)} (rendered with meaning: CTA/CTD/LOS/closed + scope).",
        source="Connector: Restrictions/GetAll",
        remediation="Confirm restrictions sets are purposeful and consistent across channels; remove stale rules.",
        risk="Medium",
        details={"RestrictionLines": restriction_lines[:800]}
    ))
    inv_items.append(CheckItem(
        key="Channel manager / CRS mapping",
        status="NEEDS_INPUT",
        summary="Mappings to CHM/CRS are not fully exposed via Connector; requires integration configuration review.",
        source="Not available via Connector",
        remediation="Validate rate/category mapping in channel manager and identify gaps/double posting.",
        risk="High",
    ))

    # ---------- Guest journey & operations ----------
    ops_items: List[CheckItem] = [
        CheckItem(
            key="Booking flows (direct vs OTA vs corporate) + IBE config",
            status="NEEDS_INPUT",
            summary="Booking engine configuration is not exposed via Connector.",
            source="Not available via Connector",
            remediation="Review IBE settings, branding and business rules in Mews and distribution stack.",
            risk="Medium",
        ),
        CheckItem(
            key="Availability blocks / groups / events usage",
            status="NEEDS_INPUT",
            summary="Event/group configuration not fully exposed via Connector in this audit scope.",
            source="Workaround: manual evidence",
            remediation="Review group blocks and event workflows; confirm integrations using correct identifiers.",
            risk="Medium",
        ),
        CheckItem(
            key="Online check-in / guest portal / comms templates",
            status="NEEDS_INPUT",
            summary="OCI and messaging templates are not exposed via Connector.",
            source="Not available via Connector",
            remediation="Audit guest comms templates and merge tags directly in UI; test end-to-end journey.",
            risk="Medium",
        ),
        CheckItem(
            key="Housekeeping & maintenance",
            status="NEEDS_INPUT",
            summary="Housekeeping boards/integrations are not exposed via Connector for full audit.",
            source="Not available via Connector",
            remediation="Review housekeeping configuration/integrations and status-driven automations in UI.",
            risk="Medium",
        ),
    ]

    # ---------- Reporting, BI & data quality ----------
    reporting_items: List[CheckItem] = [
        CheckItem(
            key="Core reports usage (Reservations/Manager/Accounting)",
            status="NEEDS_INPUT",
            summary="Report configuration is not exposed via Connector; validate in UI.",
            source="Not available via Connector",
            remediation="Confirm filter usage, totals mode, and cut-off logic align with finance operations.",
            risk="High",
        ),
        CheckItem(
            key="BI & analytics (segments/channels/markets)",
            status="NEEDS_INPUT",
            summary="BI dashboards/config not exposed via Connector; validate in BI tooling and Mews definitions.",
            source="Not available via Connector",
            remediation="Define segments/channels/markets cleanly; avoid misuse of accounting categories for analysis.",
            risk="Medium",
        ),
        CheckItem(
            key="Error patterns (rebates/manual corrections/write-offs)",
            status="NEEDS_INPUT",
            summary="Requires accounting item analysis and operational context; not fully derived in this script.",
            source="Workaround: export + analysis",
            remediation="Review patterns via exports; redesign configuration where systematic issues are found.",
            risk="Medium",
        ),
    ]

    # ---------- Integrations & automations ----------
    integrations_items: List[CheckItem] = [
        CheckItem(
            key="Marketplace stack (CHM/POS/RMS/key/CRM/vouchers/messaging)",
            status="NEEDS_INPUT",
            summary="Integration mapping health is not exposed via Connector alone.",
            source="Workaround: integration config + logs",
            remediation="Review each integration mapping and identify double-posting, gaps, and broken mappings.",
            risk="High",
        ),
        CheckItem(
            key="Accounting & data exports (Omniboost/Sun/Dynamics/Xero/custom)",
            status="NEEDS_INPUT",
            summary="Export cadence and failure handling not exposed via Connector alone.",
            source="Workaround: export tool logs",
            remediation="Validate mapping correctness, cadence, and failure alerts; document recovery process.",
            risk="High",
        ),
        CheckItem(
            key="Automation tooling (Zapier/Power Automate/custom workflows)",
            status="NEEDS_INPUT",
            summary="Automation governance/monitoring not exposed via Connector.",
            source="Workaround: workflow inventory",
            remediation="Create an automation register and monitoring plan; implement alerting and ownership.",
            risk="Medium",
        ),
    ]

    # ---------- Training, governance & ownership ----------
    governance_items: List[CheckItem] = [
        CheckItem(
            key="Training coverage (Mews University)",
            status="NEEDS_INPUT",
            summary="Training completion is not exposed via Connector.",
            source="Not available via Connector",
            remediation="Collect completion evidence for key personas; align training with responsibilities.",
            risk="Medium",
        ),
        CheckItem(
            key="Process ownership & change governance",
            status="NEEDS_INPUT",
            summary="Governance practices are organisational; not exposed via Connector.",
            source="Workaround: RACI / governance docs",
            remediation="Nominate a champion, establish change evaluation, rollout, and review process.",
            risk="Medium",
        ),
        CheckItem(
            key="Artifacts (SOPs/finance playbooks/rate governance rules)",
            status="NEEDS_INPUT",
            summary="Documents are external to Mews Connector scope.",
            source="Workaround: document review",
            remediation="Compare SOPs to live configuration; update and version-control operational artefacts.",
            risk="Medium",
        ),
    ]

    # Assemble sections in required order
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


# =========================
# PDF (PROFESSIONAL + READABLE)
# =========================

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

def build_pdf(report: AuditReport) -> bytes:
    buf = io.BytesIO()

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleX", parent=styles["Title"], fontSize=20, leading=24, alignment=TA_CENTER, spaceAfter=10))
    styles.add(ParagraphStyle(name="H1X", parent=styles["Heading1"], fontSize=15, leading=18, spaceBefore=10, spaceAfter=6))
    styles.add(ParagraphStyle(name="H2X", parent=styles["Heading2"], fontSize=12, leading=14, spaceBefore=8, spaceAfter=4))
    styles.add(ParagraphStyle(name="BodyX", parent=styles["BodyText"], fontSize=9.6, leading=12))
    styles.add(ParagraphStyle(name="SmallX", parent=styles["BodyText"], fontSize=8.6, leading=11))
    styles.add(ParagraphStyle(name="TinyX", parent=styles["BodyText"], fontSize=8.1, leading=10))
    styles.add(ParagraphStyle(name="RightTinyX", parent=styles["TinyX"], alignment=TA_RIGHT))

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

    # Cover / Executive summary
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
        "This report is evidence-based and generated directly from the Mews Connector API using the supplied credentials. "
        "Where the Connector API does not expose a control area, the report marks it as <b>NEEDS_INPUT</b> and provides a practical workaround for completing the audit.",
        styles["SmallX"]
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Scope and methodology", styles["H1X"]))
    story.append(Paragraph(
        "• Data sources: Mews Connector API (read operations), with restricted endpoints included where available.<br/>"
        "• Method: retrieve configuration entities, derive mappings (e.g., products → accounting categories; rates → groups/base; spaces → categories), "
        "then evaluate checks against baseline expectations.<br/>"
        "• Limitations: certain controls (user access, MFA/SSO, exports, reconciliations, training, governance artefacts) are not exposed via Connector and require manual evidence.",
        styles["SmallX"]
    ))
    story.append(PageBreak())

    # Detailed findings by section (keep segmentation like before)
    for sec_name, items in report.sections:
        story.append(Paragraph(esc(sec_name), styles["H1X"]))
        story.append(Spacer(1, 6))

        for it in items:
            block: List[Any] = []
            block.append(Paragraph(
                f"<b>{esc(it.key)}</b> &nbsp;&nbsp; {badge(it.status)} &nbsp;&nbsp; "
                f"<font color='#64748b'>Risk:</font> <b>{esc(it.risk)}</b>",
                styles["BodyX"]
            ))
            block.append(Paragraph(esc(it.summary or "-"), styles["BodyX"]))

            # Detail render rules:
            # - Never tables for long lists
            # - Use wrapped lines + appendices
            details = it.details or {}

            # Accounting breakdown appendix-like (more readable)
            if "AccountingCategoryBreakdown" in details:
                block.append(Spacer(1, 5))
                block.append(Paragraph("<b>Detail: Products mapped to each accounting category</b>", styles["SmallX"]))
                for cat in details["AccountingCategoryBreakdown"][:200]:
                    cname = cat.get("AccountingCategoryName")
                    cid = cat.get("AccountingCategoryId")
                    block.append(Paragraph(f"<b>{esc(cname)}</b> <font color='#64748b'>({esc(cid)})</font>", styles["SmallX"]))
                    prods = cat.get("Products") or []
                    # present as wrapped bullets
                    for p in prods[:250]:
                        line = f"• {truncate(p.get('Name') or '', 90)}  | Active={yn(p.get('IsActive'))} | Code={p.get('Code') or ''} | Type={p.get('Type') or ''}"
                        block.append(Paragraph(esc(line), styles["TinyX"]))
                    if len(prods) > 250:
                        block.append(Paragraph(esc(f"• …and {len(prods)-250} more products"), styles["TinyX"]))
                    block.append(Spacer(1, 3))

            # Payments readable lines
            if "Payments" in details:
                block.append(Spacer(1, 5))
                block.append(Paragraph("<b>Detail: Payments sample</b>", styles["SmallX"]))
                for p in (details.get("Payments") or [])[:250]:
                    if not isinstance(p, dict):
                        continue
                    amt = p.get("Amount") or {}
                    line = (
                        f"PaymentId={p.get('Id')} | Type={p.get('Type')} | State={p.get('State')} | "
                        f"Currency={amt.get('Currency') or p.get('Currency') or ''} | "
                        f"Net={amt.get('NetValue')} Gross={amt.get('GrossValue')} | "
                        f"CreatedUtc={p.get('CreatedUtc')}"
                    )
                    block.append(Paragraph(esc(truncate(line, 240)), styles["TinyX"]))
                if len(details.get("Payments") or []) > 250:
                    block.append(Paragraph(esc(f"…and {len(details.get('Payments'))-250} more"), styles["TinyX"]))

            # Spaces by category
            if "SpacesByCategory" in details:
                block.append(Spacer(1, 5))
                block.append(Paragraph("<b>Detail: Space categories and their spaces</b>", styles["SmallX"]))
                for cat in details["SpacesByCategory"][:200]:
                    block.append(Paragraph(
                        f"<b>{esc(cat.get('ResourceCategoryName'))}</b> <font color='#64748b'>({esc(cat.get('ResourceCategoryId'))})</font>",
                        styles["SmallX"]
                    ))
                    if cat.get("Type"):
                        block.append(Paragraph(esc(f"Type: {cat.get('Type')}"), styles["TinyX"]))
                    for r in (cat.get("Resources") or [])[:350]:
                        line = f"• {truncate(r.get('Name') or '', 90)} | Active={yn(r.get('IsActive'))} | State={r.get('State')} | ResourceId={r.get('Id')}"
                        block.append(Paragraph(esc(line), styles["TinyX"]))
                    if len(cat.get("Resources") or []) > 350:
                        block.append(Paragraph(esc(f"• …and {len(cat.get('Resources'))-350} more spaces"), styles["TinyX"]))
                    block.append(Spacer(1, 3))

            # Rates: ALL by RateGroup then Base->Derived
            if "RateIndex" in details:
                block.append(Spacer(1, 5))
                block.append(Paragraph("<b>Detail: Rates grouped by Rate Group and Base Rate</b>", styles["SmallX"]))
                rgroups = details["RateIndex"].get("RateGroups") or []
                for g in rgroups[:200]:
                    block.append(Paragraph(
                        f"<b>Rate group:</b> {esc(g.get('RateGroupName'))} <font color='#64748b'>({esc(g.get('RateGroupId'))})</font> "
                        f"<font color='#64748b'>Rates:</font> <b>{g.get('RateCount')}</b>",
                        styles["SmallX"]
                    ))

                    # Cancellation policies mapped by group (if available)
                    # (This is the closest “payment/cancellation policy per rate” available in Connector)
                    # CancellationPolicies/GetAll is restricted beta. :contentReference[oaicite:5]{index=5}
                    # Render inline if present in report (we add it via separate check, but it's useful here too).
                    block.append(Spacer(1, 1))

                    for node in (g.get("Tree") or [])[:500]:
                        base = node.get("Base") or {}
                        block.append(Paragraph(esc(_rate_line(base, is_base=True)), styles["TinyX"]))
                        for ch in (node.get("Derived") or [])[:800]:
                            block.append(Paragraph(esc("• " + _rate_line(ch, is_base=False)), styles["TinyX"]))
                        block.append(Spacer(1, 1))

                    if g.get("Orphans"):
                        block.append(Paragraph("<b>Derived (orphan) rates:</b>", styles["TinyX"]))
                        for r in g["Orphans"][:200]:
                            block.append(Paragraph(esc("• " + _rate_line(r, is_base=False)), styles["TinyX"]))

                    if g.get("Misc"):
                        block.append(Paragraph("<b>Other rates in group:</b>", styles["TinyX"]))
                        for r in g["Misc"][:200]:
                            block.append(Paragraph(esc("• " + _rate_line(r, is_base=False)), styles["TinyX"]))

                    block.append(Spacer(1, 4))

            # Cancellation policies mapping (by rate group)
            if "CancellationPoliciesByRateGroup" in details:
                block.append(Spacer(1, 5))
                block.append(Paragraph("<b>Detail: Cancellation policies mapped to rate groups (Restricted endpoint)</b>", styles["SmallX"]))
                cp_map = details["CancellationPoliciesByRateGroup"] or {}
                for gid, plist in list(cp_map.items())[:250]:
                    block.append(Paragraph(f"<b>RateGroupId:</b> {esc(gid)}", styles["TinyX"]))
                    for p in plist[:50]:
                        line = f"• {p.get('Name') or ''} | Type={p.get('Type') or ''} | PolicyId={p.get('Id') or ''}"
                        if p.get("Description"):
                            line += f" | {truncate(p.get('Description'), 140)}"
                        block.append(Paragraph(esc(line), styles["TinyX"]))
                    block.append(Spacer(1, 2))

            # Restrictions (descriptive lines)
            if "RestrictionLines" in details:
                block.append(Spacer(1, 5))
                block.append(Paragraph("<b>Detail: Restrictions</b>", styles["SmallX"]))
                for line in (details.get("RestrictionLines") or [])[:600]:
                    block.append(Paragraph(esc(truncate(line, 250)), styles["TinyX"]))
                if len(details.get("RestrictionLines") or []) > 600:
                    block.append(Paragraph(esc(f"…and {len(details.get('RestrictionLines'))-600} more"), styles["TinyX"]))

            if it.source:
                block.append(Spacer(1, 3))
                block.append(Paragraph(f"<font color='#64748b'><b>Source:</b> {esc(it.source)}</font>", styles["TinyX"]))
            if it.remediation:
                block.append(Paragraph(f"<b>Recommendation:</b> {esc(it.remediation)}", styles["SmallX"]))

            block.append(Spacer(1, 10))
            story.append(KeepTogether(block))

        story.append(PageBreak())

    # API call log appendix
    story.append(Paragraph("Appendix: API call log", styles["H1X"]))
    story.append(Paragraph(
        "Use this to troubleshoot scope/permissions and to confirm pagination behaviour. "
        "Any failed operation will reduce audit coverage for that area.",
        styles["SmallX"]
    ))
    story.append(Spacer(1, 6))
    for c in report.api_calls:
        line = f"{c.operation} | ok={c.ok} | http={c.status_code or ''} | {c.duration_ms}ms"
        if c.error:
            line += f" | {c.error}"
        story.append(Paragraph(esc(truncate(line, 240)), styles["TinyX"]))

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    return buf.getvalue()


def _rate_line(r: Dict[str, Any], is_base: bool) -> str:
    name = r.get("Name") or r.get("Id") or ""
    bits = []
    if r.get("Code"):
        bits.append(f"Code={r.get('Code')}")
    if r.get("GroupName"):
        bits.append(f"Group={r.get('GroupName')}")
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
    if r.get("Type"):
        bits.append(f"Type={r.get('Type')}")
    if r.get("ExternalIdentifier"):
        bits.append(f"ExternalId={r.get('ExternalIdentifier')}")
    if not is_base and r.get("BaseRateId"):
        bits.append(f"BaseRateId={r.get('BaseRateId')}")
    prefix = "Base rate" if is_base else "Derived rate"
    return f"{prefix}: {name} | RateId={r.get('Id')} | " + ", ".join(bits)


# =========================
# FLASK APP
# =========================

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
    Uses the Mews Connector API to generate a professional PDF audit report. Credentials are used once and never stored.
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

limiter = Limiter(get_remote_address, app=app, default_limits=["30 per hour"], storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))

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

    mc = MewsConnectorClient(
        base_url=base_url,
        client_token=client_token,
        access_token=access_token,
        client_name=client_name,
        timeout_seconds=int(os.environ.get("HTTP_TIMEOUT_SECONDS", "35")),
    )

    report = AuditReport(generated_utc=utc_now(), base_url=base_url, client_name=client_name)

    data = collect_data(mc, report)  # adds api_calls
    final_report = build_report(base_url, client_name, data, report.api_calls)
    pdf = build_pdf(final_report)

    # clear token refs
    client_token = None
    access_token = None

    filename = f"mews-audit-{final_report.generated_utc.strftime('%Y-%m-%dT%H%M%SZ')}.pdf"
    return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=filename)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
