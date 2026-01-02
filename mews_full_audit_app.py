# =========================================================
# mews_full_audit_app.py — Full replacement (v7.1)
# Start command: gunicorn mews_full_audit_app:app
# =========================================================
#
# v6 changes (per Sam's requirements):
# - NEEDS_INPUT: Any section where required API calls failed is marked NEEDS_INPUT (and error surfaced)
# - Product mapping Tax %: uses configured taxation rate (via Taxations/GetAll) when available
# - Logo: defaults to Mews SVG logo URL if LOGO_URL env var is not set
# - Spaces & resource categories: fetch ResourceCategories per ServiceId; then fetch Assignments using ResourceCategoryIds
#   (avoids tenant validation errors and prevents "UNASSIGNED everywhere" when assignments are available)
#
# =========================================================

import os
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, NextPageTemplate, Paragraph, Spacer, PageBreak, KeepTogether
from reportlab.platypus.tables import LongTable, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from svglib.svglib import svg2rlg
from reportlab.graphics import renderPDF


# =========================
# CONFIG
# =========================

DEFAULT_API_BASE = os.getenv("MEWS_API_BASE_URL", "https://api.mews-demo.com/api/connector/v1").rstrip("/")
DEFAULT_CLIENT_NAME = os.getenv("MEWS_CLIENT_NAME", "Mews Audit Tool 1.0.0")
DEFAULT_TIMEOUT = int(os.getenv("MEWS_HTTP_TIMEOUT_SECONDS", "30"))
MAX_PDF_MB = int(os.getenv("MAX_PDF_MB", "18"))

# Default to Mews logo if env var isn't set
LOGO_URL = (os.getenv("LOGO_URL", "").strip()
            or "https://www.mews.com/hubfs/_Project_Phoenix/images/logo/Mews%20Logo.svg")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def esc(s: Any) -> str:
    if s is None:
        return ""
    s = str(s)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )


def pick_name(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ""
    if obj.get("Name"):
        return str(obj.get("Name"))
    if obj.get("ShortName"):
        return str(obj.get("ShortName"))
    names = obj.get("Names")
    if isinstance(names, dict):
        for _, v in names.items():
            if v:
                return str(v)
    return ""


def chunk_list(items: List[Any], size: int) -> List[List[Any]]:
    if size <= 0:
        return [items]
    return [items[i:i + size] for i in range(0, len(items), size)]


# =========================
# API CALL LOG MODEL
# =========================

@dataclass
class ApiCall:
    operation: str
    ok: bool
    status_code: Optional[int]
    duration_ms: int
    error: Optional[str] = None


# =========================
# CONNECTOR CLIENT
# =========================

class MewsConnector:
    def __init__(self, base_url: str, client_token: str, access_token: str, client_name: str = DEFAULT_CLIENT_NAME):
        self.base_url = base_url.rstrip("/")
        self.client_token = client_token.strip()
        self.access_token = access_token.strip()
        self.client_name = client_name
        self.calls: List[ApiCall] = []

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        body = dict(payload)
        body.setdefault("ClientToken", self.client_token)
        body.setdefault("AccessToken", self.access_token)
        body.setdefault("Client", self.client_name)

        t0 = time.time()
        resp = None
        try:
            resp = requests.post(url, json=body, timeout=DEFAULT_TIMEOUT)
            dt = int((time.time() - t0) * 1000)

            try:
                data = resp.json()
            except Exception:
                data = {"_raw": resp.text}

            self.calls.append(ApiCall(
                operation=path,
                ok=bool(resp.ok),
                status_code=resp.status_code,
                duration_ms=dt,
                error=None if resp.ok else (data.get("Message") if isinstance(data, dict) else str(data))
            ))

            if not resp.ok:
                raise RuntimeError(f"HTTP {resp.status_code} for {path}: {data}")
            if not isinstance(data, dict):
                raise RuntimeError(f"Unexpected JSON shape for {path}: {type(data)}")
            return data
        except Exception as e:
            dt = int((time.time() - t0) * 1000)
            if resp is None:
                self.calls.append(ApiCall(operation=path, ok=False, status_code=None, duration_ms=dt, error=str(e)))
            raise

    def get(self, domain: str, operation: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._post(f"{domain}/{operation}", payload)

    def paged_get_all(
        self,
        domain: str,
        operation: str,
        base_payload: Dict[str, Any],
        result_key: str,
        count_per_page: int = 1000,
        hard_limit: int = 50000,
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        pages = 0

        while True:
            pages += 1
            payload = dict(base_payload)
            payload["Limitation"] = {"Count": count_per_page}
            if cursor:
                payload["Limitation"]["Cursor"] = cursor

            data = self.get(domain, operation, payload)

            batch = data.get(result_key)
            if batch is None:
                batch = []
            if not isinstance(batch, list):
                batch = []

            for x in batch:
                if isinstance(x, dict):
                    out.append(x)

            cursor = data.get("Cursor")
            if not cursor:
                break
            if len(out) >= hard_limit or pages > 200:
                break

        return out


# =========================
# DATA COLLECTION (v6)
# =========================

def collect_data(base_url: str, client_token: str, access_token: str, client_name: str = DEFAULT_CLIENT_NAME) -> Dict[str, Any]:
    mc = MewsConnector(base_url, client_token, access_token, client_name)
    errors: Dict[str, str] = {}

    def fetch_list(key: str, domain: str, operation: str, payload: Dict[str, Any], result_key: str,
                   count_per_page: int = 1000, hard_limit: int = 50000) -> List[Dict[str, Any]]:
        try:
            return mc.paged_get_all(domain, operation, payload, result_key, count_per_page=count_per_page, hard_limit=hard_limit)
        except Exception as e:
            errors[key] = str(e)
            return []

    cfg: Dict[str, Any] = {}
    try:
        cfg = mc.get("Configuration", "Get", {})
    except Exception as e:
        errors["configuration_get"] = str(e)
        cfg = {}

    ent = (cfg.get("Enterprise") or {}) if isinstance(cfg, dict) else {}
    ent_id = ent.get("Id")
    enterprises = [ent_id] if ent_id else []

    services = fetch_list("services_getall", "Services", "GetAll",
                          {"EnterpriseIds": enterprises} if enterprises else {}, "Services")
    service_ids = [s.get("Id") for s in services if isinstance(s, dict) and s.get("Id")]

    if service_ids:
        rate_groups = fetch_list("rate_groups_getall", "RateGroups", "GetAll", {"ServiceIds": service_ids}, "RateGroups")
        rates = fetch_list("rates_getall", "Rates", "GetAll", {"ServiceIds": service_ids}, "Rates")
        products = fetch_list("products_getall", "Products", "GetAll", {"ServiceIds": service_ids}, "Products")
        restrictions = fetch_list("restrictions_getall", "Restrictions", "GetAll", {"ServiceIds": service_ids}, "Restrictions")
    else:
        rate_groups, rates, products, restrictions = [], [], [], []
        if "services_getall" not in errors:
            errors["services_missing"] = "No ServiceIds found; service-scoped data cannot be retrieved."

    # Resource categories per service
    resource_categories: List[Dict[str, Any]] = []
    if service_ids:
        for sid in service_ids:
            cats = fetch_list(f"resource_categories_getall_{sid}", "ResourceCategories", "GetAll",
                              {"ServiceIds": [sid]}, "ResourceCategories")
            if cats:
                resource_categories.extend(cats)
    else:
        resource_categories = []

    accounting_categories = fetch_list("accounting_categories_getall", "AccountingCategories", "GetAll",
                                       {"EnterpriseIds": enterprises} if enterprises else {}, "AccountingCategories")
    resources = fetch_list("resources_getall", "Resources", "GetAll",
                           {"EnterpriseIds": enterprises} if enterprises else {}, "Resources")

    tax_envs = fetch_list("tax_environments_getall", "TaxEnvironments", "GetAll",
                          {"EnterpriseIds": enterprises} if enterprises else {}, "TaxEnvironments")
    taxations = fetch_list("taxations_getall", "Taxations", "GetAll",
                           {"EnterpriseIds": enterprises} if enterprises else {}, "Taxations")

    resource_category_assignments: List[Dict[str, Any]] = []
    try:
        rc_ids = [c.get("Id") for c in resource_categories if isinstance(c, dict) and c.get("Id")]
        if rc_ids:
            resource_category_assignments = mc.paged_get_all(
                "ResourceCategoryAssignments", "GetAll",
                {"ResourceCategoryIds": rc_ids},
                "ResourceCategoryAssignments"
            )
        else:
            resource_category_assignments = []
    except Exception as e:
        errors["resource_category_assignments_getall"] = str(e)
        resource_category_assignments = []

    payments: List[Dict[str, Any]] = []
    payments: List[Dict[str, Any]] = []
    payment_origin_counts_charged_6m: List[Dict[str, Any]] = []
    payment_origin_counts_failed_6m: List[Dict[str, Any]] = []

    try:
        # 30-day sample (kept for quick diagnostics and a compact table in the PDF)
        start = (utc_now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        payments = mc.paged_get_all(
            "Payments", "GetAll",
            {"EnterpriseIds": enterprises, "CreatedUtc": {"StartUtc": start, "EndUtc": end}},
            "Payments",
            count_per_page=500, hard_limit=20000,
        )

        # 6-month PaymentOrigin breakdowns
        # NOTE: Connector API time interval filters have a max length of 3 months, so we query in two windows.
        now = utc_now()
        start_6m = (now - timedelta(days=183)).strftime("%Y-%m-%dT%H:%M:%SZ")
        mid_3m = (now - timedelta(days=92)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_0m = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        def _coerce_origin(v: Any) -> str:
            if v is None or v == "":
                return "None"
            # sometimes enums can arrive as dicts; fall back safely
            if isinstance(v, dict):
                return str(v.get("Value") or v.get("Name") or v.get("Code") or v)  # best-effort
            return str(v)

        def _count_by_origin(pay_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            counts: Dict[str, int] = {}
            for p in pay_list:
                key = _coerce_origin(p.get("PaymentOrigin"))
                counts[key] = counts.get(key, 0) + 1
            # sort by count desc, then origin
            return [{"PaymentOrigin": k, "Count": v} for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))]

        def _fetch_payments_window(start_iso: str, end_iso: str, states: List[str], err_key: str) -> List[Dict[str, Any]]:
            try:
                return mc.paged_get_all(
                    "Payments", "GetAll",
                    {"EnterpriseIds": enterprises, "CreatedUtc": {"StartUtc": start_iso, "EndUtc": end_iso}, "States": states},
                    "Payments",
                    count_per_page=1000, hard_limit=50000,
                )
            except Exception as e:
                errors[err_key] = str(e)
                return []

        # Charged (successful)
        charged_all: List[Dict[str, Any]] = []
        charged_all.extend(_fetch_payments_window(start_6m, mid_3m, ["Charged"], "payments_origin_charged_6m_w1"))
        charged_all.extend(_fetch_payments_window(mid_3m, end_0m, ["Charged"], "payments_origin_charged_6m_w2"))
        payment_origin_counts_charged_6m = _count_by_origin(charged_all)

        # Failed / Cancelled
        failed_all: List[Dict[str, Any]] = []
        failed_all.extend(_fetch_payments_window(start_6m, mid_3m, ["Failed", "Canceled"], "payments_origin_failed_6m_w1"))
        failed_all.extend(_fetch_payments_window(mid_3m, end_0m, ["Failed", "Canceled"], "payments_origin_failed_6m_w2"))
        payment_origin_counts_failed_6m = _count_by_origin(failed_all)

    except Exception as e:
        errors["payments_getall"] = str(e)
        payments = []
        payment_origin_counts_charged_6m = []
        payment_origin_counts_failed_6m = []

    cancellation_policies: List[Dict[str, Any]] = []
    if service_ids:
        cancellation_policies = fetch_list("cancellation_policies_getall", "CancellationPolicies", "GetAll",
                                           {"ServiceIds": service_ids}, "CancellationPolicies")

    rules: List[Dict[str, Any]] = []
    if service_ids:
        rules = fetch_list("rules_getall", "Rules", "GetAll", {"ServiceIds": service_ids}, "Rules")

    counters = fetch_list("counters_getall", "Counters", "GetAll",
                          {"EnterpriseIds": enterprises} if enterprises else {}, "Counters")
    cashiers = fetch_list("cashiers_getall", "Cashiers", "GetAll",
                          {"EnterpriseIds": enterprises} if enterprises else {}, "Cashiers")

    return {
        "cfg": cfg,
        "enterprises": enterprises,
        "services": services,
        "service_ids": service_ids,
        "rate_groups": rate_groups,
        "rates": rates,
        "products": products,
        "accounting_categories": accounting_categories,
        "resources": resources,
        "resource_categories": resource_categories,
        "resource_category_assignments": resource_category_assignments,
        "restrictions": restrictions,
        "payments": payments,
        "cancellation_policies": cancellation_policies,
        "rules": rules,
        "tax_environments": tax_envs,
        "taxations": taxations,
        "counters": counters,
        "cashiers": cashiers,
        "errors": errors,
        "api_calls": [c.__dict__ for c in mc.calls],
    }


# =========================
# REPORT MODEL
# =========================

@dataclass
class CheckItem:
    key: str
    status: str
    summary: str
    source: str
    remediation: str
    details: Dict[str, Any] = field(default_factory=dict)
    risk: str = "Medium"


@dataclass
class AuditReport:
    enterprise_id: str
    enterprise_name: str
    base_url: str
    client_name: str
    generated_utc: datetime
    api_calls: List[ApiCall]
    sections: List[Tuple[str, List[CheckItem]]]


# =========================
# TABLE DERIVATIONS
# =========================

def safe_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def money_from_extended_amount(ext: Any) -> str:
    if not isinstance(ext, dict):
        return ""
    for k in ("GrossValue", "Value", "Amount", "NetValue"):
        v = safe_float(ext.get(k))
        if v is not None:
            return f"{v:.2f}"
    return ""


def configured_tax_percent_for_product(product: Dict[str, Any], taxations: List[Dict[str, Any]]) -> str:
    """
    Return configured VAT % for a product.
    Priority:
    1) Product-level Taxations (list) if it contains dicts with a rate/percent
    2) Product TaxationId / TaxationIds / TaxId -> look up in Taxations/GetAll
    3) Fallback direct fields if present
    """
    if not isinstance(product, dict):
        return ""

    # 1) If the product already contains taxation objects, prefer those.
    tx_list = product.get("Taxations")
    if isinstance(tx_list, list) and tx_list:
        first = tx_list[0]
        if isinstance(first, dict):
            for k in ("Rate", "Percentage", "Percent", "Value"):
                v = safe_float(first.get(k))
                if v is not None:
                    if 0 < v <= 1:
                        v = v * 100
                    return f"{v:.2f}%"
            # Sometimes the object uses Id only
            if first.get("Id"):
                taxation_id = first.get("Id")
            else:
                taxation_id = None
        elif isinstance(first, str):
            taxation_id = first
        else:
            taxation_id = None
    else:
        taxation_id = None

    # 2) Resolve an id from common fields
    if not taxation_id:
        tid = product.get("TaxationId") or product.get("TaxId") or product.get("Taxation")
        if isinstance(tid, dict):
            # Sometimes "Taxation" is an object
            for k in ("Rate", "Percentage", "Percent", "Value"):
                v = safe_float(tid.get(k))
                if v is not None:
                    if 0 < v <= 1:
                        v = v * 100
                    return f"{v:.2f}%"
            tid = tid.get("Id")
        if not tid:
            tids = product.get("TaxationIds")
            if isinstance(tids, list) and tids:
                tid = tids[0]
        taxation_id = tid

    # 3) Direct fields fallback (rare, but seen in some payload shapes)
    for k in ("VatPercent", "VATPercent", "TaxPercent", "TaxRate"):
        v = safe_float(product.get(k))
        if v is not None:
            if 0 < v <= 1:
                v = v * 100
            return f"{v:.2f}%"

    if not taxation_id or not isinstance(taxations, list):
        return ""

    tx = None
    for t in taxations:
        if isinstance(t, dict) and t.get("Id") == taxation_id:
            tx = t
            break
    if not isinstance(tx, dict):
        return ""

    for k in ("Rate", "Percentage", "Percent", "Value"):
        v = safe_float(tx.get(k))
        if v is not None:
            if 0 < v <= 1:
                v = v * 100
            return f"{v:.2f}%"
    return ""
    taxation_id = (
        product.get("TaxationId")
        or product.get("TaxId")
        or product.get("Taxation")
        or (product.get("Taxations")[0] if isinstance(product.get("Taxations"), list) and product.get("Taxations") else None)
        or (product.get("TaxationIds")[0] if isinstance(product.get("TaxationIds"), list) and product.get("TaxationIds") else None)
    )
    if not taxation_id or not isinstance(taxations, list):
        return ""
    tx = None
    for t in taxations:
        if isinstance(t, dict) and t.get("Id") == taxation_id:
            tx = t
            break
    if not isinstance(tx, dict):
        return ""
    for k in ("Rate", "Percentage", "Percent", "Value"):
        v = safe_float(tx.get(k))
        if v is not None:
            if 0 < v <= 1:
                v = v * 100
            return f"{v:.2f}%"
    return ""


def parse_utc(dt_str: Any) -> Optional[datetime]:
    if not isinstance(dt_str, str) or not dt_str:
        return None
    try:
        if dt_str.endswith("Z"):
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).astimezone(timezone.utc)
        return datetime.fromisoformat(dt_str).astimezone(timezone.utc)
    except Exception:
        return None


def build_accounting_categories_table(accounting_categories: List[Dict[str, Any]],
                                      products: List[Dict[str, Any]],
                                      services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    svc_by_id = {s.get("Id"): (pick_name(s) or s.get("Name") or s.get("Id") or "") for s in services if s.get("Id")}
    svc_ids_by_cat: Dict[str, List[str]] = {}
    for p in products:
        cid = p.get("AccountingCategoryId")
        sid = p.get("ServiceId")
        if cid and sid:
            svc_ids_by_cat.setdefault(cid, [])
            if sid not in svc_ids_by_cat[cid]:
                svc_ids_by_cat[cid].append(sid)

    rows: List[Dict[str, Any]] = []
    for c in accounting_categories:
        cid = c.get("Id") or ""
        svc_names = [svc_by_id.get(sid, sid) for sid in svc_ids_by_cat.get(cid, [])]
        rows.append({
            "Accounting category": c.get("Name") or "",
            "Accounting category ID": cid,
            "Ledger account code": c.get("LedgerAccountCode") or "",
            "Classification": c.get("Classification") or "",
            "Service": ", ".join([n for n in svc_names if n]) or "—",
        })
    rows.sort(key=lambda x: (x.get("Accounting category") or "").lower())
    return rows


def build_product_mapping_table(products: List[Dict[str, Any]],
                                accounting_categories: List[Dict[str, Any]],
                                taxations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Product mapping table (gross price only).
    We intentionally do NOT calculate VAT here (per latest requirement).
    """
    cat_by_id = {c.get("Id"): c for c in accounting_categories if c.get("Id")}
    rows: List[Dict[str, Any]] = []
    for p in products:
        cat = cat_by_id.get(p.get("AccountingCategoryId"))
        rows.append({
            "Product": pick_name(p) or "",
            "Accounting category": (cat.get("Name") if isinstance(cat, dict) else "UNMAPPED") or "UNMAPPED",
            "Gross price": money_from_extended_amount(p.get("Price")),
            "Charging": p.get("ChargingMode") or "",
        })
    rows.sort(key=lambda x: (x.get("Accounting category") or "", x.get("Product") or ""))
    return rows


def build_spaces_table(resources: List[Dict[str, Any]],
                       resource_categories: List[Dict[str, Any]],
                       assignments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a table of: resource category name, space name, state.

    Mews tenants differ slightly in payload shape for ResourceCategoryAssignments.
    Handle the common variants:
      - ResourceId / ResourceCategoryId
      - ResourceIds (list) / ResourceCategoryId
      - ResourceId / CategoryId (or ResourceCategory) style keys
    """
    cat_by_id = {c.get("Id"): c for c in resource_categories if isinstance(c, dict) and c.get("Id")}
    res_by_id = {r.get("Id"): r for r in resources if isinstance(r, dict) and r.get("Id")}

    def get_category_id(a: Dict[str, Any]) -> Optional[str]:
        cid = a.get("ResourceCategoryId") or a.get("CategoryId") or a.get("ResourceCategory")
        if isinstance(cid, dict):
            return cid.get("Id")
        return cid if isinstance(cid, str) else None

    def get_resource_ids(a: Dict[str, Any]) -> List[str]:
        rid = a.get("ResourceId") or a.get("Resource")
        if isinstance(rid, dict):
            rid = rid.get("Id")
        if isinstance(rid, str):
            return [rid]
        rids = a.get("ResourceIds")
        if isinstance(rids, list):
            return [x for x in rids if isinstance(x, str)]
        # Some shapes use "Resources": [{"Id": ...}, ...]
        rs = a.get("Resources")
        if isinstance(rs, list):
            out = []
            for x in rs:
                if isinstance(x, dict) and isinstance(x.get("Id"), str):
                    out.append(x["Id"])
            return out
        return []

    rows: List[Dict[str, Any]] = []
    assigned_resource_ids: set = set()

    for a in assignments:
        if not isinstance(a, dict):
            continue
        cid = get_category_id(a)
        c = cat_by_id.get(cid) if cid else None
        cat_name = (pick_name(c) or (c.get("Name") if isinstance(c, dict) else "") or "UNASSIGNED") if c else "UNASSIGNED"

        for rid in get_resource_ids(a):
            r = res_by_id.get(rid)
            if not r:
                continue
            assigned_resource_ids.add(rid)
            rows.append({
                "Resource category": cat_name,
                "Space": r.get("Name") or "",
                "State": r.get("State") or "",
            })

    # Add truly unassigned spaces (no assignment rows matched their IDs)
    for r in resources:
        rid = r.get("Id")
        if isinstance(rid, str) and rid not in assigned_resource_ids:
            rows.append({
                "Resource category": "UNASSIGNED",
                "Space": r.get("Name") or "",
                "State": r.get("State") or "",
            })

    rows.sort(key=lambda x: (x.get("Resource category") or "", x.get("Space") or ""))
    return rows


def build_rate_groups_table(rate_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for g in rate_groups:
        rows.append({
            "Rate group": pick_name(g) or (g.get("Name") or ""),
            "Rate group ID": g.get("Id") or "",
            "Activity state": "Active" if g.get("IsActive") else "Inactive",
        })
    rows.sort(key=lambda x: (x.get("Rate group") or "").lower())
    return rows


def build_rates_table(rates: List[Dict[str, Any]], rate_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rg_by_id = {g.get("Id"): g for g in rate_groups if g.get("Id")}
    rate_by_id = {r.get("Id"): r for r in rates if r.get("Id")}

    def rname(r: Optional[Dict[str, Any]]) -> str:
        if not isinstance(r, dict):
            return ""
        return pick_name(r) or (r.get("Code") or "") or ""

    rows: List[Dict[str, Any]] = []
    for r in rates:
        base = rate_by_id.get(r.get("BaseRateId")) if r.get("BaseRateId") else None
        rg = rg_by_id.get(r.get("GroupId")) if r.get("GroupId") else None

        visibility = "Public" if r.get("IsPublic") else ("Private" if r.get("IsPrivate") else "—")
        status = "Active" if r.get("IsActive") else "Inactive"
        if r.get("IsEnabled") is False:
            status = "Disabled"

        rows.append({
            "Rate": rname(r),
            "Rate ID": r.get("Id") or "",
            "Base rate": rname(base),
            "Rate group": pick_name(rg) if isinstance(rg, dict) else "",
            "Visibility": visibility,
            "Status": status,
        })
    rows.sort(key=lambda x: (x.get("Rate group") or "", x.get("Rate") or ""))
    return rows


def summarise_restriction_exceptions(ex: Any) -> str:
    if not isinstance(ex, dict) or not ex:
        return "—"
    bits: List[str] = []
    for k, label in (("MinAdvance", "Min advance"), ("MaxAdvance", "Max advance"), ("MinLength", "Min length"), ("MaxLength", "Max length")):
        v = ex.get(k)
        if v:
            bits.append(f"{label}: {v}")
    return "; ".join(bits) if bits else "—"


def summarise_restriction_time(cond: Any) -> str:
    if not isinstance(cond, dict):
        return "None → None"
    s = cond.get("StartUtc") or "None"
    e = cond.get("EndUtc") or "None"
    days = cond.get("Days")
    bits = [f"{s} → {e}"]
    if isinstance(days, list) and days:
        bits.append("Days: " + ",".join(days))
    return " | ".join(bits)


def build_restrictions_table(restrictions: List[Dict[str, Any]],
                             rates: List[Dict[str, Any]],
                             rate_groups: List[Dict[str, Any]],
                             resource_categories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now = utc_now()
    rate_by_id = {r.get("Id"): r for r in rates if r.get("Id")}
    rg_by_id = {g.get("Id"): g for g in rate_groups if g.get("Id")}
    cat_by_id = {c.get("Id"): c for c in resource_categories if c.get("Id")}

    rows: List[Dict[str, Any]] = []
    for r in restrictions:
        cond = r.get("Conditions") if isinstance(r, dict) else None
        if not isinstance(cond, dict):
            continue

        start = parse_utc(cond.get("StartUtc"))
        if start and start <= now:
            continue

        rate_bits: List[str] = []
        if cond.get("ExactRateId"):
            rr = rate_by_id.get(cond.get("ExactRateId"))
            rate_bits.append("Rate: " + (pick_name(rr) if rr else ""))
        if cond.get("BaseRateId"):
            br = rate_by_id.get(cond.get("BaseRateId"))
            rate_bits.append("Base rate: " + (pick_name(br) if br else ""))
        if cond.get("RateGroupId"):
            g = rg_by_id.get(cond.get("RateGroupId"))
            rate_bits.append("Group: " + (pick_name(g) if g else ""))
        rates_scope = "; ".join([b for b in rate_bits if b.strip()]) or "All rates"

        spaces_scope = "All spaces"
        if cond.get("ResourceCategoryId"):
            c = cat_by_id.get(cond.get("ResourceCategoryId"))
            spaces_scope = (pick_name(c) if isinstance(c, dict) else "") or "All spaces"

        rows.append({
            "Time": summarise_restriction_time(cond),
            "Rates": rates_scope,
            "Spaces": spaces_scope,
            "Exceptions": summarise_restriction_exceptions(r.get("Exceptions")),
        })

    rows.sort(key=lambda x: x.get("Time") or "")
    return rows


def build_report(data: Dict[str, Any], base_url: str, client_name: str) -> "AuditReport":
    cfg = data.get("cfg", {}) or {}
    services = data.get("services", []) or []
    rate_groups = data.get("rate_groups", []) or []
    rates = data.get("rates", []) or []
    accounting_categories = data.get("accounting_categories", []) or []
    products = data.get("products", []) or []
    payments = data.get("payments", []) or []
    resources = data.get("resources", []) or []
    resource_categories = data.get("resource_categories", []) or []
    rca = data.get("resource_category_assignments", []) or []
    restrictions = data.get("restrictions", []) or []
    tax_envs = data.get("tax_environments", []) or []
    taxations = data.get("taxations", []) or []
    counters = data.get("counters", []) or []
    cashiers = data.get("cashiers", []) or []
    errors = data.get("errors", {}) or {}

    acc_categories_table = build_accounting_categories_table(accounting_categories, products, services)
    product_mapping_table = build_product_mapping_table(products, accounting_categories, taxations)
    spaces_table = build_spaces_table(resources, resource_categories, rca)
    rate_groups_table = build_rate_groups_table(rate_groups)
    rates_table = build_rates_table(rates, rate_groups)
    restrictions_table = build_restrictions_table(restrictions, rates, rate_groups, resource_categories)

    ent = (cfg.get("Enterprise") or {}) if isinstance(cfg, dict) else {}
    enterprise_id = ent.get("Id") or (data.get("enterprises", [""])[0] if data.get("enterprises") else "")
    enterprise_name = ent.get("Name") or "Unknown"

    def status_for(keys: List[str], default_ok: str) -> Tuple[str, str]:
        errs = []
        for k in keys:
            if k in errors and errors[k]:
                errs.append(f"{k}: {errors[k]}")
        if errs:
            return "NEEDS_INPUT", " | ".join(errs)
        return default_ok, ""

    sections: List[Tuple[str, List[CheckItem]]] = []

    legal_items: List[CheckItem] = []
    tz = (cfg.get("Enterprise") or {}).get("TimeZone") if isinstance(cfg, dict) else None
    currency = (cfg.get("Enterprise") or {}).get("DefaultCurrency") if isinstance(cfg, dict) else None

    st_tax, err_tax = status_for(["tax_environments_getall", "taxations_getall"], "PASS" if (tax_envs or taxations) else "WARN")
    summary = f"TaxEnvironments={len(tax_envs)}, Taxations={len(taxations)}"
    if err_tax:
        summary += f" | {err_tax}"
    legal_items.append(CheckItem("Time zone", "PASS" if tz else "WARN", str(tz or "Not identified"), "Connector: Configuration/Get", "Set enterprise/property time zone in Mews if missing.", {}, "High" if not tz else "Low"))
    legal_items.append(CheckItem("Default currency", "PASS" if currency else "WARN", str(currency or "Not identified"), "Connector: Configuration/Get", "Ensure a default currency is set at enterprise level.", {}, "High" if not currency else "Low"))
    legal_items.append(CheckItem("Tax environment + VAT/GST rates", st_tax, summary, "Connector: TaxEnvironments/GetAll + Taxations/GetAll", "Validate tax environment selection and tax codes match jurisdiction.", {"TaxEnvironments": tax_envs[:200], "Taxations": taxations[:500]}, "Medium"))

    st_cfg, err_cfg = status_for(["configuration_get"], "PASS")
    if err_cfg:
        legal_items.append(CheckItem("Configuration retrieval", "NEEDS_INPUT", err_cfg, "Connector: Configuration/Get", "Confirm API base URL and tokens; ensure Connector API is accessible.", {}, "High"))

    sections.append(("Legal & property baseline", legal_items))

    accounting_items: List[CheckItem] = []
    st_ac, err_ac = status_for(["accounting_categories_getall"], "PASS" if accounting_categories else "WARN")
    s = f"Accounting categories returned: {len(accounting_categories)}"
    if err_ac:
        s += f" | {err_ac}"
    accounting_items.append(CheckItem(
        key="Accounting categories (list)",
        status=st_ac,
        summary=s,
        source="Connector: AccountingCategories/GetAll",
        remediation="Review category codes/classifications and ledger mappings; confirm alignment with finance export.",
        details={"AccountingCategoriesTable": acc_categories_table},
        risk="High"
    ))

    st_prod, err_prod = status_for(["products_getall", "taxations_getall"], "PASS" if products else "WARN")
    s = f"Products returned: {len(products)}"
    if err_prod:
        s += f" | {err_prod}"
    accounting_items.append(CheckItem(
        key="Product mapping (product → accounting category)",
        status=st_prod,
        summary=s,
        source="Connector: Products/GetAll + AccountingCategories/GetAll",
        remediation="Validate each product is mapped to the correct accounting category, uses the intended taxation, and has the correct charging mode.",
        details={"ProductMappingTable": product_mapping_table},
        risk="High"
    ))

    st_cash, err_cash = status_for(["cashiers_getall", "counters_getall"], "PASS" if (cashiers or counters) else "WARN")
    s = f"Cashiers={len(cashiers)}, Counters={len(counters)}"
    if err_cash:
        s += f" | {err_cash}"
    accounting_items.append(CheckItem(
        key="Cash / counters",
        status=st_cash,
        summary=s,
        source="Connector: Cashiers/GetAll + Counters/GetAll",
        remediation="Ensure cashiers are assigned and counters/numbering comply with local rules.",
        details={},
        risk="Medium"
    ))
    sections.append(("Accounting configuration", accounting_items))

    pay_items: List[CheckItem] = []
    # Default counts (populated below when 6-month windows are fetched)
    payment_origin_counts_charged_6m: Dict[str, int] = {}
    payment_origin_counts_failed_6m: Dict[str, int] = {}
    st_pay, err_pay = status_for(["payments_getall", "payments_origin_charged_6m_w1", "payments_origin_charged_6m_w2", "payments_origin_failed_6m_w1", "payments_origin_failed_6m_w2"], "PASS")
    s = f"Payments (30d sample)={len(payments)} | 6m Charged origins={len(payment_origin_counts_charged_6m)} | 6m Failed/Cancelled origins={len(payment_origin_counts_failed_6m)}"
    if err_pay:
        s += f" | {err_pay}"
    pay_items.append(CheckItem(
        key="Payments (last 30 days sample)",
        status=st_pay,
        summary=s,
        source="Connector: Payments/GetAll (CreatedUtc 30d window)",
        remediation="If empty or failing, verify token scope/permissions and that the CreatedUtc window is supported.",
        details={"Payments": payments, "PaymentOriginCountsCharged6m": payment_origin_counts_charged_6m, "PaymentOriginCountsFailed6m": payment_origin_counts_failed_6m},
        risk="Low"
    ))
    sections.append(("Payments", pay_items))

    inv_items: List[CheckItem] = []
    space_err_keys = ["services_getall", "resources_getall", "resource_category_assignments_getall"]
    space_err_keys.extend([k for k in errors.keys() if k.startswith("resource_categories_getall_")])

    st_spaces, err_spaces = status_for(space_err_keys, "PASS" if resources else "WARN")
    s = f"Spaces={len(resources)}, ResourceCategories={len(resource_categories)}, Assignments={len(rca)}"
    if err_spaces:
        s += f" | {err_spaces}"
    inv_items.append(CheckItem(
        key="Spaces and resource categories",
        status=st_spaces,
        summary=s,
        source="Connector: Services/GetAll + Resources/GetAll + ResourceCategories/GetAll + ResourceCategoryAssignments/GetAll",
        remediation="Confirm each space is assigned to the correct resource category and has the expected state. If assignments cannot be retrieved, re-check token scope/endpoint validation for your tenant.",
        details={"SpacesTable": spaces_table},
        risk="High"
    ))

    st_rg, err_rg = status_for(["rate_groups_getall"], "PASS" if rate_groups else "WARN")
    s = f"RateGroups={len(rate_groups)}"
    if err_rg:
        s += f" | {err_rg}"
    inv_items.append(CheckItem(
        key="Rate groups",
        status=st_rg,
        summary=s,
        source="Connector: RateGroups/GetAll",
        remediation="Review rate group list and activity state.",
        details={"RateGroupsTable": rate_groups_table},
        risk="Medium"
    ))

    st_rates, err_rates = status_for(["rates_getall"], "PASS" if rates else "WARN")
    s = f"Rates={len(rates)}"
    if err_rates:
        s += f" | {err_rates}"
    inv_items.append(CheckItem(
        key="Rates",
        status=st_rates,
        summary=s,
        source="Connector: Rates/GetAll",
        remediation="Review rate list, base rate inheritance, group membership, visibility and status.",
        details={"RatesTable": rates_table},
        risk="High"
    ))

    st_rest, err_rest = status_for(["restrictions_getall"], "PASS" if restrictions else "WARN")
    s = f"Restrictions returned: {len(restrictions)}; Future-only rows: {len(restrictions_table)}"
    if err_rest:
        s += f" | {err_rest}"
    inv_items.append(CheckItem(
        key="Restrictions (future stays)",
        status=st_rest,
        summary=s,
        source="Connector: Restrictions/GetAll",
        remediation="Review future-only restrictions for correctness of time window, rate scope, space scope and exceptions.",
        details={"RestrictionsTable": restrictions_table},
        risk="Medium"
    ))
    sections.append(("Spaces, rates & restrictions", inv_items))

    calls: List[ApiCall] = []
    for c in data.get("api_calls", []):
        if isinstance(c, dict):
            calls.append(ApiCall(
                operation=str(c.get("operation") or ""),
                ok=bool(c.get("ok")),
                status_code=c.get("status_code"),
                duration_ms=int(c.get("duration_ms") or 0),
                error=c.get("error"),
            ))

    return AuditReport(
        enterprise_id=str(enterprise_id or ""),
        enterprise_name=str(enterprise_name or "Unknown"),
        base_url=base_url,
        client_name=client_name,
        generated_utc=utc_now(),
        api_calls=calls,
        sections=sections,
    )


def fetch_logo():
    if not LOGO_URL:
        return None
    try:
        resp = requests.get(LOGO_URL, timeout=10)
        if not resp.ok:
            return None
        tmp = "/tmp/logo.svg"
        with open(tmp, "wb") as f:
            f.write(resp.content)
        return svg2rlg(tmp)
    except Exception:
        return None


def build_pdf(report: AuditReport) -> bytes:
    from io import BytesIO

    buf = BytesIO()

    # --- Font registration (Manrope for headings, Inter for body) ---
    FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")
    pdfmetrics.registerFont(TTFont("Inter", os.path.join(FONT_DIR, "Inter-Regular.ttf")))
    pdfmetrics.registerFont(TTFont("Manrope", os.path.join(FONT_DIR, "Manrope-Regular.ttf")))
    pdfmetrics.registerFont(TTFont("Manrope-Semibold", os.path.join(FONT_DIR, "Manrope-SemiBold.ttf")))

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleX", parent=styles["Title"], fontName="Manrope-Semibold", fontSize=20, leading=24, alignment=TA_CENTER, spaceAfter=10, textColor=colors.HexColor("#1C1D24")))
    styles.add(ParagraphStyle(name="H1X", parent=styles["Heading1"], fontName="Manrope-Semibold", fontSize=15, leading=18, spaceBefore=10, spaceAfter=6, textColor=colors.HexColor("#1C1D24")))
    styles.add(ParagraphStyle(name="BodyX", parent=styles["BodyText"], fontName="Inter", fontSize=9.6, leading=12, textColor=colors.HexColor("#1C1D24")))
    styles.add(ParagraphStyle(name="SmallX", parent=styles["BodyText"], fontName="Inter", fontSize=8.6, leading=11, textColor=colors.HexColor("#1C1D24")))
    styles.add(ParagraphStyle(name="TinyX", parent=styles["BodyText"], fontName="Inter", fontSize=8.1, leading=10, textColor=colors.HexColor("#1C1D24")))

    logo = fetch_logo()

        # --- Document + frames (Page 1 default margins; Pages 2+ left margin reduced by 50%) ---
    PAGE_W, PAGE_H = A4
    LEFT_FIRST = 16 * mm
    RIGHT = 16 * mm
    LEFT_LATER = RIGHT
    TOP = 18 * mm
    BOTTOM = 16 * mm

    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        title="Mews Configuration Audit Report",
        author="Mews Audit Tool",
    )

    frame_first = Frame(LEFT_FIRST, BOTTOM, PAGE_W - LEFT_FIRST - RIGHT, PAGE_H - TOP - BOTTOM, id="F_FIRST")
    frame_later = Frame(LEFT_LATER, BOTTOM, PAGE_W - LEFT_LATER - RIGHT, PAGE_H - TOP - BOTTOM, id="F_LATER")

    def P(text: Any, style: str = "TinyX") -> Paragraph:
        return Paragraph(esc(text), styles[style])

    def safe_para(text: str, style_name: str) -> Paragraph:
        try:
            return Paragraph(text, styles[style_name])
        except Exception:
            plain = text.replace("<", "&lt;").replace(">", "&gt;")
            return Paragraph(plain, styles[style_name])

    def badge(status: str) -> str:
        st = (status or "").upper()
        if st == "PASS":
            return "<font color='#16a34a'><b>PASS</b></font>"
        if st == "WARN":
            return "<font color='#f59e0b'><b>WARN</b></font>"
        if st == "FAIL":
            return "<font color='#dc2626'><b>FAIL</b></font>"
        if st == "NEEDS_INPUT":
            return "<font color='#7c3aed'><b>NEEDS INPUT</b></font>"
        return f"<font color='#64748b'><b>{esc(st)}</b></font>"

    STANDARD_TABLE_WIDTH = sum([44*mm, 34*mm, 38*mm, 44*mm, 18*mm, 18*mm])

    def make_long_table(header: List[str], rows: List[List[Any]], col_widths: List[float]) -> LongTable:
        data: List[List[Any]] = [[P(h, "SmallX") for h in header]]
        for r in rows:
            data.append([c if isinstance(c, Paragraph) else P(c, "TinyX") for c in r])
        # Scale all tables to a consistent width for alignment/scanability
        try:
            total_w = float(sum(col_widths)) if col_widths else 0.0
            target_w = float(STANDARD_TABLE_WIDTH)
            if total_w > 0 and target_w > 0:
                scale = target_w / total_w
                col_widths = [w * scale for w in col_widths]
        except Exception:
            pass

        t = LongTable(data, colWidths=col_widths, repeatRows=1)
        t.hAlign = "LEFT"

        id_cols = set()
        for i, h in enumerate(header):
            hl = (h or "").lower()
            if "id" in hl or "uuid" in hl:
                id_cols.add(i)

        ts = TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Inter"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F7BCF1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1C1D24")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
        for ci in sorted(id_cols):
            ts.add("FONTSIZE", (ci, 1), (ci, -1), 6.8)

        for i in range(1, len(data)):
            if i % 2 == 0:
                ts.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#EFEFFF"))

        t.setStyle(ts)
        return t

    def header_footer(canvas, doc_):
        canvas.saveState()

        top_y = A4[1] - 10 * mm  # near top margin
        right_x = A4[0] - 16 * mm

        # Logo: same visual height as the title line, top-right on the SAME line
        # 12.5pt title text ~= 4.4mm. Give the logo a ~4.8mm height to match.
        target_h = 6.2 * mm
        target_w = 24 * mm  # keep compact so it doesn't collide with the page number

        x_logo = right_x - target_w
        # drawString uses a baseline; align logo vertically with the title's text box.
        title_y = top_y - 3 * mm
        y_logo = title_y + (1.2 * mm)

        if logo:
            try:
                lw = float(getattr(logo, "width", 0) or 0)
                lh = float(getattr(logo, "height", 0) or 0)
                if lw > 0 and lh > 0:
                    s = min(target_w / lw, target_h / lh)
                    canvas.saveState()
                    canvas.translate(x_logo, y_logo)
                    canvas.scale(s, s)
                    renderPDF.draw(logo, canvas, 0, 0)
                    canvas.restoreState()
            except Exception:
                pass

        # Title on the left
        canvas.setFont("Manrope-Semibold", 12.5)
        canvas.drawString(16 * mm, title_y, "Mews Configuration Audit Report")
        # Page number at the bottom (centred)
        canvas.setFont("Inter", 8.5)
        bottom_y = 10 * mm
        canvas.drawCentredString(A4[0] / 2.0, bottom_y, f"Page {doc_.page}")

        canvas.restoreState()
    # Page templates: page 1 uses original left margin; later pages use reduced left margin
    pt_first = PageTemplate(id="First", frames=[frame_first], onPage=header_footer)
    pt_later = PageTemplate(id="Later", frames=[frame_later], onPage=header_footer)
    doc.addPageTemplates([pt_first, pt_later])

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

    total = 0
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "NEEDS_INPUT": 0, "NA": 0}
    for _, items in report.sections:
        for it in items:
            total += 1
            counts[it.status] = counts.get(it.status, 0) + 1

    story.append(Paragraph(
        f"<b>Summary</b> &nbsp;&nbsp; Items: <b>{total}</b> &nbsp;&nbsp; "
        f"PASS: <b>{counts.get('PASS',0)}</b> &nbsp;&nbsp; "
        f"WARN: <b>{counts.get('WARN',0)}</b> &nbsp;&nbsp; "
        f"FAIL: <b>{counts.get('FAIL',0)}</b> &nbsp;&nbsp; "
        f"NEEDS_INPUT: <b>{counts.get('NEEDS_INPUT',0)}</b> &nbsp;&nbsp; "
        f"NA: <b>{counts.get('NA',0)}</b>",
        styles["BodyX"]
    ))
    story.append(NextPageTemplate('Later'))
    story.append(PageBreak())

    for sec_name, items in report.sections:
        story.append(Paragraph(sec_name, styles["H1X"]))
        story.append(Spacer(1, 6))

        over_rows = []
        for it in items:
            over_rows.append([P(it.key, "SmallX"), safe_para(badge(it.status), "SmallX"), P(it.risk, "SmallX"), P(it.summary, "SmallX")])
        story.append(make_long_table(["Check", "Status", "Risk", "Summary"], over_rows, [62*mm, 20*mm, 18*mm, 78*mm]))
        story.append(Spacer(1, 8))

        for it in items:
            block: List[Any] = []
            block.append(safe_para(f"<b>{esc(it.key)}</b> &nbsp;&nbsp; {badge(it.status)} &nbsp;&nbsp; <font color='#64748b'>Risk:</font> <b>{esc(it.risk)}</b>", "BodyX"))
            block.append(Paragraph(esc(it.summary or "-"), styles["BodyX"]))
            block.append(Spacer(1, 4))

            details = it.details or {}

            def render_dict_table(title: str, header: List[str], rows_dicts: List[Dict[str, Any]], colw: List[float], chunk: int = 350):
                block.append(Paragraph(f"<b>Detail: {esc(title)}</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                for ch in chunk_list(rows, chunk):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            if "AccountingCategoriesTable" in details:
                render_dict_table(
                    "Accounting categories",
                    ["Accounting category", "Accounting category ID", "Ledger account code", "Classification", "Service"],
                    details.get("AccountingCategoriesTable") or [],
                    [50*mm, 42*mm, 30*mm, 26*mm, 32*mm],
                )

            if "ProductMappingTable" in details:
                render_dict_table(
                    "Product mapping",
                    ["Product", "Accounting category", "Gross price", "Charging"],
                    details.get("ProductMappingTable") or [],
                    [74*mm, 66*mm, 22*mm, 28*mm],
                )

            if "SpacesTable" in details:
                render_dict_table(
                    "Spaces and resource categories",
                    ["Resource category", "Space", "State"],
                    details.get("SpacesTable") or [],
                    [66*mm, 84*mm, 28*mm],
                    chunk=400,
                )

            if "RateGroupsTable" in details:
                render_dict_table(
                    "Rate groups",
                    ["Rate group", "Rate group ID", "Activity state"],
                    details.get("RateGroupsTable") or [],
                    [64*mm, 80*mm, 32*mm],
                )

            if "RatesTable" in details:
                render_dict_table(
                    "Rates",
                    ["Rate", "Rate ID", "Base rate", "Rate group", "Visibility", "Status"],
                    details.get("RatesTable") or [],
                    [44*mm, 34*mm, 38*mm, 44*mm, 18*mm, 18*mm],
                )

            if "RestrictionsTable" in details:
                render_dict_table(
                    "Restrictions (future stays)",
                    ["Time", "Rates", "Spaces", "Exceptions"],
                    details.get("RestrictionsTable") or [],
                    [46*mm, 54*mm, 38*mm, 46*mm],
                )

            if "Payments" in details:
                pays = details.get("Payments") or []
                header = ["PaymentId", "Type", "State", "Curr", "Net", "Gross", "CreatedUtc"]
                rows = []
                for p in pays:
                    amt = p.get("Amount") or {}
                    rows.append([P(p.get("Id") or ""), P(p.get("Type") or ""), P(p.get("State") or ""),
                                 P(amt.get("Currency") or p.get("Currency") or ""),
                                 P(str(amt.get("NetValue") or "")),
                                 P(str(amt.get("GrossValue") or "")),
                                 P(p.get("CreatedUtc") or "")])
                block.append(Paragraph("<b>Detail: Payments (30-day sample)</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 300):
                    block.append(make_long_table(header, ch, [38*mm, 22*mm, 16*mm, 10*mm, 16*mm, 16*mm, 44*mm]))
                    block.append(Spacer(1, 6))

                # PaymentOrigin breakdowns (last 6 months)
                charged_counts = (it.details or {}).get("PaymentOriginCountsCharged6m") or []
                failed_counts = (it.details or {}).get("PaymentOriginCountsFailed6m") or []

                if charged_counts:
                    block.append(Paragraph("<b>Payment Origin (last 6 months) — Charged</b>", styles["SmallX"]))
                    block.append(Spacer(1, 3))
                    header2 = [P("<b>Payment origin</b>"), P("<b>Count</b>")]
                    rows2 = [[P(str(r.get("PaymentOrigin") or "None")), P(str(r.get("Count") or 0))] for r in charged_counts]
                    for ch2 in chunk_list(rows2, 500):
                        block.append(make_long_table(header2, ch2, [90*mm, 30*mm]))
                        block.append(Spacer(1, 6))
                else:
                    block.append(Paragraph("<b>Payment Origin (last 6 months) — Charged</b>", styles["SmallX"]))
                    block.append(Spacer(1, 2))
                    block.append(Paragraph("<font color='#64748b'>NEEDS_INPUT: No data returned (or API call failed).</font>", styles["TinyX"]))
                    block.append(Spacer(1, 6))

                if failed_counts:
                    block.append(Paragraph("<b>Payment Origin (last 6 months) — Failed / Cancelled</b>", styles["SmallX"]))
                    block.append(Spacer(1, 3))
                    header3 = [P("<b>Payment origin</b>"), P("<b>Count</b>")]
                    rows3 = [[P(str(r.get("PaymentOrigin") or "None")), P(str(r.get("Count") or 0))] for r in failed_counts]
                    for ch3 in chunk_list(rows3, 500):
                        block.append(make_long_table(header3, ch3, [90*mm, 30*mm]))
                        block.append(Spacer(1, 6))
                else:
                    block.append(Paragraph("<b>Payment Origin (last 6 months) — Failed / Cancelled</b>", styles["SmallX"]))
                    block.append(Spacer(1, 2))
                    block.append(Paragraph("<font color='#64748b'>NEEDS_INPUT: No data returned (or API call failed).</font>", styles["TinyX"]))
                    block.append(Spacer(1, 6))

            if it.source:
                block.append(Paragraph(f"<font color='#64748b'><b>Source:</b> {esc(it.source)}</font>", styles["TinyX"]))
            if it.remediation:
                block.append(safe_para(f"<b>Recommendation:</b> {esc(it.remediation)}", "SmallX"))

            block.append(Spacer(1, 10))
            story.append(KeepTogether(block))

        story.append(PageBreak())

    story.append(Paragraph("Appendix: API call log", styles["H1X"]))
    story.append(Spacer(1, 6))
    rows = []
    for c in report.api_calls:
        line = f"{c.operation} | ok={c.ok} | http={c.status_code or ''} | {c.duration_ms}ms"
        if c.error:
            line += f" | {c.error}"
        rows.append([P(line)])
    for ch in chunk_list(rows, 500):
        story.append(make_long_table(["Call"], ch, [A4[0] - (32 * mm)]))
        story.append(Spacer(1, 6))

    doc.build(story)
    pdf = buf.getvalue()
    if len(pdf) > MAX_PDF_MB * 1024 * 1024:
        raise RuntimeError(f"Generated PDF too large ({len(pdf)/(1024*1024):.1f}MB) for environment limit ({MAX_PDF_MB}MB).")
    return pdf


HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Mews Audit Backend</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin:0;background:#0b1220;color:#e8eefc}
.wrap{max-width:920px;margin:0 auto;padding:24px}
.card{background:#111a2e;border:1px solid #1f2b4a;border-radius:14px;padding:18px;margin:14px 0}
label{display:block;font-weight:600;margin:10px 0 6px}
input{width:100%;padding:10px;border-radius:10px;border:1px solid #2a3a63;background:#0c1426;color:#e8eefc}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.btn{display:inline-block;padding:12px 14px;border-radius:12px;border:0;background:#3b82f6;color:#fff;font-weight:700;cursor:pointer}
.muted{color:#a9b7d6;font-size:13px;line-height:1.35}
code{background:#0c1426;padding:2px 6px;border-radius:8px;border:1px solid #1f2b4a}
</style></head>
<body><div class="wrap">
<h1>Mews Audit Backend</h1>
<p class="muted">POST tokens to <code>/audit</code> to generate a PDF report.</p>
<div class="card">
<form method="post" action="/audit">
  <div class="row">
    <div><label>Client token</label><input name="client_token" placeholder="ClientToken"></div>
    <div><label>Access token</label><input name="access_token" placeholder="AccessToken"></div>
  </div>
  <label>API base URL</label>
  <input name="base_url" placeholder="https://api.mews-demo.com/api/connector/v1" value="https://api.mews-demo.com/api/connector/v1">
  <div style="margin-top:14px"><button class="btn" type="submit">Generate PDF</button></div>
</form>
</div></div></body></html>
"""

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "mews-audit-secret")
CORS(app, resources={r"/*": {"origins": "*"}})


@app.get("/")
def home():
    return render_template_string(HTML)


def _extract_param(name: str) -> Optional[str]:
    if request.is_json:
        v = (request.json or {}).get(name)
        return v.strip() if isinstance(v, str) else v
    v = request.form.get(name) if request.form else None
    return v.strip() if isinstance(v, str) else v


@app.post("/audit")
def audit():
    try:
        ct = _extract_param("client_token")
        at = _extract_param("access_token")
        base_url = _extract_param("base_url") or DEFAULT_API_BASE

        if not ct or not at:
            return jsonify({"ok": False, "error": "Missing client_token or access_token"}), 400

        data = collect_data(base_url, ct, at, DEFAULT_CLIENT_NAME)
        report = build_report(data, base_url, DEFAULT_CLIENT_NAME)
        pdf = build_pdf(report)

        from io import BytesIO
        bio = BytesIO(pdf)
        bio.seek(0)
        fn = f"mews-audit-{report.enterprise_id or 'enterprise'}-{utc_now().strftime('%Y%m%d-%H%M%S')}.pdf"
        return send_file(bio, mimetype="application/pdf", as_attachment=True, download_name=fn)

    except Exception as e:
        err = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        print("AUDIT ERROR")
        print(err)
        return jsonify({"ok": False, "error": str(e), "trace": err}), 500


@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": utc_now().isoformat(), "base": DEFAULT_API_BASE})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)    # Page templates (First page uses original left margin; later pages use reduced left margin)


