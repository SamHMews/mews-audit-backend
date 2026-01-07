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

# --- Table colour palette (consistent across all tables) ---
TABLE_HEADER_BG = colors.HexColor('#f6b6e8')  # light magenta header
ROW_ALT_BG      = colors.HexColor('#eef0ff')  # subtle lavender zebra rows
GRID_COLOR      = colors.HexColor('#c7cbe6')  # soft grid line colour

from reportlab.lib.pagesizes import A4

# --- Page / margin constants ---
PAGE_W, PAGE_H = A4
from reportlab.lib.units import mm
DOC_LEFT   = 12 * mm
DOC_RIGHT  = 12 * mm
DOC_TOP    = 24 * mm
DOC_BOTTOM = 14 * mm
TABLE_FULL_W = PAGE_W - DOC_LEFT - DOC_RIGHT

from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, KeepTogether
from reportlab.platypus.tables import LongTable, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

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
        # Availability blocks (next 90 days) — chunk CollidingUtc windows (API enforces a max interval)
        availability_blocks: List[Dict[str, Any]] = []
        try:
            start = utc_now()
            end = start + timedelta(days=90)

            # The API can reject long CollidingUtc windows; use <=96h chunks for safety.
            step = timedelta(hours=96)
            cursor = start

            seen_ids: set[str] = set()
            while cursor < end:
                chunk_end = min(cursor + step, end)
                payload = {
                    "Extent": {"AvailabilityBlocks": True, "Adjustments": False},
                    "CollidingUtc": {
                        "StartUtc": cursor.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "EndUtc": chunk_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                    "ActivityStates": ["Active"],
                    "Limitation": {"Count": 1000},
                }
                data_ab = mc.get("AvailabilityBlocks", "GetAll", payload)
                chunk = data_ab.get("AvailabilityBlocks") or []
                if isinstance(chunk, list):
                    for b in chunk:
                        if not isinstance(b, dict):
                            continue
                        bid = b.get("Id")
                        if bid and bid in seen_ids:
                            continue
                        if bid:
                            seen_ids.add(bid)
                        availability_blocks.append(b)
                cursor = chunk_end
        except Exception as e:
            errors["availability_blocks_getall"] = str(e)
            availability_blocks = []

        # Rules (GetAll requires Extent)
        rules_bundle: Dict[str, Any] = {"Rules": [], "RuleActions": [], "Rates": [], "RateGroups": [], "ResourceCategories": [], "BusinessSegments": []}
        try:
            payload = {
                "Extent": {"RuleActions": True, "Rates": True, "RateGroups": True, "ResourceCategories": True, "BusinessSegments": True},
                "Limitation": {"Count": 1000},
            }
            data_rules = mc.get("Rules", "GetAll", payload)
            if isinstance(data_rules, dict):
                for k in ("Rules", "RuleActions", "Rates", "RateGroups", "ResourceCategories", "BusinessSegments"):
                    v = data_rules.get(k)
                    rules_bundle[k] = v if isinstance(v, list) else []
        except Exception as e:
            errors["rules_getall"] = str(e)

    else:
        rate_groups, rates, products, restrictions, availability_blocks, rules_bundle = [], [], [], [], [], {"Rules": [], "RuleActions": [], "Rates": [], "RateGroups": [], "ResourceCategories": [], "BusinessSegments": []}
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
    try:
        start = (utc_now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        payments = mc.paged_get_all(
            "Payments", "GetAll",
            {"EnterpriseIds": enterprises, "CreatedUtc": {"StartUtc": start, "EndUtc": end}},
            "Payments",
            count_per_page=500, hard_limit=20000,
        )
    except Exception as e:
        errors["payments_getall"] = str(e)
        payments = []
    # Payments — PaymentOrigin summary (last 90 days, limited to 1000)
    payment_origin_counts_charged_90d: List[Dict[str, Any]] = []
    payment_origin_counts_failed_90d: List[Dict[str, Any]] = []
    try:
        start90 = (utc_now() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end90 = utc_now().strftime('%Y-%m-%dT%H:%M:%SZ')
        payments_90d_charged = mc.paged_get_all(
            "Payments", "GetAll",
            {"EnterpriseIds": enterprises, "CreatedUtc": {"StartUtc": start90, "EndUtc": end90}, "States": ["Charged"]},
            "Payments",
            count_per_page=1000,
            hard_limit=1000,
        )
        counts: Dict[str, int] = {}
        for pmt in payments_90d_charged or []:
            origin = (pmt.get("PaymentOrigin") or "None").strip() if isinstance(pmt, dict) else "None"
            if not origin:
                origin = "None"
            counts[origin] = counts.get(origin, 0) + 1
        payment_origin_counts_charged_90d = [{"PaymentOrigin": k, "Count": v} for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    except Exception as e:
        errors["payments_origin_charged_90d"] = str(e)
        payment_origin_counts_charged_90d = []

    try:
        start90 = (utc_now() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end90 = utc_now().strftime('%Y-%m-%dT%H:%M:%SZ')
        payments_90d_failed = mc.paged_get_all(
            "Payments", "GetAll",
            {"EnterpriseIds": enterprises, "CreatedUtc": {"StartUtc": start90, "EndUtc": end90}, "States": ["Cancelled", "Failed"]},
            "Payments",
            count_per_page=1000,
            hard_limit=1000,
        )
        counts: Dict[str, int] = {}
        for pmt in payments_90d_failed or []:
            origin = (pmt.get("PaymentOrigin") or "None").strip() if isinstance(pmt, dict) else "None"
            if not origin:
                origin = "None"
            counts[origin] = counts.get(origin, 0) + 1
        payment_origin_counts_failed_90d = [{"PaymentOrigin": k, "Count": v} for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    except Exception as e:
        errors["payments_origin_failed_90d"] = str(e)
        payment_origin_counts_failed_90d = []

    cancellation_policies: List[Dict[str, Any]] = []
    if service_ids:
        cancellation_policies = fetch_list("cancellation_policies_getall", "CancellationPolicies", "GetAll",
                                           {"ServiceIds": service_ids}, "CancellationPolicies")

    rules: List[Dict[str, Any]] = []

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
        "availability_blocks": availability_blocks,
        "rules_bundle": rules_bundle,
        "availability_blocks": availability_blocks,
        "rules_bundle": rules_bundle,
        "payments": payments,
        "payment_origin_counts_charged_90d": payment_origin_counts_charged_90d,
        "payment_origin_counts_failed_90d": payment_origin_counts_failed_90d,
        "cancellation_policies": cancellation_policies,
        "rules": rules,
        "tax_environments": tax_envs,
        "taxations": taxations,
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
    services_by_id: Dict[str, str]
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
                        "Ledger account code": c.get("LedgerAccountCode") or "",
            "Classification": c.get("Classification") or "",
            "Service": ", ".join([n for n in svc_names if n]),
        })
    rows.sort(key=lambda x: (x.get("Accounting category") or "").lower())
    return rows


def build_product_mapping_tables(products: List[Dict[str, Any]],
                                 accounting_categories: List[Dict[str, Any]],
                                 taxations: List[Dict[str, Any]],
                                 services: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Product mapping tables (gross price only).

    Returns:
      mapped_rows   : products that have an AccountingCategoryId
      unmapped_rows : products without an AccountingCategoryId

    Note: We intentionally do NOT calculate VAT here (per latest requirement).
    """
    cat_by_id = {c.get("Id"): c for c in accounting_categories if c.get("Id")}
    svc_by_id = {s.get("Id"): (pick_name(s) or (s.get("Name") or "")) for s in services if isinstance(s, dict) and s.get("Id")}

    mapped: List[Dict[str, Any]] = []
    unmapped: List[Dict[str, Any]] = []

    for p in products:
        cat_id = p.get("AccountingCategoryId")
        cat = cat_by_id.get(cat_id) if cat_id else None
        row = {
            "Service": svc_by_id.get(p.get("ServiceId")) or "",
            "Product": pick_name(p) or "",
            "Accounting category": (cat.get("Name") if isinstance(cat, dict) else "UNMAPPED") or "UNMAPPED",
            "Gross price": money_from_extended_amount(p.get("Price")),
            "Charging": p.get("ChargingMode") or "",
        }
        if cat_id:
            mapped.append(row)
        else:
            unmapped.append(row)

    mapped.sort(key=lambda x: ((x.get("Accounting category") or ""), (x.get("Service") or ""), (x.get("Product") or "")))
    unmapped.sort(key=lambda x: ((x.get("Service") or ""), (x.get("Product") or "")))

    return mapped, unmapped


def build_spaces_table(resources: List[Dict[str, Any]],
                       resource_categories: List[Dict[str, Any]],
                       assignments: List[Dict[str, Any]],
                       services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a table of: service name, resource category name, space name, state.

    Mews tenants differ slightly in payload shape for ResourceCategoryAssignments.
    Handle the common variants:
      - ResourceId / ResourceCategoryId
      - ResourceIds (list) / ResourceCategoryId
      - ResourceId / CategoryId (or ResourceCategory) style keys
    """
    cat_by_id = {c.get("Id"): c for c in resource_categories if isinstance(c, dict) and c.get("Id")}
    res_by_id = {r.get("Id"): r for r in resources if isinstance(r, dict) and r.get("Id")}
    svc_by_id = {s.get("Id"): pick_name(s) or (s.get("Name") or "") for s in services if isinstance(s, dict) and s.get("Id")}

    def get_category_id(a: Dict[str, Any]) -> Optional[str]:
        for k in ("ResourceCategoryId", "CategoryId"):
            v = a.get(k)
            if isinstance(v, str) and v:
                return v
        # Some payloads might nest category
        cat = a.get("ResourceCategory")
        if isinstance(cat, dict) and isinstance(cat.get("Id"), str):
            return cat.get("Id")
        return None

    def get_resource_ids(a: Dict[str, Any]) -> List[str]:
        rid = a.get("ResourceId")
        if isinstance(rid, str) and rid:
            return [rid]
        rids = a.get("ResourceIds")
        if isinstance(rids, list):
            return [x for x in rids if isinstance(x, str) and x]
        return []

    rows: List[Dict[str, Any]] = []
    assigned_resource_ids: set = set()

    for a in assignments:
        if not isinstance(a, dict):
            continue
        cid = get_category_id(a)
        if not cid:
            continue
        cat = cat_by_id.get(cid) or {}
        cat_name = pick_name(cat) or (cat.get("Name") or "")
        svc_name = svc_by_id.get(cat.get("ServiceId")) or ""
        for rid in get_resource_ids(a):
            r = res_by_id.get(rid)
            if not isinstance(r, dict):
                continue
            assigned_resource_ids.add(rid)
            rows.append({
                "Service": svc_name,
                "Resource category": cat_name,
                "Space": r.get("Name") or "",
                "State": r.get("State") or "",
            })

    # Add truly unassigned spaces (no assignment rows matched their IDs)
    for r in resources:
        rid = r.get("Id")
        if isinstance(rid, str) and rid not in assigned_resource_ids:
            rows.append({
                "Service": "",
                "Resource category": "UNASSIGNED",
                "Space": r.get("Name") or "",
                "State": r.get("State") or "",
            })

    rows.sort(key=lambda x: ((x.get("Service") or "").lower(), (x.get("Resource category") or "").lower(), (x.get("Space") or "").lower()))
    return rows
def build_rate_groups_table(rate_groups: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    svc_by_id = {s.get("Id"): pick_name(s) or (s.get("Name") or "") for s in services if isinstance(s, dict) and s.get("Id")}
    rows: List[Dict[str, Any]] = []
    for g in rate_groups:
        if not isinstance(g, dict):
            continue
        rows.append({
            "Service": svc_by_id.get(g.get("ServiceId")) or "",
            "Rate group": pick_name(g) or (g.get("Name") or ""),
            "Activity state": "Active" if g.get("IsActive") else "Inactive",
        })
    rows.sort(key=lambda x: ((x.get("Service") or "").lower(), (x.get("Rate group") or "").lower()))
    return rows
def build_rates_table(rates: List[Dict[str, Any]], rate_groups: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rg_by_id = {g.get("Id"): g for g in rate_groups if isinstance(g, dict) and g.get("Id")}
    rate_by_id = {r.get("Id"): r for r in rates if isinstance(r, dict) and r.get("Id")}
    svc_by_id = {s.get("Id"): pick_name(s) or (s.get("Name") or "") for s in services if isinstance(s, dict) and s.get("Id")}

    def rname(r: Optional[Dict[str, Any]]) -> str:
        if not isinstance(r, dict):
            return ""
        return pick_name(r) or (r.get("Code") or "") or ""

    rows: List[Dict[str, Any]] = []
    for r in rates:
        if not isinstance(r, dict):
            continue
        base = rate_by_id.get(r.get("BaseRateId")) if r.get("BaseRateId") else None
        rg = rg_by_id.get(r.get("GroupId")) if r.get("GroupId") else None

        visibility = "Public" if r.get("IsPublic") else "Private"
        status = "Active" if r.get("IsActive") else "Inactive"
        if r.get("IsEnabled") is False:
            status = "Disabled"

        rows.append({
            "Service": svc_by_id.get(r.get("ServiceId")) or "",
            "Rate": rname(r),
            "Base rate": rname(base),
            "Rate group": pick_name(rg) if isinstance(rg, dict) else "",
            "Visibility": visibility,
            "Status": status,
        })

    rows.sort(key=lambda x: ((x.get("Service") or "").lower(), (x.get("Rate group") or "").lower(), (x.get("Rate") or "").lower()))
    return rows

def build_restrictions_table(restrictions: List[Dict[str, Any]],
                             rates: List[Dict[str, Any]],
                             rate_groups: List[Dict[str, Any]],
                             resource_categories: List[Dict[str, Any]],
                             services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now = utc_now()
    rate_by_id = {r.get("Id"): r for r in rates if isinstance(r, dict) and r.get("Id")}
    rg_by_id = {g.get("Id"): g for g in rate_groups if isinstance(g, dict) and g.get("Id")}
    cat_by_id = {c.get("Id"): c for c in resource_categories if isinstance(c, dict) and c.get("Id")}
    svc_by_id = {s.get("Id"): pick_name(s) or (s.get("Name") or "") for s in services if isinstance(s, dict) and s.get("Id")}

    def summarise_restriction_time(cond: Any) -> str:
        if not isinstance(cond, dict):
            return "None → None"
        s = cond.get("StartUtc") or "None"
        e = cond.get("EndUtc") or "None"
        days = cond.get("Days")
        bits = [f"{s} → {e}"]
        if isinstance(days, list) and days:
            bits.append("Days: " + ",".join([d for d in days if isinstance(d, str)]))
        return " | ".join(bits)


    def summarise_restriction_exceptions(excs: Any) -> str:
        # Exceptions are usually a list of dicts; keep it short and factual
        if not isinstance(excs, list) or not excs:
            return ""
        out: List[str] = []
        for e in excs:
            if not isinstance(e, dict):
                continue
            # Try common keys without assuming schema too hard
            # Examples we see in tenants: Type/Value, Dates, StartUtc/EndUtc, WeekDays etc.
            typ = e.get("Type") or e.get("ExceptionType") or ""
            val = e.get("Value") or e.get("Values") or ""
            s = e.get("StartUtc") or ""
            en = e.get("EndUtc") or ""
            if s or en:
                out.append(f"{typ}:{s}→{en}".strip(":"))
            elif val:
                out.append(f"{typ}:{val}".strip(":"))
            else:
                # fallback: first couple of keys
                keys = list(e.keys())[:3]
                out.append(",".join(keys))
            if len(out) >= 4:
                break
        return " | ".join([x for x in out if x])

    rows: List[Dict[str, Any]] = []
    for r in restrictions:
        if not isinstance(r, dict):
            continue
        cond = r.get("Conditions") if isinstance(r, dict) else None
        if not isinstance(cond, dict):
            continue

        # Keep "future stays" concept: end in the future
        end_utc = cond.get("EndUtc")
        try:
            if isinstance(end_utc, str) and end_utc.endswith("Z"):
                end_dt = datetime.fromisoformat(end_utc.replace("Z", "+00:00"))
            elif isinstance(end_utc, str):
                end_dt = datetime.fromisoformat(end_utc)
            else:
                end_dt = None
        except Exception:
            end_dt = None
        if end_dt and end_dt < now:
            continue

        rate_bits: List[str] = []
        if cond.get("RateId"):
            br = rate_by_id.get(cond.get("RateId"))
            rate_bits.append("Rate: " + (pick_name(br) if br else ""))
        if cond.get("RateGroupId"):
            g = rg_by_id.get(cond.get("RateGroupId"))
            rate_bits.append("Group: " + (pick_name(g) if g else ""))
        rates_scope = "; ".join([b for b in rate_bits if b.strip()]) or "All rates"

        spaces_scope = "All spaces"
        if cond.get("ResourceCategoryId"):
            c = cat_by_id.get(cond.get("ResourceCategoryId"))
            spaces_scope = (pick_name(c) if isinstance(c, dict) else "") or "All spaces"

        rows.append({
            "Service": svc_by_id.get(r.get("ServiceId")) or "",
            "Time": summarise_restriction_time(cond),
            "Rates": rates_scope,
            "Spaces": spaces_scope,
            "Exceptions": summarise_restriction_exceptions(r.get("Exceptions")),
        })

    rows.sort(key=lambda x: ((x.get("Service") or "").lower(), (x.get("Time") or "").lower(), (x.get("Rates") or "").lower()))
    return rows

def _parse_dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _nights_between(start_utc: Any, end_utc: Any, inclusive_end: bool = False) -> str:
    s = _parse_dt(start_utc)
    e = _parse_dt(end_utc)
    if not s or not e:
        return ""
    days = (e.date() - s.date()).days
    if inclusive_end:
        days = days + 1
    if days < 0:
        return ""
    return str(days)


def build_availability_blocks_summary_table(blocks: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    svc_by_id = {s.get("Id"): pick_name(s) or (s.get("Name") or "") for s in services if isinstance(s, dict) and s.get("Id")}
    counts: Dict[str, int] = {}
    for b in blocks:
        if not isinstance(b, dict):
            continue
        sid = b.get("ServiceId")
        sname = svc_by_id.get(sid) or ""
        counts[sname] = counts.get(sname, 0) + 1
    rows = [{"Service": k, "Availability blocks (next 90 days)": v} for k, v in sorted(counts.items(), key=lambda kv: (kv[0] or "").lower())]
    return rows


def build_availability_blocks_detail_table(blocks: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    svc_by_id = {s.get("Id"): pick_name(s) or (s.get("Name") or "") for s in services if isinstance(s, dict) and s.get("Id")}
    rows: List[Dict[str, Any]] = []
    for b in blocks:
        if not isinstance(b, dict):
            continue
        service_name = svc_by_id.get(b.get("ServiceId")) or ""
        name = pick_name(b) or (b.get("Name") or "") or ""
        # LOS: prefer ArrivalUtc/DepartureUtc; fall back to First/LastTimeUnitStartUtc
        los = _nights_between(b.get("ArrivalUtc"), b.get("DepartureUtc"), inclusive_end=False)
        if not los:
            los = _nights_between(b.get("FirstTimeUnitStartUtc"), b.get("LastTimeUnitStartUtc"), inclusive_end=True)
        rows.append({
            "Block": name,
            "Service": service_name,
            "LOS (nights)": los,
            "Reservation purpose": b.get("ReservationPurpose") or "",
        })
    rows.sort(key=lambda x: ((x.get("Service") or "").lower(), (x.get("Block") or "").lower()))
    return rows


def build_rules_summary_table(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"Service": "All services", "Active rules": len([r for r in rules if isinstance(r, dict)])}]


def _format_rule_conditions(conds: Any, maps: Dict[str, Dict[str, str]]) -> str:
    if not isinstance(conds, dict) or not conds:
        return ""
    pretty: List[str] = []
    for key, label in (
        ("RateId", "Rate"),
        ("RateGroupId", "Rate group"),
        ("BusinessSegmentId", "Business segment"),
        ("ResourceCategoryId", "Resource category"),
        ("ResourceCategoryType", "Resource category type"),
        ("Origin", "Origin"),
        ("TravelAgencyId", "Company/TA"),
    ):
        v = conds.get(key)
        if not isinstance(v, dict):
            continue
        val = v.get("Value")
        typ = v.get("ConditionType") or ""
        name_map = maps.get(key) or {}
        display = name_map.get(val) or (val or "")
        if display:
            pretty.append(f"{label} {typ}: {display}".strip())
    # Min/Max time units
    for key, label in (("MinimumTimeUnitCount", "Min LOS"), ("MaximumTimeUnitCount", "Max LOS")):
        v = conds.get(key)
        if isinstance(v, int):
            pretty.append(f"{label}: {v}")
    return " | ".join(pretty)


def build_rules_detail_tables(rules: List[Dict[str, Any]],
                             rule_actions: List[Dict[str, Any]],
                             services: List[Dict[str, Any]],
                             rates: List[Dict[str, Any]],
                             rate_groups: List[Dict[str, Any]],
                             resource_categories: List[Dict[str, Any]],
                             business_segments: List[Dict[str, Any]],
                             products: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    svc_by_id = {s.get("Id"): pick_name(s) or (s.get("Name") or "") for s in services if isinstance(s, dict) and s.get("Id")}
    rate_by_id = {r.get("Id"): pick_name(r) for r in rates if isinstance(r, dict) and r.get("Id")}
    rg_by_id = {g.get("Id"): pick_name(g) for g in rate_groups if isinstance(g, dict) and g.get("Id")}
    rc_by_id = {c.get("Id"): pick_name(c) for c in resource_categories if isinstance(c, dict) and c.get("Id")}
    bs_by_id = {b.get("Id"): pick_name(b) for b in business_segments if isinstance(b, dict) and b.get("Id")}
    prod_by_id = {p.get("Id"): pick_name(p) for p in products if isinstance(p, dict) and p.get("Id")}

    maps = {
        "RateId": rate_by_id,
        "RateGroupId": rg_by_id,
        "ResourceCategoryId": rc_by_id,
        "BusinessSegmentId": bs_by_id,
    }

    actions_by_rule: Dict[str, List[str]] = {}
    action_rows: List[Dict[str, Any]] = []
    rule_service = {r.get('Id'): r.get('ServiceId') for r in rules if isinstance(r, dict) and r.get('Id')}
    for a in rule_actions:
        if not isinstance(a, dict):
            continue
        rid = a.get("RuleId")
        data = a.get("Data") or {}
        disc = data.get("Discriminator") or ""
        val = data.get("Value") or {}
        action_desc = ""
        if disc == "Product" and isinstance(val, dict):
            pid = val.get("ProductId")
            at = val.get("ActionType") or ""
            pname = prod_by_id.get(pid) or (pid or "")
            action_desc = f"{at} product: {pname}".strip()
        else:
            action_desc = disc or "Action"

        if isinstance(rid, str) and rid:
            actions_by_rule.setdefault(rid, []).append(action_desc)

        action_rows.append({
            "Service": svc_by_id.get(rule_service.get(rid)) or "",
            "RuleId": rid or "",
            "Action": action_desc,
        })

    rule_rows: List[Dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        rid = r.get("Id") or ""
        conds = r.get("Conditions")
        rule_rows.append({
            "Service": svc_by_id.get(r.get("ServiceId")) or "",
            "Conditions": _format_rule_conditions(conds, maps),
            "Actions": "; ".join(actions_by_rule.get(rid) or []),
        })

    rule_rows.sort(key=lambda x: ((x.get("Service") or "").lower(), (x.get("Conditions") or "").lower()))
    action_rows.sort(key=lambda x: ((x.get("Service") or "").lower(), (x.get("RuleId") or "").lower()))
    return rule_rows, action_rows


def build_report(data: Dict[str, Any], base_url: str, client_name: str) -> "AuditReport":
    cfg = data.get("cfg", {}) or {}
    services = data.get("services", []) or []
    svc_by_id = {s.get("Id"): (pick_name(s) or (s.get("Name") or "")) for s in services if isinstance(s, dict) and s.get("Id")}
    rate_groups = data.get("rate_groups", []) or []
    rates = data.get("rates", []) or []
    accounting_categories = data.get("accounting_categories", []) or []
    products = data.get("products", []) or []
    payments = data.get("payments", []) or []
    resources = data.get("resources", []) or []
    resource_categories = data.get("resource_categories", []) or []
    rca = data.get("resource_category_assignments", []) or []
    restrictions = data.get("restrictions", []) or []
    availability_blocks = data.get("availability_blocks", []) or []
    rules_bundle = data.get("rules_bundle", {}) or {}
    tax_envs = data.get("tax_environments", []) or []
    taxations = data.get("taxations", []) or []
    counters = data.get("counters", []) or []
    cashiers = data.get("cashiers", []) or []
    errors = data.get("errors", {}) or {}

    acc_categories_table = build_accounting_categories_table(accounting_categories, products, services)
    product_mapping_mapped, product_mapping_unmapped = build_product_mapping_tables(products, accounting_categories, taxations, services)
    spaces_table = build_spaces_table(resources, resource_categories, rca, services)
    rate_groups_table = build_rate_groups_table(rate_groups, services)
    rates_table = build_rates_table(rates, rate_groups, services)
    restrictions_table = build_restrictions_table(restrictions, rates, rate_groups, resource_categories, services)

    # Availability blocks (next 90 days)
    availability_blocks_summary_table = build_availability_blocks_summary_table(availability_blocks, services)
    availability_blocks_detail_table = build_availability_blocks_detail_table(availability_blocks, services)

    # Rules
    rules = rules_bundle.get("Rules") if isinstance(rules_bundle, dict) else []
    rule_actions = rules_bundle.get("RuleActions") if isinstance(rules_bundle, dict) else []
    rules_rates = rules_bundle.get("Rates") if isinstance(rules_bundle, dict) else []
    rules_rate_groups = rules_bundle.get("RateGroups") if isinstance(rules_bundle, dict) else []
    rules_resource_categories = rules_bundle.get("ResourceCategories") if isinstance(rules_bundle, dict) else []
    rules_business_segments = rules_bundle.get("BusinessSegments") if isinstance(rules_bundle, dict) else []

    rules_summary_table = build_rules_summary_table(rules if isinstance(rules, list) else [])
    rules_detail_table, _rule_actions_table = build_rules_detail_tables(
        rules if isinstance(rules, list) else [],
        rule_actions if isinstance(rule_actions, list) else [],
        services,
        (rules_rates if isinstance(rules_rates, list) and rules_rates else rates),
        (rules_rate_groups if isinstance(rules_rate_groups, list) and rules_rate_groups else rate_groups),
        (rules_resource_categories if isinstance(rules_resource_categories, list) and rules_resource_categories else resource_categories),
        (rules_business_segments if isinstance(rules_business_segments, list) else []),
        products,
    )

    ent = (cfg.get("Enterprise") or {}) if isinstance(cfg, dict) else {}
    enterprise_id = ent.get("Id") or (data.get("enterprises", [""])[0] if data.get("enterprises") else "")
    enterprise_name = ent.get("Name") or "Unknown"

    def status_for(keys: List[str], default_ok: str) -> Tuple[str, str]:
        failed = [k for k in keys if (k in errors and errors[k])]
        if failed:
            # Keep main report clean: do not surface raw API error strings here.
            return "NEEDS_INPUT", "API call failed: " + ", ".join(failed)
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
    s = f"Products returned: {len(products)} | Mapped: {len(product_mapping_mapped)} | Unmapped: {len(product_mapping_unmapped)}"
    if err_prod:
        s += f" | {err_prod}"
    accounting_items.append(CheckItem(
        key="Product mapping (product → accounting category)",
        status=st_prod,
        summary=s,
        source="Connector: Products/GetAll + AccountingCategories/GetAll",
        remediation="Validate each product is mapped to the correct accounting category, uses the intended taxation, and has the correct charging mode.",
        details={"ProductMappingMappedTable": product_mapping_mapped, "ProductMappingUnmappedTable": product_mapping_unmapped},
        risk="High"
    ))

    st_cash, err_cash = status_for(["cashiers_getall", "counters_getall"], "PASS" if (cashiers or counters) else "WARN")
    s = f"Cashiers={len(cashiers)}, Counters={len(counters)}"
    if err_cash:
        s += f" | {err_cash}"
    sections.append(("Accounting configuration", accounting_items))

    pay_items: List[CheckItem] = []
    st_pay, err_pay = status_for(["payments_getall"], "PASS")
    payments = data.get("payments", []) or []

    # PaymentOrigin summaries (last 90 days, limited to 1000)
    po_charged = data.get("payment_origin_counts_charged_90d", []) or []
    po_failed = data.get("payment_origin_counts_failed_90d", []) or []
    err_po_charged = data.get("errors", {}).get("payments_origin_charged_90d")
    err_po_failed = data.get("errors", {}).get("payments_origin_failed_90d")

    s = f"Payments (30d sample)={len(payments)} | 90d Charged origins={len(po_charged)} | 90d Failed/Cancelled origins={len(po_failed)}"
    if err_pay:
        s += f" | {err_pay}"

    pay_items.append(
        CheckItem(
            key="Payments (last 30 days sample)",
            status=st_pay,
            summary=s,
            source="Connector: Payments/GetAll (CreatedUtc window: 30 days sample + 90 days summaries, count<=1000)",
            remediation="If empty or failing, verify token scope/permissions and that the CreatedUtc window is supported. For PaymentOrigin summaries, confirm Payments/GetAll returns PaymentOrigin in your environment.",
            details={
                "Payments": payments,
                "PaymentOriginCountsCharged90d": po_charged,
                "PaymentOriginCountsFailed90d": po_failed,
                "PaymentOriginCharged90dError": err_po_charged,
                "PaymentOriginFailed90dError": err_po_failed,
            },
            risk="Low",
        )
    )
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

    # Availability blocks (next 90 days)
    availability_blocks = data.get("availability_blocks", []) or []
    st_ab, err_ab = status_for(["availability_blocks_getall"], "PASS")
    ab_summary_table = build_availability_blocks_summary_table(availability_blocks, services)
    ab_detail_table = build_availability_blocks_detail_table(availability_blocks, services)
    ab_summary = f"Availability blocks (next 90d)={len(availability_blocks)}"
    if err_ab:
        ab_summary += f" | {err_ab}"
    inv_items.append(CheckItem(
        key="Availability blocks (next 90 days)",
        status=st_ab,
        summary=ab_summary,
        source="Connector: AvailabilityBlocks/GetAll",
        remediation="Review availability blocks that collide with the next 90 days.",
        details={
            "AvailabilityBlocksSummaryTable": ab_summary_table,
            "AvailabilityBlocksDetailTable": ab_detail_table,
        },
        risk="Low"
    ))

    # Rules
    rules_bundle = data.get("rules_bundle") or {}
    rules = rules_bundle.get("Rules") or []
    rule_actions = rules_bundle.get("RuleActions") or []
    rules_rate_groups = rules_bundle.get("RateGroups") or []
    rules_rates = rules_bundle.get("Rates") or []
    rules_resource_categories = rules_bundle.get("ResourceCategories") or []
    rules_business_segments = rules_bundle.get("BusinessSegments") or []

    st_rules, err_rules = status_for(["rules_getall"], "PASS")
    rules_summary_table = build_rules_summary_table(rules)
    rules_detail_table, _rule_actions_table = build_rules_detail_tables(
        rules=rules,
        rule_actions=rule_actions,
        services=services,
        rates=rules_rates,
        rate_groups=rules_rate_groups,
        resource_categories=rules_resource_categories,
        business_segments=rules_business_segments,
        products=products,
    )
    rules_summary = f"Rules returned: {len(rules)}; Rule actions: {len(rule_actions)}"
    if err_rules:
        rules_summary += f" | {err_rules}"
    inv_items.append(CheckItem(
        key="Rules",
        status=st_rules,
        summary=rules_summary,
        source="Connector: Rules/GetAll",
        remediation="Review rule conditions and actions for correctness and scope.",
        details={
            "RulesSummaryTable": rules_summary_table,
            "RulesDetailTable": rules_detail_table,
            
        },
        risk="Low"
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
        services_by_id=svc_by_id,
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
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleX", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, alignment=TA_LEFT, spaceAfter=10, leftIndent=0, firstLineIndent=0))
    styles.add(ParagraphStyle(name="H1X", parent=styles["Heading1"], fontSize=15, leading=18, spaceBefore=10, spaceAfter=6))
    styles.add(ParagraphStyle(name="BodyX", parent=styles["BodyText"], fontSize=9.6, leading=12))
    styles.add(ParagraphStyle(name="SmallX", parent=styles["BodyText"], fontSize=8.6, leading=11, leftIndent=0, firstLineIndent=0))
    styles.add(ParagraphStyle(name="TinyX", parent=styles["BodyText"], fontSize=8.1, leading=10, leftIndent=0, firstLineIndent=0))

    logo = fetch_logo()

    TABLE_FULL_W = A4[0] - (16 * mm) - (16 * mm)

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=DOC_LEFT, rightMargin=DOC_RIGHT, topMargin=DOC_TOP, bottomMargin=DOC_BOTTOM)

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
    def make_long_table(header, rows, col_widths=None, repeat_rows=1):
        """Create a full-width zebra-striped LongTable.

        - Accepts header items as strings OR Paragraphs.
        - Accepts row cells as strings/numbers OR Paragraphs.
        - Normalises column widths to TABLE_FULL_W.
        """
        if not rows:
            rows = []

        num_cols = len(header)

        # Default column widths: even split across full width
        if not col_widths:
            col_widths = [TABLE_FULL_W / max(1, num_cols)] * num_cols

        # Normalise width list length to match columns
        if len(col_widths) != num_cols:
            if len(col_widths) > num_cols:
                col_widths = col_widths[:num_cols]
            else:
                col_widths = col_widths + [TABLE_FULL_W / max(1, num_cols)] * (num_cols - len(col_widths))

        # Scale widths to full available width
        total = sum(col_widths)
        if total and abs(total - TABLE_FULL_W) > 0.1:
            scale = TABLE_FULL_W / total
            col_widths = [w * scale for w in col_widths]

        def _cell(val, style_name):
            return val if isinstance(val, Paragraph) else P(str(val) if val is not None else "", style_name)

        data = [[_cell(h, "SmallX") for h in header]]
        for r in rows:
            r = list(r) if isinstance(r, (list, tuple)) else [r]
            # pad / trim to column count
            if len(r) < num_cols:
                r = r + [""] * (num_cols - len(r))
            elif len(r) > num_cols:
                r = r[:num_cols]
            data.append([_cell(c, "TinyX") for c in r])

        t = LongTable(data, colWidths=col_widths, repeatRows=repeat_rows)
        t.hAlign = "LEFT"

        # Header styling (pink)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), TABLE_HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.2),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ]

        # Zebra striping for body
        for r_i in range(1, len(data)):
            bg = ROW_ALT_BG if r_i % 2 == 0 else colors.white
            style_cmds.append(("BACKGROUND", (0, r_i), (-1, r_i), bg))

        # Slightly emphasise key columns if present
        for c_i, h in enumerate(header):
            h_text = h.getPlainText() if isinstance(h, Paragraph) else str(h or "")
            hl = h_text.lower()
            if "id" == hl or hl.endswith(" id") or "uuid" in hl:
                style_cmds.append(("TEXTCOLOR", (c_i, 1), (c_i, -1), colors.HexColor("#444444")))

        t.setStyle(TableStyle(style_cmds))
        return t
    def header_footer(canvas, doc_):
        canvas.saveState()

        top_y = A4[1] - 10 * mm  # near top margin
        right_x = A4[0] - 16 * mm

        # Logo: same visual height as the title line, top-right above the title
        # 12.5pt title text ~= 4.4mm. Give the logo a ~4.8mm height to match.
        target_h = 4.8 * mm
        target_w = 18 * mm  # keep compact so it doesn't collide with the page number

        x_logo = right_x - target_w
        # Logo should be the highest item; title sits beneath it.
        logo_top = A4[1] - 6 * mm
        y_logo = logo_top - target_h
        title_y = y_logo - 6 * mm

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
        canvas.setFont("Helvetica-Bold", 12.5)
        canvas.drawString(16 * mm, title_y, "Mews Configuration Audit Report")
        # Page number in footer (bottom-right)
        canvas.setFont("Helvetica", 8.5)
        canvas.drawRightString(A4[0] - 16 * mm, 10 * mm, f"Page {doc_.page}")


        canvas.restoreState()

    story: List[Any] = []

    story.append(Spacer(1, 16))
    story.append(Paragraph("Mews Configuration Audit Report", styles["TitleX"]))
    story.append(Paragraph(
        f"<b>Enterprise:</b> {esc(report.enterprise_name or 'Unknown')}<br/>"
        f"<b>EnterpriseId:</b> {esc(report.enterprise_id or 'Unknown')}<br/>"
        f"<b>Generated (UTC):</b> {esc(report.generated_utc.strftime('%Y-%m-%d %H:%M:%S'))}<br/>"
        f"<b>URL:</b> app.mews.com/Commander/{esc(report.enterprise_id or '')}/Dashboard/index<br/>"
        f"<b>Client:</b> Mews &nbsp;&nbsp; <b>Audit Tool version:</b> 1.0.0",
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
    story.append(Paragraph("<font color='#64748b'><b>Status meanings:</b> PASS = no action required; WARN = review recommended; FAIL = action required; NEEDS_INPUT = data could not be retrieved via API (permissions/endpoint/tenant); NA = not applicable.</font>", styles["BodyX"]))
    story.append(PageBreak())

    for sec_name, items in report.sections:
        story.append(Paragraph(sec_name, styles["H1X"]))
        domain_by_section = {
            "Legal & property baseline": "Legal & Tax",
            "Accounting configuration": "Accounting & Finance",
            "Payments": "Payments & Fintech",
            "Spaces, rates & restrictions": "Revenue & Inventory",
        }
        domain = domain_by_section.get(sec_name)
        if domain:
            story.append(Paragraph(f"Domain: {esc(domain)}", styles["SmallX"]))
        story.append(Spacer(1, 6))

        over_rows = []
        for it in items:
            over_rows.append([P(it.key, "SmallX"), safe_para(badge(it.status), "SmallX"), P(it.risk, "SmallX"), P(it.summary, "SmallX")])
        story.append(make_long_table(["Check", "Status", "Risk", "RawSummary"], over_rows, [62*mm, 20*mm, 18*mm, 78*mm]))
        story.append(Spacer(1, 8))

        for it in items:
            block: List[Any] = []
            block.append(safe_para(f"<b>{esc(it.key)}</b> &nbsp;&nbsp; {badge(it.status)} &nbsp;&nbsp; <font color='#64748b'>Risk:</font> <b>{esc(it.risk)}</b>", "BodyX"))
            block.append(Paragraph(esc(it.summary or "-"), styles["BodyX"]))
            block.append(Spacer(1, 4))

            details = it.details or {}

            def render_dict_table(title: str, header: List[str], rows_dicts: List[Dict[str, Any]], colw: List[float], chunk: int = 350):
                block.append(Paragraph(f"<b>Detail: {esc(title)}</b>", styles["SmallX"]))
                block.append(Spacer(1, 8))
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                for ch in chunk_list(rows, chunk):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            if "AccountingCategoriesTable" in details:
                render_dict_table(
                    "Accounting categories",
                    ["Accounting category", "Ledger account code", "Classification", "Service"],
                    details.get("AccountingCategoriesTable") or [],
                    [50*mm, 28*mm, 30*mm, 46*mm],
                )

            if "ProductMappingMappedTable" in details:
                render_dict_table(
                    "Mapped products",
                    ["Service", "Product", "Accounting category", "Gross price", "Charging"],
                    details.get("ProductMappingMappedTable") or [],
                    [30*mm, 60*mm, 40*mm, 22*mm, 40*mm],
                )

            if "ProductMappingUnmappedTable" in details:
                render_dict_table(
                    "Unmapped products",
                    ["Service", "Product", "Accounting category", "Gross price", "Charging"],
                    details.get("ProductMappingUnmappedTable") or [],
                    [30*mm, 60*mm, 40*mm, 22*mm, 40*mm],
                )

            if "SpacesTable" in details:
                render_dict_table(
                    "Spaces and resource categories",
                    ["Service", "Resource category", "Space", "State"],
                    details.get("SpacesTable") or [],
                    [30*mm, 70*mm, 55*mm, 23*mm],
                    chunk=400,
                )

            if "RateGroupsTable" in details:
                render_dict_table(
                    "Rate groups",
                    ["Service", "Rate group", "Activity state"],
                    details.get("RateGroupsTable") or [],
                    [32*mm, 96*mm, 50*mm],
                )

            if "RatesTable" in details:
                render_dict_table(
                    "Rates",
                    ["Service", "Rate", "Base rate", "Rate group", "Visibility", "Status"],
                    details.get("RatesTable") or [],
                    [26*mm, 56*mm, 28*mm, 38*mm, 16*mm, 14*mm],
                )

            if "RestrictionsTable" in details:
                render_dict_table(
                    "Restrictions (future stays)",
                    ["Service", "Time", "Rates", "Spaces", "Exceptions"],
                    details.get("RestrictionsTable") or [],
                    [26*mm, 40*mm, 44*mm, 32*mm, 36*mm],
                )


            if "AvailabilityBlocksSummaryTable" in details:
                render_dict_table(
                    "Availability blocks (next 90 days)",
                    ["Service", "Availability blocks (next 90 days)"],
                    details.get("AvailabilityBlocksSummaryTable") or [],
                    [50*mm, 128*mm],
                )

            if "AvailabilityBlocksDetailTable" in details:
                render_dict_table(
                    "Availability blocks (detail)",
                    ["Service", "Block", "LOS (nights)", "Reservation purpose"],
                    details.get("AvailabilityBlocksDetailTable") or [],
                    [34*mm, 84*mm, 26*mm, 34*mm],
                    chunk=400,
                )

            if "RulesSummaryTable" in details:
                render_dict_table(
                    "Rules summary",
                    ["Service", "Active rules"],
                    details.get("RulesSummaryTable") or [],
                    [178*mm],
                )

            if "RulesDetailTable" in details:
                render_dict_table(
                    "Rules (conditions & actions)",
                    ["Service", "Conditions", "Actions"],
                    details.get("RulesDetailTable") or [],
                    [30*mm, 88*mm, 60*mm],
                    chunk=250,
                )
            if "Payments" in details:
                pays = details.get("Payments") or []
                header = ["Service", "PaymentId", "Type", "State", "Curr", "Net", "Gross", "CreatedUtc"]
                rows = []
                for p in pays:
                    amt = p.get("Amount") or {}
                    rows.append([P((report.services_by_id.get(p.get("ServiceId")) or p.get("ServiceId") or "")), P(p.get("Id") or ""), P(p.get("Type") or ""), P(p.get("State") or ""),
                                 P(amt.get("Currency") or p.get("Currency") or ""),
                                 P(str(amt.get("NetValue") or "")),
                                 P(str(amt.get("GrossValue") or "")),
                                 P(p.get("CreatedUtc") or "")])
                block.append(Paragraph("<b>Detail: Payments (30-day sample)</b>", styles["SmallX"]))
                block.append(Spacer(1, 8))
                for ch in chunk_list(rows, 300):
                    block.append(make_long_table(header, ch, [30*mm, 34*mm, 22*mm, 16*mm, 10*mm, 16*mm, 16*mm, 40*mm]))
                    block.append(Spacer(1, 6))
                # PaymentOrigin summary tables (last 90 days, count<=1000)
                po_charged = (it.details or {}).get("PaymentOriginCountsCharged90d") or []
                po_failed = (it.details or {}).get("PaymentOriginCountsFailed90d") or []
                err_po_charged = (it.details or {}).get("PaymentOriginCharged90dError")
                err_po_failed = (it.details or {}).get("PaymentOriginFailed90dError")

                def render_po_table(title: str,
                                    rows_in: Optional[List[Dict[str, Any]]],
                                    err: Optional[str],
                                    fallback_origins: Optional[List[Dict[str, Any]]] = None) -> None:
                    # If failed/cancelled returns nothing or errors, but charged has origins, mirror with zeros.
                    rows_norm: List[Dict[str, Any]] = list(rows_in or [])
                    if (not rows_norm) and fallback_origins:
                        rows_norm = [{"PaymentOrigin": (r.get("PaymentOrigin") or "None"), "Count": 0} for r in fallback_origins]
                        err = None  # do not show error message per requirement

                    block.append(Paragraph(f"<b>Detail: {esc(title)}</b>", styles["SmallX"]))
                    block.append(Spacer(1, 10))  # extra spacing between title and table

                    header2 = ["Service", "Payment origin", "Count"]
                    table_rows: List[List[Any]] = []
                    for r in rows_norm:
                        table_rows.append([
                            P("All services"),
                            P(str(r.get("PaymentOrigin") or "None")),
                            P(str(r.get("Count") if r.get("Count") is not None else 0)),
                        ])

                    if not table_rows:
                        table_rows.append([P("No payments returned for this filter."), P("")])

                    for ch in chunk_list(table_rows, 300):
                        block.append(make_long_table(header2, ch, [TABLE_FULL_W * 0.22, TABLE_FULL_W * 0.58, TABLE_FULL_W * 0.20]))
                        block.append(Spacer(1, 6))

                render_po_table("Payment Origin (last 90 days) — Charged", po_charged, err_po_charged)
                render_po_table("Payment Origin (last 90 days) — Failed / Cancelled", po_failed, err_po_failed, fallback_origins=po_charged)


            if it.source:
                block.append(Paragraph(f"<font color='#64748b'><b>Source:</b> {esc(it.source)}</font>", styles["TinyX"]))

            block.append(Spacer(1, 10))
            story.append(KeepTogether(block))

        story.append(PageBreak())

    story.append(Paragraph("Appendix: API call log", styles["H1X"]))
    story.append(Spacer(1, 6))

    rows = []
    for c in report.api_calls:
        rows.append([
            P(c.operation),
            P(str(bool(c.ok))),
            P(str(c.status_code or "")),
            P(str(c.duration_ms)),
            P(c.error or ""),
        ])

    full_w = A4[0] - (32 * mm)
    colw = [72*mm, 14*mm, 14*mm, 24*mm, full_w - (72*mm + 14*mm + 14*mm + 24*mm)]

    for ch in chunk_list(rows, 500):
        story.append(make_long_table(["Call", "OK", "http", "duration ms", "Notes"], ch, colw))
        story.append(Spacer(1, 6))

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
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
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
