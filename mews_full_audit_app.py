# =========================================================
# mews_full_audit_app.py — Full replacement (v3)
# Start command: gunicorn mews_full_audit_app:app
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
LOGO_URL = os.getenv("LOGO_URL", "").strip()


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
            batch = data.get(result_key) or []
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
# DATA COLLECTION (v3 fix)
# =========================

def collect_data(base_url: str, client_token: str, access_token: str, client_name: str = DEFAULT_CLIENT_NAME) -> Dict[str, Any]:
    mc = MewsConnector(base_url, client_token, access_token, client_name)

    cfg = mc.get("Configuration", "Get", {})
    ent = (cfg.get("Enterprise") or {}) if isinstance(cfg, dict) else {}
    ent_id = ent.get("Id")
    enterprises = [ent_id] if ent_id else []

    services = mc.paged_get_all("Services", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Services")
    service_ids = [s.get("Id") for s in services if isinstance(s, dict) and s.get("Id")]

    # Service-scoped endpoints
    if service_ids:
        rate_groups = mc.paged_get_all("RateGroups", "GetAll", {"ServiceIds": service_ids}, "RateGroups")
        rates = mc.paged_get_all("Rates", "GetAll", {"ServiceIds": service_ids}, "Rates")
        products = mc.paged_get_all("Products", "GetAll", {"ServiceIds": service_ids}, "Products")
        restrictions = mc.paged_get_all("Restrictions", "GetAll", {"ServiceIds": service_ids}, "Restrictions")
        resource_categories = mc.paged_get_all("ResourceCategories", "GetAll", {"ServiceIds": service_ids}, "ResourceCategories")
    else:
        rate_groups, rates, products, restrictions, resource_categories = [], [], [], [], []

    # Enterprise-scoped endpoints
    accounting_categories = mc.paged_get_all("AccountingCategories", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "AccountingCategories")
    resources = mc.paged_get_all("Resources", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Resources")

    # 🔧 Tenant-specific validation:
    # Your tenant returns "Invalid ResourceCategoryIds" if we call Assignments without ResourceCategoryIds (or with empty).
    # So: call Assignments with ResourceCategoryIds derived from ResourceCategories.
    resource_category_assignments: List[Dict[str, Any]] = []
    try:
        rc_ids = [c.get("Id") for c in resource_categories if isinstance(c, dict) and c.get("Id")]
        if rc_ids:
            resource_category_assignments = mc.paged_get_all(
                "ResourceCategoryAssignments",
                "GetAll",
                {"ResourceCategoryIds": rc_ids},
                "ResourceCategoryAssignments"
            )
        else:
            resource_category_assignments = []
    except Exception:
        # Do not fail the whole audit on this endpoint
        resource_category_assignments = []

    # Payments window (last 30 days)
    payments: List[Dict[str, Any]] = []
    try:
        start = (utc_now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        payments = mc.paged_get_all(
            "Payments",
            "GetAll",
            {"EnterpriseIds": enterprises, "CreatedUtc": {"StartUtc": start, "EndUtc": end}},
            "Payments",
            count_per_page=500,
            hard_limit=20000,
        )
    except Exception:
        payments = []

    cancellation_policies: List[Dict[str, Any]] = []
    try:
        if service_ids:
            cancellation_policies = mc.paged_get_all("CancellationPolicies", "GetAll", {"ServiceIds": service_ids}, "CancellationPolicies")
    except Exception:
        cancellation_policies = []

    rules: List[Dict[str, Any]] = []
    try:
        if service_ids:
            rules = mc.paged_get_all("Rules", "GetAll", {"ServiceIds": service_ids}, "Rules")
    except Exception:
        rules = []

    tax_envs: List[Dict[str, Any]] = []
    taxations: List[Dict[str, Any]] = []
    try:
        tax_envs = mc.paged_get_all("TaxEnvironments", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "TaxEnvironments")
    except Exception:
        tax_envs = []
    try:
        taxations = mc.paged_get_all("Taxations", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Taxations")
    except Exception:
        taxations = []

    counters: List[Dict[str, Any]] = []
    cashiers: List[Dict[str, Any]] = []
    try:
        counters = mc.paged_get_all("Counters", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Counters")
    except Exception:
        counters = []
    try:
        cashiers = mc.paged_get_all("Cashiers", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Cashiers")
    except Exception:
        cashiers = []

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


def tax_percent_from_extended_amount(ext: Any) -> str:
    if not isinstance(ext, dict):
        return ""
    net = safe_float(ext.get("NetValue"))
    gross = safe_float(ext.get("GrossValue"))
    tax_total = 0.0
    if isinstance(ext.get("TaxValues"), list):
        for tv in ext["TaxValues"]:
            if isinstance(tv, dict):
                v = safe_float(tv.get("Value"))
                if v is not None:
                    tax_total += v
    if tax_total > 0 and net and net > 0:
        return f"{(tax_total / net) * 100:.2f}%"
    if net and gross and net > 0 and gross >= net:
        return f"{((gross - net) / net) * 100:.2f}%"
    rate = safe_float(ext.get("TaxRate"))
    if rate is not None:
        return f"{rate:.2f}%"
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
                                accounting_categories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cat_by_id = {c.get("Id"): c for c in accounting_categories if c.get("Id")}
    rows: List[Dict[str, Any]] = []
    for p in products:
        cat = cat_by_id.get(p.get("AccountingCategoryId"))
        rows.append({
            "Product": pick_name(p) or "",
            "Accounting category": (cat.get("Name") if isinstance(cat, dict) else "UNMAPPED") or "UNMAPPED",
            "Base price": money_from_extended_amount(p.get("Price")),
            "Tax %": tax_percent_from_extended_amount(p.get("Price")),
            "Charging": p.get("ChargingMode") or "",
        })
    rows.sort(key=lambda x: (x.get("Accounting category") or "", x.get("Product") or ""))
    return rows


def build_spaces_table(resources: List[Dict[str, Any]],
                       resource_categories: List[Dict[str, Any]],
                       assignments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cat_by_id = {c.get("Id"): c for c in resource_categories if c.get("Id")}
    res_by_id = {r.get("Id"): r for r in resources if r.get("Id")}

    rows: List[Dict[str, Any]] = []
    for a in assignments:
        rid = a.get("ResourceId")
        cid = a.get("ResourceCategoryId")
        r = res_by_id.get(rid) if rid else None
        c = cat_by_id.get(cid) if cid else None
        if not r:
            continue
        rows.append({
            "Resource category": (c.get("Name") if isinstance(c, dict) else "UNASSIGNED") or "UNASSIGNED",
            "Space": r.get("Name") or "",
            "State": r.get("State") or "",
        })

    assigned = {a.get("ResourceId") for a in assignments if a.get("ResourceId")}
    for r in resources:
        if r.get("Id") and r.get("Id") not in assigned:
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
    if isinstance(ex.get("MinPrice"), dict):
        v = money_from_extended_amount(ex.get("MinPrice"))
        if v:
            bits.append(f"Min price: {v}")
    if isinstance(ex.get("MaxPrice"), dict):
        v = money_from_extended_amount(ex.get("MaxPrice"))
        if v:
            bits.append(f"Max price: {v}")
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
            spaces_scope = (c.get("Name") if isinstance(c, dict) else "") or "All spaces"

        rows.append({
            "Time": summarise_restriction_time(cond),
            "Rates": rates_scope,
            "Spaces": spaces_scope,
            "Exceptions": summarise_restriction_exceptions(r.get("Exceptions")),
        })

    rows.sort(key=lambda x: x.get("Time") or "")
    return rows


def build_report(data: Dict[str, Any], base_url: str, client_name: str) -> "AuditReport":
    cfg = data.get("cfg", {})
    services = data.get("services", [])
    rate_groups = data.get("rate_groups", [])
    rates = data.get("rates", [])
    accounting_categories = data.get("accounting_categories", [])
    products = data.get("products", [])
    payments = data.get("payments", [])
    resources = data.get("resources", [])
    resource_categories = data.get("resource_categories", [])
    rca = data.get("resource_category_assignments", [])
    restrictions = data.get("restrictions", [])
    tax_envs = data.get("tax_environments", [])
    taxations = data.get("taxations", [])
    counters = data.get("counters", [])
    cashiers = data.get("cashiers", [])

    acc_categories_table = build_accounting_categories_table(accounting_categories, products, services)
    product_mapping_table = build_product_mapping_table(products, accounting_categories)
    spaces_table = build_spaces_table(resources, resource_categories, rca)
    rate_groups_table = build_rate_groups_table(rate_groups)
    rates_table = build_rates_table(rates, rate_groups)
    restrictions_table = build_restrictions_table(restrictions, rates, rate_groups, resource_categories)

    ent = (cfg.get("Enterprise") or {}) if isinstance(cfg, dict) else {}
    enterprise_id = ent.get("Id") or (data.get("enterprises", [""])[0] if data.get("enterprises") else "")
    enterprise_name = ent.get("Name") or "Unknown"

    sections: List[Tuple[str, List[CheckItem]]] = []

    legal_items: List[CheckItem] = []
    tz = (cfg.get("Enterprise") or {}).get("TimeZone") if isinstance(cfg, dict) else None
    currency = (cfg.get("Enterprise") or {}).get("DefaultCurrency") if isinstance(cfg, dict) else None
    legal_items.append(CheckItem("Time zone", "PASS" if tz else "WARN", str(tz or "Not identified"), "Connector: Configuration/Get", "Set enterprise/property time zone in Mews if missing.", {}, "High" if not tz else "Low"))
    legal_items.append(CheckItem("Default currency", "PASS" if currency else "WARN", str(currency or "Not identified"), "Connector: Configuration/Get", "Ensure a default currency is set at enterprise level.", {}, "High" if not currency else "Low"))
    legal_items.append(CheckItem("Tax environment + VAT/GST rates", "PASS" if (tax_envs or taxations) else "WARN", f"TaxEnvironments={len(tax_envs)}, Taxations={len(taxations)}", "Connector: TaxEnvironments/GetAll + Taxations/GetAll", "Validate tax environment selection and tax codes match jurisdiction.", {"TaxEnvironments": tax_envs[:200], "Taxations": taxations[:500]}, "Medium"))
    sections.append(("Legal & property baseline", legal_items))

    accounting_items: List[CheckItem] = []
    accounting_items.append(CheckItem(
        key="Accounting categories (list)",
        status="PASS" if accounting_categories else "WARN",
        summary=f"Accounting categories returned: {len(accounting_categories)}",
        source="Connector: AccountingCategories/GetAll",
        remediation="Review category codes/classifications and ledger mappings; confirm alignment with finance export.",
        details={"AccountingCategoriesTable": acc_categories_table},
        risk="High"
    ))
    accounting_items.append(CheckItem(
        key="Product mapping (product → accounting category)",
        status="PASS" if products else "WARN",
        summary=f"Products returned: {len(products)}",
        source="Connector: Products/GetAll + AccountingCategories/GetAll",
        remediation="Validate each product is mapped to the correct accounting category, has expected base price/tax, and charging mode.",
        details={"ProductMappingTable": product_mapping_table},
        risk="High"
    ))
    accounting_items.append(CheckItem(
        key="Cash / counters",
        status="PASS" if (cashiers or counters) else "WARN",
        summary=f"Cashiers={len(cashiers)}, Counters={len(counters)}",
        source="Connector: Cashiers/GetAll + Counters/GetAll",
        remediation="Ensure cashiers are assigned and counters/numbering comply with local rules.",
        details={},
        risk="Medium"
    ))
    sections.append(("Accounting configuration", accounting_items))

    payments_items: List[CheckItem] = []
    payments_items.append(CheckItem(
        key="Payments (last 30 days sample)",
        status="PASS",
        summary=f"Payments retrieved: {len(payments)}",
        source="Connector: Payments/GetAll (CreatedUtc 30d window)",
        remediation="If empty, verify token scope/permissions or adjust window.",
        details={"Payments": payments},
        risk="Low"
    ))
    sections.append(("Payments", payments_items))

    inv_items: List[CheckItem] = []
    inv_items.append(CheckItem(
        key="Spaces and resource categories",
        status="PASS" if resources else "WARN",
        summary=f"Spaces={len(resources)}, ResourceCategories={len(resource_categories)}, Assignments={len(rca)}",
        source="Connector: Resources/GetAll + ResourceCategories/GetAll + ResourceCategoryAssignments/GetAll",
        remediation="Confirm each space is assigned to the correct resource category and has the expected state.",
        details={"SpacesTable": spaces_table},
        risk="High"
    ))
    inv_items.append(CheckItem(
        key="Rate groups",
        status="PASS" if rate_groups else "WARN",
        summary=f"RateGroups={len(rate_groups)}",
        source="Connector: RateGroups/GetAll",
        remediation="Review rate group list and activity state.",
        details={"RateGroupsTable": rate_groups_table},
        risk="Medium"
    ))
    inv_items.append(CheckItem(
        key="Rates",
        status="PASS" if rates else "WARN",
        summary=f"Rates={len(rates)}",
        source="Connector: Rates/GetAll",
        remediation="Review rate list, base rate inheritance, group membership, visibility and status.",
        details={"RatesTable": rates_table},
        risk="High"
    ))
    inv_items.append(CheckItem(
        key="Restrictions (future stays)",
        status="PASS" if restrictions else "WARN",
        summary=f"Restrictions returned: {len(restrictions)}; Future-only rows: {len(restrictions_table)}",
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
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleX", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, alignment=TA_CENTER, spaceAfter=10))
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
        bottomMargin=16 * mm,
        title="Mews Configuration Audit Report",
        author="Mews Audit Tool",
    )

    def P(text: Any, style: str = "TinyX") -> Paragraph:
        return Paragraph(esc(text), styles[style])

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

    def make_long_table(header: List[str], rows: List[List[Any]], col_widths: List[float]) -> LongTable:
        data: List[List[Any]] = [[P(h, "SmallX") for h in header]]
        for r in rows:
            data.append([c if isinstance(c, Paragraph) else P(c, "TinyX") for c in r])

        t = LongTable(data, colWidths=col_widths, repeatRows=1)

        id_cols = set()
        for i, h in enumerate(header):
            hl = (h or "").lower()
            if "id" in hl or "uuid" in hl:
                id_cols.add(i)

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
        for ci in sorted(id_cols):
            ts.add("FONTSIZE", (ci, 1), (ci, -1), 6.8)

        for i in range(1, len(data)):
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
    story.append(PageBreak())

    for sec_name, items in report.sections:
        story.append(Paragraph(sec_name, styles["H1X"]))
        story.append(Spacer(1, 6))

        over_rows = []
        for it in items:
            over_rows.append([P(it.key, "SmallX"), Paragraph(badge(it.status), styles["SmallX"]), P(it.risk, "SmallX"), P(it.summary, "SmallX")])
        story.append(make_long_table(["Check", "Status", "Risk", "Summary"], over_rows, [62*mm, 20*mm, 18*mm, 78*mm]))
        story.append(Spacer(1, 8))

        for it in items:
            block: List[Any] = []
            block.append(Paragraph(f"<b>{esc(it.key)}</b> &nbsp;&nbsp; {badge(it.status)} &nbsp;&nbsp; <font color='#64748b'>Risk:</font> <b>{esc(it.risk)}</b>", styles["BodyX"]))
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
                    ["Product", "Accounting category", "Base price", "Tax %", "Charging"],
                    details.get("ProductMappingTable") or [],
                    [68*mm, 58*mm, 20*mm, 18*mm, 24*mm],
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
                    [86*mm, 58*mm, 32*mm],
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

            if it.source:
                block.append(Paragraph(f"<font color='#64748b'><b>Source:</b> {esc(it.source)}</font>", styles["TinyX"]))
            if it.remediation:
                block.append(Paragraph(f"<b>Recommendation:</b> {esc(it.remediation)}", styles["SmallX"]))

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
