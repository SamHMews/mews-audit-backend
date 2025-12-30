# =========================================================
# Mews Full Audit - Production Flask Backend
# Entry point: mews_full_audit_app.py
# Start command: gunicorn mews_full_audit_app:app
# =========================================================

import os
import re
import json
import time
import math
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
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    KeepTogether,
)
from reportlab.platypus.tables import LongTable, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from svglib.svglib import svg2rlg
from reportlab.graphics import renderPDF


# =========================================================
# CONFIG
# =========================================================

DEFAULT_API_BASE = os.getenv("MEWS_API_BASE_URL", "https://api.mews-demo.com/api/connector/v1")
DEFAULT_CLIENT_NAME = os.getenv("MEWS_CLIENT_NAME", "Mews Audit Tool 1.0.0")
DEFAULT_TIMEOUT = int(os.getenv("MEWS_HTTP_TIMEOUT_SECONDS", "30"))
MAX_PDF_MB = int(os.getenv("MAX_PDF_MB", "18"))  # keep Render free tier memory safe
LOGO_URL = os.getenv("LOGO_URL", "").strip()


# =========================================================
# UTILITIES
# =========================================================

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


def yn(v: Any) -> str:
    return "Yes" if bool(v) else "No"


def pick_name(obj: Any) -> str:
    """
    Best-effort: attempt to find a human readable name in Mews objects.
    Many objects provide Localized text under Names/Name/ShortName.
    """
    if not isinstance(obj, dict):
        return ""
    if obj.get("Name"):
        return str(obj.get("Name"))
    if obj.get("ShortName"):
        return str(obj.get("ShortName"))
    names = obj.get("Names")
    if isinstance(names, dict):
        # choose first non-empty translation
        for _, v in names.items():
            if v:
                return str(v)
    return ""


def chunk_list(items: List[Any], size: int) -> List[List[Any]]:
    if size <= 0:
        return [items]
    return [items[i:i + size] for i in range(0, len(items), size)]


@dataclass
class ApiCall:
    operation: str
    ok: bool
    status_code: Optional[int]
    duration_ms: int
    error: Optional[str] = None


# =========================================================
# MEWS CONNECTOR API CLIENT
# =========================================================

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
        try:
            resp = requests.post(url, json=body, timeout=DEFAULT_TIMEOUT)
            dt = int((time.time() - t0) * 1000)
            ok = resp.ok
            try:
                data = resp.json()
            except Exception:
                data = {"_raw": resp.text}
            self.calls.append(ApiCall(operation=path, ok=ok, status_code=resp.status_code, duration_ms=dt,
                                      error=None if ok else (data.get("Message") if isinstance(data, dict) else None)))
            if not ok:
                raise RuntimeError(f"HTTP {resp.status_code} for {path}: {data}")
            if not isinstance(data, dict):
                raise RuntimeError(f"Unexpected JSON shape for {path}: {type(data)}")
            return data
        except Exception as e:
            dt = int((time.time() - t0) * 1000)
            self.calls.append(ApiCall(operation=path, ok=False, status_code=None, duration_ms=dt, error=str(e)))
            raise

    def get(self, domain: str, operation: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        path = f"{domain}/{operation}"
        return self._post(path, payload)

    def paged_get_all(
        self,
        domain: str,
        operation: str,
        base_payload: Dict[str, Any],
        result_key: str,
        count_per_page: int = 1000,
        hard_limit: int = 50000,
    ) -> Tuple[List[Dict[str, Any]], List[ApiCall]]:
        """
        GitBook Pagination (Cursor-based) pattern.
        The API expects: Limitation: { Count, Cursor? }
        Returns: result_key array + optional Cursor
        """
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

            if len(out) >= hard_limit:
                break

            if pages > 200:
                break

        return out, self.calls


# =========================================================
# DATA COLLECTION
# =========================================================

def collect_data(base_url: str, client_token: str, access_token: str, client_name: str = DEFAULT_CLIENT_NAME) -> Dict[str, Any]:
    mc = MewsConnector(base_url, client_token, access_token, client_name)

    cfg = mc.get("Configuration", "Get", {})

    # Identify enterprises/services
    ent = (cfg.get("Enterprise") or {}) if isinstance(cfg, dict) else {}
    ent_id = ent.get("Id")
    enterprises = []
    if ent_id:
        enterprises = [ent_id]

    services, calls = mc.paged_get_all("Services", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Services")
    rate_groups, calls = mc.paged_get_all("RateGroups", "GetAll", {"ServiceIds": [s.get("Id") for s in services if s.get("Id")]}, "RateGroups")
    rates, calls = mc.paged_get_all("Rates", "GetAll", {"ServiceIds": [s.get("Id") for s in services if s.get("Id")]}, "Rates")

    accounting_categories, calls = mc.paged_get_all("AccountingCategories", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "AccountingCategories")
    products, calls = mc.paged_get_all("Products", "GetAll", {"ServiceIds": [s.get("Id") for s in services if s.get("Id")]}, "Products")

    payments_window_start = (utc_now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payments_window_end = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    payments, calls = mc.paged_get_all(
        "Payments",
        "GetAll",
        {
            "EnterpriseIds": enterprises,
            "CreatedUtc": {"StartUtc": payments_window_start, "EndUtc": payments_window_end},
        },
        "Payments",
        count_per_page=500,
        hard_limit=20000,
    )

    resources, calls = mc.paged_get_all("Resources", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Resources")
    rc_payload = {"EnterpriseIds": enterprises} if enterprises else {}
    resource_categories, calls = mc.paged_get_all("ResourceCategories", "GetAll", rc_payload, "ResourceCategories")
    rca, calls = mc.paged_get_all("ResourceCategoryAssignments", "GetAll", rc_payload, "ResourceCategoryAssignments")

    restrictions, calls = mc.paged_get_all("Restrictions", "GetAll", {"ServiceIds": [s.get("Id") for s in services if s.get("Id")]}, "Restrictions")

    # optional/restricted endpoints – tolerate failures
    cancellation_policies: List[Dict[str, Any]] = []
    try:
        cancellation_policies, calls = mc.paged_get_all("CancellationPolicies", "GetAll", {"ServiceIds": [s.get("Id") for s in services if s.get("Id")]}, "CancellationPolicies")
    except Exception:
        cancellation_policies = []

    rules: List[Dict[str, Any]] = []
    try:
        rules, calls = mc.paged_get_all("Rules", "GetAll", {"ServiceIds": [s.get("Id") for s in services if s.get("Id")]}, "Rules")
    except Exception:
        rules = []

    tax_envs: List[Dict[str, Any]] = []
    taxations: List[Dict[str, Any]] = []
    try:
        tax_envs, calls = mc.paged_get_all("TaxEnvironments", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "TaxEnvironments")
    except Exception:
        tax_envs = []
    try:
        taxations, calls = mc.paged_get_all("Taxations", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Taxations")
    except Exception:
        taxations = []

    counters: List[Dict[str, Any]] = []
    cashiers: List[Dict[str, Any]] = []
    try:
        counters, calls = mc.paged_get_all("Counters", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Counters")
    except Exception:
        counters = []
    try:
        cashiers, calls = mc.paged_get_all("Cashiers", "GetAll", {"EnterpriseIds": enterprises} if enterprises else {}, "Cashiers")
    except Exception:
        cashiers = []

    return {
        "cfg": cfg,
        "enterprises": enterprises,
        "services": services,
        "rate_groups": rate_groups,
        "rates": rates,
        "accounting_categories": accounting_categories,
        "products": products,
        "payments": payments,
        "resources": resources,
        "resource_categories": resource_categories,
        "resource_category_assignments": rca,
        "restrictions": restrictions,
        "cancellation_policies": cancellation_policies,
        "rules": rules,
        "tax_environments": tax_envs,
        "taxations": taxations,
        "counters": counters,
        "cashiers": cashiers,
        "api_calls": [c.__dict__ for c in mc.calls],
    }


# =========================================================
# REPORT MODEL
# =========================================================

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


# =========================================================
# EXISTING DERIVATIONS (KEEPED)
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
                "AccountingCategoryName": (cat.get("Name") if isinstance(cat, dict) else "UNMAPPED") or "UNMAPPED",
                "Products": sorted(
                    [
                        {
                            "Id": p.get("Id"),
                            "Name": pick_name(p) or "",
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

    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for a in assignments:
        rid = a.get("ResourceId")
        cid = a.get("ResourceCategoryId") or "UNASSIGNED"
        if rid and rid in res_by_id:
            buckets.setdefault(cid, []).append(res_by_id[rid])

    assigned_ids = set(a.get("ResourceId") for a in assignments if a.get("ResourceId"))
    for r in resources:
        if r.get("Id") and r.get("Id") not in assigned_ids:
            buckets.setdefault("UNASSIGNED", []).append(r)

    out = []
    for cid, rlist in buckets.items():
        c = cat_by_id.get(cid)
        out.append(
            {
                "ResourceCategoryId": cid,
                "ResourceCategoryName": (c.get("Name") if isinstance(c, dict) else "UNASSIGNED") or "UNASSIGNED",
                "Type": (c.get("Type") if isinstance(c, dict) else "") or "",
                "Resources": sorted(
                    [
                        {
                            "Id": r.get("Id"),
                            "Name": r.get("Name") or "",
                            "IsActive": r.get("IsActive"),
                            "State": r.get("State") or "",
                        }
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

        base_rates = [r for r in group_rates if (r.get("IsBaseRate") or r.get("Type") == "Base") and not r.get("BaseRateId")]
        derived = [r for r in group_rates if r.get("BaseRateId")]

        derived_by_base: Dict[str, List[Dict[str, Any]]] = {}
        for d in derived:
            derived_by_base.setdefault(d.get("BaseRateId") or "MISSING_BASE", []).append(d)

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
            {"RateGroupId": gid, "RateGroupName": gname, "Tree": tree, "Orphans": sorted(orphans, key=lambda x: x["Name"]),
             "Misc": sorted(misc, key=lambda x: x["Name"]), "RateCount": len(group_rates)}
        )

    groups_out.sort(key=lambda x: x["RateGroupName"])
    return {"RateGroups": groups_out}


def map_cancellation_policies(cancellation_policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_rg: Dict[str, List[Dict[str, Any]]] = {}
    for p in cancellation_policies or []:
        gid = p.get("RateGroupId") or "UNASSIGNED"
        by_rg.setdefault(gid, []).append(p)
    return by_rg


def describe_restrictions(restrictions: List[Dict[str, Any]]) -> List[str]:
    out = []
    for r in restrictions or []:
        rid = r.get("Id") or ""
        cond = r.get("Conditions") or {}
        ex = r.get("Exceptions") or {}
        s = (cond.get("StartUtc") or "")
        e = (cond.get("EndUtc") or "")
        rg = cond.get("RateGroupId") or ""
        rate = cond.get("ExactRateId") or ""
        base = cond.get("BaseRateId") or ""
        cat = cond.get("ResourceCategoryId") or ""
        line = f"Id={rid} | {s} → {e} | RateGroupId={rg} | ExactRateId={rate} | BaseRateId={base} | ResourceCategoryId={cat} | Exceptions={json.dumps(ex, ensure_ascii=False)}"
        out.append(line)
    return out


# =========================================================
# TABLE-SHAPED DERIVATIONS (for PDF)
# =========================================================

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def is_uuid(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    return bool(_UUID_RE.match(val.strip()))


def safe_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def money_from_extended_amount(ext: Any) -> str:
    # Connector commonly returns 'Extended amount' as dict: { 'GrossValue': 123.45, 'NetValue': 100, 'Currency': 'GBP', ... }
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


def build_accounting_categories_table(
    accounting_categories: List[Dict[str, Any]],
    products: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
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


def build_product_mapping_table(
    products: List[Dict[str, Any]],
    accounting_categories: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
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


def build_spaces_table(
    resources: List[Dict[str, Any]],
    resource_categories: List[Dict[str, Any]],
    assignments: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
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
    for k, label in (
        ("MinAdvance", "Min advance"),
        ("MaxAdvance", "Max advance"),
        ("MinLength", "Min length"),
        ("MaxLength", "Max length"),
    ):
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
        return ""
    s = cond.get("StartUtc") or ""
    e = cond.get("EndUtc") or ""
    days = cond.get("Days")
    bits = []
    if s or e:
        bits.append(f"{s} → {e}".strip())
    if isinstance(days, list) and days:
        bits.append("Days: " + ",".join(days))
    return " | ".join(bits) if bits else ""


def build_restrictions_table(
    restrictions: List[Dict[str, Any]],
    rates: List[Dict[str, Any]],
    rate_groups: List[Dict[str, Any]],
    resource_categories: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
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
            rate_bits.append("Rate: " + (pick_name(rr) if rr else cond.get("ExactRateId")))
        if cond.get("BaseRateId"):
            br = rate_by_id.get(cond.get("BaseRateId"))
            rate_bits.append("Base rate: " + (pick_name(br) if br else cond.get("BaseRateId")))
        if cond.get("RateGroupId"):
            g = rg_by_id.get(cond.get("RateGroupId"))
            rate_bits.append("Group: " + (pick_name(g) if g else cond.get("RateGroupId")))
        rates_scope = "; ".join(rate_bits) if rate_bits else "All rates"

        space_bits: List[str] = []
        if cond.get("ResourceCategoryId"):
            c = cat_by_id.get(cond.get("ResourceCategoryId"))
            space_bits.append((c.get("Name") if isinstance(c, dict) else cond.get("ResourceCategoryId")) or "")
        if cond.get("ResourceCategoryType"):
            space_bits.append(str(cond.get("ResourceCategoryType")))
        spaces_scope = ", ".join([b for b in space_bits if b]) or "All spaces"

        rows.append({
            "Time": summarise_restriction_time(cond),
            "Rates": rates_scope,
            "Spaces": spaces_scope,
            "Exceptions": summarise_restriction_exceptions(r.get("Exceptions")),
        })

    rows.sort(key=lambda x: x.get("Time") or "")
    return rows


# =========================================================
# BUILD REPORT
# =========================================================

def build_report(data: Dict[str, Any], base_url: str, client_name: str) -> AuditReport:
    cfg = data.get("cfg", {})
    enterprises = data.get("enterprises", [])
    services = data.get("services", [])
    rate_groups = data.get("rate_groups", [])
    rates = data.get("rates", [])
    accounting_categories = data.get("accounting_categories", [])
    products = data.get("products", [])
    payments = data.get("payments", [])
    resources = data.get("resources", [])
    resource_categories = data.get("resource_categories", [])
    rca = data.get("resource_category_assignments", [])
    rules = data.get("rules", [])
    tax_envs = data.get("tax_environments", [])
    taxations = data.get("taxations", [])
    counters = data.get("counters", [])
    cashiers = data.get("cashiers", [])
    restrictions = data.get("restrictions", [])
    cancellation_policies = data.get("cancellation_policies", [])

    acc_categories_table = build_accounting_categories_table(accounting_categories, products, services)
    product_mapping_table = build_product_mapping_table(products, accounting_categories)
    spaces_table = build_spaces_table(resources, resource_categories, rca)
    rate_groups_table = build_rate_groups_table(rate_groups)
    rates_table = build_rates_table(rates, rate_groups)
    restrictions_table = build_restrictions_table(restrictions, rates, rate_groups, resource_categories)

    # Backwards-compatible derivations (kept for reference / debugging)
    acc_breakdown = map_accounting_categories_to_products(accounting_categories, products)
    spaces_by_cat = map_spaces_by_category(resources, resource_categories, rca)
    rate_index = build_rate_index(rates, rate_groups)
    restriction_lines = describe_restrictions(restrictions)

    cancellation_by_group = map_cancellation_policies(cancellation_policies) if cancellation_policies else {}

    ent = (cfg.get("Enterprise") or {}) if isinstance(cfg, dict) else {}
    enterprise_id = ent.get("Id") or (enterprises[0] if enterprises else "")
    enterprise_name = ent.get("Name") or "Unknown"

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
    accounting_items.append(CheckItem("Accounting categories (structure)", "PASS" if accounting_categories else "WARN", f"Accounting categories returned: {len(accounting_categories)}", "Connector: AccountingCategories/GetAll", "Confirm the accounting category structure matches the property’s accounting export design.", {}, "High" if not accounting_categories else "Medium"))
    accounting_items.append(CheckItem("Accounting categories (list)", "PASS" if accounting_categories else "WARN", f"Accounting categories returned: {len(accounting_categories)}", "Connector: AccountingCategories/GetAll", "Review category codes/classifications and ledger mappings; confirm alignment with finance export.", {"AccountingCategoriesTable": acc_categories_table}, "High"))
    accounting_items.append(CheckItem("Product mapping (product → accounting category)", "PASS" if products else "WARN", f"Products returned: {len(products)}", "Connector: Products/GetAll + AccountingCategories/GetAll", "Validate each product is mapped to the correct accounting category, has expected base price/tax, and charging mode.", {"ProductMappingTable": product_mapping_table}, "High"))
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
    inv_items.append(CheckItem("Spaces and resource categories", "PASS" if resources else "WARN", f"Spaces={len(resources)}, ResourceCategories={len(resource_categories)}", "Connector: Resources/GetAll + ResourceCategories/GetAll + ResourceCategoryAssignments/GetAll", "Confirm each space is assigned to the correct resource category and has the expected state.", {"SpacesTable": spaces_table}, "High"))
    inv_items.append(CheckItem("Rate groups", "PASS" if rate_groups else "WARN", f"RateGroups={len(rate_groups)}", "Connector: RateGroups/GetAll", "Review rate group list and activity state.", {"RateGroupsTable": rate_groups_table}, "Medium"))
    inv_items.append(CheckItem("Rates", "PASS" if rates else "WARN", f"Rates={len(rates)}", "Connector: Rates/GetAll", "Review rate list, base rate inheritance, group membership, visibility and status.", {"RatesTable": rates_table}, "High"))
    inv_items.append(CheckItem("Cancellation policy per Rate Group (best available)", "PASS" if cancellation_policies else "NEEDS_INPUT", (f"CancellationPolicies returned: {len(cancellation_policies)}" if cancellation_policies else "CancellationPolicies/GetAll not available for this token (restricted). Confirm in UI."), "Connector: CancellationPolicies/GetAll (restricted; may be empty)", "If unavailable, export/capture policies from Mews UI; ensure each Rate Group’s policy matches intent.", {"CancellationPoliciesByRateGroup": cancellation_by_group}, "High"))
    inv_items.append(CheckItem("Restrictions (future stays)", "PASS" if restrictions else "WARN", f"Restrictions returned: {len(restrictions)}; Future-only: {len(restrictions_table)}", "Connector: Restrictions/GetAll", "Review future-only restrictions for correctness of time window, rate scope, space scope and exceptions.", {"RestrictionsTable": restrictions_table}, "Medium"))
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
        "Users & security": users_items,
        "Accounting configuration": accounting_items,
        "Payments": payments_items,
        "Spaces, rates & restrictions": inv_items,
        "Guest journey & operations": ops_items,
        "Reporting": reporting_items,
        "Integrations": integrations_items,
        "Governance": governance_items,
    }

    SECTION_ORDER = [
        "Legal & property baseline",
        "Users & security",
        "Accounting configuration",
        "Payments",
        "Spaces, rates & restrictions",
        "Guest journey & operations",
        "Reporting",
        "Integrations",
        "Governance",
    ]

    sections: List[Tuple[str, List[CheckItem]]] = [(name, section_map[name]) for name in SECTION_ORDER if name in section_map]

    calls = []
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


# =========================================================
# PDF GENERATION (ReportLab)
# =========================================================

def fetch_logo() -> Optional[Any]:
    if not LOGO_URL:
        return None
    try:
        resp = requests.get(LOGO_URL, timeout=10)
        if not resp.ok:
            return None
        tmp = "/tmp/logo.svg"
        with open(tmp, "wb") as f:
            f.write(resp.content)
        drawing = svg2rlg(tmp)
        return drawing
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
        table_data: List[List[Any]] = [[P(h, "SmallX") for h in header]]
        for r in rows:
            table_data.append([c if isinstance(c, Paragraph) else P(c, "TinyX") for c in r])

        t = LongTable(table_data, colWidths=col_widths, repeatRows=1)

        # Detect ID-like columns and reduce font size in those columns
        id_cols = set()
        for i, h in enumerate(header):
            hl = (" " + (h or "").lower()).strip()
            if hl.endswith("id") or " id" in hl or "uuid" in hl:
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
            counts[it.status] = counts.get(it.status, 0) + 1

    story.append(Paragraph(
        f"<b>Summary</b> &nbsp;&nbsp; Items: <b>{total}</b> &nbsp;&nbsp; "
        f"PASS: <b>{counts['PASS']}</b> &nbsp;&nbsp; "
        f"WARN: <b>{counts['WARN']}</b> &nbsp;&nbsp; "
        f"FAIL: <b>{counts['FAIL']}</b> &nbsp;&nbsp; "
        f"NEEDS_INPUT: <b>{counts['NEEDS_INPUT']}</b> &nbsp;&nbsp; "
        f"NA: <b>{counts['NA']}</b>",
        styles["BodyX"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report is generated from the Mews Connector API. It includes best-effort derivations where the API does not directly expose a specific configuration relationship.",
        styles["SmallX"]
    ))
    story.append(PageBreak())

    # Detailed sections
    for sec_name, items in report.sections:
        story.append(Paragraph(sec_name, styles["H1X"]))
        story.append(Spacer(1, 6))

        # Section overview table
        over_rows = []
        for it in items:
            over_rows.append([P(it.key, "SmallX"), Paragraph(badge(it.status), styles["SmallX"]), P(it.risk, "SmallX"), P(it.summary, "SmallX")])
        over_header = ["Check", "Status", "Risk", "Summary"]
        over_colw = [62*mm, 20*mm, 18*mm, 78*mm]
        story.append(make_long_table(over_header, over_rows, over_colw))
        story.append(Spacer(1, 8))

        # Each check details
        for it in items:
            block: List[Any] = []
            block.append(Paragraph(f"<b>{esc(it.key)}</b> &nbsp;&nbsp; {badge(it.status)} &nbsp;&nbsp; <font color='#64748b'>Risk:</font> <b>{esc(it.risk)}</b>", styles["BodyX"]))
            block.append(Paragraph(esc(it.summary or "-"), styles["BodyX"]))
            block.append(Spacer(1, 4))

            details = it.details or {}

            # Accounting categories table
            if "AccountingCategoriesTable" in details:
                rows_dicts = details.get("AccountingCategoriesTable") or []
                header = ["Accounting category", "Accounting category ID", "Ledger account code", "Classification", "Service"]
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                colw = [50*mm, 42*mm, 30*mm, 26*mm, 32*mm]
                block.append(Paragraph("<b>Detail: Accounting categories</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 350):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Product mapping table
            if "ProductMappingTable" in details:
                rows_dicts = details.get("ProductMappingTable") or []
                header = ["Product", "Accounting category", "Base price", "Tax %", "Charging"]
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                colw = [68*mm, 58*mm, 20*mm, 18*mm, 24*mm]
                block.append(Paragraph("<b>Detail: Product mapping</b>", styles["SmallX"]))
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

            # Spaces and resource categories
            if "SpacesTable" in details:
                rows_dicts = details.get("SpacesTable") or []
                header = ["Resource category", "Space", "State"]
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                colw = [66*mm, 84*mm, 28*mm]
                block.append(Paragraph("<b>Detail: Spaces and resource categories</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 400):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Rate groups table
            if "RateGroupsTable" in details:
                rows_dicts = details.get("RateGroupsTable") or []
                header = ["Rate group", "Rate group ID", "Activity state"]
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                colw = [86*mm, 58*mm, 32*mm]
                block.append(Paragraph("<b>Detail: Rate groups</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 350):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Rates table
            if "RatesTable" in details:
                rows_dicts = details.get("RatesTable") or []
                header = ["Rate", "Rate ID", "Base rate", "Rate group", "Visibility", "Status"]
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                colw = [44*mm, 34*mm, 38*mm, 44*mm, 18*mm, 18*mm]
                block.append(Paragraph("<b>Detail: Rates</b>", styles["SmallX"]))
                block.append(Spacer(1, 3))
                for ch in chunk_list(rows, 350):
                    block.append(make_long_table(header, ch, colw))
                    block.append(Spacer(1, 6))

            # Restrictions (future stays)
            if "RestrictionsTable" in details:
                rows_dicts = details.get("RestrictionsTable") or []
                header = ["Time", "Rates", "Spaces", "Exceptions"]
                rows = [[P(r.get(h, "")) for h in header] for r in rows_dicts]
                colw = [46*mm, 54*mm, 38*mm, 46*mm]
                block.append(Paragraph("<b>Detail: Restrictions (future stays)</b>", styles["SmallX"]))
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
    pdf = buf.getvalue()
    if len(pdf) > MAX_PDF_MB * 1024 * 1024:
        raise RuntimeError(f"Generated PDF too large ({len(pdf)/(1024*1024):.1f}MB) for environment limit ({MAX_PDF_MB}MB).")
    return pdf


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
    POST tokens to <code>/audit</code> to generate a PDF report.
  </p>
  <div class="card">
    <form method="post" action="/audit">
      <div class="row">
        <div>
          <label>Client token</label>
          <input name="client_token" placeholder="ClientToken">
        </div>
        <div>
          <label>Access token</label>
          <input name="access_token" placeholder="AccessToken">
        </div>
      </div>
      <label>API base URL</label>
      <input name="base_url" placeholder="https://api.mews-demo.com/api/connector/v1" value="https://api.mews-demo.com/api/connector/v1">
      <div style="margin-top:14px">
        <button class="btn" type="submit">Generate PDF</button>
      </div>
    </form>
  </div>
</div>
</body>
</html>
"""

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "mews-audit-secret")
CORS(app, resources={r"/*": {"origins": "*"}})


@app.get("/")
def home():
    return render_template_string(HTML)


@app.post("/audit")
def audit():
    try:
        ct = (request.form.get("client_token") if request.form else None) or (request.json.get("client_token") if request.is_json else None)
        at = (request.form.get("access_token") if request.form else None) or (request.json.get("access_token") if request.is_json else None)
        base_url = (request.form.get("base_url") if request.form else None) or (request.json.get("base_url") if request.is_json else None) or DEFAULT_API_BASE

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
        return jsonify({"ok": False, "error": str(e), "trace": err}), 500


@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": utc_now().isoformat(), "base": DEFAULT_API_BASE})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
