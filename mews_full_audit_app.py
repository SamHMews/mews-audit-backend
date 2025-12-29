"""
mews_full_audit_app.py (single-file backend)

Improvements included:
- Adds Mews logo (SVG) to PDF header (downloaded per request; safe fallback if blocked)
- Removes payments tables (renders readable wrapped lines instead)
- Rates: shows base→derived mapping, rate group, flags (public/private, active, enabled, default, type, external id)
- Accounting categories: shows exactly which products are mapped to each category
- Spaces: shows which spaces belong to each space category (by name), not just IDs
- Restrictions: renders descriptive output (what it does, when active, targets rate/base/group/category, key parameters)
- Adds ResourceCategoryAssignments pull (if available)
- Keeps filters for endpoints that require them

Security:
- Does not store tokens; PDF generated in-memory
- Rate limiting
- CORS restricted to your GitHub Pages origin via env var ALLOWED_ORIGINS (default: https://samhmews.github.io)
"""

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
from reportlab.lib.enums import TA_RIGHT
from reportlab.graphics import renderPDF
from svglib.svglib import svg2rlg


# -----------------------------
# Models
# -----------------------------

@dataclass
class ApiCallResult:
    name: str
    ok: bool
    status_code: Optional[int]
    duration_ms: int
    error: Optional[str] = None


@dataclass
class EvidenceItem:
    key: str
    status: str  # PASS / FAIL / WARN / NA / NEEDS_INPUT
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    remediation: str = ""


@dataclass
class AuditReport:
    generated_at_utc: datetime
    base_url: str
    client_name: str
    property_name: str = ""
    enterprise_id: str = ""
    api_calls: List[ApiCallResult] = field(default_factory=list)
    sections: Dict[str, List[EvidenceItem]] = field(default_factory=dict)


# -----------------------------
# Connector API client
# -----------------------------

class MewsConnectorClient:
    def __init__(self, base_url: str, client_token: str, access_token: str, client_name: str = "mews-audit",
                 timeout_seconds: int = 35):
        self.base_url = base_url.rstrip("/")
        self.client_token = client_token
        self.access_token = access_token
        self.client_name = (client_name or "mews-audit").strip()
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def post(self, resource: str, operation: str, payload: Optional[Dict[str, Any]] = None
             ) -> Tuple[Dict[str, Any], ApiCallResult]:
        url = f"{self.base_url}/{resource}/{operation}"
        body = payload.copy() if isinstance(payload, dict) else {}
        body["ClientToken"] = self.client_token
        body["AccessToken"] = self.access_token
        body["Client"] = self.client_name  # harmless if ignored

        started = time.time()
        try:
            resp = self.session.post(url, data=json.dumps(body), timeout=self.timeout_seconds)
            ms = int((time.time() - started) * 1000)

            if resp.status_code >= 400:
                safe_err = f"HTTP {resp.status_code}"
                try:
                    j = resp.json()
                    if isinstance(j, dict) and j.get("Message"):
                        safe_err = f"HTTP {resp.status_code}: {j.get('Message')}"
                except Exception:
                    pass
                return {}, ApiCallResult(f"{resource}/{operation}", False, resp.status_code, ms, safe_err)

            try:
                data = resp.json()
            except Exception:
                return {}, ApiCallResult(f"{resource}/{operation}", False, resp.status_code, ms, "Invalid JSON response")
            return data, ApiCallResult(f"{resource}/{operation}", True, resp.status_code, ms)

        except requests.RequestException:
            ms = int((time.time() - started) * 1000)
            return {}, ApiCallResult(f"{resource}/{operation}", False, None, ms, "Network error")


# -----------------------------
# Helpers
# -----------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()

def _time_window(days: int) -> Dict[str, str]:
    end = _utc_now()
    start = end - timedelta(days=days)
    return {"StartUtc": _iso(start), "EndUtc": _iso(end)}

def _pick_name(obj: Dict[str, Any]) -> str:
    """
    Many objects expose:
    - Name (string)
    - Names (dict of locale->string)
    Try to pull something readable.
    """
    if not isinstance(obj, dict):
        return ""
    name = (obj.get("Name") or "").strip()
    if name:
        return name
    names = obj.get("Names")
    if isinstance(names, dict):
        for v in names.values():
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""

def _flag(v: Any) -> str:
    if v is True:
        return "Yes"
    if v is False:
        return "No"
    return ""

def _truncate(s: str, n: int = 140) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


# -----------------------------
# Data pull
# -----------------------------

def connector_pull_all(client: MewsConnectorClient, report: AuditReport) -> Dict[str, Any]:
    pulled: Dict[str, Any] = {}
    now = _utc_now()
    start_30d = now - timedelta(days=30)

    def call(resource: str, op: str, payload: Optional[Dict[str, Any]] = None, key: Optional[str] = None):
        data, res = client.post(resource, op, payload)
        report.api_calls.append(res)
        pulled[key or f"{resource}/{op}"] = data if res.ok else {"_error": res.error, "_status": res.status_code}
        return data, res

    # config
    cfg, _ = call("Configuration", "Get", key="config")

    # services (for filters)
    services_data, _ = call("Services", "GetAll", key="services")
    service_ids: List[str] = []
    if isinstance(services_data, dict) and isinstance(services_data.get("Services"), list):
        for s in services_data["Services"]:
            if isinstance(s, dict) and s.get("Id"):
                service_ids.append(s["Id"])

    # tax
    call("TaxEnvironments", "GetAll", key="tax_envs")
    call("Taxations", "GetAll", key="taxations")

    # products + categories (service-scoped in many environments)
    if service_ids:
        call("Products", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 1000}}, key="products")
        call("ProductCategories", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 1000}}, key="product_categories")
    else:
        call("Products", "GetAll", {"Limitation": {"Count": 1000}}, key="products")
        call("ProductCategories", "GetAll", {"Limitation": {"Count": 1000}}, key="product_categories")

    # rules (needs ServiceIds in some tenants)
    if service_ids:
        call("Rules", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 1000}}, key="rules")
    else:
        call("Rules", "GetAll", {"Limitation": {"Count": 1000}}, key="rules")

    # accounting
    call("AccountingCategories", "GetAll", {"Limitation": {"Count": 2000}}, key="accounting_categories")
    call("Cashiers", "GetAll", {"Limitation": {"Count": 1000}}, key="cashiers")
    call("Counters", "GetAll", {"Limitation": {"Count": 1000}}, key="counters")

    # payments require filters
    call("Payments", "GetAll", {
        "CreatedUtc": {"StartUtc": _iso(start_30d), "EndUtc": _iso(now)},
        "Limitation": {"Count": 500}
    }, key="payments_500")

    # inventory
    call("Resources", "GetAll", {"Limitation": {"Count": 5000}}, key="resources")
    if service_ids:
        call("ResourceCategories", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 2000}}, key="resource_categories")
    else:
        call("ResourceCategories", "GetAll", {"Limitation": {"Count": 2000}}, key="resource_categories")

    # Space ↔ Category mapping (workhorse for your requirement)
    # Not all environments support it; we try and keep failure as a note.
    if service_ids:
        call("ResourceCategoryAssignments", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 5000}}, key="resource_category_assignments")
    else:
        call("ResourceCategoryAssignments", "GetAll", {"Limitation": {"Count": 5000}}, key="resource_category_assignments")

    # rates
    call("Rates", "GetAll", {"Limitation": {"Count": 5000}}, key="rates")
    if service_ids:
        call("RateGroups", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 2000}}, key="rate_groups")
    else:
        call("RateGroups", "GetAll", {"Limitation": {"Count": 2000}}, key="rate_groups")

    # restrictions (make them descriptive later)
    if service_ids:
        call("Restrictions", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 5000}}, key="restrictions")
    else:
        call("Restrictions", "GetAll", {"Limitation": {"Count": 5000}}, key="restrictions")

    return pulled


# -----------------------------
# Derivations for detailed reporting
# -----------------------------

def derive_accounting_category_products(pulled: Dict[str, Any]) -> List[Dict[str, Any]]:
    acc = pulled.get("accounting_categories", {})
    prod = pulled.get("products", {})
    cats = acc.get("AccountingCategories", []) if isinstance(acc, dict) else []
    products = prod.get("Products", []) if isinstance(prod, dict) else []

    cats_by_id = {c.get("Id"): c for c in cats if isinstance(c, dict) and c.get("Id")}

    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for p in products:
        if not isinstance(p, dict):
            continue
        acc_id = p.get("AccountingCategoryId") or "UNMAPPED"
        buckets.setdefault(acc_id, []).append(p)

    out = []
    for acc_id, plist in buckets.items():
        c = cats_by_id.get(acc_id)
        out.append({
            "AccountingCategoryId": acc_id,
            "AccountingCategoryName": _pick_name(c) if c else ("UNMAPPED" if acc_id == "UNMAPPED" else acc_id),
            "Products": sorted([
                {
                    "Id": p.get("Id"),
                    "Name": _pick_name(p),
                    "Code": p.get("Code"),
                    "IsActive": p.get("IsActive"),
                    "Type": p.get("Type"),
                    "ProductCategoryId": p.get("ProductCategoryId"),
                } for p in plist
            ], key=lambda x: (x.get("Name") or "")),
        })
    out.sort(key=lambda x: x["AccountingCategoryName"])
    return out


def derive_spaces_by_category(pulled: Dict[str, Any]) -> List[Dict[str, Any]]:
    res = pulled.get("resources", {})
    rc = pulled.get("resource_categories", {})
    asn = pulled.get("resource_category_assignments", {})

    resources = res.get("Resources", []) if isinstance(res, dict) else []
    categories = rc.get("ResourceCategories", []) if isinstance(rc, dict) else []
    assignments = asn.get("ResourceCategoryAssignments", []) if isinstance(asn, dict) else []

    cat_by_id = {c.get("Id"): c for c in categories if isinstance(c, dict) and c.get("Id")}
    res_by_id = {r.get("Id"): r for r in resources if isinstance(r, dict) and r.get("Id")}

    # resourceId -> list of categoryIds
    res_to_cat: Dict[str, List[str]] = {}
    if isinstance(assignments, list):
        for a in assignments:
            if not isinstance(a, dict):
                continue
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
        c = cat_by_id.get(cid)
        out.append({
            "ResourceCategoryId": cid,
            "ResourceCategoryName": _pick_name(c) if c else ("UNASSIGNED" if cid == "UNASSIGNED" else cid),
            "Type": (c.get("Type") if isinstance(c, dict) else ""),
            "Resources": sorted([
                {
                    "Id": r.get("Id"),
                    "Name": r.get("Name"),
                    "IsActive": r.get("IsActive"),
                    "State": r.get("State"),
                } for r in rlist
            ], key=lambda x: (x.get("Name") or "")),
        })
    out.sort(key=lambda x: x["ResourceCategoryName"])
    return out


def derive_rate_details(pulled: Dict[str, Any]) -> Dict[str, Any]:
    rates_data = pulled.get("rates", {})
    groups_data = pulled.get("rate_groups", {})
    rates = rates_data.get("Rates", []) if isinstance(rates_data, dict) else []
    groups = groups_data.get("RateGroups", []) if isinstance(groups_data, dict) else []

    rg_by_id = {g.get("Id"): g for g in groups if isinstance(g, dict) and g.get("Id")}
    rate_by_id = {r.get("Id"): r for r in rates if isinstance(r, dict) and r.get("Id")}

    def rate_label(r: Dict[str, Any]) -> str:
        return _pick_name(r) or (r.get("Code") or "") or (r.get("Id") or "")

    def group_label(gid: Optional[str]) -> str:
        g = rg_by_id.get(gid) if gid else None
        return _pick_name(g) if g else (gid or "")

    # Base rates (best-effort; some tenants use IsBaseRate/BaseRateId, some not)
    base_rates = [r for r in rates if r.get("IsBaseRate") or (not r.get("BaseRateId") and r.get("Type") == "Base")]
    derived_rates = [r for r in rates if r.get("BaseRateId")]

    derived_by_base: Dict[str, List[Dict[str, Any]]] = {}
    for r in derived_rates:
        derived_by_base.setdefault(r.get("BaseRateId"), []).append(r)

    tree = []
    for br in sorted(base_rates, key=rate_label):
        br_id = br.get("Id")
        children = sorted(derived_by_base.get(br_id, []), key=rate_label)
        tree.append({
            "Base": _rate_to_rich(br, group_label(br.get("GroupId"))),
            "Derived": [_rate_to_rich(ch, group_label(ch.get("GroupId"))) for ch in children]
        })

    # Orphans + misc
    orphans = [_rate_to_rich(r, group_label(r.get("GroupId"))) for r in derived_rates if r.get("BaseRateId") not in rate_by_id]
    misc = [_rate_to_rich(r, group_label(r.get("GroupId"))) for r in rates if (not r.get("IsBaseRate") and not r.get("BaseRateId") and r not in base_rates)]

    groups_rich = [{
        "Id": g.get("Id"),
        "Name": _pick_name(g),
        "IsActive": g.get("IsActive"),
        "IsPublic": g.get("IsPublic"),
    } for g in sorted(groups, key=lambda x: _pick_name(x) or "")]

    return {"RateTree": tree, "RateOrphans": orphans, "RateMisc": misc, "RateGroups": groups_rich}


def _rate_to_rich(r: Dict[str, Any], group_name: str) -> Dict[str, Any]:
    return {
        "Id": r.get("Id"),
        "Name": _pick_name(r),
        "Code": r.get("Code"),
        "GroupId": r.get("GroupId"),
        "GroupName": group_name,
        "BaseRateId": r.get("BaseRateId"),
        "IsBaseRate": r.get("IsBaseRate"),
        "IsActive": r.get("IsActive"),
        "IsEnabled": r.get("IsEnabled"),
        "IsPublic": r.get("IsPublic"),
        "IsPrivate": r.get("IsPrivate"),
        "IsDefault": r.get("IsDefault"),
        "Type": r.get("Type"),
        "ExternalIdentifier": r.get("ExternalIdentifier"),
        "ShortName": r.get("ShortName"),
    }


def derive_restrictions_pretty(pulled: Dict[str, Any]) -> List[str]:
    rdata = pulled.get("restrictions", {})
    rates_data = pulled.get("rates", {})
    groups_data = pulled.get("rate_groups", {})
    rc_data = pulled.get("resource_categories", {})

    restrictions = rdata.get("Restrictions", []) if isinstance(rdata, dict) else []
    rates = rates_data.get("Rates", []) if isinstance(rates_data, dict) else []
    groups = groups_data.get("RateGroups", []) if isinstance(groups_data, dict) else []
    cats = rc_data.get("ResourceCategories", []) if isinstance(rc_data, dict) else []

    rate_by_id = {r.get("Id"): r for r in rates if isinstance(r, dict) and r.get("Id")}
    group_by_id = {g.get("Id"): g for g in groups if isinstance(g, dict) and g.get("Id")}
    cat_by_id = {c.get("Id"): c for c in cats if isinstance(c, dict) and c.get("Id")}

    def rate_name(rid: Optional[str]) -> str:
        r = rate_by_id.get(rid) if rid else None
        return _pick_name(r) if r else (rid or "")

    def group_name(gid: Optional[str]) -> str:
        g = group_by_id.get(gid) if gid else None
        return _pick_name(g) if g else (gid or "")

    def cat_name(cid: Optional[str]) -> str:
        c = cat_by_id.get(cid) if cid else None
        return _pick_name(c) if c else (cid or "")

    lines: List[str] = []
    for x in restrictions:
        if not isinstance(x, dict):
            continue
        cond = x.get("Conditions") or {}
        # What it affects:
        parts = []

        rid = x.get("Id")
        parts.append(f"RestrictionId={rid}")

        # Active window (if present)
        start = x.get("StartUtc") or ""
        end = x.get("EndUtc") or ""
        if start or end:
            parts.append(f"Active={start} → {end}")

        # Target scope
        if cond.get("ResourceCategoryId"):
            parts.append(f"SpaceCategory={cat_name(cond.get('ResourceCategoryId'))}")
        if cond.get("RateGroupId"):
            parts.append(f"RateGroup={group_name(cond.get('RateGroupId'))}")
        if cond.get("RateId") or cond.get("ExactRateId"):
            parts.append(f"Rate={rate_name(cond.get('ExactRateId') or cond.get('RateId'))}")
        if cond.get("BaseRateId"):
            parts.append(f"BaseRate={rate_name(cond.get('BaseRateId'))}")

        # Behaviour (descriptive)
        behaviours = []
        for k in ("ClosedToArrival", "ClosedToDeparture", "IsClosed", "Closed"):
            if k in cond and cond.get(k) is not None:
                behaviours.append(f"{k}={cond.get(k)}")
        for k in ("MinimumLength", "MaximumLength", "MinLength", "MaxLength"):
            if k in cond and cond.get(k) is not None:
                behaviours.append(f"{k}={cond.get(k)}")
        if cond.get("Days"):
            behaviours.append(f"Days={cond.get('Days')}")
        if cond.get("ArrivalDays"):
            behaviours.append(f"ArrivalDays={cond.get('ArrivalDays')}")
        if behaviours:
            parts.append("Rules: " + "; ".join(behaviours))

        lines.append(" | ".join(parts))
    return lines


# -----------------------------
# Audit build
# -----------------------------

def run_full_audit(client: MewsConnectorClient, base_url: str, client_name: str) -> AuditReport:
    report = AuditReport(
        generated_at_utc=_utc_now(),
        base_url=base_url,
        client_name=client_name,
    )

    pulled = connector_pull_all(client, report)
    cfg = pulled.get("config") if isinstance(pulled.get("config"), dict) else {}

    if isinstance(cfg, dict) and "_error" not in cfg:
        enterprise = cfg.get("Enterprise") or {}
        report.property_name = enterprise.get("Name") or cfg.get("Name") or ""
        report.enterprise_id = enterprise.get("Id") or ""

    # Derivations
    acc_breakdown = derive_accounting_category_products(pulled)
    spaces_breakdown = derive_spaces_by_category(pulled)
    rate_details = derive_rate_details(pulled)
    restriction_lines = derive_restrictions_pretty(pulled)

    # Sections: keep this lightweight; most detail is in details blocks for PDF
    report.sections["Payments setup & reconciliation"] = [
        EvidenceItem(
            key="Payments (last 30 days sample)",
            status="PASS",
            summary="Payments are listed as readable lines (no table).",
            details={"Payments": (pulled.get("payments_500") or {}).get("Payments", [])},
            source="Connector: Payments/GetAll (CreatedUtc 30d window)",
            remediation="If unexpectedly empty, verify permissions or adjust date window."
        )
    ]

    report.sections["Accounting configuration"] = [
        EvidenceItem(
            key="Accounting categories → products mapping",
            status="PASS" if acc_breakdown else "WARN",
            summary=f"Categories with mapped products: {len(acc_breakdown)}",
            details={"AccountingCategoryBreakdown": acc_breakdown},
            source="Connector: AccountingCategories/GetAll + Products/GetAll",
            remediation="Validate categories are complete and products are mapped correctly."
        )
    ]

    report.sections["Inventory, rates & revenue structure"] = [
        EvidenceItem(
            key="Spaces by space category",
            status="PASS" if spaces_breakdown else "WARN",
            summary=f"Space categories (with spaces): {len(spaces_breakdown)}",
            details={"SpacesByCategory": spaces_breakdown},
            source="Connector: Resources/GetAll + ResourceCategories/GetAll + ResourceCategoryAssignments/GetAll",
            remediation="Ensure each space belongs to the correct category; no unassigned spaces unless intended."
        ),
        EvidenceItem(
            key="Rates (full detail)",
            status="PASS",
            summary="Base → derived, rate groups, and key flags are included.",
            details=rate_details,
            source="Connector: Rates/GetAll + RateGroups/GetAll",
            remediation="Validate structure, derivations, and public/private/active/enabled flags."
        ),
        EvidenceItem(
            key="Restrictions (descriptive)",
            status="PASS" if restriction_lines else "WARN",
            summary=f"Restrictions rendered: {len(restriction_lines)}",
            details={"RestrictionLines": restriction_lines},
            source="Connector: Restrictions/GetAll",
            remediation="Confirm restrictions are meaningful and applied to correct rates/categories and periods."
        )
    ]

    # You can extend other sections later; keeping focus on your requested deep detail first.
    report.sections.setdefault("Legal & property baseline", [])
    report.sections.setdefault("Users, access & security", [])
    report.sections.setdefault("Guest journey & operations", [])
    report.sections.setdefault("Reporting, BI & data quality", [])
    report.sections.setdefault("Integrations & automations", [])
    report.sections.setdefault("Training, governance & ownership", [])

    # Store pulled/derived for PDF (without tokens)
    report._pulled = pulled  # type: ignore
    return report


# -----------------------------
# PDF generation (no overlap, no tables for payments)
# -----------------------------

MEWS_LOGO_SVG = "https://www.mews.com/hubfs/_Project_Phoenix/images/logo/Mews%20Logo.svg"

def _fetch_logo_drawing(max_width_mm: float = 35):
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


def _status_colour(status: str):
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

def _badge(status: str) -> str:
    col = _status_colour(status).hexval()
    return f"<font color='{col}'><b>{status}</b></font>"

def build_pdf(report: AuditReport) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=14 * mm,
        title="Mews Configuration Audit Report"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=9, leading=11))
    styles.add(ParagraphStyle(name="Tiny", parent=styles["Normal"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="H1", parent=styles["Heading1"], spaceAfter=8))
    styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], spaceBefore=10, spaceAfter=6))
    styles.add(ParagraphStyle(name="RightTiny", parent=styles["Tiny"], alignment=TA_RIGHT))

    logo = _fetch_logo_drawing()

    def header_footer(canvas, doc_):
        canvas.saveState()
        top_y = A4[1] - 12 * mm
        if logo:
            renderPDF.draw(logo, canvas, 16 * mm, top_y - (logo.height or 0))
            canvas.setFont("Helvetica-Bold", 14)
            canvas.drawString(16 * mm + 40 * mm, top_y - 3 * mm, "Mews Configuration Audit Report")
        else:
            canvas.setFont("Helvetica-Bold", 14)
            canvas.drawString(16 * mm, top_y - 3 * mm, "Mews Configuration Audit Report")

        canvas.setFont("Helvetica", 8.5)
        canvas.drawRightString(A4[0] - 16 * mm, top_y - 3 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    story: List[Any] = []

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"Generated: {report.generated_at_utc.strftime('%d/%m/%Y %H:%M UTC')} &nbsp;&nbsp;|&nbsp;&nbsp; Base URL: {report.base_url}",
        styles["Small"]
    ))
    story.append(Paragraph(
        f"Enterprise: {report.property_name or 'Unknown'} &nbsp;&nbsp;|&nbsp;&nbsp; EnterpriseId: {report.enterprise_id or 'Unknown'} &nbsp;&nbsp;|&nbsp;&nbsp; Client: {report.client_name}",
        styles["Small"]
    ))
    story.append(Spacer(1, 10))

    # Summary counts
    total = 0
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "NEEDS_INPUT": 0, "NA": 0}
    for sec_items in report.sections.values():
        for it in sec_items:
            total += 1
            k = (it.status or "").upper()
            counts[k] = counts.get(k, 0) + 1

    story.append(Paragraph("Summary", styles["H2"]))
    story.append(Paragraph(
        f"Total checks: {total} | PASS: {counts['PASS']} | WARN: {counts['WARN']} | FAIL: {counts['FAIL']} | NEEDS_INPUT: {counts['NEEDS_INPUT']} | NA: {counts['NA']}",
        styles["Small"]
    ))
    story.append(Spacer(1, 8))

    # Sections
    for sec_name, items in report.sections.items():
        if not items:
            continue
        story.append(Paragraph(sec_name, styles["H2"]))
        story.append(Spacer(1, 4))

        for it in items:
            block: List[Any] = []
            block.append(Paragraph(f"<b>{it.key}</b> &nbsp;&nbsp; {_badge(it.status)}", styles["Small"]))
            block.append(Paragraph(it.summary or "-", styles["Small"]))

            # Render details (heavy detail; wrap always; never tables for payments)
            details = it.details or {}

            if "Payments" in details and isinstance(details["Payments"], list):
                # readable multi-line payment entries
                block.append(Spacer(1, 3))
                block.append(Paragraph("<b>Payments (sample)</b>", styles["Tiny"]))
                for p in details["Payments"][:200]:
                    if not isinstance(p, dict):
                        continue
                    amt = p.get("Amount") or {}
                    line = (
                        f"PaymentId={p.get('Id')} | Type={p.get('Type')} | State={p.get('State')} | "
                        f"Currency={amt.get('Currency') or p.get('Currency') or ''} | "
                        f"Net={amt.get('NetValue')} Gross={amt.get('GrossValue')} | "
                        f"CreatedUtc={p.get('CreatedUtc')}"
                    )
                    block.append(Paragraph(_truncate(line, 220), styles["Tiny"]))
                if len(details["Payments"]) > 200:
                    block.append(Paragraph(f"…and {len(details['Payments'])-200} more", styles["Tiny"]))

            if "AccountingCategoryBreakdown" in details:
                block.append(Spacer(1, 3))
                block.append(Paragraph("<b>Accounting categories → products</b>", styles["Tiny"]))
                for cat in details["AccountingCategoryBreakdown"][:200]:
                    cname = cat.get("AccountingCategoryName")
                    cid = cat.get("AccountingCategoryId")
                    block.append(Paragraph(f"<b>{cname}</b> ({cid})", styles["Tiny"]))
                    prods = cat.get("Products", [])
                    for p in prods[:200]:
                        line = f"• {_truncate(p.get('Name') or '', 90)} ({p.get('Code') or ''}) | Active={_flag(p.get('IsActive'))} | Type={p.get('Type') or ''} | ProductId={p.get('Id')}"
                        block.append(Paragraph(line, styles["Tiny"]))
                    if len(prods) > 200:
                        block.append(Paragraph(f"• …and {len(prods)-200} more products", styles["Tiny"]))
                    block.append(Spacer(1, 2))

            if "SpacesByCategory" in details:
                block.append(Spacer(1, 3))
                block.append(Paragraph("<b>Spaces by space category</b>", styles["Tiny"]))
                for cat in details["SpacesByCategory"][:200]:
                    block.append(Paragraph(f"<b>{cat.get('ResourceCategoryName')}</b> ({cat.get('ResourceCategoryId')})", styles["Tiny"]))
                    if cat.get("Type"):
                        block.append(Paragraph(f"Type: {cat.get('Type')}", styles["Tiny"]))
                    res = cat.get("Resources", [])
                    for r in res[:300]:
                        line = f"• {_truncate(r.get('Name') or '', 90)} | Active={_flag(r.get('IsActive'))} | State={r.get('State')} | ResourceId={r.get('Id')}"
                        block.append(Paragraph(line, styles["Tiny"]))
                    if len(res) > 300:
                        block.append(Paragraph(f"• …and {len(res)-300} more spaces", styles["Tiny"]))
                    block.append(Spacer(1, 2))

            if "RateTree" in details:
                block.append(Spacer(1, 3))
                block.append(Paragraph("<b>Rates (base → derived)</b>", styles["Tiny"]))
                for node in details["RateTree"][:200]:
                    base = node.get("Base", {})
                    block.append(Paragraph(_format_rate_line(base, is_base=True), styles["Tiny"]))
                    for ch in node.get("Derived", [])[:400]:
                        block.append(Paragraph("• " + _format_rate_line(ch, is_base=False), styles["Tiny"]))
                    block.append(Spacer(1, 1))

                orphans = details.get("RateOrphans") or []
                if orphans:
                    block.append(Spacer(1, 2))
                    block.append(Paragraph("<b>Derived rates with missing base (orphans)</b>", styles["Tiny"]))
                    for r in orphans[:200]:
                        block.append(Paragraph("• " + _format_rate_line(r, is_base=False), styles["Tiny"]))

                misc = details.get("RateMisc") or []
                if misc:
                    block.append(Spacer(1, 2))
                    block.append(Paragraph("<b>Rates with no base relationship (misc)</b>", styles["Tiny"]))
                    for r in misc[:200]:
                        block.append(Paragraph("• " + _format_rate_line(r, is_base=False), styles["Tiny"]))

                groups = details.get("RateGroups") or []
                if groups:
                    block.append(Spacer(1, 2))
                    block.append(Paragraph("<b>Rate groups</b>", styles["Tiny"]))
                    for g in groups[:300]:
                        block.append(Paragraph(
                            f"• {g.get('Name')} | Active={_flag(g.get('IsActive'))} | Public={_flag(g.get('IsPublic'))} | RateGroupId={g.get('Id')}",
                            styles["Tiny"]
                        ))

            if "RestrictionLines" in details:
                block.append(Spacer(1, 3))
                block.append(Paragraph("<b>Restrictions (descriptive)</b>", styles["Tiny"]))
                for line in details["RestrictionLines"][:400]:
                    block.append(Paragraph(_truncate(line, 250), styles["Tiny"]))
                if len(details["RestrictionLines"]) > 400:
                    block.append(Paragraph(f"…and {len(details['RestrictionLines'])-400} more", styles["Tiny"]))

            block.append(Paragraph(f"<b>Source:</b> {it.source or '-'}", styles["Tiny"]))
            if it.remediation:
                block.append(Paragraph(f"<b>Remediation:</b> {it.remediation}", styles["Tiny"]))
            block.append(Spacer(1, 8))
            story.append(KeepTogether(block))

        story.append(PageBreak())

    # API call log
    story.append(Paragraph("API call log", styles["H2"]))
    for c in report.api_calls:
        line = f"{c.name} | ok={c.ok} | http={c.status_code or ''} | {c.duration_ms}ms"
        if c.error:
            line += f" | {c.error}"
        story.append(Paragraph(_truncate(line, 240), styles["Tiny"]))

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    return buf.getvalue()


def _format_rate_line(r: Dict[str, Any], is_base: bool) -> str:
    name = r.get("Name") or r.get("Id")
    bits = []
    if r.get("Code"):
        bits.append(f"Code={r.get('Code')}")
    if r.get("GroupName"):
        bits.append(f"Group={r.get('GroupName')}")
    if r.get("IsPublic") is not None:
        bits.append(f"Public={_flag(r.get('IsPublic'))}")
    if r.get("IsPrivate") is not None:
        bits.append(f"Private={_flag(r.get('IsPrivate'))}")
    if r.get("IsActive") is not None:
        bits.append(f"Active={_flag(r.get('IsActive'))}")
    if r.get("IsEnabled") is not None:
        bits.append(f"Enabled={_flag(r.get('IsEnabled'))}")
    if r.get("IsDefault") is not None:
        bits.append(f"Default={_flag(r.get('IsDefault'))}")
    if r.get("Type"):
        bits.append(f"Type={r.get('Type')}")
    if r.get("ExternalIdentifier"):
        bits.append(f"ExternalId={r.get('ExternalIdentifier')}")
    if not is_base and r.get("BaseRateId"):
        bits.append(f"BaseRateId={r.get('BaseRateId')}")
    prefix = "Base rate" if is_base else "Derived rate"
    return f"{prefix}: {name} | RateId={r.get('Id')} | " + ", ".join(bits)


# -----------------------------
# Flask app
# -----------------------------

HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mews Configuration Audit (Backend)</title>
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
  </style>
</head>
<body>
<div class="wrap">
  <h1>Mews Audit Backend</h1>
  <p class="muted">This backend is called by your GitHub Pages frontend. You can also run it here for quick testing.</p>

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
        <label>Connector base URL (optional)</label>
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
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

allowed_origins = os.environ.get("ALLOWED_ORIGINS", "https://samhmews.github.io").split(",")
allowed_origins = [o.strip() for o in allowed_origins if o.strip()]
CORS(app, resources={r"/audit": {"origins": allowed_origins}})

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
    base_url = (request.form.get("base_url") or "").strip() or os.environ.get(
        "MEWS_CONNECTOR_BASE_URL", "https://api.mews-demo.com/api/connector/v1"
    )
    base_url = base_url.rstrip("/")

    if not client_token or not access_token:
        flash("Please provide both tokens.", "error")
        return redirect(url_for("index"))

    if not base_url.lower().startswith("https://"):
        flash("Base URL must start with https://", "error")
        return redirect(url_for("index"))

    client = MewsConnectorClient(
        base_url=base_url,
        client_token=client_token,
        access_token=access_token,
        client_name=client_name,
        timeout_seconds=int(os.environ.get("HTTP_TIMEOUT_SECONDS", "35")),
    )

    report = run_full_audit(client, base_url, client_name)
    pdf_bytes = build_pdf(report)

    # best-effort clear tokens
    client_token = None
    access_token = None

    filename = f"mews-audit-{report.generated_at_utc.strftime('%Y-%m-%dT%H%M%SZ')}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
