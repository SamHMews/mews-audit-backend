"""
mews_full_audit_app.py

Backend (Flask) service:
- Accepts ClientToken + AccessToken (+ optional Client name + optional base_url) via POST /audit
- Calls Mews Connector API endpoints (demo/prod depending on base_url)
- Generates a readable, professional PDF (no overlapping, wrapped text, lists of names)
- Handles endpoints requiring filters properly (no more "Invalid Limitation" / "Please specify filters")
- Never logs or stores credentials; PDF generated in-memory and streamed back
- Rate-limited + basic security headers
- CORS restricted to GitHub Pages domain (configurable)

Run locally:
  pip install -r requirements.txt
  export SECRET_KEY="change-me"
  python mews_full_audit_app.py
"""

import io
import csv
import json
import os
import re
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
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


# -----------------------------
# Errors / models
# -----------------------------

class AuditError(Exception):
    """Safe-to-show user error."""


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
    attachments_used: List[str] = field(default_factory=list)


# -----------------------------
# Connector API client
# -----------------------------

class MewsConnectorClient:
    """
    Generic Connector client: POST {base}/{resource}/{operation}
    Always includes: ClientToken, AccessToken, and (optionally) Client.
    """

    def __init__(self, base_url: str, client_token: str, access_token: str, client_name: str = "mews-audit",
                 timeout_seconds: int = 30):
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
        # Some environments expect Client. It’s harmless if ignored.
        body["Client"] = self.client_name

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
# Upload helpers (workarounds)
# -----------------------------

def read_uploaded_csv(file_storage) -> List[Dict[str, str]]:
    if not file_storage:
        return []
    content = file_storage.read().decode("utf-8", errors="replace")
    file_storage.seek(0)
    rows = []
    reader = csv.DictReader(io.StringIO(content))
    for r in reader:
        rows.append({(k or "").strip(): (v or "").strip() for k, v in r.items()})
    return rows


def read_uploaded_json(file_storage) -> Any:
    if not file_storage:
        return None
    content = file_storage.read().decode("utf-8", errors="replace")
    file_storage.seek(0)
    try:
        return json.loads(content)
    except Exception:
        return None


def normalise_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().lower()


def safe_get(d: Dict[str, Any], path: str, default=None):
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


# -----------------------------
# City tax heuristic
# -----------------------------

CITY_TAX_HINTS = ["city tax", "tourism tax", "local tax", "occupancy tax", "tourist tax", "kurtaxe", "ortstaxe"]


def find_city_tax_products(products: List[Dict[str, Any]], categories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cat_by_id = {c.get("Id"): normalise_text(c.get("Name", "")) for c in categories if isinstance(c, dict)}
    hits: List[Dict[str, Any]] = []
    for p in products:
        name = normalise_text(p.get("Name", ""))
        code = normalise_text(p.get("Code", ""))
        cat_name = cat_by_id.get(p.get("ProductCategoryId"), "")
        hay = " ".join([name, code, cat_name])
        if any(h in hay for h in CITY_TAX_HINTS):
            hits.append(p)
    return hits


# -----------------------------
# Connector pulling (FIXED filters)
# -----------------------------

def connector_pull_all(client: MewsConnectorClient, report: AuditReport) -> Dict[str, Any]:
    """
    Pulls a broad dataset.
    IMPORTANT: Many endpoints REQUIRE filters (per your PDF log). We now supply valid filters.
    """
    pulled: Dict[str, Any] = {}
    now = datetime.now(timezone.utc)
    start_30d = now - timedelta(days=30)

    def call(resource: str, op: str, payload: Optional[Dict[str, Any]] = None, key: Optional[str] = None):
        data, res = client.post(resource, op, payload)
        report.api_calls.append(res)
        pulled[key or f"{resource}/{op}"] = data if res.ok else {"_error": res.error, "_status": res.status_code}
        return data, res

    # ---- Legal & property baseline
    call("Configuration", "Get", key="config")
    call("TaxEnvironments", "GetAll", key="tax_envs")
    call("Taxations", "GetAll", key="taxations")

    call("Products", "GetAll", key="products")

    # ProductCategories/GetAll in your log failed with "Invalid Limitation."
    call("ProductCategories", "GetAll", {"Limitation": {"Count": 1000}}, key="product_categories")

    # Rules/GetAll failed with "Invalid ServiceIds." -> require ServiceIds.
    # We fetch services first, then call rules with those ServiceIds.
    services_data, _ = call("Services", "GetAll", key="services")
    service_ids: List[str] = []
    if isinstance(services_data, dict) and isinstance(services_data.get("Services"), list):
        for s in services_data["Services"]:
            if isinstance(s, dict) and s.get("Id"):
                service_ids.append(s["Id"])

    if service_ids:
        call("Rules", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 1000}}, key="rules")
    else:
        # Keep a placeholder error so the report reflects why rules are missing
        pulled["rules"] = {"_error": "No ServiceIds available to query rules.", "_status": None}

    # Images (we'll re-call later with actual IDs)
    pulled["image_urls"] = {}

    # ---- Accounting config
    call("AccountingCategories", "GetAll", key="accounting_categories")
    call("Cashiers", "GetAll", key="cashiers")
    call("Counters", "GetAll", key="counters")

    # LedgerBalances/GetAll failed with "Invalid Limitation."
    call("LedgerBalances", "GetAll", {"Limitation": {"Count": 1000}}, key="ledger_balances")

    # ---- Payments (requires at least one filter)
    call("Payments", "GetAll", {
        "CreatedUtc": {"StartUtc": start_30d.isoformat(), "EndUtc": now.isoformat()},
        "Limitation": {"Count": 200}
    }, key="payments_200")

    call("PaymentRequests", "GetAll", {"Limitation": {"Count": 200}}, key="payment_requests_200")

    # ---- Inventory, rates, restrictions
    call("Resources", "GetAll", key="resources")

    # ResourceCategories/GetAll failed with "Invalid ServiceIds." -> include ServiceIds if possible
    if service_ids:
        call("ResourceCategories", "GetAll", {"ServiceIds": service_ids, "Limitation": {"Count": 1000}}, key="resource_categories")
    else:
        pulled["resource_categories"] = {"_error": "No ServiceIds available to query resource categories.", "_status": None}

    call("Rates", "GetAll", key="rates")

    # RateGroups/GetAll failed with "Invalid Limitation." -> add Limitation
    call("RateGroups", "GetAll", {"Limitation": {"Count": 1000}}, key="rate_groups")

    call("Restrictions", "GetAll", {"Limitation": {"Count": 1000}}, key="restrictions")

    # ---- Reservations (requires StartUtc)
    call("Reservations", "GetAll", {
        "StartUtc": start_30d.isoformat(),
        "EndUtc": now.isoformat(),
        "Limitation": {"Count": 200}
    }, key="reservations_200")

    # ReservationGroups requires UpdatedUtc or IDs
    call("ReservationGroups", "GetAll", {
        "UpdatedUtc": {"StartUtc": start_30d.isoformat(), "EndUtc": now.isoformat()},
        "Limitation": {"Count": 200}
    }, key="reservation_groups_200")

    # Customers requires filters
    call("Customers", "GetAll", {
        "UpdatedUtc": {"StartUtc": start_30d.isoformat(), "EndUtc": now.isoformat()},
        "Limitation": {"Count": 200}
    }, key="customers_200")

    # Exports/GetAll in your log required ExportIds (and would always fail unfiltered)
    # We skip calling it to avoid noisy failures and mark NEEDS_INPUT in report.
    pulled["exports_50"] = {"_error": "Connector Exports/GetAll requires ExportIds filter; skipped.", "_status": None}

    return pulled


# -----------------------------
# Section builders (now include NAMES, not just counts)
# -----------------------------

def _list_names(items: List[Dict[str, Any]], name_key: str = "Name", code_key: Optional[str] = "Code",
                max_items: int = 30) -> Dict[str, Any]:
    """
    Returns a structure suitable for PDF rendering:
    - total count
    - first N display strings
    """
    out: List[str] = []
    for it in items[:max_items]:
        if not isinstance(it, dict):
            continue
        name = (it.get(name_key) or "").strip()
        code = (it.get(code_key) or "").strip() if code_key else ""
        if code and name:
            out.append(f"{name} ({code})")
        elif name:
            out.append(name)
        elif code:
            out.append(code)
        else:
            # last resort: id
            if it.get("Id"):
                out.append(str(it["Id"]))
    return {"total": len(items), "top": out, "truncated": len(items) > max_items}


def build_legal_property_section(pulled: Dict[str, Any], report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    cfg = pulled.get("config") or {}

    if isinstance(cfg, dict) and "_error" in cfg:
        items.append(EvidenceItem(
            key="Configuration access",
            status="FAIL",
            summary="Unable to retrieve configuration via Connector API.",
            details={"error": cfg.get("_error")},
            source="Connector: Configuration/Get",
            remediation="Verify ClientToken/AccessToken/environment base URL and permissions."
        ))
        report.sections["Legal & property baseline"] = items
        return

    enterprise = cfg.get("Enterprise") or {}
    report.property_name = enterprise.get("Name", "") or cfg.get("Name", "") or ""
    report.enterprise_id = enterprise.get("Id", "") or ""

    tz = enterprise.get("TimeZoneIdentifier") or cfg.get("TimeZoneIdentifier")
    items.append(EvidenceItem(
        key="Time zone",
        status="PASS" if tz else "WARN",
        summary=tz or "Missing time zone in configuration.",
        details={"TimeZoneIdentifier": tz},
        source="Connector: Configuration/Get",
        remediation="Set enterprise/property time zone in Mews if missing."
    ))

    currencies = enterprise.get("Currencies") or cfg.get("Currencies") or []
    default_ccy = None
    if isinstance(currencies, list):
        for c in currencies:
            if isinstance(c, dict) and c.get("IsDefault"):
                default_ccy = c.get("Code")
    items.append(EvidenceItem(
        key="Default currency",
        status="PASS" if default_ccy else "WARN",
        summary=default_ccy or "Default currency not identified.",
        details={"Currencies": currencies},
        source="Connector: Configuration/Get",
        remediation="Ensure a default currency is set at enterprise level."
    ))

    pricing_mode = enterprise.get("PricingMode") or enterprise.get("Pricing") or cfg.get("PricingMode")
    manual_pm = (manual.get("pricing_mode") or "").strip()
    items.append(EvidenceItem(
        key="Pricing mode (gross/net)",
        status="PASS" if (pricing_mode or manual_pm) else "NEEDS_INPUT",
        summary=str(pricing_mode or manual_pm or "Not returned by API; confirm manually."),
        details={"PricingMode": pricing_mode},
        source="Connector: Configuration/Get" if pricing_mode else "Workaround: manual attestation",
        remediation="" if pricing_mode else "Confirm whether pricing is gross or net in the Mews UI/contract."
    ))

    tax_env = enterprise.get("TaxEnvironmentCode") or cfg.get("TaxEnvironmentCode")
    taxations = pulled.get("taxations") or {}
    taxations_list = []
    if isinstance(taxations, dict) and isinstance(taxations.get("Taxations"), list):
        taxations_list = taxations["Taxations"]

    items.append(EvidenceItem(
        key="Tax environment + VAT/GST rates",
        status="PASS" if tax_env and taxations_list else "WARN",
        summary=f"TaxEnvironmentCode={tax_env or 'Unknown'}, Taxations={len(taxations_list)}",
        details={"TaxEnvironmentCode": tax_env, "Taxations": _list_names(taxations_list, name_key="Name", code_key=None, max_items=20)},
        source="Connector: Configuration/Get + Taxations/GetAll",
        remediation="Verify tax environment selection and confirm VAT/GST rates exist & are correct."
    ))

    products = (pulled.get("products") or {}).get("Products") if isinstance(pulled.get("products"), dict) else []
    categories = (pulled.get("product_categories") or {}).get("ProductCategories") if isinstance(pulled.get("product_categories"), dict) else []
    rules = (pulled.get("rules") or {}).get("Rules") if isinstance(pulled.get("rules"), dict) else []
    products = products if isinstance(products, list) else []
    categories = categories if isinstance(categories, list) else []
    rules = rules if isinstance(rules, list) else []

    city_tax_products = find_city_tax_products(products, categories)
    city_tax_rule_hits: List[Dict[str, Any]] = []
    if city_tax_products and rules:
        ids = {p.get("Id") for p in city_tax_products if isinstance(p, dict)}
        for r in rules:
            rj = json.dumps(r, ensure_ascii=False).lower()
            if any((i or "").lower() in rj for i in ids if isinstance(i, str)):
                city_tax_rule_hits.append(r)

    items.append(EvidenceItem(
        key="City tax product + rule",
        status="PASS" if city_tax_products else "WARN",
        summary=f"City-tax-like products={len(city_tax_products)}, matching rules={len(city_tax_rule_hits)}",
        details={
            "CityTaxProducts": _list_names(city_tax_products, name_key="Name", code_key="Code", max_items=20),
            "RuleNames": _list_names(city_tax_rule_hits, name_key="Name", code_key=None, max_items=10),
            "Heuristic": "Matched by product/category name/code containing city/tourism/occupancy tax keywords."
        },
        source="Connector: Products/GetAll + ProductCategories/GetAll + Rules/GetAll",
        remediation="If missing/incorrect: standardise city tax product naming/codes or use a dedicated category; ensure a rule applies it consistently."
    ))

    legal_env = enterprise.get("LegalEnvironmentCode") or cfg.get("LegalEnvironmentCode")
    items.append(EvidenceItem(
        key="Fiscalisation (where relevant)",
        status="NEEDS_INPUT",
        summary=f"LegalEnvironmentCode={legal_env or 'Unknown'}. Requires manual confirmation.",
        details={
            "FiscalisationRequired": (manual.get("fiscalisation_required") or "").strip() or "Unknown",
            "FiscalisationConfigured": (manual.get("fiscalisation_configured") or "").strip() or "Unknown",
        },
        source="Workaround: manual attestation",
        remediation="Confirm fiscalisation requirement for the jurisdiction and validate fiscalisation settings/provider in the Mews UI."
    ))

    addr = enterprise.get("Address") or cfg.get("Address") or {}
    addr_ok = isinstance(addr, dict) and bool(addr.get("City")) and bool(addr.get("CountryCode") or addr.get("Country"))
    items.append(EvidenceItem(
        key="Property address",
        status="PASS" if addr_ok else "WARN",
        summary="Address present" if addr_ok else "Address incomplete or missing fields.",
        details={"Address": addr},
        source="Connector: Configuration/Get",
        remediation="Fill street/city/postcode/country for invoices, integrations, and compliance."
    ))

    logo_id = enterprise.get("LogoImageId") or cfg.get("LogoImageId")
    cover_id = enterprise.get("CoverImageId") or cfg.get("CoverImageId")
    items.append(EvidenceItem(
        key="Branding (logo/cover IDs)",
        status="PASS" if (logo_id or cover_id) else "WARN",
        summary=f"LogoImageId={'present' if logo_id else 'none'}, CoverImageId={'present' if cover_id else 'none'}",
        details={"LogoImageId": logo_id, "CoverImageId": cover_id},
        source="Connector: Configuration/Get",
        remediation="Upload logo/cover in Mews for consistent guest-facing surfaces."
    ))

    missing_legal = []
    for k in ("vat_number", "company_reg_number", "company_name"):
        if not (manual.get(k) or "").strip():
            missing_legal.append(k)
    items.append(EvidenceItem(
        key="Legal identifiers (VAT/company reg/etc.)",
        status="NEEDS_INPUT" if missing_legal else "PASS",
        summary=("Missing: " + ", ".join(missing_legal)) if missing_legal else "Provided via manual fields.",
        details={
            "VATNumber": (manual.get("vat_number") or "").strip(),
            "CompanyRegistrationNumber": (manual.get("company_reg_number") or "").strip(),
            "InvoiceHeaderCompanyName": (manual.get("company_name") or "").strip(),
        },
        source="Workaround: manual input",
        remediation="Populate missing identifiers and validate against contracts and invoice requirements."
    ))

    report.sections["Legal & property baseline"] = items


def build_inventory_rates_section(pulled: Dict[str, Any], report: AuditReport):
    items: List[EvidenceItem] = []

    rc = (pulled.get("resource_categories") or {}).get("ResourceCategories") if isinstance(pulled.get("resource_categories"), dict) else []
    rs = (pulled.get("resources") or {}).get("Resources") if isinstance(pulled.get("resources"), dict) else []
    rates = (pulled.get("rates") or {}).get("Rates") if isinstance(pulled.get("rates"), dict) else []
    groups = (pulled.get("rate_groups") or {}).get("RateGroups") if isinstance(pulled.get("rate_groups"), dict) else []
    restrictions = (pulled.get("restrictions") or {}).get("Restrictions") if isinstance(pulled.get("restrictions"), dict) else []

    rc = rc if isinstance(rc, list) else []
    rs = rs if isinstance(rs, list) else []
    rates = rates if isinstance(rates, list) else []
    groups = groups if isinstance(groups, list) else []
    restrictions = restrictions if isinstance(restrictions, list) else []

    items.append(EvidenceItem(
        key="Space categories/types",
        status="PASS" if rc else "WARN",
        summary=f"Resource categories={len(rc)}, resources={len(rs)}",
        details={
            "ResourceCategories": _list_names(rc, name_key="Name", code_key="Code", max_items=30),
            "Resources": _list_names(rs, name_key="Name", code_key="Code", max_items=30)
        },
        source="Connector: ResourceCategories/GetAll + Resources/GetAll",
        remediation="Verify inventory model supports dorm beds/long-stay/multi-room setups as required."
    ))

    items.append(EvidenceItem(
        key="Rates",
        status="PASS" if rates else "WARN",
        summary=f"Rates={len(rates)}",
        details={"Rates": _list_names(rates, name_key="Name", code_key="Code", max_items=40)},
        source="Connector: Rates/GetAll",
        remediation="Validate base rates, derivations and packages (e.g., breakfast as product vs included)."
    ))

    items.append(EvidenceItem(
        key="Rate groups",
        status="PASS" if groups else "WARN",
        summary=f"Rate groups={len(groups)}",
        details={"RateGroups": _list_names(groups, name_key="Name", code_key="Code", max_items=40)},
        source="Connector: RateGroups/GetAll",
        remediation="Ensure rate groups align to channel/corporate strategy and are used consistently."
    ))

    # Restrictions: list names if available; otherwise show IDs + key flags
    restriction_names = []
    for r in restrictions[:40]:
        if not isinstance(r, dict):
            continue
        name = r.get("Name") or r.get("Id")
        # Try to surface a couple of common fields if present
        extra_bits = []
        for k in ("MinLengthOfStay", "MaxLengthOfStay", "ClosedToArrival", "ClosedToDeparture"):
            if k in r and r.get(k) is not None:
                extra_bits.append(f"{k}={r.get(k)}")
        if extra_bits:
            restriction_names.append(f"{name} — " + ", ".join(extra_bits))
        else:
            restriction_names.append(str(name))

    items.append(EvidenceItem(
        key="Restrictions & seasonality",
        status="PASS" if restrictions else "WARN",
        summary=f"Restrictions={len(restrictions)}",
        details={
            "RestrictionsTop": restriction_names,
            "Truncated": len(restrictions) > 40
        },
        source="Connector: Restrictions/GetAll",
        remediation="Validate LOS/CTA/CTD consistency across calendars and channels."
    ))

    items.append(EvidenceItem(
        key="Channel manager / CRS mapping",
        status="NEEDS_INPUT",
        summary="Not available via Connector. Use Channel Manager API or upload mapping export.",
        details={},
        source="Workaround: Channel Manager API / export",
        remediation="Pull mapping via Channel Manager API and cross-check IDs against Connector resources/rates."
    ))

    report.sections["Inventory, rates & revenue structure"] = items


def build_accounting_section(pulled: Dict[str, Any], report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    cats = (pulled.get("accounting_categories") or {}).get("AccountingCategories") if isinstance(pulled.get("accounting_categories"), dict) else []
    cashiers = (pulled.get("cashiers") or {}).get("Cashiers") if isinstance(pulled.get("cashiers"), dict) else []
    counters = (pulled.get("counters") or {}).get("Counters") if isinstance(pulled.get("counters"), dict) else []
    ledgers = (pulled.get("ledger_balances") or {}).get("LedgerBalances") if isinstance(pulled.get("ledger_balances"), dict) else []

    cats = cats if isinstance(cats, list) else []
    cashiers = cashiers if isinstance(cashiers, list) else []
    counters = counters if isinstance(counters, list) else []
    ledgers = ledgers if isinstance(ledgers, list) else []

    items.append(EvidenceItem(
        key="Accounting categories",
        status="PASS" if cats else "WARN",
        summary=f"Categories={len(cats)}",
        details={"AccountingCategories": _list_names(cats, name_key="Name", code_key="Code", max_items=40)},
        source="Connector: AccountingCategories/GetAll",
        remediation="Ensure separate categories for revenue, payments, taxes, deposits, fees, city tax."
    ))

    items.append(EvidenceItem(
        key="Cashiers",
        status="PASS" if cashiers else "WARN",
        summary=f"Cashiers={len(cashiers)}",
        details={"Cashiers": _list_names(cashiers, name_key="Name", code_key=None, max_items=40)},
        source="Connector: Cashiers/GetAll",
        remediation="If cash is accepted, ensure cashiers are assigned and controlled."
    ))

    items.append(EvidenceItem(
        key="Counters (invoice/bill sequences)",
        status="PASS" if counters else "WARN",
        summary=f"Counters={len(counters)}",
        details={"Counters": _list_names(counters, name_key="Name", code_key=None, max_items=40)},
        source="Connector: Counters/GetAll",
        remediation="Verify numbering prefixes and legal sequencing rules by jurisdiction."
    ))

    items.append(EvidenceItem(
        key="Payment type → accounting category mapping",
        status="NEEDS_INPUT",
        summary="No direct mapping table in Connector. Provide mapping notes or infer from real transactions.",
        details={"MappingNotes": (manual.get("payment_mapping") or "").strip()},
        source="Workaround: manual mapping + inference",
        remediation="Provide mapping of terminals/gateways/external payment types to accounting categories."
    ))

    items.append(EvidenceItem(
        key="Ledger balances (evidence)",
        status="WARN" if not ledgers else "PASS",
        summary=f"Ledger balances retrieved={len(ledgers)}",
        details={"LedgerBalances": _list_names(ledgers, name_key="Name", code_key=None, max_items=40)},
        source="Connector: LedgerBalances/GetAll",
        remediation="Define target ledger model (guest/deposit/AR/TA) and validate accounting export flows."
    ))

    report.sections["Accounting configuration"] = items


def build_users_security_section(report: AuditReport, uploads: Dict[str, Any], manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    user_rows = uploads.get("users_csv_rows") or []
    if user_rows:
        active = [r for r in user_rows if normalise_text(r.get("Status", r.get("status", ""))) in ("active", "enabled", "true", "yes")]
        shared = [r for r in user_rows if "shared" in normalise_text(r.get("Email", r.get("email", ""))) or "generic" in normalise_text(r.get("Email", r.get("email", "")))]
        items.append(EvidenceItem(
            key="User list & roles",
            status="PASS",
            summary=f"Users={len(user_rows)}, active={len(active)}, possible shared/generic={len(shared)}",
            details={"UsersTop": user_rows[:25], "Truncated": len(user_rows) > 25},
            source="Workaround: uploaded CSV",
            remediation="Remove shared logins; ensure roles match responsibilities; map departments where used."
        ))
    else:
        items.append(EvidenceItem(
            key="User list & roles",
            status="NEEDS_INPUT",
            summary="Connector doesn’t expose users/roles. Upload a users CSV export.",
            details={"ExpectedColumns": ["Email", "Name", "Role", "Department", "Status"]},
            source="Workaround: upload CSV",
            remediation="Export users from Mews UI or IdP and upload."
        ))

    items.append(EvidenceItem(
        key="2FA / passkeys adoption",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Requires IdP policy evidence or admin attestation.",
        details={"MFAAdoption": (manual.get("mfa_adoption") or "").strip()},
        source="Workaround: IdP policy / attestation",
        remediation="Confirm MFA/passkey enforcement for admin/back-office users in IdP."
    ))

    items.append(EvidenceItem(
        key="SSO / SCIM configuration",
        status="NEEDS_INPUT",
        summary=f"SSO enforced={(manual.get('sso_enforced') or 'Unknown').strip()}, SCIM used={(manual.get('scim_used') or 'Unknown').strip()}",
        details={},
        source="Workaround: IdP config / attestation",
        remediation="Confirm SSO enforcement; validate SCIM provisioning mappings."
    ))

    items.append(EvidenceItem(
        key="Auditability (editable history windows)",
        status="NA",
        summary="Not rendered separately here; available in Configuration/Get fields (OEHW/AEHW).",
        details={},
        source="Connector: Configuration/Get",
        remediation=""
    ))

    report.sections["Users, access & security"] = items


def build_payments_section(pulled: Dict[str, Any], report: AuditReport, uploads: Dict[str, Any], manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    payments = (pulled.get("payments_200") or {}).get("Payments") if isinstance(pulled.get("payments_200"), dict) else []
    payments = payments if isinstance(payments, list) else []

    # Show a few payment identifiers if present
    pay_top = []
    for p in payments[:25]:
        if not isinstance(p, dict):
            continue
        pay_top.append({
            "Id": p.get("Id"),
            "Type": p.get("Type"),
            "Currency": p.get("Currency"),
            "Amount": p.get("Amount"),
            "CreatedUtc": p.get("CreatedUtc"),
            "State": p.get("State"),
        })

    items.append(EvidenceItem(
        key="Payments (last 30 days sample)",
        status="PASS" if payments else "WARN",
        summary=f"Payments retrieved={len(payments)}",
        details={"PaymentsTop": pay_top, "Truncated": len(payments) > 25},
        source="Connector: Payments/GetAll (CreatedUtc window)",
        remediation="If unexpectedly empty, verify permissions or adjust date window."
    ))

    items.append(EvidenceItem(
        key="KYC & Mews Payments onboarding status",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide attestation or upload evidence.",
        details={"KYCStatus": (manual.get("kyc_status") or "").strip()},
        source="Workaround: manual evidence",
        remediation="Confirm KYC status, payout currencies, and fee behaviour in Mews Payments UI."
    ))

    payout_json = uploads.get("payouts_json")
    if payout_json:
        items.append(EvidenceItem(
            key="Payouts & fees evidence",
            status="PASS",
            summary="Payout/fee statement provided via upload.",
            details={"StatementPreview": str(payout_json)[:1200]},
            source="Workaround: uploaded payout statement",
            remediation="Align payouts/fees to GL mapping; validate against accounting export."
        ))
    else:
        items.append(EvidenceItem(
            key="Payouts & fees reconciliation",
            status="NEEDS_INPUT",
            summary="Not available in Connector here. Upload payout/fee statements.",
            details={},
            source="Workaround: upload statement",
            remediation="Upload payout/fee statements to reconcile to GL and validate report alignment."
        ))

    report.sections["Payments setup & reconciliation"] = items


def build_guest_ops_section(pulled: Dict[str, Any], report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    res = (pulled.get("reservations_200") or {}).get("Reservations") if isinstance(pulled.get("reservations_200"), dict) else []
    res = res if isinstance(res, list) else []

    res_top = []
    for r in res[:25]:
        if not isinstance(r, dict):
            continue
        res_top.append({
            "Id": r.get("Id"),
            "StartUtc": r.get("StartUtc"),
            "EndUtc": r.get("EndUtc"),
            "State": r.get("State"),
            "Channel": r.get("Channel") or r.get("Origin") or r.get("Source"),
        })

    items.append(EvidenceItem(
        key="Reservations (last 30 days sample)",
        status="PASS" if res else "WARN",
        summary=f"Reservations retrieved={len(res)}",
        details={"ReservationsTop": res_top, "Truncated": len(res) > 25},
        source="Connector: Reservations/GetAll (StartUtc/EndUtc window)",
        remediation="If unexpectedly empty, adjust date window or verify permissions."
    ))

    items.append(EvidenceItem(
        key="Online check-in / guest comms templates",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Requires manual verification.",
        details={"OCIEnabled": (manual.get("oci_enabled") or "").strip()},
        source="Workaround: manual evidence",
        remediation="Confirm OCI settings, templates, merge tags, and brand alignment in the Mews UI."
    ))

    items.append(EvidenceItem(
        key="Housekeeping & maintenance configuration",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide evidence / integration details.",
        details={},
        source="Workaround: manual evidence",
        remediation="Validate housekeeping boards/integrations and automations tied to status changes."
    ))

    report.sections["Guest journey & operations"] = items


def build_reporting_section(report: AuditReport, uploads: Dict[str, Any], manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    bi_csv = uploads.get("bi_csv_rows") or []
    if bi_csv:
        items.append(EvidenceItem(
            key="Core reports / BI exports consistency",
            status="PASS",
            summary=f"BI export rows provided={len(bi_csv)}",
            details={"BIExportTop": bi_csv[:30], "Truncated": len(bi_csv) > 30},
            source="Workaround: uploaded BI export CSV",
            remediation="Compare totals vs operational data; validate cut-offs and totals mode."
        ))
    else:
        items.append(EvidenceItem(
            key="Core reports / BI exports",
            status="NEEDS_INPUT",
            summary="Connector doesn’t provide report output. Upload exports for reconciliation.",
            details={},
            source="Workaround: upload report exports",
            remediation="Upload Reservations/Manager/Accounting/BI exports to validate consistency."
        ))

    items.append(EvidenceItem(
        key="Rebates / corrections / write-offs patterns",
        status="NEEDS_INPUT",
        summary="Not a direct API metric. Provide exports/logs or notes.",
        details={"Notes": (manual.get("error_patterns_notes") or "").strip()},
        source="Workaround: scan exports + manual notes",
        remediation="If systematic, address root config/process issues to reduce manual corrections."
    ))

    report.sections["Reporting, BI & data quality"] = items


def build_integrations_section(pulled: Dict[str, Any], report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    items.append(EvidenceItem(
        key="Marketplace stack (CHM/POS/RMS/etc.)",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide integration inventory and mapping evidence.",
        details={"Integrations": (manual.get("integrations_list") or "").strip()},
        source="Workaround: manual inventory",
        remediation="Document mappings; check for double posting, gaps, broken mappings."
    ))

    # Exports skipped on purpose (needs ExportIds)
    exports_err = pulled.get("exports_50", {}).get("_error") if isinstance(pulled.get("exports_50"), dict) else None
    items.append(EvidenceItem(
        key="Accounting/data exports",
        status="NEEDS_INPUT",
        summary=exports_err or "Connector exports require IDs; provide export IDs or evidence from target system.",
        details={},
        source="Workaround: provide ExportIds or external logs",
        remediation="Provide export IDs to query or confirm export cadence/failures in target system logs."
    ))

    items.append(EvidenceItem(
        key="Automation tooling robustness",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide workflow inventory + monitoring evidence.",
        details={"AutomationNotes": (manual.get("automation_notes") or "").strip()},
        source="Workaround: manual inventory",
        remediation="Ensure workflows are documented, monitored, and resilient with alerting."
    ))

    report.sections["Integrations & automations"] = items


def build_training_section(report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    items.append(EvidenceItem(
        key="Training coverage (Mews University completion)",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide completion export or attestation.",
        details={"TrainingEvidence": (manual.get("training_evidence") or "").strip()},
        source="Workaround: export/attestation",
        remediation="Align training completion with responsibilities (FO/Finance/Revenue)."
    ))
    items.append(EvidenceItem(
        key="Process ownership & governance",
        status="NEEDS_INPUT",
        summary="Provide internal champion and change governance process.",
        details={
            "Owner": (manual.get("process_owner") or "").strip(),
            "Governance": (manual.get("governance_notes") or "").strip(),
        },
        source="Workaround: manual input",
        remediation="Define change governance for Mews configuration and integrations."
    ))
    items.append(EvidenceItem(
        key="Artifacts (SOPs, playbooks, governance rules)",
        status="NEEDS_INPUT",
        summary="Provide links/uploads for SOPs and playbooks.",
        details={"Artifacts": (manual.get("artifacts_links") or "").strip()},
        source="Workaround: links/uploads",
        remediation="Ensure SOPs match actual configuration and practice."
    ))
    report.sections["Training, governance & ownership"] = items


def run_full_audit(client: MewsConnectorClient, base_url: str, client_name: str,
                   uploads: Dict[str, Any], manual: Dict[str, Any]) -> AuditReport:
    report = AuditReport(
        generated_at_utc=datetime.now(timezone.utc),
        base_url=base_url,
        client_name=client_name,
        attachments_used=uploads.get("attachments_used", []),
    )

    pulled = connector_pull_all(client, report)

    # Fetch image URLs if IDs exist (and only if IDs exist)
    cfg = pulled.get("config") if isinstance(pulled.get("config"), dict) else {}
    if isinstance(cfg, dict) and "_error" not in cfg:
        enterprise = cfg.get("Enterprise") or {}
        ids = []
        for k in ("LogoImageId", "CoverImageId"):
            v = enterprise.get(k) or cfg.get(k)
            if v:
                ids.append(v)
        if ids:
            data, res = client.post("Images", "GetUrls", {"ImageIds": ids})
            report.api_calls.append(res)
            pulled["image_urls"] = data if res.ok else {"_error": res.error, "_status": res.status_code}

    # Build sections
    build_legal_property_section(pulled, report, manual)
    build_users_security_section(report, uploads, manual)
    build_accounting_section(pulled, report, manual)
    build_payments_section(pulled, report, uploads, manual)
    build_inventory_rates_section(pulled, report)
    build_guest_ops_section(pulled, report, manual)
    build_reporting_section(report, uploads, manual)
    build_integrations_section(pulled, report, manual)
    build_training_section(report, manual)

    return report


# -----------------------------
# PDF generation (READABLE)
# -----------------------------

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
    return f"<font color='{_status_colour(status).hexval()}'><b>{status}</b></font>"


def _wrap_kv_table(kv: List[Tuple[str, str]], col_widths: List[int]) -> Table:
    rows = [[k, v] for k, v in kv]
    t = Table(rows, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def build_pdf(report: AuditReport) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=14 * mm,
        title="Mews Configuration Audit Report"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=9, leading=11))
    styles.add(ParagraphStyle(name="Tiny", parent=styles["Normal"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="H1", parent=styles["Heading1"], spaceAfter=8))
    styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], spaceBefore=10, spaceAfter=6))

    story: List[Any] = []

    # Header
    story.append(Paragraph("Mews Configuration Audit Report", styles["H1"]))
    story.append(Paragraph(
        f"Generated: {report.generated_at_utc.strftime('%d/%m/%Y %H:%M UTC')} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Base URL: {report.base_url}",
        styles["Small"]
    ))
    story.append(Paragraph(
        f"Enterprise: {report.property_name or 'Unknown'} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"EnterpriseId: {report.enterprise_id or 'Unknown'} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Client: {report.client_name}",
        styles["Small"]
    ))
    story.append(Spacer(1, 10))

    # Summary
    total = 0
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "NEEDS_INPUT": 0, "NA": 0}
    for sec_items in report.sections.values():
        for it in sec_items:
            total += 1
            k = (it.status or "").upper()
            counts[k] = counts.get(k, 0) + 1

    story.append(Paragraph("Summary", styles["H2"]))
    summary_tbl = _wrap_kv_table([
        ("Total checks", str(total)),
        ("PASS", str(counts["PASS"])),
        ("WARN", str(counts["WARN"])),
        ("FAIL", str(counts["FAIL"])),
        ("NEEDS_INPUT", str(counts["NEEDS_INPUT"])),
        ("NA", str(counts["NA"])),
    ], col_widths=[45 * mm, 120 * mm])
    story.append(summary_tbl)
    story.append(Spacer(1, 10))

    if report.attachments_used:
        story.append(Paragraph("Uploads used", styles["H2"]))
        story.append(Paragraph(", ".join(report.attachments_used), styles["Small"]))
        story.append(Spacer(1, 10))

    # Sections
    for sec_name, items in report.sections.items():
        story.append(Paragraph(sec_name, styles["H2"]))
        story.append(Spacer(1, 6))

        for it in items:
            block: List[Any] = []

            block.append(Paragraph(f"<b>{it.key}</b> &nbsp;&nbsp; {_badge(it.status)}", styles["Small"]))
            block.append(Paragraph(it.summary or "-", styles["Small"]))

            # Render details in a readable way
            details = it.details or {}
            if details:
                # If we have list-of-names structures, print them as bullets
                # Common shapes:
                #   {"Rates": {"total":..., "top":[...], "truncated":...}}
                #   {"RestrictionsTop":[...]}
                def render_name_list(title: str, obj: Any):
                    if isinstance(obj, dict) and "top" in obj and "total" in obj:
                        top = obj.get("top") or []
                        total_ = obj.get("total") or 0
                        trunc = obj.get("truncated")
                        block.append(Spacer(1, 3))
                        block.append(Paragraph(f"<b>{title}</b> (showing {min(len(top), 999)} of {total_})", styles["Tiny"]))
                        for s in top:
                            block.append(Paragraph(f"• {str(s)}", styles["Tiny"]))
                        if trunc:
                            block.append(Paragraph(f"• …and {total_ - len(top)} more", styles["Tiny"]))

                # Known keys we want to render nicely
                for k in ("Rates", "RateGroups", "ResourceCategories", "Resources", "AccountingCategories",
                          "Cashiers", "Counters", "Taxations", "CityTaxProducts", "RuleNames"):
                    if k in details:
                        render_name_list(k, details[k])

                if "RestrictionsTop" in details and isinstance(details["RestrictionsTop"], list):
                    block.append(Spacer(1, 3))
                    block.append(Paragraph("<b>Restrictions</b> (top items)", styles["Tiny"]))
                    for s in details["RestrictionsTop"][:40]:
                        block.append(Paragraph(f"• {str(s)}", styles["Tiny"]))
                    if details.get("Truncated"):
                        block.append(Paragraph("• …and more", styles["Tiny"]))

                # For generic dict details (like Address), show compact KV
                if "Address" in details and isinstance(details["Address"], dict):
                    addr = details["Address"]
                    kv = []
                    for kk in ("Street", "City", "PostalCode", "PostCode", "CountryCode", "Country"):
                        if kk in addr and addr.get(kk):
                            kv.append((kk, str(addr.get(kk))))
                    if kv:
                        block.append(Spacer(1, 3))
                        block.append(Paragraph("<b>Address</b>", styles["Tiny"]))
                        block.append(_wrap_kv_table(kv, [35 * mm, 130 * mm]))

                # If we have "PaymentsTop"/"ReservationsTop" tables, show a small table
                for table_key, cols in [
                    ("PaymentsTop", ["Id", "Type", "Currency", "Amount", "CreatedUtc", "State"]),
                    ("ReservationsTop", ["Id", "StartUtc", "EndUtc", "State", "Channel"])
                ]:
                    if table_key in details and isinstance(details[table_key], list) and details[table_key]:
                        rows = [cols]
                        for row in details[table_key][:25]:
                            rows.append([str(row.get(c, ""))[:80] for c in cols])
                        t = Table(rows, colWidths=[25*mm, 22*mm, 18*mm, 18*mm, 45*mm, 25*mm] if table_key=="PaymentsTop"
                                  else [30*mm, 40*mm, 40*mm, 25*mm, 30*mm],
                                  hAlign="LEFT")
                        t.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                            ("FONTSIZE", (0, 0), (-1, -1), 7),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("PADDING", (0, 0), (-1, -1), 3),
                        ]))
                        block.append(Spacer(1, 3))
                        block.append(t)
                        if details.get("Truncated"):
                            block.append(Paragraph("Showing top items only.", styles["Tiny"]))

            # Source + remediation (wrapped)
            block.append(Paragraph(f"<b>Source:</b> {it.source or '-'}", styles["Tiny"]))
            if it.remediation:
                block.append(Paragraph(f"<b>Remediation:</b> {it.remediation}", styles["Tiny"]))

            block.append(Spacer(1, 8))
            story.append(KeepTogether(block))

        story.append(PageBreak())

    # API call log (kept, but readable)
    story.append(Paragraph("API call log", styles["H2"]))
    log_rows = [["Operation", "OK", "HTTP", "ms", "Error"]]
    for c in report.api_calls:
        log_rows.append([c.name, "Yes" if c.ok else "No", str(c.status_code or ""), str(c.duration_ms), c.error or ""])
    log_tbl = Table(log_rows, colWidths=[55*mm, 10*mm, 12*mm, 12*mm, 80*mm], hAlign="LEFT")
    log_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(log_tbl)

    doc.build(story)
    return buf.getvalue()


# -----------------------------
# Web UI (your backend can be headless; UI here is optional)
# -----------------------------

HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mews Configuration Audit (Backend)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{font-family:system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin:0; background:#0b1220; color:#e8eefc;}
    .wrap{max-width:920px; margin:0 auto; padding:24px;}
    .card{background:#111a2e; border:1px solid #1f2b4a; border-radius:14px; padding:18px; margin:14px 0;}
    label{display:block; font-weight:600; margin:10px 0 6px;}
    input, textarea{width:100%; padding:10px; border-radius:10px; border:1px solid #2a3a63; background:#0c1426; color:#e8eefc;}
    input[type=file]{padding:8px;}
    .row{display:grid; grid-template-columns: 1fr 1fr; gap:14px;}
    .btn{display:inline-block; padding:12px 14px; border-radius:12px; border:0; background:#3b82f6; color:white; font-weight:700; cursor:pointer;}
    .muted{color:#a9b7d6; font-size:13px; line-height:1.35;}
    .flash{padding:10px 12px; border-radius:12px; margin:10px 0;}
    .flash.error{background:#3b1420; border:1px solid #7a2034;}
    .flash.ok{background:#13311d; border:1px solid #1e5a35;}
    details{margin-top:10px;}
    summary{cursor:pointer; color:#cfe0ff;}
  </style>
</head>
<body>
<div class="wrap">
  <h1>Mews Configuration Audit (Backend)</h1>
  <p class="muted">This backend is intended to be called from your GitHub Pages frontend. You can also run it directly here for testing.</p>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="flash {{ 'error' if category=='error' else 'ok' }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  <form action="{{ url_for('audit') }}" method="post" enctype="multipart/form-data" class="card">
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

    <details>
      <summary>Optional uploads</summary>
      <div class="row">
        <div>
          <label>Users export CSV</label>
          <input name="users_csv" type="file" accept=".csv">
        </div>
        <div>
          <label>BI/Report export CSV</label>
          <input name="bi_csv" type="file" accept=".csv">
        </div>
      </div>
      <div class="row">
        <div>
          <label>Payout/Fee statement JSON</label>
          <input name="payouts_json" type="file" accept=".json">
        </div>
        <div></div>
      </div>
    </details>

    <details>
      <summary>Optional attestations</summary>
      <div class="row">
        <div><input name="pricing_mode" placeholder="Pricing mode (gross/net)"></div>
        <div><input name="kyc_status" placeholder="KYC status"></div>
      </div>
      <div class="row">
        <div><input name="fiscalisation_required" placeholder="Fiscalisation required?"></div>
        <div><input name="fiscalisation_configured" placeholder="Fiscalisation configured?"></div>
      </div>
      <div class="row">
        <div><input name="vat_number" placeholder="VAT number"></div>
        <div><input name="company_reg_number" placeholder="Company reg number"></div>
      </div>
      <input name="company_name" placeholder="Company name (invoice header)">
      <textarea name="payment_mapping" rows="3" placeholder="Payment mapping notes"></textarea>
      <textarea name="integrations_list" rows="3" placeholder="Integrations list"></textarea>
      <textarea name="automation_notes" rows="3" placeholder="Automation notes"></textarea>
      <textarea name="training_evidence" rows="3" placeholder="Training evidence"></textarea>
      <input name="process_owner" placeholder="Process owner">
      <textarea name="governance_notes" rows="3" placeholder="Governance notes"></textarea>
      <textarea name="artifacts_links" rows="3" placeholder="Artifacts links/notes"></textarea>
      <textarea name="error_patterns_notes" rows="3" placeholder="Error patterns notes"></textarea>
      <input name="oci_enabled" placeholder="OCI enabled / comms notes">
      <div class="row">
        <input name="sso_enforced" placeholder="SSO enforced?">
        <input name="scim_used" placeholder="SCIM used?">
      </div>
      <input name="mfa_adoption" placeholder="MFA adoption notes">
    </details>

    <div style="margin-top:14px;">
      <button class="btn" type="submit">Generate PDF audit</button>
    </div>
  </form>
</div>
</body>
</html>
"""


# -----------------------------
# Flask app
# -----------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# CORS: allow only your GitHub Pages domain by default
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "https://samhmews.github.io").split(",")
allowed_origins = [o.strip() for o in allowed_origins if o.strip()]
CORS(app, resources={r"/audit": {"origins": allowed_origins}})

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["30 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


@app.after_request
def add_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


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

    if not client_token or not access_token:
        flash("Please provide both Client token and Access token.", "error")
        return redirect(url_for("index"))

    if not base_url.lower().startswith("https://"):
        flash("Base URL must start with https://", "error")
        return redirect(url_for("index"))

    # Uploads (in memory only)
    attachments_used = []
    users_csv_rows = []
    bi_csv_rows = []
    payouts_json = None

    if request.files.get("users_csv") and request.files["users_csv"].filename:
        users_csv_rows = read_uploaded_csv(request.files["users_csv"])
        attachments_used.append(f"users_csv: {request.files['users_csv'].filename}")

    if request.files.get("bi_csv") and request.files["bi_csv"].filename:
        bi_csv_rows = read_uploaded_csv(request.files["bi_csv"])
        attachments_used.append(f"bi_csv: {request.files['bi_csv'].filename}")

    if request.files.get("payouts_json") and request.files["payouts_json"].filename:
        payouts_json = read_uploaded_json(request.files["payouts_json"])
        attachments_used.append(f"payouts_json: {request.files['payouts_json'].filename}")

    uploads = {
        "attachments_used": attachments_used,
        "users_csv_rows": users_csv_rows,
        "bi_csv_rows": bi_csv_rows,
        "payouts_json": payouts_json,
    }

    manual = {k: (request.form.get(k) or "") for k in request.form.keys()}

    try:
        client = MewsConnectorClient(
            base_url=base_url,
            client_token=client_token,
            access_token=access_token,
            client_name=client_name,
            timeout_seconds=int(os.environ.get("HTTP_TIMEOUT_SECONDS", "30")),
        )

        report = run_full_audit(client, base_url, client_name, uploads, manual)
        pdf_bytes = build_pdf(report)

        # best-effort clear credentials
        client_token = None
        access_token = None

        filename = f"mews-audit-{report.generated_at_utc.strftime('%Y-%m-%dT%H%M%SZ')}.pdf"
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )

    except AuditError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception:
        flash("Unexpected error while generating the audit. Please try again.", "error")
        return redirect(url_for("index"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
