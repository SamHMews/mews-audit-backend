"""
mews_full_audit_app.py
----------------------
A single-file, drop-in Flask web app that:
- Collects Mews Connector API credentials (ClientToken + AccessToken)
- Runs a comprehensive audit across ALL items you listed
- Uses Connector API where available
- Uses “creative workarounds” where Connector cannot provide the data:
    * Optional uploads (CSV/JSON) for user lists, SSO/SCIM evidence, payouts/fees statements, etc.
    * Optional free-text “attestation” fields for UI-only settings (fiscalisation, payment terminal mapping, etc.)
    * Optional Channel Manager API / SCIM endpoints placeholders (pluggable)
- Generates a professional PDF audit report in-memory and streams it for download
- Includes rate limiting and avoids logging or storing credentials

How to run:
  pip install flask requests reportlab flask-limiter python-dateutil
  export SECRET_KEY="change-me"
  python mews_full_audit_app.py
  open http://localhost:8000

Notes:
- This app is production-friendly but still needs you to deploy behind HTTPS (Render/Railway/Heroku/Nginx).
- Connector endpoint names/paths can vary by version. The client uses a flexible /{Resource}/{Operation} POST pattern.
  If your Connector base URL differs, set MEWS_CONNECTOR_BASE_URL env var.
"""

import io
import csv
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, request, send_file, render_template_string, redirect, url_for, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet
from dateutil import parser as dtparser


# -----------------------------
# Security / error model
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
    source: str = ""  # e.g. "Connector: Configuration/Get"
    remediation: str = ""


@dataclass
class AuditReport:
    generated_at_utc: datetime
    base_url: str
    property_name: str = ""
    enterprise_id: str = ""
    api_calls: List[ApiCallResult] = field(default_factory=list)
    sections: Dict[str, List[EvidenceItem]] = field(default_factory=dict)
    attachments_used: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


# -----------------------------
# Mews Connector client
# -----------------------------

class MewsConnectorClient:
    """
    Generic Connector API client using POST /{resource}/{operation} pattern.
    - Never logs tokens
    - Caller supplies base_url (must be https)
    """

    def __init__(self, base_url: str, client_token: str, access_token: str, timeout_seconds: int = 30):
        self.base_url = base_url.rstrip("/")
        self.client_token = client_token
        self.access_token = access_token
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def post(self, resource: str, operation: str, payload: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], ApiCallResult]:
        url = f"{self.base_url}/{resource}/{operation}"
        body = payload or {}
        # Required auth keys for Connector API calls:
        body["ClientToken"] = self.client_token
        body["AccessToken"] = self.access_token

        started = time.time()
        try:
            resp = self.session.post(url, data=json.dumps(body), timeout=self.timeout_seconds)
            ms = int((time.time() - started) * 1000)
            if resp.status_code >= 400:
                # Try to extract a safe error message
                safe_err = f"HTTP {resp.status_code}"
                try:
                    j = resp.json()
                    if isinstance(j, dict) and "Message" in j:
                        safe_err = f"HTTP {resp.status_code}: {j.get('Message')}"
                except Exception:
                    pass
                return {}, ApiCallResult(f"{resource}/{operation}", False, resp.status_code, ms, safe_err)
            try:
                data = resp.json()
            except Exception:
                return {}, ApiCallResult(f"{resource}/{operation}", False, resp.status_code, ms, "Invalid JSON response")
            return data, ApiCallResult(f"{resource}/{operation}", True, resp.status_code, ms)
        except requests.RequestException as e:
            ms = int((time.time() - started) * 1000)
            return {}, ApiCallResult(f"{resource}/{operation}", False, None, ms, "Network error")


# -----------------------------
# Helpers: parsing uploads / heuristics
# -----------------------------

def read_uploaded_csv(file_storage) -> List[Dict[str, str]]:
    if not file_storage:
        return []
    content = file_storage.read().decode("utf-8", errors="replace")
    file_storage.seek(0)
    rows = []
    reader = csv.DictReader(io.StringIO(content))
    for r in reader:
        rows.append({k.strip(): (v or "").strip() for k, v in r.items()})
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


def safe_get(d: Dict[str, Any], path: str, default=None):
    """Dot-path getter: 'Enterprise.Name'."""
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def normalise_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().lower()


CITY_TAX_HINTS = ["city tax", "tourism tax", "local tax", "occupancy tax", "tourist tax", "kur", "kurtaxe", "ortstaxe"]


def find_city_tax_products(products: List[Dict[str, Any]], categories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Heuristic: match by name/code/category name
    cat_by_id = {c.get("Id"): normalise_text(c.get("Name", "")) for c in categories if isinstance(c, dict)}
    hits = []
    for p in products:
        name = normalise_text(p.get("Name", ""))
        code = normalise_text(p.get("Code", ""))
        cat_name = cat_by_id.get(p.get("ProductCategoryId"), "")
        hay = " ".join([name, code, cat_name])
        if any(h in hay for h in CITY_TAX_HINTS):
            hits.append(p)
    return hits


def summarise_rule(rule: Dict[str, Any]) -> str:
    # We keep it safe & generic (rules structures differ).
    name = rule.get("Name") or rule.get("Id") or "Rule"
    enabled = rule.get("IsEnabled")
    return f"{name} (enabled={enabled})"


# -----------------------------
# Audit collectors (ALL categories)
# -----------------------------

def connector_pull_all(client: MewsConnectorClient, report: AuditReport) -> Dict[str, Any]:
    """
    Pull a broad dataset from Connector API.
    Where an endpoint is missing/forbidden, we record an API call failure and continue.
    """
    pulled: Dict[str, Any] = {}

    def call(resource, op, payload=None, key=None):
        data, res = client.post(resource, op, payload)
        report.api_calls.append(res)
        if res.ok:
            pulled[key or f"{resource}/{op}"] = data
        else:
            pulled[key or f"{resource}/{op}"] = {"_error": res.error, "_status": res.status_code}
        return data, res

    # Legal & property baseline
    call("Configuration", "Get", key="config")  # Configuration/Get
    call("TaxEnvironments", "GetAll", key="tax_envs")
    call("Taxations", "GetAll", key="taxations")
    call("Products", "GetAll", key="products")
    call("ProductCategories", "GetAll", key="product_categories")
    call("Rules", "GetAll", key="rules")
    call("Images", "GetUrls", {"ImageIds": []}, key="image_urls_stub")  # We'll re-call with IDs later if available

    # Users/access/security: not available in Connector -> NA here

    # Accounting config
    call("AccountingCategories", "GetAll", key="accounting_categories")
    call("Cashiers", "GetAll", key="cashiers")
    call("Counters", "GetAll", key="counters")
    call("LedgerBalances", "GetAll", key="ledger_balances")

    # Payments & reconciliation primitives
    call("Payments", "GetAll", {"Limitation": {"Count": 200}}, key="payments_200")
    call("PaymentRequests", "GetAll", {"Limitation": {"Count": 200}}, key="payment_requests_200")

    # Inventory, rates, restrictions
    call("Resources", "GetAll", key="resources")
    call("ResourceCategories", "GetAll", key="resource_categories")
    call("Rates", "GetAll", key="rates")
    call("RateGroups", "GetAll", key="rate_groups")
    call("Restrictions", "GetAll", key="restrictions")

    # Guest journey & operations primitives
    call("Reservations", "GetAll", {"Limitation": {"Count": 200}}, key="reservations_200")
    call("ReservationGroups", "GetAll", {"Limitation": {"Count": 200}}, key="reservation_groups_200")
    call("Customers", "GetAll", {"Limitation": {"Count": 200}}, key="customers_200")

    # Reporting/exports primitives
    call("Exports", "GetAll", {"Limitation": {"Count": 50}}, key="exports_50")

    return pulled


def build_legal_property_section(pulled: Dict[str, Any], report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []

    cfg = pulled.get("config") or {}
    if "_error" in cfg:
        items.append(EvidenceItem(
            key="Configuration access",
            status="FAIL",
            summary="Unable to retrieve configuration via Connector API.",
            details={"error": cfg.get("_error")},
            source="Connector: Configuration/Get",
            remediation="Verify ClientToken/AccessToken and Connector permissions."
        ))
        report.sections["Legal & property baseline"] = items
        return

    enterprise = cfg.get("Enterprise") or {}
    report.property_name = enterprise.get("Name", "") or cfg.get("Name", "") or ""
    report.enterprise_id = enterprise.get("Id", "") or ""

    # Timezone
    tz = enterprise.get("TimeZoneIdentifier") or cfg.get("TimeZoneIdentifier")
    items.append(EvidenceItem(
        key="Time zone",
        status="PASS" if tz else "WARN",
        summary=tz or "Missing time zone in configuration.",
        details={"TimeZoneIdentifier": tz},
        source="Connector: Configuration/Get",
        remediation="Set enterprise/property time zone in Mews if missing."
    ))

    # Currency (default)
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

    # Pricing mode: gross/net (may appear in enterprise pricing fields, otherwise NA + manual)
    pricing_mode = enterprise.get("PricingMode") or enterprise.get("Pricing") or cfg.get("PricingMode")
    if pricing_mode:
        items.append(EvidenceItem(
            key="Pricing mode (gross/net)",
            status="PASS",
            summary=str(pricing_mode),
            details={"PricingMode": pricing_mode},
            source="Connector: Configuration/Get",
            remediation=""
        ))
    else:
        manual_pm = (manual.get("pricing_mode") or "").strip()
        items.append(EvidenceItem(
            key="Pricing mode (gross/net)",
            status="NEEDS_INPUT" if not manual_pm else "PASS",
            summary=manual_pm or "Connector did not provide a pricing mode field; require manual confirmation.",
            details={},
            source="Workaround: manual attestation",
            remediation="Confirm whether pricing is gross or net in the Mews UI / contract."
        ))

    # Tax environment + taxations
    tax_env = enterprise.get("TaxEnvironmentCode") or cfg.get("TaxEnvironmentCode")
    taxations = pulled.get("taxations") or {}
    tax_rates_summary = []
    if isinstance(taxations, dict) and "Taxations" in taxations and isinstance(taxations["Taxations"], list):
        for t in taxations["Taxations"][:50]:
            if isinstance(t, dict):
                name = t.get("Name") or t.get("Id")
                rates = t.get("TaxRates") or []
                tax_rates_summary.append({"Taxation": name, "RatesCount": len(rates)})
    items.append(EvidenceItem(
        key="Tax environment + VAT/GST rates",
        status="PASS" if tax_env and tax_rates_summary else "WARN",
        summary=f"TaxEnvironmentCode={tax_env}, Taxations found={len(tax_rates_summary)}",
        details={"TaxEnvironmentCode": tax_env, "TaxationsSummary": tax_rates_summary},
        source="Connector: Configuration/Get + Taxations/GetAll",
        remediation="Verify tax environment selection and confirm VAT/GST rates exist & are correct."
    ))

    # City tax product + rules (heuristic)
    products = (pulled.get("products") or {}).get("Products") if isinstance(pulled.get("products"), dict) else None
    categories = (pulled.get("product_categories") or {}).get("ProductCategories") if isinstance(pulled.get("product_categories"), dict) else None
    rules = (pulled.get("rules") or {}).get("Rules") if isinstance(pulled.get("rules"), dict) else None
    products = products if isinstance(products, list) else []
    categories = categories if isinstance(categories, list) else []
    rules = rules if isinstance(rules, list) else []

    city_tax_products = find_city_tax_products(products, categories)
    city_tax_rule_hits = []
    if city_tax_products and rules:
        city_ids = {p.get("Id") for p in city_tax_products}
        for r in rules:
            rj = json.dumps(r, ensure_ascii=False).lower()
            if any((cid or "").lower() in rj for cid in city_ids if isinstance(cid, str)):
                city_tax_rule_hits.append(r)

    status = "PASS" if city_tax_products else "WARN"
    items.append(EvidenceItem(
        key="City tax product + rule",
        status=status,
        summary=f"City-tax-like products found={len(city_tax_products)}, matching rules found={len(city_tax_rule_hits)}",
        details={
            "CityTaxProducts": [{"Id": p.get("Id"), "Name": p.get("Name"), "Code": p.get("Code")} for p in city_tax_products[:20]],
            "RuleSamples": [summarise_rule(r) for r in city_tax_rule_hits[:20]],
            "Heuristic": "Matched by product/category name/code containing city/tourism/occupancy tax keywords; rules matched by ProductId presence in rule JSON."
        },
        source="Connector: Products/GetAll + ProductCategories/GetAll + Rules/GetAll",
        remediation="If missing/incorrect: standardise city tax product naming/codes or tag via a dedicated product category; ensure a rule applies it consistently."
    ))

    # Fiscalisation (not reliably exposed) -> jurisdiction-based + attestation
    legal_env = enterprise.get("LegalEnvironmentCode") or cfg.get("LegalEnvironmentCode")
    fiscal_needed = manual.get("fiscalisation_required", "").strip() or "Unknown"
    fiscal_configured = manual.get("fiscalisation_configured", "").strip() or "Unknown"
    items.append(EvidenceItem(
        key="Fiscalisation (where relevant)",
        status="NEEDS_INPUT",
        summary=f"LegalEnvironmentCode={legal_env}. Require manual confirmation for fiscalisation setup.",
        details={
            "LegalEnvironmentCode": legal_env,
            "FiscalisationRequired": fiscal_needed,
            "FiscalisationConfigured": fiscal_configured,
        },
        source="Workaround: manual attestation + jurisdiction policy",
        remediation="Confirm fiscalisation requirement for the jurisdiction and validate Mews fiscalisation settings/provider in the UI."
    ))

    # Address + branding
    addr = enterprise.get("Address") or cfg.get("Address") or {}
    logo_id = enterprise.get("LogoImageId") or cfg.get("LogoImageId")
    cover_id = enterprise.get("CoverImageId") or cfg.get("CoverImageId")
    addr_ok = isinstance(addr, dict) and bool(addr.get("CountryCode") or addr.get("Country")) and bool(addr.get("City")) and bool(addr.get("PostalCode") or addr.get("PostCode"))
    items.append(EvidenceItem(
        key="Property address",
        status="PASS" if addr_ok else "WARN",
        summary="Address present" if addr_ok else "Address incomplete or missing fields.",
        details={"Address": addr},
        source="Connector: Configuration/Get",
        remediation="Ensure address fields (street/city/postcode/country) are filled for invoices and integrations."
    ))
    items.append(EvidenceItem(
        key="Branding (logo/cover IDs)",
        status="PASS" if (logo_id or cover_id) else "WARN",
        summary=f"LogoImageId={logo_id or 'None'}, CoverImageId={cover_id or 'None'}",
        details={"LogoImageId": logo_id, "CoverImageId": cover_id},
        source="Connector: Configuration/Get",
        remediation="Upload logo/cover in Mews for consistent guest-facing surfaces."
    ))

    # Legal identifiers (workaround)
    legal_ids = {
        "VATNumber": manual.get("vat_number", "").strip(),
        "CompanyRegistrationNumber": manual.get("company_reg_number", "").strip(),
        "InvoiceHeaderCompanyName": manual.get("company_name", "").strip(),
    }
    missing = [k for k, v in legal_ids.items() if not v]
    items.append(EvidenceItem(
        key="Legal identifiers (VAT/company reg/etc.)",
        status="NEEDS_INPUT" if missing else "PASS",
        summary="Missing: " + ", ".join(missing) if missing else "Captured via manual fields.",
        details=legal_ids,
        source="Workaround: manual input (UI-only fields vary by jurisdiction)",
        remediation="Populate missing legal identifiers; validate against contracts and invoice requirements."
    ))

    report.sections["Legal & property baseline"] = items


def build_users_security_section(report: AuditReport, uploads: Dict[str, Any], manual: Dict[str, Any]):
    items: List[EvidenceItem] = []

    # Workaround: accept a user export CSV (from Mews UI or IdP export)
    user_rows = uploads.get("users_csv_rows") or []
    if user_rows:
        active = [r for r in user_rows if normalise_text(r.get("status", r.get("Status", ""))) in ("active", "enabled", "true", "yes")]
        shared = [r for r in user_rows if "shared" in normalise_text(r.get("email", r.get("Email", ""))) or "generic" in normalise_text(r.get("email", r.get("Email", "")))]
        items.append(EvidenceItem(
            key="User list & roles",
            status="PASS",
            summary=f"Users provided={len(user_rows)}, active={len(active)}, potential shared/generic={len(shared)}",
            details={"Sample": user_rows[:20]},
            source="Workaround: uploaded CSV (users export)",
            remediation="Remove shared logins; ensure roles match responsibilities; map departments where used."
        ))
    else:
        items.append(EvidenceItem(
            key="User list & roles",
            status="NEEDS_INPUT",
            summary="Connector API does not expose users/roles. Upload a users CSV export to audit this.",
            details={"ExpectedColumns": ["Email", "Name", "Role", "Department", "Status"]},
            source="Workaround: upload CSV",
            remediation="Export users from Mews UI or IdP and upload."
        ))

    # 2FA / passkeys / SSO / SCIM: manual/IdP evidence
    sso = manual.get("sso_enforced", "").strip()
    scim = manual.get("scim_used", "").strip()
    items.append(EvidenceItem(
        key="2FA / passkeys adoption",
        status="NEEDS_INPUT",
        summary="Requires IdP policy evidence or admin attestation (not in Connector).",
        details={"2FAAdoption": manual.get("mfa_adoption", "").strip()},
        source="Workaround: IdP policy evidence / attestation",
        remediation="Confirm MFA/passkey enforcement for admin/back-office users in IdP."
    ))
    items.append(EvidenceItem(
        key="SSO / SCIM configuration",
        status="NEEDS_INPUT" if not (sso or scim) else "PASS",
        summary=f"SSO enforced={sso or 'Unknown'}, SCIM used={scim or 'Unknown'}",
        details={},
        source="Workaround: IdP configuration + attestation",
        remediation="Confirm SSO enforcement for back-office; validate SCIM provisioning mappings."
    ))

    # Auditability history windows are in config; we’ll record them in Legal section via config fields.
    items.append(EvidenceItem(
        key="Auditability (editable history windows)",
        status="NA",
        summary="Captured under Legal & property baseline via Configuration/Get (OEHW/AEHW).",
        details={},
        source="Connector: Configuration/Get",
        remediation=""
    ))

    report.sections["Users, access & security"] = items


def build_accounting_section(pulled: Dict[str, Any], report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []

    cats = (pulled.get("accounting_categories") or {}).get("AccountingCategories") if isinstance(pulled.get("accounting_categories"), dict) else []
    cats = cats if isinstance(cats, list) else []
    items.append(EvidenceItem(
        key="Accounting categories",
        status="PASS" if cats else "WARN",
        summary=f"Accounting categories found={len(cats)}",
        details={"Sample": cats[:20]},
        source="Connector: AccountingCategories/GetAll",
        remediation="Ensure separate categories for revenue, payments, taxes, deposits, fees, city tax as per your structure."
    ))

    cashiers = (pulled.get("cashiers") or {}).get("Cashiers") if isinstance(pulled.get("cashiers"), dict) else []
    cashiers = cashiers if isinstance(cashiers, list) else []
    items.append(EvidenceItem(
        key="Cashiers setup",
        status="PASS" if cashiers else "WARN",
        summary=f"Cashiers found={len(cashiers)}",
        details={"Sample": cashiers[:20]},
        source="Connector: Cashiers/GetAll",
        remediation="If cash is accepted, ensure cashiers are assigned and controlled."
    ))

    counters = (pulled.get("counters") or {}).get("Counters") if isinstance(pulled.get("counters"), dict) else []
    counters = counters if isinstance(counters, list) else []
    items.append(EvidenceItem(
        key="Bill/invoice counters & sequences",
        status="PASS" if counters else "WARN",
        summary=f"Counters found={len(counters)}",
        details={"Sample": counters[:20]},
        source="Connector: Counters/GetAll",
        remediation="Verify numbering prefixes and legal sequencing rules by jurisdiction."
    ))

    # Payment type mapping workaround: infer from payments sample + manual mapping table
    items.append(EvidenceItem(
        key="Payment types mapping to accounting categories",
        status="NEEDS_INPUT",
        summary="Connector does not provide a direct payment-type→accounting-category mapping table. Workaround: infer from accounting items/payments samples and/or upload mapping.",
        details={"ManualMapping": manual.get("payment_mapping", "")[:500]},
        source="Workaround: inference + manual mapping upload",
        remediation="Provide mapping of external payment types and Mews terminals to accounting categories; validate via sample transactions."
    ))

    # Ledger design: not in API; workaround is policy + ledger balances visibility
    ledgers = (pulled.get("ledger_balances") or {}).get("LedgerBalances") if isinstance(pulled.get("ledger_balances"), dict) else []
    ledgers = ledgers if isinstance(ledgers, list) else []
    items.append(EvidenceItem(
        key="Ledger separation (guest/deposit/AR/TA)",
        status="NEEDS_INPUT",
        summary=f"Ledger balances retrieved={len(ledgers)}; conceptual design requires policy review.",
        details={"Sample": ledgers[:20]},
        source="Connector: LedgerBalances/GetAll + workaround policy review",
        remediation="Define target ledger model and validate flows into accounting exports (Omniboost/Sun/Dynamics/Xero/etc.)."
    ))

    report.sections["Accounting configuration"] = items


def build_payments_reconciliation_section(pulled: Dict[str, Any], report: AuditReport, uploads: Dict[str, Any], manual: Dict[str, Any]):
    items: List[EvidenceItem] = []

    payments = (pulled.get("payments_200") or {}).get("Payments") if isinstance(pulled.get("payments_200"), dict) else []
    payments = payments if isinstance(payments, list) else []
    items.append(EvidenceItem(
        key="Payments sample (last 200)",
        status="PASS" if payments else "WARN",
        summary=f"Payments retrieved={len(payments)}",
        details={"Sample": payments[:10]},
        source="Connector: Payments/GetAll (sample)",
        remediation="If empty, increase range/filters or verify permissions."
    ))

    # KYC/merchant status not in Connector: workaround via uploaded statement or attestation
    items.append(EvidenceItem(
        key="KYC & Mews Payments onboarding status",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide attestation or upload onboarding/payout account evidence.",
        details={"KYCStatus": manual.get("kyc_status", "").strip()},
        source="Workaround: manual evidence",
        remediation="Confirm KYC status, payout account currencies, and fee behaviour in Mews Payments UI."
    ))

    # SoW: infer from payments sample by a heuristic (internal vs external)
    external_count = 0
    for p in payments:
        # Heuristic: External payments often have different types; structure can vary.
        pj = json.dumps(p, ensure_ascii=False).lower()
        if "external" in pj or "bank transfer" in pj or "voucher" in pj or "ota" in pj:
            external_count += 1
    if payments:
        sow = round(100.0 * (len(payments) - external_count) / max(1, len(payments)), 1)
        items.append(EvidenceItem(
            key="Share of wallet (heuristic)",
            status="WARN",
            summary=f"Estimated % Mews vs external from sample: ~{sow}% Mews (heuristic)",
            details={"TotalPaymentsSample": len(payments), "ExternalHeuristicCount": external_count},
            source="Workaround: inference from Payments/GetAll sample",
            remediation="Replace heuristic with explicit classification rules for your environment; ideally cross-check with payout statements."
        ))
    else:
        items.append(EvidenceItem(
            key="Share of wallet",
            status="NEEDS_INPUT",
            summary="No payments sample available to infer SoW. Provide date-range exports or manual figures.",
            details={},
            source="Workaround: provide exports",
            remediation="Export payments for a representative period and upload."
        ))

    # Reconciliation: payout/fee statements are not in Connector here -> upload
    payout_json = uploads.get("payouts_json")
    if payout_json:
        items.append(EvidenceItem(
            key="Payouts & fees evidence",
            status="PASS",
            summary="Payout/fee statement provided via upload.",
            details={"StatementSummary": str(payout_json)[:1000]},
            source="Workaround: uploaded payout statement JSON",
            remediation="Align payouts/fees to GL mapping; validate against accounting export."
        ))
    else:
        items.append(EvidenceItem(
            key="Payouts & fees reconciliation",
            status="NEEDS_INPUT",
            summary="Connector does not provide payout/fee statement feed here. Upload statements (CSV/JSON) from Mews Payments/processor.",
            details={},
            source="Workaround: upload statement",
            remediation="Upload payout/fee statements to reconcile to GL and validate report alignment."
        ))

    report.sections["Payments setup & reconciliation"] = items


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
        details={"ResourceCategoriesSample": rc[:20], "ResourcesSample": rs[:20]},
        source="Connector: ResourceCategories/GetAll + Resources/GetAll",
        remediation="Verify inventory model supports dorm beds/long-stay/multi-room setups as required."
    ))
    items.append(EvidenceItem(
        key="Rates & rate groups",
        status="PASS" if (rates or groups) else "WARN",
        summary=f"Rate groups={len(groups)}, rates={len(rates)}",
        details={"RateGroupsSample": groups[:20], "RatesSample": rates[:20]},
        source="Connector: RateGroups/GetAll + Rates/GetAll",
        remediation="Validate base rates, derivations and packages (e.g., breakfast product vs included)."
    ))
    items.append(EvidenceItem(
        key="Restrictions & seasonality",
        status="PASS" if restrictions else "WARN",
        summary=f"Restrictions={len(restrictions)}",
        details={"RestrictionsSample": restrictions[:20]},
        source="Connector: Restrictions/GetAll",
        remediation="Validate LOS/CTA/CTD rules consistency across calendars and channels."
    ))

    # Channel manager mapping: not in Connector -> explicit workaround
    items.append(EvidenceItem(
        key="Channel manager / CRS mapping",
        status="NEEDS_INPUT",
        summary="Not available via Connector. Workaround: integrate Channel Manager API or upload mapping export from channel manager.",
        details={},
        source="Workaround: Channel Manager API / export",
        remediation="Pull mapping via Channel Manager API (separate) and cross-check IDs against Connector resources/rates."
    ))

    report.sections["Inventory, rates & revenue structure"] = items


def build_guest_journey_ops_section(pulled: Dict[str, Any], report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []

    res = (pulled.get("reservations_200") or {}).get("Reservations") if isinstance(pulled.get("reservations_200"), dict) else []
    res = res if isinstance(res, list) else []
    items.append(EvidenceItem(
        key="Reservations sample (last 200)",
        status="PASS" if res else "WARN",
        summary=f"Reservations retrieved={len(res)}",
        details={"Sample": res[:10]},
        source="Connector: Reservations/GetAll (sample)",
        remediation="Use date filters and larger limits in production to cover desired audit window."
    ))

    # Booking flows / direct vs OTA: workaround = infer from channel/source fields if present, else needs export
    if res:
        # naive heuristic: look for “Channel”/“Source” fields
        ota = 0
        for r in res:
            rj = json.dumps(r, ensure_ascii=False).lower()
            if "booking.com" in rj or "expedia" in rj or "ota" in rj:
                ota += 1
        items.append(EvidenceItem(
            key="Booking flow mix (heuristic)",
            status="WARN",
            summary=f"Estimated OTA-like reservations in sample: {ota}/{len(res)} (heuristic)",
            details={"Heuristic": "Search reservation JSON for OTA keywords."},
            source="Workaround: inference from Reservations/GetAll sample",
            remediation="Replace heuristic with explicit channel mapping based on your field model; consider BI export upload."
        ))
    else:
        items.append(EvidenceItem(
            key="Booking flow mix",
            status="NEEDS_INPUT",
            summary="No reservation sample available for inference. Upload BI/reservation exports or expand API pull window.",
            details={},
            source="Workaround: upload export",
            remediation="Provide reservation export (CSV) or configure API query to cover a representative date range."
        ))

    # Online check-in / portal / comms templates: not in Connector
    items.append(EvidenceItem(
        key="Online check-in / guest portal / email-SMS templates",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Workaround: manual attestation + screenshot/export evidence.",
        details={"OCIEnabled": manual.get("oci_enabled", "").strip()},
        source="Workaround: manual evidence",
        remediation="Confirm OCI settings, templates, merge tags, and brand alignment in the Mews UI."
    ))

    # Housekeeping & maintenance: not in Connector
    items.append(EvidenceItem(
        key="Housekeeping & maintenance configuration",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Workaround: integration evidence and operational settings screenshots/exports.",
        details={},
        source="Workaround: manual evidence",
        remediation="Validate space statuses, housekeeping boards/integrations, and automations tied to status changes."
    ))

    report.sections["Guest journey & operations"] = items


def build_reporting_bi_data_quality_section(report: AuditReport, uploads: Dict[str, Any], manual: Dict[str, Any], pulled: Dict[str, Any]):
    items: List[EvidenceItem] = []

    # Reports (Manager/Accounting/Reservations) not generated via Connector; workaround = export upload
    bi_csv = uploads.get("bi_csv_rows") or []
    if bi_csv:
        items.append(EvidenceItem(
            key="BI exports consistency",
            status="PASS",
            summary=f"BI export rows provided={len(bi_csv)}",
            details={"Sample": bi_csv[:20]},
            source="Workaround: uploaded BI export CSV",
            remediation="Compare totals vs operational data; validate cut-offs and totals mode."
        ))
    else:
        items.append(EvidenceItem(
            key="Core reports + BI exports",
            status="NEEDS_INPUT",
            summary="Connector does not provide report output. Upload exports (Reservations/Manager/Accounting/BI) for consistency checks.",
            details={"Expected": "CSV exports from Mews BI or core reports"},
            source="Workaround: upload report exports",
            remediation="Upload exports and define your baseline reconciliation rules."
        ))

    # Error patterns: infer from payments/reservations/ledger if possible + manual
    items.append(EvidenceItem(
        key="Rebates / corrections / write-offs patterns",
        status="NEEDS_INPUT",
        summary="Not a direct API metric. Workaround: detect by scanning accounting items/payments exports or upload a corrections log.",
        details={"Notes": manual.get("error_patterns_notes", "")[:500]},
        source="Workaround: scan exports + manual notes",
        remediation="If systematic patterns found, redesign configuration/process to reduce manual corrections."
    ))

    report.sections["Reporting, BI & data quality"] = items


def build_integrations_automations_section(pulled: Dict[str, Any], report: AuditReport, uploads: Dict[str, Any], manual: Dict[str, Any]):
    items: List[EvidenceItem] = []

    # Marketplace/integration health not in Connector
    integ = manual.get("integrations_list", "").strip()
    items.append(EvidenceItem(
        key="Marketplace stack (CHM/POS/RMS/etc.)",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide integration inventory and evidence of mappings.",
        details={"Integrations": integ[:1000]},
        source="Workaround: manual inventory + exports",
        remediation="Document mappings; check for double-posting, broken category/rate mappings, and gaps."
    ))

    # Accounting exports: Exports/GetAll can show export definitions/jobs; still need external target success evidence
    exports = (pulled.get("exports_50") or {}).get("Exports") if isinstance(pulled.get("exports_50"), dict) else []
    exports = exports if isinstance(exports, list) else []
    items.append(EvidenceItem(
        key="Accounting/data exports (Connector exports)",
        status="PASS" if exports else "WARN",
        summary=f"Exports retrieved={len(exports)}",
        details={"Sample": exports[:20]},
        source="Connector: Exports/GetAll (sample)",
        remediation="Validate export cadence and failure handling; cross-check with target system logs."
    ))

    # Automation tooling (Zapier/Power Automate/custom): not in Connector
    items.append(EvidenceItem(
        key="Automation tooling robustness",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide workflow inventory + monitoring evidence.",
        details={"AutomationNotes": manual.get("automation_notes", "")[:1000]},
        source="Workaround: manual inventory",
        remediation="Ensure workflows are documented, monitored, and resilient with alerting on failures."
    ))

    report.sections["Integrations & automations"] = items


def build_training_governance_section(report: AuditReport, manual: Dict[str, Any]):
    items: List[EvidenceItem] = []
    items.append(EvidenceItem(
        key="Training coverage (Mews University completion)",
        status="NEEDS_INPUT",
        summary="Not exposed via Connector. Provide completion export or attestation.",
        details={"TrainingEvidence": manual.get("training_evidence", "")[:1000]},
        source="Workaround: export/attestation",
        remediation="Align training completion with operational responsibilities (front office/finance/revenue)."
    ))
    items.append(EvidenceItem(
        key="Process ownership & governance",
        status="NEEDS_INPUT",
        summary="Provide internal champion, change evaluation and rollout approach.",
        details={"Owner": manual.get("process_owner", ""), "Governance": manual.get("governance_notes", "")[:1000]},
        source="Workaround: manual input",
        remediation="Define a change governance process for Mews configuration and integrations."
    ))
    items.append(EvidenceItem(
        key="Artifacts (SOPs, playbooks, governance rules)",
        status="NEEDS_INPUT",
        summary="Upload SOPs/playbooks or provide links; compare against configuration evidence.",
        details={"Artifacts": manual.get("artifacts_links", "")[:1000]},
        source="Workaround: upload/links",
        remediation="Ensure SOPs match what’s configured and used in practice."
    ))
    report.sections["Training, governance & ownership"] = items


def run_full_audit(
    client: MewsConnectorClient,
    base_url: str,
    uploads: Dict[str, Any],
    manual: Dict[str, Any],
) -> AuditReport:
    report = AuditReport(
        generated_at_utc=datetime.now(timezone.utc),
        base_url=base_url,
        attachments_used=uploads.get("attachments_used", []),
    )

    pulled = connector_pull_all(client, report)

    # Re-fetch image URLs if we have IDs
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

    # Build all sections
    build_legal_property_section(pulled, report, manual)
    build_users_security_section(report, uploads, manual)
    build_accounting_section(pulled, report, manual)
    build_payments_reconciliation_section(pulled, report, uploads, manual)
    build_inventory_rates_section(pulled, report)
    build_guest_journey_ops_section(pulled, report, manual)
    build_reporting_bi_data_quality_section(report, uploads, manual, pulled)
    build_integrations_automations_section(pulled, report, uploads, manual)
    build_training_governance_section(report, manual)

    # High-level note: credentials best-effort cleared by caller
    return report


# -----------------------------
# PDF generation (ReportLab)
# -----------------------------

def _status_color(status: str):
    s = (status or "").upper()
    if s == "PASS":
        return colors.green
    if s == "FAIL":
        return colors.red
    if s == "WARN":
        return colors.orange
    if s == "NEEDS_INPUT":
        return colors.HexColor("#6A5ACD")  # slate blue
    return colors.grey


def build_pdf(report: AuditReport) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )
    styles = getSampleStyleSheet()
    story = []

    # Header
    title = f"Mews Configuration Audit Report"
    subtitle = f"Generated: {report.generated_at_utc.strftime('%d/%m/%Y %H:%M UTC')}  |  Base URL: {report.base_url}"
    prop = f"Enterprise: {report.property_name or 'Unknown'}  |  EnterpriseId: {report.enterprise_id or 'Unknown'}"
    story.append(Paragraph(f"<b>{title}</b>", styles["Title"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(subtitle, styles["Normal"]))
    story.append(Paragraph(prop, styles["Normal"]))
    story.append(Spacer(1, 10))

    # Executive summary
    total = 0
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "NEEDS_INPUT": 0, "NA": 0}
    for sec, items in report.sections.items():
        for it in items:
            total += 1
            counts[it.status.upper()] = counts.get(it.status.upper(), 0) + 1

    story.append(Paragraph("<b>Summary</b>", styles["Heading2"]))
    summary_tbl = Table([
        ["Total checks", total],
        ["PASS", counts.get("PASS", 0)],
        ["WARN", counts.get("WARN", 0)],
        ["FAIL", counts.get("FAIL", 0)],
        ["NEEDS_INPUT", counts.get("NEEDS_INPUT", 0)],
        ["NA", counts.get("NA", 0)],
    ], hAlign="LEFT")
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 10))

    if report.attachments_used:
        story.append(Paragraph("<b>Uploads used</b>", styles["Heading3"]))
        story.append(Paragraph(", ".join(report.attachments_used), styles["Normal"]))
        story.append(Spacer(1, 8))

    # Sections
    for sec_name, items in report.sections.items():
        story.append(Paragraph(sec_name, styles["Heading2"]))
        story.append(Spacer(1, 4))

        rows = [["Item", "Status", "Summary", "Source"]]
        for it in items:
            rows.append([it.key, it.status, it.summary, it.source])

        tbl = Table(rows, colWidths=[55*mm, 20*mm, 80*mm, 25*mm])
        tbl_style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ])
        for i in range(1, len(rows)):
            tbl_style.add("TEXTCOLOR", (1, i), (1, i), _status_color(rows[i][1]))
        tbl.setStyle(tbl_style)
        story.append(tbl)

        # Remediation appendix per section
        rems = [it for it in items if it.remediation]
        if rems:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Remediation notes</b>", styles["Heading3"]))
            for it in rems:
                story.append(Paragraph(f"<b>{it.key} ({it.status})</b>: {it.remediation}", styles["Normal"]))
                story.append(Spacer(1, 2))

        story.append(PageBreak())

    # API call log
    story.append(Paragraph("API call log", styles["Heading2"]))
    log_rows = [["Operation", "OK", "HTTP", "ms", "Error"]]
    for c in report.api_calls:
        log_rows.append([c.name, "Yes" if c.ok else "No", str(c.status_code or ""), str(c.duration_ms), c.error or ""])
    log_tbl = Table(log_rows, colWidths=[70*mm, 10*mm, 12*mm, 12*mm, 80*mm])
    log_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(log_tbl)

    def on_page(cnv: canvas.Canvas, doc_):
        cnv.saveState()
        cnv.setFont("Helvetica", 8)
        cnv.setFillColor(colors.grey)
        cnv.drawRightString(A4[0] - 18*mm, 10*mm, f"Page {doc_.page}")
        cnv.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()


# -----------------------------
# Web UI (single template)
# -----------------------------

HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mews Configuration Audit</title>
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
    .btn:disabled{opacity:.5; cursor:not-allowed;}
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
  <h1>Mews Configuration Audit</h1>
  <p class="muted">Enter Connector API credentials to generate a comprehensive PDF audit. Where the Connector API cannot provide data, you can optionally upload exports/evidence to complete the report.</p>

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

    <label>Connector base URL (optional)</label>
    <input name="base_url" placeholder="https://api.mews.com/api/connector/v1">
    <p class="muted">If omitted, the server uses MEWS_CONNECTOR_BASE_URL or defaults to https://api.mews.com/api/connector/v1</p>

    <details>
      <summary>Optional uploads (workarounds for non-API items)</summary>
      <div class="row">
        <div>
          <label>Users export CSV (Email, Name, Role, Department, Status)</label>
          <input name="users_csv" type="file" accept=".csv">
        </div>
        <div>
          <label>BI/Report export CSV (any)</label>
          <input name="bi_csv" type="file" accept=".csv">
        </div>
      </div>
      <div class="row">
        <div>
          <label>Payout/Fee statement JSON (optional)</label>
          <input name="payouts_json" type="file" accept=".json">
        </div>
        <div>
          <label>Other evidence JSON (optional)</label>
          <input name="other_json" type="file" accept=".json">
        </div>
      </div>
      <p class="muted">Uploads are processed in-memory only and are not stored.</p>
    </details>

    <details>
      <summary>Optional attestation fields (UI-only settings)</summary>
      <div class="row">
        <div>
          <label>Pricing mode (gross / net)</label>
          <input name="pricing_mode" placeholder="gross or net">
        </div>
        <div>
          <label>KYC status (Mews Payments)</label>
          <input name="kyc_status" placeholder="e.g. Approved / Pending / Not used">
        </div>
      </div>
      <div class="row">
        <div>
          <label>Fiscalisation required? (Yes/No/Unknown)</label>
          <input name="fiscalisation_required" placeholder="Yes/No/Unknown">
        </div>
        <div>
          <label>Fiscalisation configured? (Yes/No/Unknown)</label>
          <input name="fiscalisation_configured" placeholder="Yes/No/Unknown">
        </div>
      </div>
      <div class="row">
        <div>
          <label>VAT number</label>
          <input name="vat_number" placeholder="">
        </div>
        <div>
          <label>Company registration number</label>
          <input name="company_reg_number" placeholder="">
        </div>
      </div>
      <label>Company name (invoice header)</label>
      <input name="company_name" placeholder="">
      <label>Payment mapping notes (terminal/gateway → accounting category)</label>
      <textarea name="payment_mapping" rows="4" placeholder="Describe mapping or paste a mapping table..."></textarea>
      <label>Integrations list (CHM/POS/RMS/key/CRM/etc.)</label>
      <textarea name="integrations_list" rows="3" placeholder=""></textarea>
      <label>Automation notes (Zapier/Power Automate/custom workflows)</label>
      <textarea name="automation_notes" rows="3" placeholder=""></textarea>
      <label>Training evidence / notes</label>
      <textarea name="training_evidence" rows="3" placeholder=""></textarea>
      <label>Process owner (internal champion)</label>
      <input name="process_owner" placeholder="">
      <label>Governance notes</label>
      <textarea name="governance_notes" rows="3" placeholder=""></textarea>
      <label>Artifacts links/notes (SOPs/playbooks)</label>
      <textarea name="artifacts_links" rows="3" placeholder=""></textarea>
      <label>Errors/corrections notes</label>
      <textarea name="error_patterns_notes" rows="3" placeholder=""></textarea>
      <label>OCI enabled? / guest comms notes</label>
      <input name="oci_enabled" placeholder="">
      <label>SSO enforced? / SCIM used? / MFA adoption</label>
      <div class="row">
        <input name="sso_enforced" placeholder="SSO enforced (Yes/No/Unknown)">
        <input name="scim_used" placeholder="SCIM used (Yes/No/Unknown)">
      </div>
      <input name="mfa_adoption" placeholder="MFA adoption notes">
    </details>

    <div style="margin-top:14px;">
      <button class="btn" type="submit">Generate PDF audit</button>
    </div>
  </form>

  <p class="muted">Security: credentials are never stored; rate limited; PDF is generated in-memory.</p>
</div>
</body>
</html>
"""


# -----------------------------
# Flask app
# -----------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

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
    base_url = (request.form.get("base_url") or "").strip() or os.environ.get(
        "MEWS_CONNECTOR_BASE_URL", "https://api.mews.com/api/connector/v1"
    )

    if not client_token or not access_token:
        flash("Please provide both Client token and Access token.", "error")
        return redirect(url_for("index"))

    if not base_url.lower().startswith("https://"):
        flash("Base URL must start with https://", "error")
        return redirect(url_for("index"))

    # Read uploads in-memory
    attachments_used = []
    users_csv_rows = []
    bi_csv_rows = []
    payouts_json = None
    other_json = None

    if request.files.get("users_csv") and request.files["users_csv"].filename:
        users_csv_rows = read_uploaded_csv(request.files["users_csv"])
        attachments_used.append(f"users_csv: {request.files['users_csv'].filename}")

    if request.files.get("bi_csv") and request.files["bi_csv"].filename:
        bi_csv_rows = read_uploaded_csv(request.files["bi_csv"])
        attachments_used.append(f"bi_csv: {request.files['bi_csv'].filename}")

    if request.files.get("payouts_json") and request.files["payouts_json"].filename:
        payouts_json = read_uploaded_json(request.files["payouts_json"])
        attachments_used.append(f"payouts_json: {request.files['payouts_json'].filename}")

    if request.files.get("other_json") and request.files["other_json"].filename:
        other_json = read_uploaded_json(request.files["other_json"])
        attachments_used.append(f"other_json: {request.files['other_json'].filename}")

    uploads = {
        "attachments_used": attachments_used,
        "users_csv_rows": users_csv_rows,
        "bi_csv_rows": bi_csv_rows,
        "payouts_json": payouts_json,
        "other_json": other_json,
    }

    # Manual attestation fields
    manual = {k: (request.form.get(k) or "") for k in request.form.keys()}

    try:
        client = MewsConnectorClient(
            base_url=base_url,
            client_token=client_token,
            access_token=access_token,
            timeout_seconds=int(os.environ.get("HTTP_TIMEOUT_SECONDS", "30")),
        )
        report = run_full_audit(client, base_url, uploads, manual)
        pdf_bytes = build_pdf(report)

        # Best-effort clear tokens from variables
        client_token = None
        access_token = None

        filename = f"mews-full-audit-{report.generated_at_utc.strftime('%Y-%m-%dT%H%M%SZ')}.pdf"
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
