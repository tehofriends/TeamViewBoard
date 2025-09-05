import io
import json
import re
import urllib.request
import urllib.parse
import streamlit_authenticator as stauth
from datetime import datetime
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

# Optional PDF export (install first if missing: pip install reportlab)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import cm
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False

st.set_page_config(page_title="Leadership Summary", layout="wide")
# ---- Authentication (resilient to 0.3.x / 0.4.x behaviors) ----
import streamlit as st
import streamlit_authenticator as stauth
from collections.abc import Mapping

try:
    from streamlit_authenticator.utilities.exceptions import DeprecationError
except Exception:
    class DeprecationError(Exception): pass

def _to_builtin(x):
    if isinstance(x, Mapping): return {k:_to_builtin(v) for k,v in x.items()}
    if isinstance(x, list):    return [_to_builtin(v) for v in x]
    return x

def _with_email_aliases(creds: dict) -> dict:
    """Allow login by username OR email by cloning entries under the email key."""
    out = {"usernames": {}}
    src = creds.get("usernames", {})
    for uname, rec in src.items():
        out["usernames"][uname] = rec
        email = (rec or {}).get("email")
        if email and email not in out["usernames"]:
            out["usernames"][email] = rec  # alias: login using email works too
    return out

def setup_auth():
    try:
        creds  = _to_builtin(st.secrets["credentials"])
        cookie = _to_builtin(st.secrets["cookie"])
        pre    = _to_builtin(st.secrets.get("preauthorized", {})).get("emails", [])
    except Exception:
        st.warning("No secrets.toml found — authentication is disabled for this session.")
        return None

    # sanity checks
    if "usernames" not in creds or not isinstance(creds["usernames"], dict):
        st.error("secrets.toml: [credentials.usernames] is missing or malformed.")
        st.stop()
    for k, rec in creds["usernames"].items():
        if "password" not in rec or not str(rec["password"]).startswith("$2b$"):
            st.error(f"User '{k}' is missing a valid bcrypt hash. See the setup steps.")
            st.stop()

    creds = _with_email_aliases(creds)  # allow email login

    cname = cookie.get("name"); ckey = cookie.get("key"); cdays = int(cookie.get("expiry_days", 30))
    if not cname or not ckey:
        st.error("secrets.toml: [cookie] must include 'name' and 'key'.")
        st.stop()

    try:
        return stauth.Authenticate(creds, cname, ckey, cdays, pre)  # old signature
    except TypeError:
        return stauth.Authenticate(
            credentials=creds, cookie_name=cname, key=ckey,
            cookie_expiry_days=cdays, preauthorized=pre,
        )

def auth_login(authenticator):
    if authenticator is None:
        return ("developer", True, "dev-user")  # dev mode: bypass when no secrets
    try:
        res = authenticator.login(
            fields={
                "Form name": "Login",
                "Username": "Username or Email",
                "Password": "Password",
                "Login": "Login",
            },
            location="main",
        )
    except (DeprecationError, TypeError):
        res = authenticator.login("Login", "main")

    if res is None:                # first render before submit
        return (None, None, None)
    if isinstance(res, (list, tuple)) and len(res) == 3:
        return res
    if isinstance(res, dict):
        return (res.get("name"), res.get("authentication_status"), res.get("username"))
    return (None, None, None)

authenticator = setup_auth()
name, auth_status, username = auth_login(authenticator)

if authenticator is not None:
    if auth_status is False:
        st.error("Username/password is incorrect.")
        st.stop()
    elif auth_status is None:
        st.info("Please log in.")
        st.stop()
    else:
        # Sometimes a clean rerun helps show the post-login state immediately
        if not st.session_state.get("_logged_in_once"):
            st.session_state["_logged_in_once"] = True
            st.rerun()
        with st.sidebar:
            authenticator.logout("Logout", "sidebar")
            st.caption(f"Signed in as **{name}**")


# --- Uniform layout for metric cards + full-width buttons ---
st.markdown("""
<style>
.metric-card{
  background:#fff;
  border:1px solid #e9ecef;
  border-radius:12px;
  padding:14px 14px 10px;
  text-align:center;
  min-height:180px;
  display:flex;
  flex-direction:column;
  justify-content:space-between;
  box-shadow:0 1px 2px rgba(0,0,0,0.04);
}
.metric-title{
  font-weight:600;
  font-size:14px;
  line-height:1.3;
  min-height:42px;
  margin:0 0 6px;
}
.metric-value{
  font-weight:800;
  font-size:28px;
  line-height:1;
  margin:0 6px 8px;
}
.metric-sub{
  text-align:left;
  font-size:13px;
  color:#2f2f2f;
  margin-top:2px;
}
.metric-sub ul{
  margin:0;
  padding-left:18px;
  list-style:disc;
  max-height:90px;
  overflow:auto;
}
.metric-sub li{ margin:2px 0; }
section.main .stButton > button { width:100%; border-radius:10px; }
</style>
""", unsafe_allow_html=True)

# ==========================
# Helpers
# ==========================
def normalize_json_url(url: str) -> str:
    """Rewrite JSONBlob share URLs to the raw API endpoint."""
    try:
        u = urllib.parse.urlparse(url)
    except Exception:
        return url
    if u.netloc.endswith("jsonblob.com"):
        parts = [p for p in u.path.split("/") if p]
        if len(parts) == 1 and parts[0].isdigit():
            return f"{u.scheme}://{u.netloc}/api/jsonBlob/{parts[0]}"
        if len(parts) == 2 and parts[0].lower() == "jsonblob" and parts[1].isdigit():
            return f"{u.scheme}://{u.netloc}/api/jsonBlob/{parts[1]}"
    return url

def fetch_json(url: str) -> Dict[str, Any]:
    try:
        norm = normalize_json_url(url)
        req = urllib.request.Request(
            norm,
            headers={
                "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
                "User-Agent": "Mozilla/5.0",
            },
        )
        raw = urllib.request.urlopen(req).read().decode("utf-8", "replace").lstrip("\ufeff")
        data = json.loads(raw)
        return data
    except Exception as e:
        st.sidebar.error(f"Failed to fetch JSON: {str(e)}")
        return {}

def to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return default
        s = str(x).strip()
        if s == "":
            return default
        return int(float(s.replace(",", "")))
    except Exception:
        return default

def sum_field(rows: List[Dict[str, Any]], field: str) -> int:
    return sum(to_int(r.get(field, 0)) for r in (rows or []))

def first_field(rows: List[Dict[str, Any]], field: str) -> int:
    if not rows:
        return 0
    return to_int(rows[0].get(field, 0))

def df_from_rows(rows: List[Dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(rows or [])

def page_nav_set(page: str, table_key: str = "", table_title: str = ""):
    st.session_state["page"] = page
    st.session_state["table_key"] = table_key
    st.session_state["table_title"] = table_title

def _tokenize_path(path: str):
    parts = []
    for chunk in path.split("."):
        if not chunk:
            continue
        pos = 0
        m = re.match(r'^([^\[\]]+)', chunk)
        if m:
            parts.append(m.group(1))
            pos = m.end()
        while pos < len(chunk):
            m_idx = re.match(r'\[(\d+)\]', chunk[pos:])
            m_key = re.match(r'\[["\']([^"\']+)["\']\]', chunk[pos:])
            if m_idx:
                parts.append(int(m_idx.group(1)))
                pos += m_idx.end()
            elif m_key:
                parts.append(m_key.group(1))
                pos += m_key.end()
            else:
                rem = chunk[pos:].strip("[]")
                if rem:
                    parts.append(rem)
                break
    return parts

def _resolve_path(obj: Any, path: str):
    cur = obj
    for tok in _tokenize_path(path):
        try:
            if isinstance(tok, int):
                if isinstance(cur, list) and 0 <= tok < len(cur):
                    cur = cur[tok]
                else:
                    return None
            else:
                if isinstance(cur, dict) and tok in cur:
                    cur = cur[tok]
                else:
                    return None
        except Exception:
            return None
    return cur

def _mapping_dict(mapping_obj: Any) -> Dict[str, str]:
    if isinstance(mapping_obj, dict):
        return {str(k): str(v) for k, v in mapping_obj.items()}
    if isinstance(mapping_obj, list):
        out: Dict[str, str] = {}
        for item in mapping_obj:
            if isinstance(item, dict):
                k = item.get("key") or item.get("name") or item.get("id")
                p = item.get("path")
                if k and p:
                    out[str(k)] = str(p)
        return out
    return {}

def get_scalar(
    data: Dict[str, Any],
    mapping: Dict[str, str],
    map_key: str,
    default_paths: List[str],
    default_value: int = 0,
) -> int:
    paths = []
    if mapping and map_key in mapping:
        paths.append(mapping[map_key])
    if default_paths:
        paths.extend(default_paths)
    for p in paths:
        v = _resolve_path(data, p)
        if v is not None and not isinstance(v, (list, dict)):
            return to_int(v, default_value)
    st.session_state.setdefault("path_errors", []).append(f"Scalar path not found for {map_key}: {paths}")
    return default_value

def get_array(
    data: Dict[str, Any],
    mapping: Dict[str, str],
    map_key: str,
    default_paths: List[str],
) -> List[Dict[str, Any]]:
    paths = []
    if mapping and map_key in mapping:
        paths.append(mapping[map_key])
    if default_paths:
        paths.extend(default_paths)
    for p in paths:
        v = _resolve_path(data, p)
        if isinstance(v, list):
            return v
    st.session_state.setdefault("path_errors", []).append(f"Array path not found for {map_key}: {paths}")
    return []

def truthy(v: Any) -> bool:
    s = str(v).strip().lower()
    return v is True or s in {"1", "true", "yes", "y", "t", "on"}

def parse_chat_date(val: Any) -> str:
    """Returns date string 'YYYY-MM-DD' or '—' from ISO or date-like strings."""
    if val is None:
        return "—"
    s = str(val).strip()
    if not s:
        return "—"
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except Exception:
        pass
    if len(s) >= 10 and re.match(r"\d{4}-\d{2}-\d{2}", s):
        return s[:10]
    return s

def metric_card(title: str, value: int | str):
    st.markdown(
        f"""<div class="metric-card">
              <div class="metric-title">{title}</div>
              <div class="metric-value">{value}</div>
            </div>""",
        unsafe_allow_html=True,
    )

def metric_card_with_button(title: str, value: int|str,
                            btn_text: str|None=None, btn_key: str|None=None,
                            table_key: str|None=None, page_title: str|None=None,
                            rerun: bool=True):
    st.markdown(
        f"""<div class="metric-card">
              <div class="metric-title">{title}</div>
              <div class="metric-value">{value}</div>
            </div>""",
        unsafe_allow_html=True,
    )
    if btn_text and btn_key and table_key and page_title:
        if st.button(btn_text, key=btn_key, use_container_width=True):
            page_nav_set("table", table_key, page_title)
            if rerun: st.rerun()

def metric_list_card(title: str, total_value: int|str, items: list[str],
                     btn_text: str|None=None, btn_key: str|None=None,
                     table_key: str|None=None, page_title: str|None=None):
    ul = "".join(f"<li>{x}</li>" for x in items)
    st.markdown(
        f"""<div class="metric-card">
              <div class="metric-title">{title}</div>
              <div class="metric-value">{total_value}</div>
              <div class="metric-sub"><ul>{ul}</ul></div>
            </div>""",
        unsafe_allow_html=True,
    )
    if btn_text and btn_key and table_key and page_title:
        if st.button(btn_text, key=btn_key, use_container_width=True):
            page_nav_set("table", table_key, page_title); st.rerun()

# ==========================
# Session State
# ==========================
if "data" not in st.session_state:
    st.session_state["data"] = {}
if "page" not in st.session_state:
    st.session_state["page"] = "dashboard"  # or "table"
if "table_key" not in st.session_state:
    st.session_state["table_key"] = ""
if "table_title" not in st.session_state:
    st.session_state["table_title"] = ""
if "path_errors" not in st.session_state:
    st.session_state["path_errors"] = []
if "tables_map" not in st.session_state:
    st.session_state["tables_map"] = {}

# ==========================
# Load JSON (URL or Upload)
# ==========================
st.sidebar.header("Data Source")
src_mode = st.sidebar.radio("Choose data source", ["JSON from URL", "Upload JSON file"], index=0)
if src_mode == "JSON from URL":
    url = st.sidebar.text_input("JSON URL", value="https://jsonblob.com/1413163546090594304")
    if st.sidebar.button("Load JSON", use_container_width=True):
        try:
            st.session_state["data"] = fetch_json(url)
            if not st.session_state["data"]:
                st.sidebar.error("Empty or invalid JSON received.")
            else:
                st.sidebar.success("JSON loaded successfully.")
                st.sidebar.expander("DEBUG: Loaded JSON data").write(st.session_state["data"])
                # basic validation
                data_inner = st.session_state["data"].get("data", {})
                missing_inner = [s for s in ["users", "providers", "chats", "orders"] if s not in data_inner]
                if missing_inner:
                    st.sidebar.warning(f"Missing 'data' subsections: {', '.join(missing_inner)}")
                page_nav_set("dashboard")
                st.rerun()
        except Exception as e:
            st.sidebar.error(f"Failed to load JSON: {str(e)}")
else:
    uploaded_file = st.sidebar.file_uploader("Upload .json", type=["json"])
    if uploaded_file:
        try:
            st.session_state["data"] = json.load(uploaded_file)
            st.sidebar.success("JSON loaded successfully.")
            st.sidebar.expander("DEBUG: Loaded JSON data").write(st.session_state["data"])
            data_inner = st.session_state["data"].get("data", {})
            missing_inner = [s for s in ["users", "providers", "chats", "orders"] if s not in data_inner]
            if missing_inner:
                st.sidebar.warning(f"Missing 'data' subsections: {', '.join(missing_inner)}")
            page_nav_set("dashboard")
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Failed to read JSON: {str(e)}")

# ==========================
# Build Metrics (mapping-aware)
# ==========================
data = st.session_state["data"] or {}
mapping = _mapping_dict(data.get("mapping") or data.get("mappings"))
if not mapping:
    st.sidebar.warning("JSON is missing 'mapping' or 'mappings' section. Using default paths only.")
st.sidebar.expander("DEBUG: Mapping dictionary").write(mapping)

# Reset path errors for this run
st.session_state["path_errors"] = []

# Users
total_users = first_field(
    get_array(data, mapping, "user.total", default_paths=["data.users.totalUsers"]),
    "total_users"
)
users_registered = get_array(
    data, mapping, "user.usersRegistered",
    default_paths=["data.users.usersRegistered"],
)
mobile = sum(to_int(r.get("total_users", 0)) for r in users_registered
             if truthy(r.get("mobile_verified")) and not truthy(r.get("email_verified")))
email  = sum(to_int(r.get("total_users", 0)) for r in users_registered
             if truthy(r.get("email_verified")) and not truthy(r.get("mobile_verified")))
both   = sum(to_int(r.get("total_users", 0)) for r in users_registered
             if truthy(r.get("email_verified")) and truthy(r.get("mobile_verified")))
attempted_not_registered = first_field(
    get_array(data, mapping, "user.totalUnverified", default_paths=["data.users.usersWithUnverified"]),
    "total_users_with_unverified"
)
# list used by "Attempted but not registered" → View results
users_attempted_login = get_array(
    data, mapping, "user.usersAttemptedLogin",
    default_paths=["data.users.usersAttemptedLogin", "users.usersAttemptedLogin"],
)

# Providers
providers_by_status = get_array(
    data, mapping, "providers.providersByStatus",
    default_paths=["data.providers.providersByStatus"],
)
providers_by_country = get_array(
    data, mapping, "providers.providersByCountry",
    default_paths=["data.providers.providersByCountry"],
)
providers_registered_by_company = get_array(
    data, mapping, "providers.registeredByCompany",
    default_paths=["data.providers.providersRegisteredByCompany"],
)
providers_rejected = get_array(
    data, mapping, "providers.rejected",
    default_paths=["data.providers.providersRejected"],
)
pending_review = get_array(
    data, mapping, "providers.pendingReview",
    default_paths=["data.providers.providersPendingReview"],
)
providers_with_bank_details = get_array(
    data, mapping, "providers.withBankDetails",
    default_paths=["data.providers.providersWithBankDetails"],
)
providers_bank_not_active = get_array(
    data, mapping, "providers.bankNotActive",
    default_paths=["data.providers.providersBankNotActive"],
)
rejected_total = sum_field(providers_rejected, "total_providers")
pending_review_total = sum_field(pending_review, "total_providers")
with_bank_details = first_field(providers_with_bank_details, "providers_with_bank_details")
bank_not_active = first_field(providers_bank_not_active, "providers_bank_not_active")

# Services & Products
providers_by_ps = get_array(
    data, mapping, "providers.byProductsServices",
    default_paths=["data.providers.providersByProductsServices"],
)
total_services = sum_field(providers_by_ps, "totalServices")
total_products = sum_field(providers_by_ps, "totalProducts")
submitted_not_active = get_array(
    data, mapping, "providers.submittedNotActive",
    default_paths=["data.providers.providersSubmittedNotActive"],
)
kyc_na_services = sum_field(submitted_not_active, "totalServices")
kyc_na_products = sum_field(submitted_not_active, "totalProducts")

# Chats
active_chats_yday = get_array(
    data, mapping, "chats.activeChatsYesterday",
    default_paths=["data.chats.activeChatsYesterday"],
)

# total unique chats till yesterday (scalar OR array fallback)
# --- Total unique chats till yesterday: same structure as "Last day chats"
total_chats_till_yday_rows = get_array(
    data, mapping, "chats.totalChatsTillYesterday",
    default_paths=["data.chats.totalChatsTillYesterday", "chats.totalChatsTillYesterday"],
)

till_yday_date = parse_chat_date(total_chats_till_yday_rows[0].get("activity_date")) if total_chats_till_yday_rows else "—"
till_yday_prod = sum_field(total_chats_till_yday_rows, "productChatCount")
till_yday_serv = sum_field(total_chats_till_yday_rows, "serviceChatCount")
till_yday_job  = sum_field(total_chats_till_yday_rows, "jobChatCount")

# (Optional) If you still want a single total number, you can compute:
till_yday_total = till_yday_prod + till_yday_serv + till_yday_job


chat_date = active_chats_yday[0].get("activity_date") if active_chats_yday else ""
chat_date_str = parse_chat_date(chat_date)
prod_chat = sum_field(active_chats_yday, "productChatCount")
serv_chat = sum_field(active_chats_yday, "serviceChatCount")
job_chat  = sum_field(active_chats_yday, "jobChatCount")

# Orders summary & detail arrays
order_summary = get_array(
    data, mapping, "orders.orderSummary",
    default_paths=["data.orders.orderSummary", "orders.orderSummary"],
)
total_orders_val       = first_field(order_summary, "total_orders")
completed_orders_val   = first_field(order_summary, "completed_orders")
inprogress_orders_val  = first_field(order_summary, "inprogress_orders")
rejected_orders_val    = first_field(order_summary, "rejected_orders")
cancelled_orders_val   = first_field(order_summary, "cancelled_orders")
admin_cancelled_val    = first_field(order_summary, "admin_cancelled_orders")

# detail lists for orders (for View Results)
cancelled_orders_rows       = get_array(data, mapping, "orders.cancelledOrders",
                                       default_paths=["data.orders.cancelledOrders","orders.cancelledOrders"])
rejected_orders_rows        = get_array(data, mapping, "orders.rejectedOrders",
                                       default_paths=["data.orders.rejectedOrders","orders.rejectedOrders"])
admin_cancelled_orders_rows = get_array(data, mapping, "orders.adminCancelledOrders",
                                       default_paths=["data.orders.adminCancelledOrders","orders.adminCancelledOrders"])

# ---------- Actions detail arrays (for View Details) ----------
providers_rejected_details = get_array(
    data, mapping, "providers.rejectedDetails",
    default_paths=["data.providers.providersRejectedDetails", "providers.providersRejectedDetails"],
)
providers_review_details = get_array(
    data, mapping, "providers.reviewDetails",
    default_paths=["data.providers.providersReviewDetails", "providers.providersReviewDetails"],
)
providers_active_missing_bank = get_array(
    data, mapping, "providers.activeMissingBank",
    default_paths=["data.providers.providersActiveMissingBank", "providers.providersActiveMissingBank"],
)
providers_attempted_kyc_not_submitted = get_array(
    data, mapping, "providers.attemptedKycNotSubmitted",
    default_paths=["data.providers.providersAttemptedKycNotSubmitted", "providers.providersAttemptedKycNotSubmitted"],
)
providers_not_active_with_services = get_array(
    data, mapping, "providers.notActiveWithServices",
    default_paths=["data.providers.providersNotActiveWithServices", "providers.providersNotActiveWithServices"],
)

# Prefer detail-list lengths where applicable
rejected_total = len(providers_rejected_details) or rejected_total
pending_review_total = len(providers_review_details) or pending_review_total
bank_not_active = len(providers_active_missing_bank) or bank_not_active
attempted_kyc_not_completed = len(providers_attempted_kyc_not_submitted)
offerings_without_kyc_active = len(providers_not_active_with_services)

# ----- Persist table datasets for the table view (avoid NameError on reruns) -----
st.session_state["tables_map"] = {
    # Users
    "usersAttemptedLogin": users_attempted_login,

    # Actions (SITHA ADMIN team)
    "providersRejectedDetails": providers_rejected_details,
    "providersReviewDetails": providers_review_details,
    "providersActiveMissingBank": providers_active_missing_bank,
    "providersAttemptedKycNotSubmitted": providers_attempted_kyc_not_submitted,
    "providersNotActiveWithServices": providers_not_active_with_services,

    # Orders
    "cancelledOrders": cancelled_orders_rows,
    "rejectedOrders": rejected_orders_rows,
    "adminCancelledOrders": admin_cancelled_orders_rows,
}

# ==========================
# PDF Export (single page)
# ==========================
def make_leadership_pdf_bytes() -> bytes:
    buf = io.BytesIO()

    # ----- Text-only fallback if reportlab is not installed -----
    if not REPORTLAB_OK:
        text = io.StringIO()
        text.write("Leadership Summary\n\n")
        text.write(f"Users: Total={total_users}, Mobile={mobile}, Email={email}, Both={both}, Attempted Not Registered={attempted_not_registered}\n")
        text.write("Provider status: " + ", ".join(
            f"{r.get('status')}={to_int(r.get('total_providers'))}" for r in (providers_by_status or [])
        ) + "\n")
        text.write(f"Actions: Rejected={rejected_total}, Pending Review={pending_review_total}, Bank Done={with_bank_details}, Bank Not Active={bank_not_active}\n")
        text.write(f"Services/Products: Services={total_services}, Products={total_products}, KYC-NA Services={kyc_na_services}, KYC-NA Products={kyc_na_products}\n")
        text.write(f"Chats (yday {chat_date_str}): Product={prod_chat}, Service={serv_chat}, Job={job_chat}\n")
        # <<< use the new breakdown vars here >>>
        text.write(f"Total unique chats till yesterday ({till_yday_date}): "
                   f"Products={till_yday_prod}, Services={till_yday_serv}, Jobs={till_yday_job}\n")
        text.write(f"Orders: Total={total_orders_val}, Completed={completed_orders_val}, "
                   f"In Progress={inprogress_orders_val}, Rejected={rejected_orders_val}, "
                   f"Cancelled={cancelled_orders_val}, Admin Cancelled={admin_cancelled_val}\n")
        return text.getvalue().encode("utf-8")

    # ----- Pretty single-page PDF with ReportLab -----
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    x = 2 * cm
    y = height - 2 * cm
    line_gap = 0.7 * cm

    def draw_header(title):
        nonlocal y
        c.setFont("Helvetica-Bold", 16); c.drawString(x, y, title); y -= line_gap

    def draw_line(text_str):
        nonlocal y
        c.setFont("Helvetica", 11); c.drawString(x, y, text_str); y -= 0.55 * cm

    c.setFont("Helvetica-Bold", 18); c.drawString(x, y, "Leadership Summary"); y -= 1.0 * cm

    draw_header("User")
    draw_line(f"Total: {total_users}")
    draw_line(f"Register via → Mobile: {mobile}, Email: {email}, Both: {both}")
    draw_line(f"Attempted but not registered: {attempted_not_registered}")
    y -= 0.3 * cm

    draw_header("Provider")
    if providers_by_status:
        parts = [f"{r.get('status')}: {to_int(r.get('total_providers'))}" for r in providers_by_status]
        draw_line("# providers with status → " + ", ".join(parts))
    y -= 0.3 * cm

    draw_header("Actions on SITHA ADMIN team")
    draw_line(f"REJECTED: {rejected_total}")
    draw_line(f"Pending review by Type: {pending_review_total}")
    draw_line(f"KYC pending but Bank Done: {with_bank_details}")
    draw_line(f"Missing bank details for provider: {bank_not_active}")
    y -= 0.3 * cm

    draw_header("Services and products")
    draw_line(f"Services: {total_services} | Products: {total_products}")
    draw_line(f"KYC Not active but services: {kyc_na_services}")
    draw_line(f"KYC not active but products: {kyc_na_products}")
    y -= 0.3 * cm

    draw_header("CHATS")
    draw_line(f"Last day ({chat_date_str}) → Products: {prod_chat}, Services: {serv_chat}, Jobs: {job_chat}")
    # <<< use the new breakdown vars here >>>
    draw_line(f"Total unique chats till yesterday ({till_yday_date}) → "
              f"Products: {till_yday_prod}, Services: {till_yday_serv}, Jobs: {till_yday_job}")
    y -= 0.3 * cm

    draw_header("Summary of Orders")
    draw_line(f"Total: {total_orders_val}")
    draw_line(f"Completed: {completed_orders_val}")
    draw_line(f"In-Progress: {inprogress_orders_val}")
    draw_line(f"Rejected: {rejected_orders_val}")
    draw_line(f"Cancelled: {cancelled_orders_val}")
    draw_line(f"Admin Cancelled: {admin_cancelled_val}")

    c.showPage(); c.save()
    return buf.getvalue()

# ==========================
# View pages
# ==========================
def render_table_page():
    st.title(st.session_state.get("table_title") or "Results")
    key = st.session_state.get("table_key") or ""
    table_map = st.session_state.get("tables_map", {})
    rows = table_map.get(key, [])
    st.expander("DEBUG: Table data for key " + key).write(rows)
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        st.dataframe(df_from_rows(rows), use_container_width=True)
    else:
        st.info("No tabular results available.")
    if st.button("⬅ Back to Leadership", use_container_width=True):
        page_nav_set("dashboard")
        st.rerun()

# ==========================
# Dashboard
# ==========================
def render_dashboard():
    if not data:
        st.warning("No data loaded. Please load a valid JSON file or URL from the sidebar.")
        return

    st.title("Leadership Summary")

    # ---------- User ----------
    st.header("User")
    u1, u2, u3 = st.columns(3)

    with u1:
        metric_card_with_button("Total", total_users)

    with u2:
        reg_total = mobile + email + both
        reg_items = [
            f"Mobile: <strong>{mobile}</strong>",
            f"Email: <strong>{email}</strong>",
            f"Both: <strong>{both}</strong>",
        ]
        metric_list_card("Register via", reg_total, reg_items)

    with u3:
        st.markdown("**Attempted but not registered**")
        st.markdown(f"<div style='font-size:28px;font-weight:700'>{attempted_not_registered}</div>", unsafe_allow_html=True)
        if st.button("View results", key="view_attempted_login", use_container_width=True):
            page_nav_set("table", "usersAttemptedLogin", "Users — Attempted but not registered")
            st.rerun()

    # ---------- Provider ----------
    st.divider()
    st.header("Provider")
    p1, p2, p3 = st.columns(3)

    with p1:
        status_total = sum_field(providers_by_status, "total_providers")
        status_items = [f"{r.get('status')}: <strong>{to_int(r.get('total_providers'))}</strong>"
                        for r in providers_by_status]
        metric_list_card("# providers with status", status_total, status_items)

    with p2:
        country_total = sum_field(providers_by_country, "Total_Providers")
        country_items = [f"{r.get('Country') or '—'}, {r.get('Status')}: "
                         f"<strong>{to_int(r.get('Total_Providers'))}</strong>"
                         for r in providers_by_country[:12]]
        metric_list_card("By country", country_total, country_items)

    with p3:
        by_company_total = sum_field(providers_registered_by_company, "total_providers")
        by_company_items = [f"{str(r.get('company_type')).upper()}: "
                            f"<strong>{to_int(r.get('total_providers'))}</strong>"
                            for r in providers_registered_by_company]
        metric_list_card("Providers type registered (FYI)", by_company_total, by_company_items)

    # ---------- Actions on SITHA ADMIN team ----------
    st.divider()
    st.header("Actions on SITHA ADMIN team")

    cols = st.columns(5)
    items = [
        ("REJECTED", rejected_total, "View Details",
         "providersRejectedDetails", "Rejected Providers (Details)", "btn_rejected_details"),
        ("Pending review per Group", pending_review_total, "View Details",
         "providersReviewDetails", "Pending Review (Details)", "btn_review_details"),
        ("Providers Attempted KYC but not completed", attempted_kyc_not_completed, "View Details",
         "providersAttemptedKycNotSubmitted", "Attempted KYC - Not Completed", "btn_attempted_kyc"),
        ("Missing bank details for ACTIVE provider", bank_not_active, "View Details",
         "providersActiveMissingBank", "Active Providers - Missing Bank", "btn_active_missing_bank"),
        ("Offerings without KYC Active", offerings_without_kyc_active, "View Results",
         "providersNotActiveWithServices", "Offerings without KYC Active", "btn_not_active_with_services"),
    ]
    for col, (title, value, btn_text, table_key, page_title, btn_key) in zip(cols, items):
        with col:
            metric_card_with_button(title, value, btn_text, btn_key, table_key, page_title)

    # ---------- Services and products ----------
    st.divider()
    st.header("Services and products")
    s1, s2, s3, s4 = st.columns(4)
    with s1: metric_card_with_button("Services", total_services)
    with s2: metric_card_with_button("Products", total_products)
    with s3: metric_card_with_button("KYC Not active but services", kyc_na_services)
    with s4: metric_card_with_button("KYC not active but products", kyc_na_products)

    # ---------- CHATS ----------
    st.divider()
    st.header("CHATS")
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("**Last day chats**")
        st.markdown(f"- Date: **{chat_date_str}**")
        st.markdown(f"- Products: **{prod_chat}**")
        st.markdown(f"- Services: **{serv_chat}**")
        st.markdown(f"- Jobs: **{job_chat}**")

    with c2:
        st.markdown("**Total unique Chats till Yesterday**")
        st.markdown(f"- Date: **{till_yday_date}**")
        st.markdown(f"- Products: **{till_yday_prod}**")
        st.markdown(f"- Services: **{till_yday_serv}**")
        st.markdown(f"- Jobs: **{till_yday_job}**")

    # ---------- Summary of Orders ----------
    st.divider()
    st.header("Summary of Orders")
    o1, o2, o3, o4, o5, o6 = st.columns(6)
    with o1: metric_card_with_button("Total Orders",     total_orders_val)
    with o2: metric_card_with_button("Completed",        completed_orders_val)
    with o3: metric_card_with_button("In-Progress",      inprogress_orders_val)
    with o4: metric_card_with_button("Rejected",         rejected_orders_val,
                                     "View Results", "btn_rejected_orders",
                                     "rejectedOrders", "Orders — Rejected")
    with o5: metric_card_with_button("Cancelled",        cancelled_orders_val,
                                     "View Results", "btn_cancelled_orders",
                                     "cancelledOrders", "Orders — Cancelled")
    with o6: metric_card_with_button("Admin Cancelled",  admin_cancelled_val,
                                     "View Results", "btn_admin_cancelled_orders",
                                     "adminCancelledOrders", "Orders — Admin Cancelled")

    # ---------- Export ----------
    st.divider()
    left, right = st.columns([1, 3])
    with left:
        pdf_bytes = make_leadership_pdf_bytes()
        st.download_button(
            label="⬇ Download Leadership PDF",
            data=pdf_bytes,
            file_name="leadership_summary.pdf",
            mime="application/pdf" if REPORTLAB_OK else "text/plain",
            use_container_width=True,
        )
    with right:
        if not REPORTLAB_OK:
            st.info("PDF export using ReportLab is optional. Install with `pip install reportlab` for a nicer PDF.")

# ==========================
# Router
# ==========================
if st.session_state["page"] == "table":
    render_table_page()
else:
    render_dashboard()
