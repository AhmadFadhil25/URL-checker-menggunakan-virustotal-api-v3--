"""
Virexa — Domain Threat Scanner
Streamlit app that checks domains/URLs against VirusTotal API v3.
"""

import base64
import io
import os
import time
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from openpyxl import load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side

# ============================================================
# CONFIG
# ============================================================
VT_BASE_URL           = "https://www.virustotal.com/api/v3"
VT_THRESHOLD_DEFAULT  = 2
POLL_MAX_ATTEMPTS     = 4
POLL_INTERVAL_SECONDS = 6
REQUEST_TIMEOUT       = 30
MIN_REQUEST_INTERVAL  = 16          # 4 req/min public VT API
CHECKPOINT_FILE       = "vt_checkpoint.csv"

STATUS_MALICIOUS  = "MALICIOUS"
STATUS_PHISHING   = "PHISHING"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_CLEAN      = "BERSIH"
STATUS_PENDING    = "SCAN BELUM SELESAI"
STATUS_ERROR      = "ERROR"

STATUS_FILL_MAP = {
    STATUS_MALICIOUS:  ("C0392B", "FFFFFF"),
    STATUS_PHISHING:   ("D4560A", "FFFFFF"),
    STATUS_SUSPICIOUS: ("F0A500", "1C1608"),
    STATUS_CLEAN:      ("FFFFFF", "000000"),
    STATUS_PENDING:    ("F5F5F5", "888888"),
    STATUS_ERROR:      ("FFE5E5", "CC0000"),
}

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Root & body ── */
:root {
    --bg0: #0f1117;
    --bg1: #171b24;
    --bg2: #1e2330;
    --bg3: #252b3b;
    --border: #2a3148;
    --text:   #e2e8f0;
    --muted:  #7c8db0;
    --red:    #c0392b;
    --orange: #d4560a;
    --amber:  #d4930a;
    --green:  #27ae60;
    --accent: #c0392b;
}

html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg0) !important;
    color: var(--text) !important;
    font-family: 'Space Grotesk', sans-serif !important;
}

[data-testid="stApp"] {
    background: var(--bg0) !important;
}

/* ── Header ── */
h1, h2, h3, h4 {
    font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 700 !important;
    color: var(--text) !important;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: var(--bg1) !important;
    border-right: 1px solid var(--border) !important;
}

[data-testid="stSidebar"] * {
    color: var(--text) !important;
}

/* ── Inputs ── */
[data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input,
[data-testid="stTextArea"] textarea {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    border-radius: 8px !important;
    font-family: 'Space Grotesk', sans-serif !important;
}

[data-testid="stTextInput"] input:focus,
[data-testid="stNumberInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px rgba(192,57,43,0.25) !important;
}

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background: var(--bg2) !important;
    border: 2px dashed var(--border) !important;
    border-radius: 12px !important;
    padding: 16px !important;
}

[data-testid="stFileUploader"]:hover {
    border-color: var(--accent) !important;
}

/* ── Buttons ── */
[data-testid="stButton"] button {
    background: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    border-radius: 8px !important;
    font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 600 !important;
    transition: all 0.2s !important;
}

[data-testid="stButton"] button:hover {
    border-color: var(--accent) !important;
    background: var(--bg3) !important;
}

[data-testid="stButton"] button[kind="primary"] {
    background: var(--accent) !important;
    border-color: var(--accent) !important;
    color: #fff !important;
}

[data-testid="stButton"] button[kind="primary"]:hover {
    background: #a93226 !important;
}

/* ── Download button ── */
[data-testid="stDownloadButton"] button {
    background: var(--green) !important;
    border-color: var(--green) !important;
    color: #fff !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
}

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: var(--bg1) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 16px 20px !important;
}

[data-testid="stMetricValue"] {
    color: var(--text) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 2rem !important;
}

[data-testid="stMetricLabel"] {
    color: var(--muted) !important;
    font-size: 0.8rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}

/* ── Tabs ── */
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid var(--border) !important;
    gap: 4px !important;
}

[data-testid="stTabs"] [role="tab"] {
    background: transparent !important;
    color: var(--muted) !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 600 !important;
    padding: 8px 16px !important;
}

[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: var(--accent) !important;
    border-bottom-color: var(--accent) !important;
    background: transparent !important;
}

/* ── Progress bar ── */
[data-testid="stProgress"] > div > div {
    background: var(--accent) !important;
}

/* ── Alerts ── */
[data-testid="stAlert"] {
    border-radius: 8px !important;
    background: var(--bg2) !important;
}

/* ── Divider ── */
hr {
    border-color: var(--border) !important;
}

/* ── Custom VT table ── */
.vt-wrap {
    overflow-x: auto;
    border-radius: 12px;
    border: 1px solid var(--border);
    margin-top: 12px;
}

.vt-table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 0.88rem;
}

.vt-table th {
    background: #1e2330;
    color: #7c8db0;
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 12px 16px;
    border-bottom: 1px solid #2a3148;
    white-space: nowrap;
    text-align: left;
}

.vt-table td {
    padding: 10px 16px;
    border-bottom: 1px solid #1e2330;
    color: #e2e8f0;
    vertical-align: middle;
}

.vt-table tr:last-child td { border-bottom: none; }

.vt-table tr.row-mal  { background: rgba(192,57,43,0.12); }
.vt-table tr.row-phi  { background: rgba(212,86,10,0.12); }
.vt-table tr.row-sus  { background: rgba(212,147,10,0.10); }
.vt-table tr.row-ok   { background: transparent; }
.vt-table tr.row-pend { background: rgba(255,255,255,0.03); }
.vt-table tr.row-err  { background: rgba(255,80,80,0.07); }

.vt-table tr:hover { filter: brightness(1.08); }

.vt-table .domain-cell {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    max-width: 340px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.vt-table .score-cell {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    white-space: nowrap;
}

/* ── Badges ── */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    white-space: nowrap;
}

.b-mal  { background: #c0392b; color: #fff; }
.b-phi  { background: #d4560a; color: #fff; }
.b-sus  { background: #d4930a; color: #1c1608; }
.b-ok   { background: rgba(39,174,96,0.18); color: #2ecc71; border: 1px solid rgba(39,174,96,0.3); }
.b-pend { background: rgba(255,255,255,0.07); color: #7c8db0; }
.b-err  { background: rgba(255,80,80,0.15); color: #ff6b6b; }

/* ── Source pill ── */
.src-pill {
    font-size: 0.7rem;
    color: #7c8db0;
    font-family: 'JetBrains Mono', monospace;
}

/* ── App title ── */
.virexa-title {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 4px;
}

.virexa-title .shield { font-size: 2rem; }

.virexa-title h1 {
    margin: 0 !important;
    font-size: 1.9rem !important;
    background: linear-gradient(90deg, #e2e8f0, #c0392b);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
</style>
"""


# ============================================================
# CHECKPOINT MANAGEMENT
# ============================================================
def load_checkpoint() -> dict:
    if not os.path.exists(CHECKPOINT_FILE):
        return {}
    try:
        df = pd.read_csv(CHECKPOINT_FILE)
        results = {}
        for _, row in df.iterrows():
            qname = str(row["qname"]).strip()
            mal  = None if pd.isna(row.get("malicious",  float("nan"))) else int(row["malicious"])
            sus  = None if pd.isna(row.get("suspicious", float("nan"))) else int(row["suspicious"])
            tot  = None if pd.isna(row.get("total_engines", float("nan"))) else int(row["total_engines"])
            results[qname] = {
                "malicious":     mal,
                "suspicious":    sus,
                "total_engines": tot,
                "status":        str(row.get("status", "")),
                "source":        str(row.get("source", "")),
            }
        return results
    except Exception:
        return {}


def append_checkpoint(qname: str, result: dict):
    file_exists = os.path.exists(CHECKPOINT_FILE)
    df_row = pd.DataFrame([{
        "qname":         qname,
        "malicious":     "" if result.get("malicious") is None else result["malicious"],
        "suspicious":    "" if result.get("suspicious") is None else result["suspicious"],
        "total_engines": "" if result.get("total_engines") is None else result["total_engines"],
        "status":        result.get("status", ""),
        "source":        result.get("source", ""),
    }])
    df_row.to_csv(CHECKPOINT_FILE, mode="a", header=not file_exists, index=False)


# ============================================================
# VIRUSTOTAL LOGIC
# ============================================================
_last_request_time = 0.0


def get_default_api_key() -> str:
    try:
        key = st.secrets.get("VT_API_KEY", "")
    except Exception:
        key = ""
    if not key:
        key = os.environ.get("VT_API_KEY", "")
    return str(key).strip()


def throttle(interval: float):
    global _last_request_time
    if interval <= 0:
        return
    if _last_request_time > 0:
        elapsed   = time.monotonic() - _last_request_time
        remaining = interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
    _last_request_time = time.monotonic()


def vt_request(session, method, endpoint, interval, **kwargs):
    throttle(interval)
    response = session.request(
        method,
        f"{VT_BASE_URL}{endpoint}",
        timeout=REQUEST_TIMEOUT,
        **kwargs,
    )
    if response.status_code == 401:
        raise RuntimeError("API key VirusTotal tidak valid.")
    if response.status_code == 429:
        raise RuntimeError("Rate limit VT (HTTP 429) tercapai.")
    return response


def url_to_vt_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def normalize_qname(value: str) -> str:
    value = str(value).strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        return "https://" + value
    return value


def determine_status(malicious: int, suspicious: int, is_phishing_category: bool, threshold: int) -> str:
    if malicious > threshold and is_phishing_category:
        return STATUS_PHISHING
    if malicious > threshold:
        return STATUS_MALICIOUS
    if suspicious > 0:
        return STATUS_SUSPICIOUS
    return STATUS_CLEAN


def get_existing_url_report(session, url: str, interval: float) -> dict | None:
    vt_id    = url_to_vt_id(url)
    response = vt_request(session, "GET", f"/urls/{vt_id}", interval)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    data       = response.json().get("data", {})
    attrs      = data.get("attributes", {})
    stats      = attrs.get("last_analysis_stats", {})
    malicious  = int(stats.get("malicious",  0))
    suspicious = int(stats.get("suspicious", 0))
    undetected = int(stats.get("undetected", 0))
    harmless   = int(stats.get("harmless",   0))
    total      = malicious + suspicious + undetected + harmless

    # Detect phishing category from per-engine results
    analysis_results   = attrs.get("last_analysis_results", {})
    is_phishing_cat    = any(
        str(eng.get("category", "")).lower() == "phishing"
        for eng in analysis_results.values()
        if eng.get("category")
    )

    return {
        "malicious":     malicious,
        "suspicious":    suspicious,
        "total_engines": total,
        "is_phishing":   is_phishing_cat,
    }


def submit_url_scan(session, url: str, interval: float) -> str:
    response = vt_request(session, "POST", "/urls", interval, data={"url": url})
    response.raise_for_status()
    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        raise RuntimeError("VT tidak mengembalikan Analysis ID.")
    return analysis_id


def get_analysis_result(session, analysis_id: str, interval: float) -> dict:
    for attempt in range(1, POLL_MAX_ATTEMPTS + 1):
        response = vt_request(session, "GET", f"/analyses/{analysis_id}", interval)
        response.raise_for_status()
        attrs = response.json().get("data", {}).get("attributes", {})

        if attrs.get("status") == "completed":
            stats      = attrs.get("stats", {})
            malicious  = int(stats.get("malicious",  0))
            suspicious = int(stats.get("suspicious", 0))
            total      = sum(stats.values())
            return {
                "malicious":     malicious,
                "suspicious":    suspicious,
                "total_engines": total,
                "is_phishing":   False,   # category info not in analysis response
                "source":        "scan baru",
            }

        if attempt < POLL_MAX_ATTEMPTS:
            time.sleep(POLL_INTERVAL_SECONDS)

    return {
        "malicious":     None,
        "suspicious":    None,
        "total_engines": None,
        "is_phishing":   False,
        "source":        "scan baru",
        "status":        STATUS_PENDING,
    }


def check_virustotal(session, qname: str, threshold: int, interval: float) -> dict:
    scan_url = normalize_qname(qname)
    existing = get_existing_url_report(session, scan_url, interval)

    if existing is not None:
        status = determine_status(
            existing["malicious"],
            existing["suspicious"],
            existing["is_phishing"],
            threshold,
        )
        return {
            "malicious":     existing["malicious"],
            "suspicious":    existing["suspicious"],
            "total_engines": existing["total_engines"],
            "status":        status,
            "source":        "database VT",
        }

    # Submit new scan
    analysis_id = submit_url_scan(session, scan_url, interval)
    result      = get_analysis_result(session, analysis_id, interval)

    if result.get("status") == STATUS_PENDING:
        return result

    status = determine_status(
        result["malicious"],
        result["suspicious"],
        result["is_phishing"],
        threshold,
    )
    result["status"] = status
    return result


# ============================================================
# FILE READING
# ============================================================
def read_uploaded_table(uploaded_file) -> pd.DataFrame:
    filename = getattr(uploaded_file, "name", "") or ""
    ext      = Path(filename).suffix.lower()

    if ext == ".csv":
        for enc in (None, "latin-1"):
            try:
                uploaded_file.seek(0)
                kw = {"encoding": enc} if enc else {}
                return pd.read_csv(uploaded_file, sep=None, engine="python", **kw)
            except Exception:
                continue
        uploaded_file.seek(0)
        return pd.read_csv(uploaded_file)
    elif ext in (".xlsx", ".xls"):
        return pd.read_excel(uploaded_file)
    else:
        try:
            uploaded_file.seek(0)
            return pd.read_excel(uploaded_file)
        except Exception:
            uploaded_file.seek(0)
            return pd.read_csv(uploaded_file, sep=None, engine="python")


def group_qnames(uploaded_file) -> pd.DataFrame:
    df         = read_uploaded_table(uploaded_file)
    df.columns = [str(c).strip().lower() for c in df.columns]

    if "qname" not in df.columns:
        alt = [c for c in df.columns if "qname" in c or "domain" in c or "url" in c]
        if alt:
            df.rename(columns={alt[0]: "qname"}, inplace=True)
        else:
            raise ValueError("Kolom 'qname' tidak ditemukan di file.")

    df["qname"] = df["qname"].astype(str).str.strip()
    df          = df[df["qname"].ne("") & df["qname"].ne("nan")].copy()

    if "count" in df.columns:
        df["count"] = pd.to_numeric(df["count"], errors="coerce").fillna(0)
        if (df["count"] == 0).all():
            grouped = df.groupby("qname", as_index=False, sort=False).size()
            grouped.rename(columns={"size": "count"}, inplace=True)
        else:
            df["count"] = df["count"].apply(lambda x: 1 if x <= 0 else x)
            grouped = df.groupby("qname", as_index=False, sort=False)["count"].sum()
    else:
        grouped = df.groupby("qname", as_index=False, sort=False).size()
        grouped.rename(columns={"size": "count"}, inplace=True)

    grouped["count"] = grouped["count"].astype(int)
    return grouped


def parse_manual_input(text: str) -> pd.DataFrame:
    lines  = [l.strip() for l in text.strip().splitlines() if l.strip()]
    qnames = list(dict.fromkeys(lines))       # deduplicate, preserve order
    return pd.DataFrame({"qname": qnames, "count": [1] * len(qnames)})


# ============================================================
# EXCEL EXPORT
# ============================================================
def create_excel_result(grouped_df: pd.DataFrame, checkpoint_data: dict, threshold: int) -> bytes:
    rows = []
    for _, r in grouped_df.iterrows():
        q    = str(r["qname"])
        cnt  = int(r["count"])
        info = checkpoint_data.get(q)
        if info:
            mal = info.get("malicious")
            tot = info.get("total_engines")
            score_str = f"{mal}/{tot}" if (mal is not None and tot) else "-"
            status    = info.get("status", STATUS_PENDING)
            source    = info.get("source", "-")
        else:
            score_str = "-"
            status    = "BELUM DICEK"
            source    = "-"
        rows.append({"Domain / URL": q, "Jumlah": cnt, "Score": score_str,
                     "Status": status, "Sumber": source})

    out_df = pd.DataFrame(rows)
    output = io.BytesIO()
    out_df.to_excel(output, index=False, sheet_name="Hasil", engine="openpyxl")
    output.seek(0)

    wb    = load_workbook(output)
    ws    = wb["Hasil"]
    thin  = Side(style="thin", color="000000")
    brd   = Border(left=thin, right=thin, top=thin, bottom=thin)

    hdr_fill = PatternFill(fill_type="solid", fgColor="1E2330")
    hdr_font = Font(bold=True, color="7C8DB0")

    col_widths = {"A": 55, "B": 10, "C": 14, "D": 24, "E": 18}
    for col, w in col_widths.items():
        ws.column_dimensions[col].width = w

    for cell in ws[1]:
        cell.fill      = hdr_fill
        cell.font      = hdr_font
        cell.border    = brd
        cell.alignment = Alignment(horizontal="center", vertical="center")

    for row in range(2, ws.max_row + 1):
        status_val = str(ws.cell(row=row, column=4).value or "").strip()
        fill_bg, fill_fg = STATUS_FILL_MAP.get(status_val, ("FFFFFF", "000000"))
        fill_pat = PatternFill(fill_type="solid", fgColor=fill_bg)
        font_obj = Font(bold=(status_val in (STATUS_MALICIOUS, STATUS_PHISHING)),
                        color=fill_fg)
        for col in range(1, 6):
            cell           = ws.cell(row=row, column=col)
            cell.border    = brd
            cell.fill      = fill_pat
            cell.font      = font_obj
            h_align        = "center" if col in (2, 3) else "left"
            cell.alignment = Alignment(horizontal=h_align, vertical="center")

    ws.freeze_panes         = "A2"
    ws.auto_filter.ref      = ws.dimensions

    result = io.BytesIO()
    wb.save(result)
    result.seek(0)
    return result.getvalue()


# ============================================================
# HTML TABLE RENDER
# ============================================================
def _status_badge(status: str) -> str:
    mapping = {
        STATUS_MALICIOUS:  ("b-mal",  STATUS_MALICIOUS),
        STATUS_PHISHING:   ("b-phi",  STATUS_PHISHING),
        STATUS_SUSPICIOUS: ("b-sus",  STATUS_SUSPICIOUS),
        STATUS_CLEAN:      ("b-ok",   STATUS_CLEAN),
        STATUS_PENDING:    ("b-pend", STATUS_PENDING),
        STATUS_ERROR:      ("b-err",  STATUS_ERROR),
    }
    cls, label = mapping.get(status, ("b-pend", status or "—"))
    return f'<span class="badge {cls}">{label}</span>'


def _row_class(status: str) -> str:
    return {
        STATUS_MALICIOUS:  "row-mal",
        STATUS_PHISHING:   "row-phi",
        STATUS_SUSPICIOUS: "row-sus",
        STATUS_CLEAN:      "row-ok",
        STATUS_PENDING:    "row-pend",
        STATUS_ERROR:      "row-err",
    }.get(status, "")


def render_result_table(grouped_df: pd.DataFrame, checkpoint_data: dict) -> str:
    rows_html = ""
    for _, r in grouped_df.iterrows():
        q    = str(r["qname"])
        cnt  = int(r["count"])
        info = checkpoint_data.get(q)

        if info:
            mal    = info.get("malicious")
            tot    = info.get("total_engines")
            status = info.get("status", STATUS_PENDING)
            source = info.get("source", "-")
            score  = f"{mal}/{tot}" if (mal is not None and tot) else "—"
        else:
            status = "BELUM DICEK"
            source = "—"
            score  = "—"

        badge  = _status_badge(status)
        rc     = _row_class(status)
        src_td = f'<span class="src-pill">{source}</span>'

        rows_html += f"""
        <tr class="{rc}">
          <td class="domain-cell" title="{q}">{q}</td>
          <td style="text-align:center">{cnt}</td>
          <td class="score-cell" style="text-align:center">{score}</td>
          <td>{badge}</td>
          <td>{src_td}</td>
        </tr>"""

    return f"""
    <div class="vt-wrap">
      <table class="vt-table">
        <thead>
          <tr>
            <th>Domain / URL</th>
            <th style="text-align:center">Jumlah</th>
            <th style="text-align:center">Score</th>
            <th>Status</th>
            <th>Sumber</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
    """


# ============================================================
# SCANNING LOGIC (shared between file & manual tabs)
# ============================================================
def run_scan(grouped_df: pd.DataFrame, checkpoint_data: dict, api_key: str,
             threshold: int, interval: float):
    total_qnames = len(grouped_df)
    selesai      = sum(1 for q in grouped_df["qname"] if q in checkpoint_data)
    tersisa      = total_qnames - selesai

    if tersisa == 0:
        st.success("Semua domain sudah selesai dicek.")
        return checkpoint_data, selesai

    session = requests.Session()
    session.headers.update({
        "x-apikey":   api_key,
        "Accept":     "application/json",
        "User-Agent": "Virexa/2.0 (Streamlit)",
    })

    progress_bar = st.progress(selesai / total_qnames)
    status_box   = st.empty()

    try:
        for _, row in grouped_df.iterrows():
            qname = str(row["qname"]).strip()
            if qname in checkpoint_data:
                continue

            if not st.session_state.get("is_running", True):
                status_box.warning("Proses dihentikan.")
                break

            status_box.info(
                f"**[{selesai + 1}/{total_qnames}]** Memeriksa `{qname}`…"
            )

            try:
                result = check_virustotal(session, qname, threshold, interval)
            except Exception as err:
                result = {
                    "malicious":     None,
                    "suspicious":    None,
                    "total_engines": None,
                    "status":        f"ERROR: {str(err)[:60]}",
                    "source":        "error",
                }

            append_checkpoint(qname, result)
            checkpoint_data[qname] = result
            selesai += 1
            progress_bar.progress(selesai / total_qnames)

        st.session_state.is_running = False
        if selesai == total_qnames:
            status_box.success("✅ Semua domain selesai dicek.")
        time.sleep(0.8)
        st.rerun()

    finally:
        session.close()

    return checkpoint_data, selesai


# ============================================================
# PAGE SETUP
# ============================================================
st.set_page_config(
    page_title="Virexa — Domain Threat Scanner",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Title
st.markdown("""
<div class="virexa-title">
  <span class="shield">🛡️</span>
  <h1>Virexa</h1>
</div>
<p style="color:#7c8db0;margin-top:-4px;margin-bottom:20px;font-size:0.9rem;">
  Domain Threat Scanner — powered by VirusTotal API v3
</p>
""", unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Pengaturan")

    user_api_key = st.text_input(
        "VirusTotal API Key",
        value=get_default_api_key(),
        type="password",
        placeholder="Masukkan VT API key…",
    )
    api_key = user_api_key.strip()

    threshold = st.number_input(
        "Threshold Malicious",
        min_value=1,
        max_value=20,
        value=VT_THRESHOLD_DEFAULT,
        step=1,
        help="Jumlah engine yang mendeteksi malicious untuk dianggap ancaman.",
    )

    delay = st.number_input(
        "Delay antar request (detik)",
        min_value=5,
        max_value=60,
        value=MIN_REQUEST_INTERVAL,
        step=1,
        help="VT Public API: maks 4 req/menit, disarankan ≥16 detik.",
    )

    st.divider()
    if st.button("🗑️ Reset Checkpoint", use_container_width=True):
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
        st.success("Checkpoint dihapus.")
        st.rerun()

    st.divider()
    st.caption(
        "**Catatan:** VT Public API dibatasi 4 req/menit. "
        "Gunakan API Premium untuk pengecekan lebih cepat."
    )

# ── Session state ─────────────────────────────────────────────
if "is_running" not in st.session_state:
    st.session_state.is_running = False

# ── Main content ──────────────────────────────────────────────
tab_file, tab_manual = st.tabs(["📂 Upload File (Excel / CSV)", "✏️ Input Manual"])

# ════════════════════════════════════════════════════════════
# TAB 1 — File Upload
# ════════════════════════════════════════════════════════════
with tab_file:
    uploaded_file = st.file_uploader(
        "Upload file Excel atau CSV yang berisi kolom **qname**",
        type=["xlsx", "xls", "csv"],
        label_visibility="visible",
    )

    if uploaded_file is not None:
        try:
            grouped_df      = group_qnames(uploaded_file)
            checkpoint_data = load_checkpoint()

            total_qnames = len(grouped_df)
            selesai      = sum(1 for q in grouped_df["qname"] if q in checkpoint_data)
            tersisa      = total_qnames - selesai

            # ── Status metrics ──
            mal_count = sum(
                1 for v in checkpoint_data.values()
                if v.get("status") == STATUS_MALICIOUS
            )
            phi_count = sum(
                1 for v in checkpoint_data.values()
                if v.get("status") == STATUS_PHISHING
            )
            sus_count = sum(
                1 for v in checkpoint_data.values()
                if v.get("status") == STATUS_SUSPICIOUS
            )
            ok_count  = sum(
                1 for v in checkpoint_data.values()
                if v.get("status") == STATUS_CLEAN
            )

            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total Unik",  total_qnames)
            c2.metric("🔴 Malicious", mal_count)
            c3.metric("🟠 Phishing",  phi_count)
            c4.metric("🟡 Suspicious", sus_count)
            c5.metric("🟢 Bersih",    ok_count)

            st.markdown(f"**{selesai}/{total_qnames}** sudah dicek · **{tersisa}** tersisa")

            # ── Control buttons ──
            col_btn1, col_btn2 = st.columns([3, 1])
            with col_btn1:
                btn_label   = "▶️ Lanjutkan Pengecekan" if selesai > 0 else "🔍 Mulai Pengecekan"
                start_click = st.button(
                    btn_label,
                    type="primary",
                    use_container_width=True,
                    disabled=(tersisa == 0 or not api_key),
                    key="start_file",
                )
            with col_btn2:
                stop_click = st.button("⏹️ Hentikan", use_container_width=True, key="stop_file")

            if not api_key:
                st.warning("Masukkan API Key di panel kiri terlebih dahulu.")

            if stop_click:
                st.session_state.is_running = False

            if start_click and api_key:
                st.session_state.is_running = True

            if st.session_state.is_running and tersisa > 0:
                checkpoint_data, selesai = run_scan(
                    grouped_df, checkpoint_data, api_key, int(threshold), float(delay)
                )

            # ── Results table ──
            st.markdown(render_result_table(grouped_df, checkpoint_data),
                        unsafe_allow_html=True)

            # ── Download ──
            if selesai > 0:
                st.divider()
                excel_bytes   = create_excel_result(grouped_df, checkpoint_data, int(threshold))
                dl_label      = (
                    "⬇️ Download Excel Lengkap"
                    if tersisa == 0
                    else f"⬇️ Download Hasil Sementara ({selesai}/{total_qnames})"
                )
                st.download_button(
                    label=dl_label,
                    data=excel_bytes,
                    file_name="virexa_result.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                )

        except Exception as exc:
            st.error(f"Gagal memproses file: {exc}")

    else:
        st.info("Upload file Excel atau CSV yang berisi kolom **qname** untuk memulai.")


# ════════════════════════════════════════════════════════════
# TAB 2 — Manual Input
# ════════════════════════════════════════════════════════════
with tab_manual:
    st.markdown("Masukkan satu domain/URL per baris.")
    manual_text = st.text_area(
        "Domain / URL",
        height=200,
        placeholder="contoh.com\nhttps://domain-lain.id\nmalware-site.net",
        label_visibility="collapsed",
    )

    if manual_text.strip():
        try:
            grouped_df_m    = parse_manual_input(manual_text)
            checkpoint_data = load_checkpoint()

            total_m  = len(grouped_df_m)
            selesai_m = sum(1 for q in grouped_df_m["qname"] if q in checkpoint_data)
            tersisa_m = total_m - selesai_m

            mal_m = sum(1 for v in checkpoint_data.values() if v.get("status") == STATUS_MALICIOUS)
            phi_m = sum(1 for v in checkpoint_data.values() if v.get("status") == STATUS_PHISHING)
            sus_m = sum(1 for v in checkpoint_data.values() if v.get("status") == STATUS_SUSPICIOUS)
            ok_m  = sum(1 for v in checkpoint_data.values() if v.get("status") == STATUS_CLEAN)

            c1m, c2m, c3m, c4m, c5m = st.columns(5)
            c1m.metric("Total", total_m)
            c2m.metric("🔴 Malicious",  mal_m)
            c3m.metric("🟠 Phishing",   phi_m)
            c4m.metric("🟡 Suspicious", sus_m)
            c5m.metric("🟢 Bersih",     ok_m)

            col_m1, col_m2 = st.columns([3, 1])
            with col_m1:
                btn_m = "▶️ Lanjutkan" if selesai_m > 0 else "🔍 Periksa Sekarang"
                start_m = st.button(
                    btn_m,
                    type="primary",
                    use_container_width=True,
                    disabled=(tersisa_m == 0 or not api_key),
                    key="start_manual",
                )
            with col_m2:
                stop_m = st.button("⏹️ Hentikan", use_container_width=True, key="stop_manual")

            if not api_key:
                st.warning("Masukkan API Key di panel kiri terlebih dahulu.")

            if stop_m:
                st.session_state.is_running = False

            if start_m and api_key:
                st.session_state.is_running = True

            if st.session_state.is_running and tersisa_m > 0:
                checkpoint_data, selesai_m = run_scan(
                    grouped_df_m, checkpoint_data, api_key, int(threshold), float(delay)
                )

            st.markdown(render_result_table(grouped_df_m, checkpoint_data),
                        unsafe_allow_html=True)

            if selesai_m > 0:
                st.divider()
                excel_bytes_m = create_excel_result(grouped_df_m, checkpoint_data, int(threshold))
                st.download_button(
                    label="⬇️ Download Excel",
                    data=excel_bytes_m,
                    file_name="virexa_manual_result.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                )

        except Exception as exc:
            st.error(f"Gagal memproses input: {exc}")
    else:
        st.info("Ketik atau paste domain/URL di kotak di atas, satu per baris.")
