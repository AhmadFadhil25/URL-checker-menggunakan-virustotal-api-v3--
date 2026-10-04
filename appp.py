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
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_THRESHOLD = 2                  # malicious > 2 => phishing
POLL_MAX_ATTEMPTS = 3
POLL_INTERVAL_SECONDS = 5
REQUEST_TIMEOUT = 30

MIN_REQUEST_INTERVAL = 16         # Rate limit VT Public: 4 req/menit
CHECKPOINT_FILE = "vt_checkpoint.csv"


# ============================================================
# CHECKPOINT MANAGEMENT (FILE CSV LOKAL)
# ============================================================
def load_checkpoint() -> dict:
    """Membaca hasil pengecekan sebelumnya dari file CSV lokal."""
    if not os.path.exists(CHECKPOINT_FILE):
        return {}
    try:
        df = pd.read_csv(CHECKPOINT_FILE)
        results = {}
        for _, row in df.iterrows():
            qname = str(row["qname"]).strip()
            mal = None if pd.isna(row["malicious"]) else int(row["malicious"])
            results[qname] = {
                "malicious": mal,
                "status": str(row["status"]),
                "source": str(row["source"]),
            }
        return results
    except Exception:
        return {}


def append_checkpoint(qname: str, malicious, status: str, source: str):
    """Menyimpan hasil 1 baris langsung ke disk seketika saat pengecekan selesai."""
    file_exists = os.path.exists(CHECKPOINT_FILE)
    df_row = pd.DataFrame([{
        "qname": qname,
        "malicious": "" if malicious is None else malicious,
        "status": status,
        "source": source,
    }])
    df_row.to_csv(CHECKPOINT_FILE, mode="a", header=not file_exists, index=False)


# ============================================================
# PAGE CONFIG & STATE
# ============================================================
st.set_page_config(
    page_title="Qname VirusTotal Checker",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Qname VirusTotal Checker")
st.caption(
    "Dilengkapi auto-save per baris. Jika koneksi putus atau berhenti di tengah jalan, "
    "data terakhir langsung tersimpan dan bisa langsung diunduh."
)

if "is_running" not in st.session_state:
    st.session_state.is_running = False


# ============================================================
# VIRUSTOTAL FUNCTIONS
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


def throttle():
    global _last_request_time
    if MIN_REQUEST_INTERVAL <= 0:
        return

    if _last_request_time > 0:
        elapsed = time.monotonic() - _last_request_time
        remaining = MIN_REQUEST_INTERVAL - elapsed
        if remaining > 0:
            time.sleep(remaining)

    _last_request_time = time.monotonic()


def vt_request(session, method, endpoint, **kwargs):
    throttle()
    response = session.request(
        method,
        f"{VT_BASE_URL}{endpoint}",
        timeout=REQUEST_TIMEOUT,
        **kwargs,
    )

    if response.status_code == 401:
        raise RuntimeError("API key VirusTotal tidak valid.")

    if response.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit (HTTP 429) tercapai.")

    return response


def url_to_vt_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")


def normalize_qname(value: str) -> str:
    value = str(value).strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        return "https://" + value
    return value


def get_existing_url_report(session, url: str):
    vt_id = url_to_vt_id(url)
    response = vt_request(session, "GET", f"/urls/{vt_id}")

    if response.status_code == 404:
        return None

    response.raise_for_status()
    data = response.json().get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return int(stats.get("malicious", 0))


def submit_url_scan(session, url: str) -> str:
    response = vt_request(session, "POST", "/urls", data={"url": url})
    response.raise_for_status()
    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        raise RuntimeError("VirusTotal tidak mengembalikan Analysis ID.")
    return analysis_id


def get_analysis_result(session, analysis_id: str):
    for attempt in range(1, POLL_MAX_ATTEMPTS + 1):
        response = vt_request(session, "GET", f"/analyses/{analysis_id}")
        response.raise_for_status()

        attributes = response.json().get("data", {}).get("attributes", {})
        if attributes.get("status") == "completed":
            stats = attributes.get("stats", {})
            return int(stats.get("malicious", 0)), "scan baru"

        if attempt < POLL_MAX_ATTEMPTS:
            time.sleep(POLL_INTERVAL_SECONDS)

    return None, "scan belum selesai"


def check_virustotal(session, qname: str):
    scan_url = normalize_qname(qname)
    existing = get_existing_url_report(session, scan_url)
    if existing is not None:
        return existing, "database VT"

    analysis_id = submit_url_scan(session, scan_url)
    return get_analysis_result(session, analysis_id)


# ============================================================
# FILE READING (EXCEL & CSV)
# ============================================================
def read_uploaded_table(uploaded_file) -> pd.DataFrame:
    """Membaca file upload sebagai DataFrame, mendukung .xlsx/.xls maupun .csv."""
    filename = getattr(uploaded_file, "name", "") or ""
    ext = Path(filename).suffix.lower()

    if ext == ".csv":
        # Coba beberapa delimiter & encoding umum agar lebih toleran terhadap variasi file CSV
        uploaded_file.seek(0)
        try:
            return pd.read_csv(uploaded_file, sep=None, engine="python")
        except Exception:
            uploaded_file.seek(0)
            try:
                return pd.read_csv(uploaded_file, encoding="latin-1", sep=None, engine="python")
            except Exception:
                uploaded_file.seek(0)
                return pd.read_csv(uploaded_file)
    elif ext in (".xlsx", ".xls"):
        return pd.read_excel(uploaded_file)
    else:
        # Fallback: coba Excel dulu, kalau gagal coba CSV
        try:
            uploaded_file.seek(0)
            return pd.read_excel(uploaded_file)
        except Exception:
            uploaded_file.seek(0)
            return pd.read_csv(uploaded_file, sep=None, engine="python")


# ============================================================
# EXCEL PROCESSING
# ============================================================
def group_qnames(uploaded_file):
    df = read_uploaded_table(uploaded_file)
    df.columns = [str(c).strip().lower() for c in df.columns]

    if "qname" not in df.columns:
        alt_cols = [c for c in df.columns if "qname" in c or "domain" in c or "url" in c]
        if alt_cols:
            df.rename(columns={alt_cols[0]: "qname"}, inplace=True)
        else:
            raise ValueError("Kolom 'qname' tidak ditemukan di file.")

    df["qname"] = df["qname"].astype(str).str.strip()
    df = df[df["qname"].ne("") & df["qname"].ne("nan")].copy()

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


def create_excel(grouped_df: pd.DataFrame, phishing_qnames: set) -> bytes:
    output = io.BytesIO()
    grouped_df.to_excel(output, index=False, sheet_name="Qname", engine="openpyxl")
    output.seek(0)

    workbook = load_workbook(output)
    sheet = workbook["Qname"]

    thin_side = Side(style="thin", color="000000")
    border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    header_fill = PatternFill(fill_type="solid", fgColor="D9EAF7")
    normal_fill = PatternFill(fill_type="solid", fgColor="FFFFFF")
    phishing_fill = PatternFill(fill_type="solid", fgColor="C00000")

    header_font = Font(bold=True, color="000000")
    normal_font = Font(bold=False, color="000000")
    phishing_font = Font(bold=True, color="FFFFFF")

    for cell in sheet[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.border = border
        cell.alignment = Alignment(horizontal="center", vertical="center")

    for row in range(2, sheet.max_row + 1):
        qname = str(sheet.cell(row=row, column=1).value).strip()
        is_phishing = qname in phishing_qnames

        for col in range(1, 3):
            cell = sheet.cell(row=row, column=col)
            cell.border = border
            cell.alignment = Alignment(
                horizontal="center" if col == 2 else "left",
                vertical="center",
            )
            if is_phishing:
                cell.fill = phishing_fill
                cell.font = phishing_font
            else:
                cell.fill = normal_fill
                cell.font = normal_font

    sheet.column_dimensions["A"].width = 55
    sheet.column_dimensions["B"].width = 14
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions

    result = io.BytesIO()
    workbook.save(result)
    result.seek(0)
    return result.getvalue()


# ============================================================
# STREAMLIT UI
# ============================================================
with st.sidebar:
    st.header("⚙️ Pengaturan")
    user_api_key = st.text_input(
        "VirusTotal API Key",
        value=get_default_api_key(),
        type="password",
    )
    api_key = user_api_key.strip()

    st.divider()
    if st.button("🗑️ Reset & Hapus Checkpoint"):
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
        st.success("File checkpoint berhasil dihapus.")
        st.rerun()

uploaded_file = st.file_uploader("Upload Excel atau CSV", type=["xlsx", "xls", "csv"])

if uploaded_file is not None:
    try:
        grouped_df = group_qnames(uploaded_file)
        
        # Load progress terakhir dari file checkpoint lokal
        checkpoint_data = load_checkpoint()

        total_qnames = len(grouped_df)
        selesai = sum(1 for q in grouped_df["qname"] if q in checkpoint_data)
        tersisa = total_qnames - selesai

        st.subheader("Status Antrean")
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Qname Unik", total_qnames)
        m2.metric("Selesai Dicek", selesai)
        m3.metric("Belum Dicek", tersisa)

        st.dataframe(grouped_df, use_container_width=True, hide_index=True)

        if not api_key:
            st.warning("Masukkan API Key di panel kiri terlebih dahulu.")
            st.stop()

        col_btn1, col_btn2 = st.columns([3, 1])
        with col_btn1:
            btn_text = "▶️ Lanjutkan Pengecekan" if selesai > 0 else "🔍 Mulai Pengecekan"
            start_clicked = st.button(
                btn_text,
                type="primary",
                use_container_width=True,
                disabled=(tersisa == 0),
            )
        with col_btn2:
            stop_clicked = st.button("⏹️ Hentikan", use_container_width=True)

        if stop_clicked:
            st.session_state.is_running = False
            st.warning("Proses dihentikan oleh pengguna.")

        if start_clicked:
            st.session_state.is_running = True

        # Proses Pengecekan
        if st.session_state.is_running and tersisa > 0:
            session = requests.Session()
            session.headers.update(
                {
                    "x-apikey": api_key,
                    "Accept": "application/json",
                    "User-Agent": "Qname-VT-Checker/3.0",
                }
            )

            progress_bar = st.progress(selesai / total_qnames)
            status_box = st.empty()

            try:
                for idx, row in grouped_df.iterrows():
                    qname = str(row["qname"]).strip()

                    # Lewati domain yang sudah pernah tersimpan di checkpoint
                    if qname in checkpoint_data:
                        continue

                    status_box.info(
                        f"**[{selesai + 1}/{total_qnames}]** Memeriksa `{qname}` ke VirusTotal..."
                    )

                    try:
                        malicious, source = check_virustotal(session, qname)

                        if malicious is not None and malicious > VT_THRESHOLD:
                            st_text = "TERINDIKASI PHISHING"
                        elif malicious is None:
                            st_text = "SCAN BELUM SELESAI"
                        else:
                            st_text = "BERSIH"

                        append_checkpoint(qname, malicious, st_text, source)
                        checkpoint_data[qname] = {"malicious": malicious, "status": st_text, "source": source}

                    except Exception as err:
                        append_checkpoint(qname, None, f"ERROR: {str(err)[:40]}", "error")
                        checkpoint_data[qname] = {"malicious": None, "status": "ERROR", "source": "error"}

                    selesai += 1
                    progress_bar.progress(selesai / total_qnames)

                st.session_state.is_running = False
                status_box.success("Seluruh domain selesai dicek.")
                time.sleep(1)
                st.rerun()

            finally:
                session.close()

        # Bagian Download Data Hasil Terakhir
        if selesai > 0:
            st.divider()
            st.subheader("Hasil Terkumpul Saat Ini")

            phishing_set = set()
            display_rows = []

            for _, row in grouped_df.iterrows():
                q = row["qname"]
                c = row["count"]
                info = checkpoint_data.get(q)

                if info:
                    mal = info["malicious"]
                    st_val = info["status"]
                    src = info["source"]
                    if mal is not None and mal > VT_THRESHOLD:
                        phishing_set.add(q)
                else:
                    mal = None
                    st_val = "BELUM DICEK"
                    src = "-"

                display_rows.append({
                    "qname": q,
                    "count": c,
                    "malicious": mal,
                    "status": st_val,
                    "source": src,
                })

            res_df = pd.DataFrame(display_rows)
            st.dataframe(res_df, use_container_width=True, hide_index=True)

            # Excel hanya mewarnai domain yang sudah dicek dan terbukti phishing
            excel_bytes = create_excel(grouped_df, phishing_set)

            label_download = (
                "⬇️ Download Excel Lengkap"
                if tersisa == 0
                else f"⬇️ Download Hasil Sementara ({selesai}/{total_qnames} Selesai)"
            )

            st.download_button(
                label=label_download,
                data=excel_bytes,
                file_name="qname_virustotal_result.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary",
                use_container_width=True,
            )

    except Exception as exc:
        st.error(f"Gagal memproses data: {exc}")
else:
    st.info("Upload file Excel atau CSV berisi kolom **qname** untuk memulai proses.")
