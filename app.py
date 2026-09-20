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

# Public VirusTotal API: batas gratis 4 request per menit (interval 16 detik).
# Ubah ke 0 jika menggunakan API berbayar (Private API).
MIN_REQUEST_INTERVAL = 16


# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="Qname VirusTotal Checker",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Qname VirusTotal Checker")
st.caption(
    "Gabungkan qname yang sama → hitung jumlah kemunculan (hit) → "
    "cek reputasi VirusTotal → tandai phishing."
)


# ============================================================
# VIRUSTOTAL FUNCTIONS
# ============================================================
_last_request_time = 0.0


def get_default_api_key() -> str:
    """Membaca API key bawaan dari Streamlit secrets atau environment variable."""
    try:
        key = st.secrets.get("VT_API_KEY", "")
    except Exception:
        key = ""

    if not key:
        key = os.environ.get("VT_API_KEY", "")

    return str(key).strip()


def throttle():
    """Menjaga jeda request agar tidak terkena HTTP 429 Too Many Requests."""
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
        raise RuntimeError(
            "VirusTotal API rate limit tercapai (HTTP 429). "
            "Coba lagi nanti atau sesuaikan interval request."
        )

    return response


def url_to_vt_id(url: str) -> str:
    """Konversi URL ke Base64 URL-safe tanpa padding '=' sesuai format VT."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")


def normalize_qname(value: str) -> str:
    """Menambahkan skema https:// jika qname berupa domain polos."""
    value = str(value).strip()

    if not value:
        return ""

    if not value.startswith(("http://", "https://")):
        return "https://" + value

    return value


def get_existing_url_report(session, url: str):
    """Mengecek apakah laporan URL sudah tersedia di database VirusTotal."""
    vt_id = url_to_vt_id(url)

    response = vt_request(
        session,
        "GET",
        f"/urls/{vt_id}",
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))

    return {
        "malicious": malicious,
        "stats": stats,
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def submit_url_scan(session, url: str) -> str:
    """Mengirim URL baru untuk dianalisis oleh VirusTotal."""
    response = vt_request(
        session,
        "POST",
        "/urls",
        data={"url": url},
    )

    response.raise_for_status()

    analysis_id = response.json().get("data", {}).get("id")

    if not analysis_id:
        raise RuntimeError("VirusTotal tidak mengembalikan Analysis ID.")

    return analysis_id


def get_analysis_result(session, analysis_id: str):
    """Melakukan polling status analisis URL yang baru dikirim."""
    for attempt in range(1, POLL_MAX_ATTEMPTS + 1):
        response = vt_request(
            session,
            "GET",
            f"/analyses/{analysis_id}",
        )
        response.raise_for_status()

        attributes = response.json().get("data", {}).get("attributes", {})
        status = attributes.get("status", "unknown")

        if status == "completed":
            stats = attributes.get("stats", {})
            return int(stats.get("malicious", 0)), "scan baru"

        if attempt < POLL_MAX_ATTEMPTS:
            time.sleep(POLL_INTERVAL_SECONDS)

    return None, "scan belum selesai"


def check_virustotal(session, qname: str):
    """Mengecek database VT terlebih dahulu, jika tidak ada lakukan pemindaian baru."""
    scan_url = normalize_qname(qname)

    existing = get_existing_url_report(session, scan_url)

    if existing is not None:
        return existing["malicious"], "database VT"

    analysis_id = submit_url_scan(session, scan_url)
    return get_analysis_result(session, analysis_id)


# ============================================================
# EXCEL PROCESSING
# ============================================================
def group_qnames(uploaded_file):
    """
    Membaca Excel dan menghitung akumulasi kemunculan (hit) per qname unik:
    - Jika kolom 'count' berisi angka > 0, nilainya akan dijumlahkan.
    - Jika kolom 'count' tidak ada, kosong, atau 0, setiap baris dihitung sebagai 1 hit.
    """
    df = pd.read_excel(uploaded_file)

    # Normalisasi nama kolom menjadi huruf kecil tanpa spasi berlebih
    df.columns = [str(c).strip().lower() for c in df.columns]

    # Deteksi kolom domain / qname
    if "qname" not in df.columns:
        alt_cols = [c for c in df.columns if "qname" in c or "domain" in c or "url" in c]
        if alt_cols:
            df.rename(columns={alt_cols[0]: "qname"}, inplace=True)
        else:
            raise ValueError(
                "Kolom 'qname' tidak ditemukan di file Excel. "
                "Pastikan ada kolom dengan nama 'qname'."
            )

    df["qname"] = df["qname"].astype(str).str.strip()
    df = df[df["qname"].ne("") & df["qname"].ne("nan")].copy()

    # Logika penghitungan hit / count
    if "count" in df.columns:
        df["count"] = pd.to_numeric(df["count"], errors="coerce").fillna(0)
        # Jika seluruh baris count bernilai 0, hitung berdasarkan frekuensi kemunculan baris
        if (df["count"] == 0).all():
            grouped = df.groupby("qname", as_index=False, sort=False).size()
            grouped.rename(columns={"size": "count"}, inplace=True)
        else:
            # Jika ada angka, jadikan minimal 1 untuk baris yang bernilai 0
            df["count"] = df["count"].apply(lambda x: 1 if x <= 0 else x)
            grouped = (
                df.groupby("qname", as_index=False, sort=False)["count"]
                .sum()
            )
    else:
        # Jika tidak ada kolom count sama sekali di file asal, hitung frekuensi per baris
        grouped = df.groupby("qname", as_index=False, sort=False).size()
        grouped.rename(columns={"size": "count"}, inplace=True)

    grouped["count"] = grouped["count"].astype(int)
    return grouped


def create_excel(grouped_df: pd.DataFrame, phishing_qnames: set) -> bytes:
    """
    Membuat file Excel output yang hanya berisi kolom 'qname' dan 'count'.
    Baris terindikasi phishing diberi warna latar merah tua dengan font putih tebal.
    """
    output = io.BytesIO()

    grouped_df.to_excel(output, index=False, sheet_name="Qname", engine="openpyxl")
    output.seek(0)

    workbook = load_workbook(output)
    sheet = workbook["Qname"]

    thin_side = Side(style="thin", color="000000")
    border = Border(
        left=thin_side,
        right=thin_side,
        top=thin_side,
        bottom=thin_side,
    )

    header_fill = PatternFill(fill_type="solid", fgColor="D9EAF7")
    normal_fill = PatternFill(fill_type="solid", fgColor="FFFFFF")
    phishing_fill = PatternFill(fill_type="solid", fgColor="C00000")

    header_font = Font(bold=True, color="000000")
    normal_font = Font(bold=False, color="000000")
    phishing_font = Font(bold=True, color="FFFFFF")

    # Format Header
    for cell in sheet[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.border = border
        cell.alignment = Alignment(horizontal="center", vertical="center")

    # Format Isi Baris
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
    st.header("Konfigurasi")

    default_key = get_default_api_key()

    user_api_key = st.text_input(
        "VirusTotal API Key",
        value=default_key,
        type="password",
        help="Masukkan API key VirusTotal Anda di sini. Input ini diprioritaskan dibanding Secrets/Env.",
    )

    api_key = user_api_key.strip()

    if api_key:
        st.success("VirusTotal API Key: siap digunakan")
    else:
        st.error("VirusTotal API Key belum diisi.")

    st.divider()
    st.write(f"Threshold: **malicious > {VT_THRESHOLD}**")
    st.write(f"Polling: **{POLL_MAX_ATTEMPTS}x**")
    st.write(f"Request interval: **{MIN_REQUEST_INTERVAL} detik**")


uploaded_file = st.file_uploader(
    "Upload Excel",
    type=["xlsx", "xls"],
    help="Upload file Excel yang berisi kolom qname (dan opsional kolom count).",
)

if uploaded_file is not None:
    try:
        grouped_df = group_qnames(uploaded_file)

        st.subheader("Hasil Grouping & Perhitungan Hit")

        col1, col2 = st.columns(2)
        col1.metric("Total qname unik", len(grouped_df))
        col2.metric("Total hit terakumulasi", int(grouped_df["count"].sum()))

        st.dataframe(
            grouped_df,
            use_container_width=True,
            hide_index=True,
        )

        if not api_key:
            st.warning(
                "Masukkan VT_API_KEY pada sidebar sebelah kiri terlebih dahulu sebelum melakukan pengecekan."
            )
            st.stop()

        if st.button(
            "🔍 Cek VirusTotal",
            type="primary",
            use_container_width=True,
        ):
            session = requests.Session()
            session.headers.update(
                {
                    "x-apikey": api_key,
                    "Accept": "application/json",
                    "User-Agent": "Qname-VirusTotal-Checker/1.0",
                }
            )

            phishing_qnames = set()
            result_rows = []

            progress = st.progress(0)
            status_box = st.empty()

            total = len(grouped_df)

            try:
                for index, row in grouped_df.iterrows():
                    qname = str(row["qname"]).strip()
                    count = int(row["count"])

                    current = len(result_rows) + 1

                    status_box.write(
                        f"**[{current}/{total}]** Mengecek `{qname}` "
                        f"(akumulasi hit: {count})"
                    )

                    try:
                        malicious, source = check_virustotal(session, qname)

                        if malicious is not None and malicious > VT_THRESHOLD:
                            phishing_qnames.add(qname)
                            status = "TERINDIKASI PHISHING"
                        elif malicious is None:
                            status = "SCAN BELUM SELESAI"
                        else:
                            status = "TIDAK TERINDIKASI PHISHING"

                        result_rows.append(
                            {
                                "qname": qname,
                                "count": count,
                                "malicious": malicious,
                                "status": status,
                                "source": source,
                            }
                        )

                    except requests.exceptions.Timeout:
                        result_rows.append(
                            {
                                "qname": qname,
                                "count": count,
                                "malicious": None,
                                "status": "TIMEOUT",
                                "source": "error",
                            }
                        )

                    except requests.RequestException as exc:
                        result_rows.append(
                            {
                                "qname": qname,
                                "count": count,
                                "malicious": None,
                                "status": f"ERROR REQUEST: {exc}",
                                "source": "error",
                            }
                        )

                    except Exception as exc:
                        result_rows.append(
                            {
                                "qname": qname,
                                "count": count,
                                "malicious": None,
                                "status": f"ERROR: {exc}",
                                "source": "error",
                            }
                        )

                    progress.progress(current / total)

            finally:
                session.close()

            status_box.success("Pengecekan selesai.")

            result_df = pd.DataFrame(result_rows)

            phishing_count = sum(result_df["status"].eq("TERINDIKASI PHISHING"))
            clean_count = sum(result_df["status"].eq("TIDAK TERINDIKASI PHISHING"))

            c1, c2, c3 = st.columns(3)
            c1.metric("Qname dicek", len(result_df))
            c2.metric("Terindikasi phishing", phishing_count)
            c3.metric("Tidak terindikasi", clean_count)

            st.subheader("Hasil Analisis Reputasi")

            display_df = result_df[
                ["qname", "count", "malicious", "status", "source"]
            ]

            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True,
            )

            final_excel = create_excel(grouped_df, phishing_qnames)

            st.download_button(
                label="⬇️ Download Excel Hasil",
                data=final_excel,
                file_name="qname_virustotal_result.xlsx",
                mime=(
                    "application/vnd.openxmlformats-officedocument."
                    "spreadsheetml.sheet"
                ),
                type="primary",
                use_container_width=True,
            )

            st.caption(
                "Excel hasil berisi kolom 'qname' dan 'count'. "
                "Baris dengan malicious > 2 diberi sorotan merah dengan font putih tebal."
            )

    except Exception as exc:
        st.error(f"Gagal membaca Excel: {exc}")
else:
    st.info("Upload file Excel berisi daftar qname untuk memulai proses.")
