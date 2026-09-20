"""
Qname Duplicate Counter + VirusTotal Checker - Streamlit App
Menghitung berapa kali sebuah qname (URL/domain) muncul berulang di dalam
data yang di-upload, menandai qname yang jumlah kemunculannya melebihi
ambang batas sebagai TERINDIKASI PHISHING, lalu (opsional) mengecek tiap
qname unik ke VirusTotal untuk mendapatkan jumlah engine yang menandainya
sebagai malicious.

Jalankan dengan: streamlit run app.py
"""

import base64
import time
from io import BytesIO

import pandas as pd
import requests
import streamlit as st
from openpyxl.styles import Alignment, Font, PatternFill

st.set_page_config(page_title="Qname Duplicate Counter", page_icon="🛡️", layout="wide")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
PHISHING_STATUS = "TERINDIKASI PHISHING"
SAFE_STATUS = "TIDAK TERINDIKASI PHISHING"


class ProcessingError(Exception):
    """Error yang bisa ditampilkan langsung ke user (pesan sudah ramah)."""


# ================= LOGIKA DUPLIKAT =================
def hitung_duplikat(df: pd.DataFrame, qname_col: str, threshold: int, count_col: str = None) -> pd.DataFrame:
    """Kelompokkan berdasarkan qname, lalu hitung Count.

    Jika count_col diisi, Count = jumlah (sum) nilai kolom tersebut per qname
    (dipakai kalau file sumber sudah punya kolom count sendiri).
    Jika tidak, Count = jumlah baris (kemunculan) qname tersebut.

    Melempar ProcessingError dengan pesan yang jelas jika data bermasalah,
    supaya UI bisa menampilkannya tanpa menghentikan/crash seluruh aplikasi.
    """
    if df is None or df.empty:
        raise ProcessingError("Data kosong — tidak ada yang bisa diproses.")
    if qname_col not in df.columns:
        raise ProcessingError(f"Kolom qname '{qname_col}' tidak ditemukan di data.")
    if count_col is not None and count_col not in df.columns:
        raise ProcessingError(f"Kolom count '{count_col}' tidak ditemukan di data.")

    try:
        work = df[[qname_col]].copy() if count_col is None else df[[qname_col, count_col]].copy()
        work[qname_col] = work[qname_col].astype(str).str.strip()
        work = work[work[qname_col].str.lower() != "nan"]
        work = work[work[qname_col] != ""]
    except Exception as e:
        raise ProcessingError(f"Gagal membaca kolom qname: {e}") from e

    if work.empty:
        raise ProcessingError("Setelah dibersihkan, tidak ada qname yang valid untuk diproses.")

    invalid_count_rows = 0
    try:
        if count_col is not None:
            numeric = pd.to_numeric(work[count_col], errors="coerce")
            invalid_count_rows = int(numeric.isna().sum())
            work[count_col] = numeric.fillna(0)
            counts = work.groupby(qname_col, as_index=False)[count_col].sum()
            counts.columns = ["Qname", "Count"]
            counts["Count"] = counts["Count"].astype(int)
        else:
            counts = work[qname_col].value_counts().reset_index()
            counts.columns = ["Qname", "Count"]
    except Exception as e:
        raise ProcessingError(f"Gagal menghitung Count: {e}") from e

    if invalid_count_rows:
        st.warning(
            f"⚠️ {invalid_count_rows} baris punya nilai count yang bukan angka — "
            "dianggap 0 dan tetap diproses."
        )

    counts["Status"] = counts["Count"].apply(
        lambda c: PHISHING_STATUS if c > threshold else SAFE_STATUS
    )
    counts["Malicious"] = None
    counts["Info VT"] = None
    counts = counts.sort_values("Count", ascending=False).reset_index(drop=True)
    return counts


# ================= RATE LIMITER =================
class RateLimiter:
    """Menjaga jeda minimum antar request ke VirusTotal (menghindari 429)."""

    def __init__(self, interval_seconds: float):
        self.interval = interval_seconds
        self.last = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        remaining = self.interval - (time.monotonic() - self.last)
        if self.last > 0 and remaining > 0:
            time.sleep(remaining)
        self.last = time.monotonic()


# ================= VIRUSTOTAL API =================
def vt_request(session, limiter, method, endpoint, **kwargs):
    limiter.wait()
    resp = session.request(method, f"{VT_BASE_URL}{endpoint}", timeout=30, **kwargs)
    if resp.status_code == 401:
        raise RuntimeError("API key VirusTotal tidak valid.")
    if resp.status_code == 429:
        raise RuntimeError("Rate limit VirusTotal tercapai (429). Perbesar jeda antar request lalu lanjutkan.")
    return resp


def qname_to_vt_id(qname: str) -> str:
    return base64.urlsafe_b64encode(qname.encode()).decode().rstrip("=")


def vt_get_existing_report(session, limiter, qname):
    resp = vt_request(session, limiter, "GET", f"/urls/{qname_to_vt_id(qname)}")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    attrs = resp.json().get("data", {}).get("attributes", {})
    last_analysis = attrs.get("last_analysis_date")
    if last_analysis is None:
        return None
    malicious = int(attrs.get("last_analysis_stats", {}).get("malicious", 0))
    age_days = (time.time() - last_analysis) / 86_400
    return malicious, age_days


def vt_submit_qname(session, limiter, qname):
    resp = vt_request(session, limiter, "POST", "/urls", data={"url": qname})
    if resp.status_code == 400:
        raise ValueError(f"Qname ditolak oleh VirusTotal: {qname}")
    resp.raise_for_status()
    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        raise RuntimeError("Gagal mendapatkan Analysis ID dari VirusTotal.")
    return analysis_id


def vt_get_analysis(session, limiter, analysis_id, poll_max_attempts, log):
    for attempt in range(1, poll_max_attempts + 1):
        resp = vt_request(session, limiter, "GET", f"/analyses/{analysis_id}")
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        status = attrs.get("status", "unknown")
        if status == "completed":
            return attrs.get("stats", {})
        log(f"Analisis belum selesai ({status}). Cek ulang {attempt}/{poll_max_attempts}...")
    log("Batas cek tercapai. Skor diasumsikan AMAN (0 malicious) sementara.")
    return {"malicious": 0}


def check_qname_virustotal(session, limiter, qname, max_age_days, poll_max_attempts, log):
    existing = vt_get_existing_report(session, limiter, qname)
    if existing is not None:
        malicious, age_days = existing
        if age_days <= max_age_days:
            log(f"Menggunakan laporan lama ({age_days:.1f} hari lalu).")
            return malicious, f"Laporan lama ({age_days:.1f} hari)"
        log(f"Laporan berumur {age_days:.1f} hari. Melakukan scan baru...")
    else:
        log("Belum ada laporan. Melakukan scan baru...")

    analysis_id = vt_submit_qname(session, limiter, qname)
    stats = vt_get_analysis(session, limiter, analysis_id, poll_max_attempts, log)
    return int(stats.get("malicious", 0)), "Scan baru"


# ================= STYLING (tampilan di web) =================
def status_row_style(row, vt_threshold=None):
    if row.get("Status") == PHISHING_STATUS:
        return ["background-color: #F4CCCC; font-weight: bold"] * len(row)
    if vt_threshold is not None and pd.notna(row.get("Malicious")) and row.get("Malicious") > vt_threshold:
        return ["background-color: #FFF2CC; font-weight: bold"] * len(row)
    return [""] * len(row)


# ================= EXPORT EXCEL =================
def to_excel_bytes(df: pd.DataFrame, vt_threshold=None) -> bytes:
    if df is None or df.empty:
        raise ProcessingError("Tidak ada data hasil untuk diekspor ke Excel.")

    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Hasil")
        ws = writer.sheets["Hasil"]

        fill_red = PatternFill("solid", fgColor="F4CCCC")
        fill_yellow = PatternFill("solid", fgColor="FFF2CC")
        bold = Font(bold=True)
        center = Alignment(horizontal="center", vertical="center")

        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill("solid", fgColor="0B1F3A")
        for c in range(1, len(df.columns) + 1):
            cell = ws.cell(row=1, column=c)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = center

        status_col = df.columns.get_loc("Status") + 1
        malicious_col = df.columns.get_loc("Malicious") + 1 if "Malicious" in df.columns else None
        for r in range(2, len(df) + 2):
            status_val = ws.cell(row=r, column=status_col).value
            malicious_val = ws.cell(row=r, column=malicious_col).value if malicious_col else None
            fill = None
            if status_val == PHISHING_STATUS:
                fill = fill_red
            elif vt_threshold is not None and isinstance(malicious_val, (int, float)) and malicious_val > vt_threshold:
                fill = fill_yellow
            for c in range(1, len(df.columns) + 1):
                cell = ws.cell(row=r, column=c)
                if fill:
                    cell.fill = fill
                    cell.font = bold
                if c > 1:
                    cell.alignment = center

        for col_cells in ws.columns:
            length = max((len(str(c.value)) if c.value is not None else 0) for c in col_cells)
            ws.column_dimensions[col_cells[0].column_letter].width = min(max(length + 2, 10), 60)

    return output.getvalue()


# ================= UI =================
st.title("🛡️ Qname Duplicate Counter")
st.caption(
    "Hitung berapa kali sebuah qname (URL/domain) muncul berulang di data Anda, lalu opsional "
    "cek tiap qname unik ke VirusTotal untuk info malicious tambahan."
)

try:
    _secret_key = st.secrets.get("VT_API_KEY", "").strip()
except Exception:
    _secret_key = ""

with st.sidebar:
    st.header("⚙️ Pengaturan Duplikat")
    threshold = st.number_input(
        "Ambang batas Count (di atas ini = phishing)",
        min_value=0, value=2, step=1,
        help="Contoh: jika diisi 2, qname yang muncul 3 kali atau lebih akan ditandai merah.",
    )

    st.divider()
    st.header("🌐 Pengaturan VirusTotal (opsional)")
    if _secret_key:
        api_key = _secret_key
        st.success("API key sudah dikonfigurasi oleh admin (lewat Secrets).")
    else:
        api_key = st.text_input(
            "VirusTotal API Key",
            type="password",
            help="Key hanya dipakai selama sesi ini di browser Anda dan tidak disimpan di server.",
        )
    vt_threshold = st.number_input("Ambang batas Malicious VT (di atas ini ditandai kuning)", min_value=0, value=3, step=1)
    max_age_days = st.number_input("Toleransi umur laporan VT (hari)", min_value=0, value=10, step=1)
    poll_max_attempts = st.number_input("Maks. cek ulang status scan baru", min_value=1, value=3, step=1)
    request_interval = st.number_input(
        "Jeda antar request ke VirusTotal (detik)",
        min_value=0, value=16, step=1,
        help="16 detik cocok untuk akun gratis (4 request/menit). Isi 0 jika memakai akun premium.",
    )
    st.caption("Dapatkan API key gratis di virustotal.com → Profil → API Key.")

tab1, tab2 = st.tabs(["📤 Upload File", "✍️ Input Manual"])

source_df = None
qname_col = None
count_col = None

with tab1:
    uploaded = st.file_uploader("Upload file Excel (.xlsx) atau CSV berisi daftar qname", type=["xlsx", "csv"])
    if uploaded is not None:
        try:
            uploaded.seek(0)
            if uploaded.name.endswith(".csv"):
                try:
                    parsed_df = pd.read_csv(uploaded)
                except UnicodeDecodeError:
                    uploaded.seek(0)
                    parsed_df = pd.read_csv(uploaded, encoding="latin-1")
            else:
                parsed_df = pd.read_excel(uploaded)

            if parsed_df.empty or len(parsed_df.columns) == 0:
                st.error("File berhasil dibaca tapi tidak ada data/kolom di dalamnya.")
            else:
                source_df = parsed_df
        except Exception as e:
            st.error(
                f"Gagal membaca file '{uploaded.name}'. Pastikan formatnya benar (.xlsx atau .csv) "
                f"dan tidak rusak.\n\nDetail: {e}"
            )

        if source_df is not None:
            st.write("Pratinjau file:")
            st.dataframe(source_df.head(), use_container_width=True)
            qname_col = st.selectbox("Pilih kolom yang berisi qname", source_df.columns)

            mode = st.radio(
                "Cara menghitung Count",
                ["Hitung jumlah baris (setiap baris = 1 kemunculan)", "Jumlahkan kolom count yang sudah ada di file"],
                help="Pilih opsi kedua jika file Anda sudah punya kolom angka yang harus dijumlahkan per qname.",
            )
            if mode.startswith("Jumlahkan"):
                other_cols = [c for c in source_df.columns if c != qname_col]
                if not other_cols:
                    st.warning("Tidak ada kolom lain selain qname untuk dijumlahkan. Menggunakan hitung jumlah baris.")
                else:
                    count_col = st.selectbox("Pilih kolom count yang akan dijumlahkan", other_cols)

with tab2:
    manual_text = st.text_area(
        "Tempel daftar qname (satu qname per baris, boleh ada yang duplikat)", height=220,
        placeholder="linkphising.com\nlinkphising.com\nlinkphising.com\ncontoh-aman.com",
    )
    if manual_text.strip():
        manual_qnames = [u.strip() for u in manual_text.splitlines() if u.strip()]
        source_df = pd.DataFrame({"Qname": manual_qnames})
        qname_col = "Qname"

ready = source_df is not None and qname_col is not None and not source_df.empty
if ready:
    st.success(f"Siap memproses **{len(source_df)}** baris data.")

run = st.button("🔍 Hitung Duplikat", type="primary", disabled=not ready)

if "results_df" not in st.session_state:
    st.session_state.results_df = None

if run:
    try:
        with st.spinner("Menghitung..."):
            new_result = hitung_duplikat(source_df, qname_col, threshold, count_col)
        st.session_state.results_df = new_result
        st.toast("✅ Perhitungan berhasil.")
    except ProcessingError as e:
        st.error(f"❌ Gagal memproses data: {e}\n\nHasil sebelumnya (jika ada) tetap tersimpan di bawah.")
    except Exception as e:
        st.error(
            f"❌ Terjadi kesalahan tak terduga saat memproses data: {e}\n\n"
            "Data yang sudah diupload tidak hilang — coba periksa kolom yang dipilih lalu klik "
            "'Hitung Duplikat' lagi tanpa perlu upload ulang."
        )

if st.session_state.results_df is not None:
    df_res = st.session_state.results_df
    st.subheader("📊 Hasil Perhitungan Duplikat")
    st.dataframe(df_res.style.apply(status_row_style, axis=1, vt_threshold=vt_threshold), use_container_width=True)

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Qname Unik", len(df_res))
    c2.metric("Terindikasi Phishing (Count)", int((df_res["Status"] == PHISHING_STATUS).sum()))
    c3.metric("Ambang Batas Count", f"> {threshold}")

    st.divider()
    st.subheader("🌐 Cek ke VirusTotal (opsional)")
    st.caption(
        "Setiap qname unik di atas akan dicek ke VirusTotal untuk mendapatkan jumlah engine "
        "yang menandainya sebagai malicious. Proses ini bisa dilanjutkan/di-resume — qname yang "
        "sudah dicek tidak akan diulang jika terjadi error di tengah jalan."
    )

    already_checked = int(df_res["Malicious"].notna().sum())
    total_qname = len(df_res)
    if already_checked:
        st.info(f"{already_checked}/{total_qname} qname sudah pernah dicek ke VirusTotal.")

    cek_vt = st.button(
        "🌐 Cek Semua Qname ke VirusTotal",
        disabled=(already_checked == total_qname),
    )

    if cek_vt:
        if not api_key.strip():
            st.error("Masukkan VirusTotal API Key di sidebar terlebih dahulu.")
            st.stop()

        work_df = st.session_state.results_df.copy()
        to_process = work_df.index[work_df["Malicious"].isna()].tolist()

        session = requests.Session()
        session.headers.update({
            "x-apikey": api_key.strip(),
            "Accept": "application/json",
            "User-Agent": "Streamlit-Qname-Checker/1.0",
        })
        limiter = RateLimiter(request_interval)

        progress = st.progress(0.0)
        status_placeholder = st.empty()
        log_placeholder = st.empty()
        table_placeholder = st.empty()

        try:
            for done, idx in enumerate(to_process, start=1):
                qname = work_df.loc[idx, "Qname"]
                status_placeholder.markdown(f"**[{done}/{len(to_process)}]** Memproses: `{qname}`")

                def log(msg):
                    log_placeholder.caption(msg)

                try:
                    malicious, info = check_qname_virustotal(
                        session, limiter, qname, max_age_days, poll_max_attempts, log
                    )
                    work_df.loc[idx, ["Malicious", "Info VT"]] = [malicious, info]
                except ValueError as e:
                    work_df.loc[idx, ["Malicious", "Info VT"]] = [None, f"URL TIDAK VALID: {e}"]
                except requests.exceptions.Timeout:
                    work_df.loc[idx, ["Malicious", "Info VT"]] = [None, "TIMEOUT"]
                except requests.RequestException as e:
                    work_df.loc[idx, ["Malicious", "Info VT"]] = [None, f"ERROR: {e}"]
                except RuntimeError as e:
                    # Simpan progres sejauh ini sebelum berhenti (mis. kena rate limit 429).
                    st.session_state.results_df = work_df
                    progress.progress(done / max(len(to_process), 1))
                    status_placeholder.error(
                        f"⛔ Berhenti: {e}\n\n"
                        f"Progres {done - 1}/{len(to_process)} qname yang baru sudah tersimpan — "
                        "klik tombol 'Cek Semua Qname ke VirusTotal' lagi untuk melanjutkan dari sini "
                        "tanpa mengulang dari awal."
                    )
                    break

                progress.progress(done / max(len(to_process), 1))
                st.session_state.results_df = work_df
                table_placeholder.dataframe(
                    work_df.style.apply(status_row_style, axis=1, vt_threshold=vt_threshold),
                    use_container_width=True,
                )
            else:
                status_placeholder.success("✅ Selesai mengecek semua qname ke VirusTotal.")
                log_placeholder.empty()
        except Exception as e:
            # Jaring pengaman terakhir: apa pun yang terjadi, progres yang sudah didapat tetap disimpan.
            st.session_state.results_df = work_df
            st.error(
                f"❌ Terjadi kesalahan tak terduga: {e}\n\n"
                "Progres yang sudah didapat tetap tersimpan — coba klik tombol cek VirusTotal lagi "
                "untuk melanjutkan tanpa mengulang dari awal."
            )
        finally:
            session.close()

        st.rerun()

    df_final = st.session_state.results_df
    st.divider()
    st.subheader("📋 Hasil Akhir")
    st.dataframe(df_final.style.apply(status_row_style, axis=1, vt_threshold=vt_threshold), use_container_width=True)

    try:
        excel_bytes = to_excel_bytes(df_final, vt_threshold=vt_threshold)
        st.download_button(
            "⬇️ Unduh Hasil (Excel)",
            data=excel_bytes,
            file_name="hasil_qname_counter.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as e:
        st.error(
            f"❌ Gagal membuat file Excel: {e}\n\n"
            "Hasil perhitungan di atas tetap bisa dilihat/disalin manual meski file Excel gagal dibuat."
        )
