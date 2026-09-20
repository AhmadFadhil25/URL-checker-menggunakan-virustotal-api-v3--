"""
Qname Duplicate Counter - Streamlit App
Menghitung berapa kali sebuah qname (URL/domain) muncul berulang di dalam
data yang di-upload, lalu menandai qname yang jumlah kemunculannya melebihi
ambang batas tertentu sebagai TERINDIKASI PHISHING (ditandai warna merah).

Jalankan dengan: streamlit run app.py
"""

from io import BytesIO

import pandas as pd
import streamlit as st
from openpyxl.styles import Alignment, Font, PatternFill

st.set_page_config(page_title="Qname Duplicate Counter", page_icon="🛡️", layout="wide")

PHISHING_STATUS = "TERINDIKASI PHISHING"
SAFE_STATUS = "TIDAK TERINDIKASI PHISHING"


class ProcessingError(Exception):
    """Error yang bisa ditampilkan langsung ke user (pesan sudah ramah)."""


# ================= LOGIKA UTAMA =================
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
    counts = counts.sort_values("Count", ascending=False).reset_index(drop=True)
    return counts


# ================= STYLING (tampilan di web) =================
def status_row_style(row):
    if row.get("Status") == PHISHING_STATUS:
        return ["background-color: #F4CCCC; font-weight: bold"] * len(row)
    return [""] * len(row)


# ================= EXPORT EXCEL =================
def to_excel_bytes(df: pd.DataFrame) -> bytes:
    if df is None or df.empty:
        raise ProcessingError("Tidak ada data hasil untuk diekspor ke Excel.")

    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Hasil")
        ws = writer.sheets["Hasil"]

        fill_red = PatternFill("solid", fgColor="F4CCCC")
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
        for r in range(2, len(df) + 2):
            status_val = ws.cell(row=r, column=status_col).value
            for c in range(1, len(df.columns) + 1):
                cell = ws.cell(row=r, column=c)
                if status_val == PHISHING_STATUS:
                    cell.fill = fill_red
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
    "Hitung berapa kali sebuah qname (URL/domain) muncul berulang di data Anda. "
    "Qname yang muncul lebih dari ambang batas akan ditandai sebagai phishing."
)

with st.sidebar:
    st.header("⚙️ Pengaturan")
    threshold = st.number_input(
        "Ambang batas Count (di atas ini = phishing)",
        min_value=0, value=2, step=1,
        help="Contoh: jika diisi 2, qname yang muncul 3 kali atau lebih akan ditandai merah.",
    )

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
        # Error yang sudah dikenali & pesannya ramah — hasil sebelumnya (jika ada) tetap disimpan.
        st.error(f"❌ Gagal memproses data: {e}\n\nHasil sebelumnya (jika ada) tetap tersimpan di bawah.")
    except Exception as e:
        # Jaring pengaman untuk error tak terduga — tetap tidak menghapus hasil sebelumnya.
        st.error(
            f"❌ Terjadi kesalahan tak terduga saat memproses data: {e}\n\n"
            "Data yang sudah diupload tidak hilang — coba periksa kolom yang dipilih lalu klik "
            "'Hitung Duplikat' lagi tanpa perlu upload ulang."
        )

if st.session_state.results_df is not None:
    df_res = st.session_state.results_df
    st.subheader("📊 Hasil Perhitungan")
    st.dataframe(df_res.style.apply(status_row_style, axis=1), use_container_width=True)

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Qname Unik", len(df_res))
    c2.metric("Terindikasi Phishing", int((df_res["Status"] == PHISHING_STATUS).sum()))
    c3.metric("Ambang Batas", f"> {threshold}")

    try:
        excel_bytes = to_excel_bytes(df_res)
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
