"""
Analisis Frekuensi + Pembongkar Otomatis Cipher Klasik (Challenge 1)

Tempel ciphertext -> diagram frekuensi huruf -> teks asli muncul otomatis.
Algoritma yang dikenali (sesuai slide "Algoritma Substitusi dan Transposisi"):
  Substitusi : Caesar Cipher / ROT13, Tabel Substitusi (2 tabel contoh slide), Cipher Homofonik
  Transposisi: Rail Fence Cipher, Columnar Transposition
Jalankan dengan:  streamlit run app.py
"""
import inspect
import re
import string
from collections import Counter
from itertools import permutations

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Kriptanalisis - Analisis Frekuensi", layout="wide")

ALPHABET = string.ascii_uppercase

# Tombol: gunakan width="stretch" bila tersedia (Streamlit baru), jika tidak use_container_width
_STRETCH = (
    {"width": "stretch"}
    if "width" in inspect.signature(st.button).parameters
    else {"use_container_width": True}
)

# ---------------------------------------------------------------------------
# DATA
# ---------------------------------------------------------------------------
# Kata umum (>= 3 huruf) untuk menilai apakah hasil dekripsi "terbaca".
# Tambahkan kata baru di sini bila ada pesan yang tidak terdeteksi.
COMMON_WORDS = set(
    """
    THE AND FOR ARE BUT NOT YOU ALL CAN HER WAS ONE OUR OUT DAY GET HAS HIM HIS HOW
    ITS MAY NEW NOW OLD SEE TWO WAY WHO BOY DID WITH THAT THIS HAVE FROM THEY WILL
    WOULD THERE THEIR WHAT ABOUT WHICH WHEN YOUR SAID EACH THEM THESE SOME TIME VERY
    HELLO WORLD WANT LEARN SECRET MESSAGE MEET AFTER PARTY TOGA ROTATE CREAM DOLLS
    WHEEL BOOK ENJOY HOPE CIPHER KEY ATTACK DAWN CRYPTOGRAPHY ENCRYPTION PLAINTEXT
    PEOPLE FIRST WRITE LOOK MAKE LIKE INTO MORE COME MADE FIND LONG DOWN CALL
    YANG DAN DARI INI ITU UNTUK DENGAN TIDAK ADALAH PADA SAYA KAMU ANAK KITA AKAN
    ATAU JUGA SUDAH BISA ADA DALAM ORANG LEBIH SAJA MAU BELAJAR HALO DUNIA SATE
    MAKAN SUKA KODING PESAN RAHASIA SANDI KUNCI PROGRAM NAKAL BAIK SELAMAT PAGI
    SIANG MALAM TERIMA KASIH APA SIAPA MANA KAPAN BAGAIMANA TEMAN TEMANNYA AWASI
    KRIPTO KRIPTOGRAFI UDINUS ASTERIX OBELIX DIAN NUSWANTORO UNIVERSITAS SEMARANG
    MAHASISWA KULIAH KOMPUTER INFORMATIKA TEKNIK ENKRIPSI DEKRIPSI KATA HURUF ANGKA
    AKU DIA KAMI MEREKA TETAPI KARENA JIKA MAKA BELUM SEDANG HARUS INGIN BUKAN SANGAT
    PALING SEMUA SETIAP BANYAK SEDIKIT BESAR KECIL BARU LAMA BURUK MINUM TIDUR PERGI
    DATANG PULANG RUMAH SEKOLAH KAMPUS HARI SORE BESOK KEMARIN TOLONG MAAF NASI AYAM
    IKAN AIR IBU BAPAK GURU DOSEN UJIAN TUGAS APLIKASI DATA
    """.split()
)
MAX_WORD = max(len(w) for w in COMMON_WORDS)
MIN_SCORE = 16  # minimal "skor terbaca" agar hasil dianggap meyakinkan

# Dua tabel substitusi contoh dari slide (huruf A..Z -> baris cipherteks)
KEYWORD_SENTENCE = "we hope you enjoy this book"
RANDOM_TABLE = "DIQMTBZSYKVOFERJAUWPXHLCNG"

# Tabel homofonik dari slide: tiap huruf -> beberapa unit cipherteks (AA..DZ)
HOMOPHONES = {
    "A": "BU CP AV AH BT BS CQ", "B": "AT", "C": "DL BK AU", "D": "BV DY DM AI",
    "E": "DK CO AW BL AA CR BM CS AF AG BO BN BE", "F": "BW CM CN", "G": "DN BJ",
    "H": "AS CL CK", "I": "DJ BI AX CJ AB BP CU CT", "J": "BX", "K": "DI",
    "L": "AR BH CI AJ", "M": "DH BG AY", "N": "BY DG DF CH AC BR DU DT",
    "O": "DZ BF DX AK CG BQ DR", "P": "BZ DE AZ", "Q": "DD",
    "R": "AQ DC DQ AL CE CF CV DS", "S": "AP AN AO CD DW DV",
    "T": "CB DB DP CC AD CY CW CX AE", "U": "CA AM BA", "V": "BB", "W": "CZ",
    "X": "BD", "Y": "DO DA", "Z": "BC",
}
HOMO_REVERSE = {u: p for p, units in HOMOPHONES.items() for u in units.split()}


# ---------------------------------------------------------------------------
# ALGORITMA (arah dekripsi)
# ---------------------------------------------------------------------------
def caesar(text, k):
    """Caesar Cipher: ci = (pi + k) mod 26. Dekripsi = caesar(text, -k).
    Hanya huruf yang digeser (besar/kecil dipertahankan); angka & simbol tetap."""
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base + k) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def keyword_table(sentence):
    """Tabel substitusi dari kalimat kunci: buang huruf ganda, sambung huruf yang belum ada."""
    seen = []
    for c in sentence.upper():
        if c in ALPHABET and c not in seen:
            seen.append(c)
    return "".join(seen + [c for c in ALPHABET if c not in seen])


def substitute_decrypt(text, cipher_alphabet):
    """Dekripsi tabel substitusi: huruf ke-i cipher_alphabet -> huruf ke-i alfabet."""
    table = dict(zip(cipher_alphabet, ALPHABET))
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            m = table[c.upper()]
            out.append(m.lower() if c.islower() else m)
        else:
            out.append(c)
    return "".join(out)


def homophonic_decrypt(text):
    """Cipher homofonik: unit 2 huruf dipisah spasi, dicari di tabel. None bila bukan homofonik."""
    tokens = text.split()
    if len(tokens) >= 2 and all(len(t) == 2 and t.upper() in HOMO_REVERSE for t in tokens):
        return "".join(HOMO_REVERSE[t.upper()] for t in tokens)
    return None


def strip_spaces(text):
    return re.sub(r"\s+", "", text)


def _rail_order(length, rails):
    cycle = 2 * (rails - 1)

    def rail(i):
        r = i % cycle
        return r if r < rails else cycle - r

    return sorted(range(length), key=lambda i: (rail(i), i))


def rail_fence_decrypt(text, rails):
    """Rail Fence: kebalikan dari tulis zigzag pada `rails` baris lalu baca baris per baris."""
    plain = [""] * len(text)
    for pos, i in enumerate(_rail_order(len(text), rails)):
        plain[i] = text[pos]
    return "".join(plain)


def columnar_decrypt(text, key):
    """Columnar Transposition (versi slide). None bila panjang teks tidak kelipatan jumlah kolom."""
    n = len(key)
    if len(text) % n:
        return None
    out = []
    for b in range(0, len(text), n):
        block = [""] * n
        for j, k in enumerate(key):
            block[k - 1] = text[b + j]
        out.append("".join(block))
    plain = "".join(out)
    pad = len(plain) - len(plain.rstrip("."))
    return plain[: len(plain) - min(pad, n - 1)]


# ---------------------------------------------------------------------------
# PENILAIAN "TERBACA" & PENGENALAN ALGORITMA
# ---------------------------------------------------------------------------
def clean_letters(text):
    """Ambil hanya huruf A-Z, ubah ke kapital."""
    return "".join(c.upper() for c in text if c.isascii() and c.isalpha())


def segment_cover(letters):
    """Total (panjang^2) kata umum yang bisa menyusun deretan huruf tanpa spasi."""
    n = len(letters)
    best = [0] * (n + 1)
    for i in range(1, n + 1):
        best[i] = best[i - 1]
        for L in range(3, min(i, MAX_WORD) + 1):
            if letters[i - L:i] in COMMON_WORDS:
                best[i] = max(best[i], best[i - L] + L * L)
    return best[n]


def readability(text):
    """Skor keterbacaan: makin banyak/panjang kata umum yang ditemukan, makin besar."""
    tokens = re.findall(r"[A-Za-z]+", text)
    if len(tokens) == 1:  # tanpa spasi: coba susun dari kata-kata umum
        return segment_cover(tokens[0].upper())
    return sum(len(t) ** 2 for t in tokens if t.upper() in COMMON_WORDS)


def build_candidates(ct):
    """Coba semua algoritma & kunci yang mungkin, kembalikan daftar kandidat (nama, hasil, skor)."""
    cands = []

    def add(name, plain, need=MIN_SCORE):
        if plain is not None:
            cands.append({"name": name, "plain": plain, "score": readability(plain), "need": need})

    # Caesar / ROT-n (k = 0 berarti teks sudah terbaca)
    for k in range(26):
        if k == 0:
            name = "tanpa enkripsi"
        elif k == 13:
            name = "ROT13 (Caesar Cipher dengan k = 13)"
        else:
            name = f"Caesar Cipher (k = {k})"
        add(name, caesar(ct, -k))

    # Tabel substitusi contoh dari slide
    add(f"Tabel Substitusi, kunci kalimat \"{KEYWORD_SENTENCE}\"", substitute_decrypt(ct, keyword_table(KEYWORD_SENTENCE)))
    add("Tabel Substitusi acak (contoh slide)", substitute_decrypt(ct, RANDOM_TABLE))

    # Transposisi: spasi dibuang, kunci dicoba semua
    # Kuncinya banyak (ratusan), jadi teks acak mudah "kebetulan" memuat beberapa kata umum.
    # Karena itu skor harus tinggi relatif terhadap panjang teks (kalimat asli jauh di atas teks acak).
    flat = strip_spaces(ct)
    need = max(MIN_SCORE, 1.5 * len(flat))
    for r in range(2, min(10, len(flat) - 1) + 1):
        add(f"Rail Fence Cipher ({r} rel)", rail_fence_decrypt(flat, r), need)
    for n in range(2, 7):
        if len(flat) % n == 0:
            for key in permutations(range(1, n + 1)):
                add(f"Columnar Transposition (kunci {','.join(map(str, key))})", columnar_decrypt(flat, list(key)), need)
    return cands


def solve(ct):
    """Kenali algoritma dan bongkar. Status: ok / plain / ambiguous / none."""
    homo = homophonic_decrypt(ct)
    if homo:
        return {"status": "ok", "items": [{"name": "Cipher Homofonik", "plain": homo}]}

    seen, uniq = set(), []
    for c in build_candidates(ct):  # urutan tetap -> seri dimenangkan algoritma yang lebih sederhana
        if c["plain"] not in seen:
            seen.add(c["plain"])
            uniq.append(c)
    uniq = [c for c in uniq if c["score"] >= c["need"]]  # buang kandidat yang kurang meyakinkan
    if not uniq:
        return {"status": "none", "items": []}
    uniq.sort(key=lambda c: -c["score"])

    top = uniq[0]
    rivals = [c for c in uniq[1:] if c["score"] * 3 > top["score"]]
    if rivals:
        return {"status": "ambiguous", "items": [top] + rivals[:4]}
    if top["name"] == "tanpa enkripsi":
        return {"status": "plain", "items": [top]}
    return {"status": "ok", "items": [top]}


# ---------------------------------------------------------------------------
# TAMPILAN
# ---------------------------------------------------------------------------
SAMPLE_CIPHER = caesar("AWASI ASTERIX DAN TEMANNYA OBELIX", 3)  # contoh dari slide

st.title("🔓 Analisis Frekuensi Cipher Substitusi")
st.write(
    "Tempel ciphertext, lalu lihat diagram frekuensi hurufnya dan teks aslinya. "
    "Algoritma dikenali otomatis."
)

ciphertext = st.text_area("Masukkan Ciphertext di sini:", SAMPLE_CIPHER, height=110)

letters = clean_letters(ciphertext)
total = len(letters)

if total == 0:
    st.warning("Ciphertext harus mengandung huruf alfabet (A-Z).")
    st.stop()

counts = Counter(letters)
freq_pct = {c: counts.get(c, 0) / total * 100 for c in ALPHABET}
sorted_chars = sorted(ALPHABET, key=lambda c: (-counts.get(c, 0), c))

# --- tombol karakter + diagram ---------------------------------------------
if "selected_char" not in st.session_state:
    st.session_state.selected_char = None

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🔍 Tombol Karakter Ciphertext")
    st.write("Klik salah satu huruf untuk melihat posisi dan frekuensinya pada teks:")
    cols_btn = st.columns(6)
    for i, char in enumerate(sorted_chars):
        with cols_btn[i % 6]:
            if st.button(f"{char} ({counts.get(char, 0)})", key=f"btn_{char}", **_STRETCH):
                st.session_state.selected_char = char

    sel = st.session_state.selected_char
    if sel:
        st.info(
            f"Huruf **{sel}** muncul sebanyak **{counts.get(sel, 0)} kali** "
            f"(**{freq_pct[sel]:.2f}%** dari total {total} huruf)."
        )
        highlighted = "".join(
            f"**[{c}]**" if (c.isascii() and c.upper() == sel) else c for c in ciphertext
        )
        st.markdown(f"**Tinjauan Teks:** {highlighted}")

with col2:
    st.subheader("📈 Diagram Frekuensi Huruf (%)")
    st.bar_chart(pd.Series(freq_pct, name="Persen (%)"))

top3 = counts.most_common(3)
st.caption(
    "Huruf yang paling sering muncul: "
    + ", ".join(f"**{c}** ({n}x)" for c, n in top3)
    + ". Pada cipher substitusi, huruf-huruf ini biasanya mewakili huruf yang paling umum "
    "di bahasa aslinya (A, N, I di bahasa Indonesia; E, T, A di bahasa Inggris). "
    "Pada transposisi, frekuensi huruf sama dengan teks aslinya."
)

# --- teks asli (dekripsi otomatis) ------------------------------------------
st.markdown("---")
st.subheader("📝 Teks Asli (Hasil Dekripsi Otomatis)")

sol = solve(ciphertext)

if sol["status"] == "ok":
    item = sol["items"][0]
    st.success(f"Terdeteksi: **{item['name']}**")
    st.text_area("Hasil:", item["plain"], height=120)
elif sol["status"] == "plain":
    st.info("Teks ini tampaknya sudah terbaca (bukan ciphertext).")
    st.text_area("Hasil:", sol["items"][0]["plain"], height=120)
elif sol["status"] == "ambiguous":
    st.warning("Ada beberapa kemungkinan yang sama-sama terbaca. Pilih yang masuk akal:")
    for item in sol["items"]:
        st.markdown(f"**{item['name']}**: {item['plain']}")
else:
    st.warning(
        "Algoritma tidak dikenali atau teksnya belum meyakinkan. Aplikasi mengenali: Caesar / ROT13, "
        "tabel substitusi contoh slide, homofonik (unit 2 huruf dipisah spasi), Rail Fence, dan "
        "Columnar Transposition. Pesan juga harus memuat kata umum bahasa Indonesia/Inggris "
        "yang ada di daftar aplikasi."
    )