import streamlit as st
import pandas as pd
from collections import Counter

# Konfigurasi halaman Streamlit
st.set_page_config(page_title="Kriptanalisis - Analisis Frekuensi", layout="wide")

st.title("🔓 Alat Analisis Frekuensi Cipher Substitusi")
st.write("Aplikasi web interaktif untuk membantu memecahkan cipher substitusi menggunakan teknik analisis frekuensi.")

# Input Ciphertext dari pengguna
ciphertext = st.text_area("Masukkan Ciphertext di sini:", "Uryyb Jbeyq! V jnag gb jebat gur pyny yratthfx.")

if ciphertext:
    # Pra-pemrosesan teks untuk statistik
    cleaned_text = ''.join([c.upper() for c in ciphertext if c.isalpha()])
    total_chars = len(cleaned_text)

    if total_chars > 0:
        # Menghitung frekuensi kemunculan
        freq_count = Counter(cleaned_text)
        
        # Urutkan abjad berdasarkan frekuensi terbanyak ke tersedikit untuk penempatan tombol yang informatif
        sorted_chars = sorted("ABCDEFGHIJKLMNOPQRSTUVWXYZ", key=lambda x: freq_count.get(x, 0), reverse=True)

        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("🔍 Switch / Tombol Karakter Ciphertext")
            st.write("Klik salah satu huruf di bawah untuk melihat posisi dan frekuensinya pada teks:")
            
            # Membuat grid tombol (switch per huruf)
            if 'selected_char' not in st.session_state:
                st.session_state.selected_char = None

            # Menampilkan tombol dalam baris-baris kecil
            cols_btn = st.columns(6)
            for i, char in enumerate(sorted_chars):
                count = freq_count.get(char, 0)
                percentage = (count / total_chars) * 100 if total_chars > 0 else 0
                btn_label = f"{char} ({count})"
                
                with cols_btn[i % 6]:
                    if st.button(btn_label, key=f"btn_{char}", use_container_width=True):
                        st.session_state.selected_char = char

            # Menampilkan informasi detail huruf yang sedang dipilih
            if st.session_state.selected_char:
                sel = st.session_state.selected_char
                c_count = freq_count.get(sel, 0)
                c_pct = (c_count / total_chars) * 100
                st.info(f"Huruf **{sel}** muncul sebanyak **{c_count} kali** (**{c_pct:.2f}%** dari total huruf).")
                
                # Tampilkan ciphertext dengan huruf yang dipilih diberi tanda kurung/sorotan agar mudah dilacak
                highlighted_preview = "".join([f"**[{c}]**" if c.upper() == sel else c for c in ciphertext])
                st.markdown(f"**Tinjauan Teks:** {highlighted_preview}")

        with col2:
            st.subheader("📈 Grafik Distribusi Frekuensi (%)")
            # Menyiapkan data untuk bar chart sederhana berbasis persentase
            chart_data = {char: (freq_count.get(char, 0) / total_chars) * 100 for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
            st.bar_chart(pd.Series(chart_data))

        st.markdown("---")
        st.subheader("🔄 Panel Substitusi Kunci (Trial & Error)")
        st.write("Masukkan pemetaan huruf substitusi Anda. Format: `CIPHER=PLAIN` dipisahkan spasi (Contoh: `U=H R=E Y=L`).")
        
        # Input pemetaan substitusi
        sub_input = st.text_input("Kamus Substitusi:", "U=H R=E Y=L J=O B=W E=Q")
        
        # Memproses kamus substitusi
        mapping = {}
        if sub_input:
            pairs = sub_input.split()
            for pair in pairs:
                if '=' in pair:
                    k, v = pair.split('=')
                    mapping[k.strip().upper()] = v.strip().upper()
        
        # Menerapkan dekripsi secara akurat pada teks asli
        decrypted_text = []
        for char in ciphertext:
            upper_c = char.upper()
            if upper_c in mapping:
                plain_char = mapping[upper_c]
                # Menjaga konsistensi huruf kapital/kecil dari ciphertext aslinya
                decrypted_text.append(plain_char.lower() if char.islower() else plain_char)
            else:
                # Jika huruf belum dipetakan, tampilkan tanda underscore '_' atau tetap karakter asli (di sini kita pakai karakter asli atau tanda '*' agar kentara, atau tetap apa adanya)
                decrypted_text.append(char)
        
        st.text_area("Hasil Dekripsi Sementara:", ''.join(decrypted_text), height=150)
    else:
        st.warning("Ciphertext harus mengandung huruf alfabet.")