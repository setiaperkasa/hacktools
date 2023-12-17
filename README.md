# Hacktools

"The quieter you become, the more you can hear."

Hacktools adalah serangkaian alat komprehensif yang dirancang untuk meningkatkan langkah-langkah keamanan siber dengan melakukan berbagai pemeriksaan dan analisis pada berbagai jenis file dan kode. Berikut adalah gambaran umum dari kemampuannya:

## Fitur

### Pemeriksaan Gambar
- **Pengecekan Validitas**: Memverifikasi apakah file gambar (jpg, jpeg, png, gif) valid dan tidak rusak.
- **Pemeriksaan Metadata Shellcode**: Memeriksa penyisipan shellcode dalam metadata gambar, teknik yang sering digunakan dalam steganografi.

### Pemeriksaan PDF
- **Pengecekan Keaslian**: Menentukan apakah file PDF asli atau palsu.
- **Deteksi Kode PHP**: Memindai adanya kode PHP dalam file PDF, yang bisa menjadi tanda adanya niat jahat.

### Pemeriksaan Kode PHP
- **Deteksi Tanda Peringatan**: Mencari berbagai tanda peringatan dalam file PHP, termasuk:
  - Penggunaan langsung `$_POST` atau `$_GET` tanpa escaping yang tepat.
  - Penggunaan `mysql_query` yang tidak aman.
  - `mysqli_query` tanpa binding parameter.

### Pemeriksaan Web Shell
- **Deteksi Tanda-tanda Web Shell**: Mencari tanda-tanda umum web shell dalam file PHP, yang sering digunakan untuk tujuan jahat.

### Pemeriksaan Hak Akses Folder
- **Pemeriksaan Izin Folder**: Menganalisis izin folder untuk mengidentifikasi potensi risiko keamanan.

### Pemeriksaan Upload File Injection
- **Pemeriksaan Injeksi File Upload**: Memeriksa kode untuk kerentanan yang mungkin memungkinkan upload file jahat.

### Pemeriksaan Directory Traversal
- **Pemeriksaan Kerentanan Directory Traversal**: Memeriksa kerentanan yang bisa memungkinkan serangan traversal direktori, teknik umum yang digunakan untuk mengakses file yang tidak diizinkan.

---

Hacktools dikembangkan dengan tujuan untuk menyediakan seperangkat alat yang mudah digunakan, namun kuat untuk profesional dan penggemar keamanan TI.

## Instalasi

Anda dapat menginstal Hacktools dengan mengikuti langkah-langkah berikut:

1. **Klon repositori ini** ke komputer Anda dengan perintah berikut:

   ```bash
   git clone https://github.com/setiaperkasa/hacktools.git
   ```
   
2. **Navigasi** Masuk ke direktori proyek:
	```bash
	cd hacktools
	```

3. **Persiapan** Pastikan Anda memiliki paket-paket yang dibutuhkan dengan menjalankan perintah berikut:
	```bash
	pip install -r requirements.txt
	```

---

## Penggunaan

1. Jalankan aplikasi.
2. Klik menu "Scan" dan pilih "Scan Direktori."
3. Pilih direktori yang ingin Anda pindai.
4. Pemindaian akan dimulai, dan Anda akan melihat bilah kemajuan yang menunjukkan kemajuan pemindaian.
5. Setelah pemindaian selesai, daftar file yang mencurigakan dan potensi kerentanan akan ditampilkan di jendela aplikasi.


## Lisensi
Proyek ini dilisensikan di bawah Lisensi MIT - lihat berkas [LICENSE](LICENSE) untuk rincian lebih lanjut.


## Penulis

Setia Perkasa
Linkedin : https://www.linkedin.com/in/blackevil03/