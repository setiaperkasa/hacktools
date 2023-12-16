# Hacktools

“The quieter you become, the more you can hear.”

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
