# 🔐 IP Threat Intelligence Checker

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-Web_Framework-black)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![Status](https://img.shields.io/badge/Project-Active-success)

Sistem berbasis web untuk menganalisis dan mengkorelasikan tingkat ancaman sebuah IP Address menggunakan multi-source Threat Intelligence API.

Project ini mengintegrasikan:

- 🛡️ VirusTotal API
- 🚨 AbuseIPDB API
- 📊 Correlation & Risk Scoring Engine
- 🌐 Flask Web Interface
- 🗄️ SQLite Database (History & Analytics)

---

## 📌 Deskripsi

IP Threat Intelligence Checker adalah aplikasi web yang digunakan untuk:

- Melakukan pengecekan IP Address terhadap database ancaman global
- Menggabungkan hasil dari beberapa sumber Threat Intelligence
- Menghitung skor risiko akhir (Final Threat Score 0–100)
- Mengklasifikasikan tingkat risiko
- Menyimpan riwayat scan
- Menampilkan statistik dan dashboard analitik

Sistem ini dikembangkan sebagai implementasi konsep **Cyber Threat Intelligence (CTI)** berbasis integrasi multi-source API.

---

## 🚀 Fitur Utama

### ✅ Single IP Check
- Validasi IP
- Analisis VirusTotal
- Analisis AbuseIPDB
- Perhitungan Final Risk Score
- Klasifikasi Risiko:
  - SAFE
  - LOW
  - MEDIUM
  - HIGH

---

### 📊 Correlation Engine

Sistem menghitung skor berdasarkan:

- Rasio malicious vendor
- Abuse confidence score
- Jumlah laporan abuse
- Weighting logic untuk menghasilkan `final_score`

Contoh:

```
Final Score: 58 / 100
Risk Level: MEDIUM
Source Used:
✔ VirusTotal
✔ AbuseIPDB
```

---

### 📁 History & Database

- Penyimpanan hasil scan
- Detail vendor per scan
- Statistik keseluruhan
- Riwayat scan terbaru

---

### 📈 Dashboard Statistik

- Total scan
- Unique IP
- Distribusi risk level
- Scan hari ini
- 5 scan terakhir

---

## 🏗️ Arsitektur Sistem

```
User Input
    ↓
Flask Controller
    ↓
Threat Intelligence Layer
    ├── VirusTotal API
    ├── AbuseIPDB API
    ↓
Correlation Engine
    ↓
SQLite Database
    ↓
Web Dashboard / Detail View
```

---

## 🛠️ Teknologi yang Digunakan

- Python 3.10+
- Flask
- SQLite3
- Requests
- python-dotenv
- HTML5 / Bootstrap
- VirusTotal Public API
- AbuseIPDB API

---

# 📦 Instalasi

## 1️⃣ Clone Repository

```bash
git clone https://github.com/username/ip-threat-checker.git
cd ip-threat-checker
```

---

## 2️⃣ Buat Virtual Environment

```bash
python -m venv venv
```

Aktifkan:

Windows:
```bash
venv\Scripts\activate
```

Mac/Linux:
```bash
source venv/bin/activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

Jika belum ada:

```bash
pip install flask requests python-dotenv
```

---

# 🔑 Konfigurasi API (.env)

## 1️⃣ Buat File `.env`

Di root folder project, buat file:

```
.env
```

Struktur folder:

```
ip-threat-checker/
│── app.py
│── database.py
│── config.py
│── .env
│── instance/
```

---

## 2️⃣ Isi File `.env`

Masukkan:

```
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

---

## 3️⃣ Pastikan config.py Memuat Environment

Contoh:

```python
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    VT_API_KEY = os.getenv("VT_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    DATABASE_PATH = "instance/ip_checker.db"
```

---

# ▶️ Menjalankan Aplikasi

```bash
python app.py
```

Akses melalui:

```
http://127.0.0.1:5000
```

---

# 🗄️ Database

Database SQLite otomatis dibuat di:

```
instance/ip_checker.db
```

Tabel utama:

- `scan_history`
- `scan_details`

---

# 🔐 Konsep Threat Intelligence

Sistem ini menerapkan:

- Indicator of Compromise (IoC) analysis
- Multi-source validation
- Risk correlation scoring
- Confidence-based classification
- Threat categorization

---

# 🎯 Tujuan Pengembangan

Project ini dibuat untuk:

- Implementasi konsep Cyber Threat Intelligence
- Integrasi multi-source API
- Analisis korelasi ancaman IP
- Laporan Praktik Kerja Lapangan (PKL)

---

# 📜 License

Project ini dibuat untuk tujuan edukasi dan pembelajaran.
