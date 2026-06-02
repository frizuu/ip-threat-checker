"""
app.py - Main Application
Pegadaian IP Security Checker
Sistem Automasi Pengecekan IP menggunakan VirusTotal API

Author: Fariz Ubaidillah - PKL Pegadaian 2026
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from config import Config
from database import Database
from vt_client import VirusTotalClient
from ip_validator import IPValidator
import json
import csv
from io import StringIO
from flask import Response
from abuseipdb import AbuseIPDBClient

# ==========================================
# INISIALISASI APP
# ==========================================
app = Flask(__name__)
app.config.from_object(Config)

# Inisialisasi komponen
db = Database()
vt = VirusTotalClient()
validator = IPValidator()
abuse = AbuseIPDBClient()

def correlate_threat(vt_result, abuse_result):
    """
    Menggabungkan hasil VirusTotal dan AbuseIPDB
    """
    vt_score = (vt_result.get("malicious", 0) * 3) + \
               (vt_result.get("suspicious", 0) * 2)

    abuse_score = abuse_result.get("abuse_score", 0)

    final_score = vt_score + (abuse_score // 10)

    # Tentukan risk level
    if final_score > 4:
        risk_level = "HIGH"
    elif final_score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    return final_score, risk_level


def apply_multi_source_result(vt_result, abuse_result, scan_type):
    """
    Standarisasi hasil VirusTotal + AbuseIPDB.
    Rumus korelasi mengikuti single check sebagai acuan utama.
    """
    if abuse_result.get("success"):
        vt_result["abuse_score"] = abuse_result.get("abuse_score", 0)
        vt_result["abuse_reports"] = abuse_result.get("total_reports", 0)
    else:
        vt_result["abuse_score"] = 0
        vt_result["abuse_reports"] = 0

    normalized_abuse_result = {
        "abuse_score": vt_result["abuse_score"]
    }
    final_score, risk_level = correlate_threat(
        vt_result,
        normalized_abuse_result
    )

    vt_result["final_score"] = final_score
    vt_result["risk_level"] = risk_level
    vt_result["scan_type"] = scan_type
    vt_result["source_vt"] = vt_result.get("success", False)
    vt_result["source_abuse"] = abuse_result.get("success", False)

    return vt_result

# ==========================================
# ROUTES - HALAMAN WEB
# ==========================================

@app.route('/')
def index():
    """Halaman Dashboard"""
    stats = db.get_statistics()
    api_valid = vt.check_api_key() if Config.VT_API_KEY != 'YOUR_API_KEY_HERE' else False
    return render_template('index.html', stats=stats, api_valid=api_valid)


@app.route('/single-check', methods=['GET', 'POST'])
def single_check():
    """Halaman Pengecekan Single IP"""
    result = None
    error = None
    ip_input = ''

    if request.method == 'POST':
        ip_input = request.form.get('ip_address', '').strip()

        # ===============================
        # VALIDASI IP
        # ===============================
        validation = validator.validate(ip_input)

        if not validation['valid']:
            error = validation['message']
        else:
            # ===============================
            # 1️⃣ VIRUSTOTAL CHECK
            # ===============================
            vt_result = vt.check_ip(ip_input)

            if not vt_result.get("success"):
                error = vt_result.get("error", "VirusTotal error")
            else:

                # ===============================
                # 2️⃣ ABUSEIPDB CHECK
                # ===============================
                abuse_result = abuse.check_ip(ip_input)

                vt_result = apply_multi_source_result(
                    vt_result,
                    abuse_result,
                    "single"
                )

                # ===============================
                # SAVE TO DATABASE
                # ===============================
                scan_id = db.save_scan(vt_result)
                vt_result["scan_id"] = scan_id

                result = vt_result

                flash(
                    f'IP {ip_input} berhasil dicek (Multi-Source Mode)!',
                    'success'
                )

    return render_template(
        'single_check.html',
        result=result,
        error=error,
        ip_input=ip_input
    )


@app.route('/bulk-check', methods=['GET', 'POST'])
def bulk_check():
    """Halaman Pengecekan Bulk IP"""
    results = []
    errors = []
    ip_input = ''

    if request.method == 'POST':
        ip_input = request.form.get('ip_list', '').strip()
        file = request.files.get('ip_file')

        # ===============================
        # HANDLE FILE UPLOAD
        # ===============================
        if file and file.filename != '':
            try:
                file_content = file.read().decode('utf-8')
                if ip_input:
                    ip_input += "\n" + file_content
                else:
                    ip_input = file_content
            except Exception:
                errors.append("Gagal membaca file. Pastikan format UTF-8.")

        if not ip_input:
            errors.append('Masukkan minimal 1 IP address')
        else:
            # ===============================
            # PARSE & VALIDATE
            # ===============================
            parsed_ips = validator.parse_bulk(ip_input)

            valid_ips = [p for p in parsed_ips if p['valid']]
            invalid_ips = [p for p in parsed_ips if not p['valid']]

            for inv in invalid_ips:
                errors.append(f"{inv['ip']}: {inv['message']}")

            # ===============================
            # PROCESS VALID IPS
            # ===============================
            for ip_data in valid_ips:

                ip_address = ip_data['ip']

                # ---- 1️⃣ VirusTotal ----
                vt_result = vt.check_ip(ip_address)

                if not vt_result.get("success"):
                    errors.append(
                        f"{ip_address}: {vt_result.get('error', 'VirusTotal error')}")
                    continue

                # ---- 2️⃣ AbuseIPDB ----
                abuse_result = abuse.check_ip(ip_address)

                vt_result = apply_multi_source_result(
                    vt_result,
                    abuse_result,
                    "bulk"
                )

                # ===============================
                # SAVE TO DATABASE
                # ===============================
                scan_id = db.save_scan(vt_result)
                vt_result["scan_id"] = scan_id

                results.append(vt_result)

        if results:
            flash(f'{len(results)} IP berhasil dicek (Multi-Source Mode)!', 'success')

    return render_template(
        'bulk_check.html',
        results=results,
        errors=errors,
        ip_input=ip_input
    )


@app.route('/history')
def history():
    """Halaman Riwayat Scan"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    search = request.args.get('search', '').strip()

    if search:
        scans = db.search_ip(search)
    else:
        scans = db.get_history(limit=per_page, offset=offset)

    return render_template(
        'history.html',
        scans=scans,
        search=search,
        page=page
    )

@app.route("/export_history")
def export_history():
    import csv
    import io
    from database import Database
    from flask import Response

    db = Database()
    scans = db.get_history(limit=1000, offset=0)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')

    # ===============================
    # SUMMARY SECTION
    # ===============================
    total_scans = len(scans)
    high = sum(1 for s in scans if s["risk_level"] == "HIGH")
    medium = sum(1 for s in scans if s["risk_level"] == "MEDIUM")
    safe = sum(1 for s in scans if s["risk_level"] == "SAFE")

    writer.writerow(["IP Threat Intelligence Report"])
    writer.writerow([])
    writer.writerow(["Generated At:", __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow(["Total Scans:", total_scans])
    writer.writerow(["High Risk:", high])
    writer.writerow(["Medium Risk:", medium])
    writer.writerow(["Safe:", safe])
    writer.writerow([])
    writer.writerow(["=" * 80])
    writer.writerow([])

    # ===============================
    # TABLE HEADER
    # ===============================
    writer.writerow([
        "ID",
        "IP Address",
        "Risk Level",
        "Risk Score",
        "Malicious",
        "Suspicious",
        "Harmless",
        "Country",
        "AS Owner",
        "Scan Type",
        "Scan Date"
    ])

    # ===============================
    # DATA ROWS
    # ===============================
    for scan in scans:
        risk_score = (scan["malicious"] * 3) + (scan["suspicious"] * 2)

        writer.writerow([
            scan["id"],
            scan["ip_address"],
            scan["risk_level"],
            risk_score,
            scan["malicious"],
            scan["suspicious"],
            scan["harmless"],
            scan["country"] or "-",
            scan["as_owner"] or "-",
            scan["scan_type"],
            scan["scan_date"]
        ])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=ip_threat_report.csv"
        }
    )


@app.route('/detail/<int:scan_id>')
def detail(scan_id):
    """Halaman Detail Scan"""
    scan = db.get_scan_by_id(scan_id)

    if not scan:
        flash('Data scan tidak ditemukan', 'error')
        return redirect(url_for('history'))

    return render_template('detail.html', scan=scan)


@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Hapus record scan"""
    db.delete_scan(scan_id)
    flash('Record berhasil dihapus', 'success')
    return redirect(url_for('history'))


@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Hapus semua riwayat"""
    count = db.clear_history()
    flash(f'{count} record berhasil dihapus', 'success')
    return redirect(url_for('history'))


# ==========================================
# API ENDPOINTS (untuk AJAX / Integrasi)
# ==========================================

@app.route('/api/check-ip', methods=['POST'])
def api_check_ip():
    """API endpoint untuk cek IP via AJAX"""
    data = request.get_json()

    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address diperlukan'}), 400

    ip = data['ip'].strip()
    validation = validator.validate(ip)

    if not validation['valid']:
        return jsonify({'error': validation['message']}), 400

    result = vt.check_ip(ip)

    if result['success']:
        abuse_result = abuse.check_ip(ip)
        result = apply_multi_source_result(
            result,
            abuse_result,
            "api"
        )
        scan_id = db.save_scan(result)
        result['scan_id'] = scan_id
        # Hapus raw_response dari API response (terlalu besar)
        result.pop('raw_response', None)
        result.pop('vendor_details', None)

    return jsonify(result)


@app.route('/api/validate-ip', methods=['POST'])
def api_validate_ip():
    """API endpoint untuk validasi IP"""
    data = request.get_json()

    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address diperlukan'}), 400

    result = validator.validate(data['ip'])
    return jsonify(result)


@app.route('/api/stats')
def api_stats():
    """API endpoint untuk statistik"""
    stats = db.get_statistics()
    return jsonify(stats)


# ==========================================
# TEMPLATE FILTERS
# ==========================================

@app.template_filter('risk_color')
def risk_color_filter(risk_level):
    """Filter Jinja2 untuk warna berdasarkan risk level"""
    colors = {
        'HIGH': 'danger',
        'MEDIUM': 'warning',
        'SAFE': 'success',
        'UNKNOWN': 'secondary'
    }
    return colors.get(risk_level, 'secondary')


@app.template_filter('risk_icon')
def risk_icon_filter(risk_level):
    """Filter Jinja2 untuk icon berdasarkan risk level"""
    icons = {
        'HIGH': 'bi-exclamation-triangle-fill',
        'MEDIUM': 'bi-exclamation-circle-fill',
        'SAFE': 'bi-shield-check',
        'UNKNOWN': 'bi-question-circle'
    }
    return icons.get(risk_level, 'bi-question-circle')


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found(e):
    return render_template('base.html', error='Halaman tidak ditemukan'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('base.html', error='Server error'), 500


# ==========================================
# MAIN
# ==========================================

if __name__ == '__main__':
    print("=" * 60)
    print("  PEGADAIAN IP SECURITY CHECKER")
    print("  Sistem Automasi Pengecekan IP - VirusTotal API")
    print("=" * 60)

    # Cek API key
    if Config.VT_API_KEY == 'YOUR_API_KEY_HERE':
        print("\n⚠️  WARNING: API Key belum dikonfigurasi!")
        print("  1. Daftar di https://www.virustotal.com/gui/join-us")
        print("  2. Copy API Key dari profil")
        print("  3. Set di config.py atau environment variable VT_API_KEY")
        print()

    print(f"\n🌐 Server berjalan di: http://127.0.0.1:5000")
    print(f"📁 Database: {Config.DATABASE_PATH}\n")

    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    )
