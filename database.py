"""
database.py - Database Handler (Multi-Source Version)
Support: VirusTotal + AbuseIPDB + Correlation
"""

import sqlite3
import os
from datetime import datetime
from config import Config


class Database:

    def __init__(self):
        os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
        self.db_path = Config.DATABASE_PATH
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
            # ==========================================
    # SEARCH HISTORY BY IP
    # ==========================================
    def search_ip(self, keyword: str, limit=100, offset=0) -> list:

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT *
            FROM scan_history
            WHERE ip_address LIKE ?
            ORDER BY scan_date DESC
            LIMIT ? OFFSET ?
        ''', (f"%{keyword}%", limit, offset))

        rows = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return rows

    

        # ==============================
        # MAIN TABLE
        # ==============================
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,

                malicious INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0,
                harmless INTEGER DEFAULT 0,
                undetected INTEGER DEFAULT 0,
                total_vendors INTEGER DEFAULT 0,

                risk_level TEXT DEFAULT 'UNKNOWN',

                -- Multi-source fields
                final_score INTEGER DEFAULT 0,
                abuse_score INTEGER DEFAULT 0,
                abuse_reports INTEGER DEFAULT 0,
                source_vt INTEGER DEFAULT 0,
                source_abuse INTEGER DEFAULT 0,

                country TEXT DEFAULT '-',
                as_owner TEXT DEFAULT '-',
                network TEXT DEFAULT '-',

                raw_response TEXT,
                scan_type TEXT DEFAULT 'single'
            )
        ''')

        # ==============================
        # VENDOR DETAIL TABLE
        # ==============================
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                vendor_name TEXT NOT NULL,
                category TEXT DEFAULT 'undetected',
                result TEXT DEFAULT 'clean',
                method TEXT DEFAULT 'blacklist',
                FOREIGN KEY (scan_id) REFERENCES scan_history(id)
                    ON DELETE CASCADE
            )
        ''')

        conn.commit()
        conn.close()

    # ==========================================
    # SAVE SCAN
    # ==========================================
    def save_scan(self, scan_data: dict) -> int:

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scan_history (
                ip_address,
                scan_date,
                malicious,
                suspicious,
                harmless,
                undetected,
                total_vendors,
                risk_level,
                final_score,
                abuse_score,
                abuse_reports,
                source_vt,
                source_abuse,
                country,
                as_owner,
                network,
                raw_response,
                scan_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_data.get('ip_address'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            scan_data.get('malicious', 0),
            scan_data.get('suspicious', 0),
            scan_data.get('harmless', 0),
            scan_data.get('undetected', 0),
            scan_data.get('total_vendors', 0),
            scan_data.get('risk_level', 'UNKNOWN'),
            scan_data.get('final_score', 0),
            scan_data.get('abuse_score', 0),
            scan_data.get('abuse_reports', 0),
            int(scan_data.get('source_vt', False)),
            int(scan_data.get('source_abuse', False)),
            scan_data.get('country', '-'),
            scan_data.get('as_owner', '-'),
            scan_data.get('network', '-'),
            scan_data.get('raw_response', ''),
            scan_data.get('scan_type', 'single')
        ))

        scan_id = cursor.lastrowid

        # Save vendor details
        vendor_details = scan_data.get('vendor_details', [])
        for detail in vendor_details:
            cursor.execute('''
                INSERT INTO scan_details
                (scan_id, vendor_name, category, result, method)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                scan_id,
                detail.get('vendor_name', ''),
                detail.get('category', 'undetected'),
                detail.get('result', 'clean'),
                detail.get('method', 'blacklist')
            ))

        conn.commit()
        conn.close()

        return scan_id

    # ==========================================
    # GET SCAN BY ID
    # ==========================================
    def get_scan_by_id(self, scan_id: int) -> dict:

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT * FROM scan_history WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()

        if not scan:
            conn.close()
            return None

        scan_dict = dict(scan)

        # convert integer to boolean
        scan_dict['source_vt'] = bool(scan_dict.get('source_vt'))
        scan_dict['source_abuse'] = bool(scan_dict.get('source_abuse'))

        cursor.execute('''
            SELECT * FROM scan_details
            WHERE scan_id = ?
            ORDER BY category, vendor_name
        ''', (scan_id,))

        scan_dict['details'] = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return scan_dict

    # ==========================================
    # HISTORY
    # ==========================================
    def get_history(self, limit=100, offset=0) -> list:

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM scan_history
            ORDER BY scan_date DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))

        rows = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return rows
    
        # ==========================================
    # CLEAR ALL HISTORY
    # ==========================================
    def clear_history(self):

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM scan_details")
        cursor.execute("DELETE FROM scan_history")

        conn.commit()
        conn.close()
        
    # ==========================================
    # STATISTICS (Dashboard)
    # ==========================================
    def get_statistics(self) -> dict:

        conn = self.get_connection()
        cursor = conn.cursor()

        stats = {}

        # Total scan
        cursor.execute('SELECT COUNT(*) as total FROM scan_history')
        stats['total_scans'] = cursor.fetchone()['total']

        # Unique IPs
        cursor.execute(
            'SELECT COUNT(DISTINCT ip_address) as total FROM scan_history'
        )
        stats['unique_ips'] = cursor.fetchone()['total']

        # Risk level distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count
            FROM scan_history
            GROUP BY risk_level
        ''')

        risk_counts = {
            row['risk_level']: row['count']
            for row in cursor.fetchall()
        }

        stats['high_risk'] = risk_counts.get('HIGH', 0)
        stats['medium_risk'] = risk_counts.get('MEDIUM', 0)
        stats['low_risk'] = risk_counts.get('LOW', 0)
        stats['safe'] = risk_counts.get('SAFE', 0)

        # Scan hari ini
        cursor.execute('''
            SELECT COUNT(*) as total
            FROM scan_history
            WHERE DATE(scan_date) = DATE('now')
        ''')
        stats['today_scans'] = cursor.fetchone()['total']

        # Recent scans (5 terakhir)
        cursor.execute('''
            SELECT *
            FROM scan_history
            ORDER BY scan_date DESC
            LIMIT 5
        ''')

        stats['recent_scans'] = [
            dict(row) for row in cursor.fetchall()
        ]

        conn.close()
        return stats