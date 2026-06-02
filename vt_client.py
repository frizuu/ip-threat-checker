"""
vt_client.py - VirusTotal API Client
Modul untuk berkomunikasi dengan VirusTotal API v3
"""

import requests
import time
import json
from config import Config


class VirusTotalClient:
    """Client untuk VirusTotal API v3"""

    def __init__(self):
        """Inisialisasi client"""
        self.api_key = Config.VT_API_KEY
        self.base_url = Config.VT_BASE_URL
        self.headers = {
            'x-apikey': self.api_key,
            'Accept': 'application/json'
        }
        self.last_request_time = 0
        self.request_count = 0

    def _rate_limit(self):
        """
        Mengatur rate limiting agar tidak melebihi batas API gratis
        Free tier: 4 requests per menit, 500 per hari
        """
        current_time = time.time()
        elapsed = current_time - self.last_request_time

        # Reset counter setiap 60 detik
        if elapsed >= Config.VT_RATE_PERIOD:
            self.request_count = 0
            self.last_request_time = current_time

        # Jika sudah mencapai limit, tunggu
        if self.request_count >= Config.VT_RATE_LIMIT:
            wait_time = Config.VT_RATE_PERIOD - elapsed
            if wait_time > 0:
                print(f"[VT] Rate limit reached. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time)
                self.request_count = 0
                self.last_request_time = time.time()

        self.request_count += 1

    def check_ip(self, ip_address: str) -> dict:
        """
        Mengecek reputasi IP address di VirusTotal

        Args:
            ip_address: IP address yang akan dicek

        Returns:
            dict: Hasil analisis dengan format standar

        API Endpoint: GET /api/v3/ip_addresses/{ip}
        """
        self._rate_limit()

        url = f"{self.base_url}/ip_addresses/{ip_address}"

        try:
            print(f"[VT] Checking IP: {ip_address}")
            response = requests.get(
                url,
                headers=self.headers,
                timeout=30
            )

            # Handle HTTP errors
            if response.status_code == 401:
                return {
                    'success': False,
                    'error': 'API Key tidak valid. Silakan periksa konfigurasi.',
                    'error_code': 401
                }
            elif response.status_code == 429:
                return {
                    'success': False,
                    'error': 'Rate limit exceeded. Coba lagi dalam 1 menit.',
                    'error_code': 429
                }
            elif response.status_code == 404:
                return {
                    'success': False,
                    'error': f'IP {ip_address} tidak ditemukan di database VirusTotal.',
                    'error_code': 404
                }
            elif response.status_code != 200:
                return {
                    'success': False,
                    'error': f'HTTP Error {response.status_code}',
                    'error_code': response.status_code
                }

            # Parse response
            data = response.json()
            return self._parse_response(ip_address, data)

        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timeout. Periksa koneksi internet.',
                'error_code': 'TIMEOUT'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Tidak dapat terhubung ke VirusTotal. Periksa koneksi internet.',
                'error_code': 'CONNECTION_ERROR'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error tidak terduga: {str(e)}',
                'error_code': 'UNKNOWN'
            }

    def _parse_response(self, ip_address: str, data: dict) -> dict:
        """
        Parse response dari VirusTotal API

        Struktur response VT API v3:
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": int,
                        "suspicious": int,
                        "harmless": int,
                        "undetected": int,
                        "timeout": int
                    },
                    "last_analysis_results": {
                        "vendor_name": {
                            "category": "malicious|suspicious|harmless|undetected",
                            "result": "clean|malware|...",
                            "method": "blacklist|whitelist",
                            "engine_name": "vendor"
                        }
                    },
                    "country": "ID",
                    "as_owner": "PT Telkom Indonesia",
                    "network": "xxx.xxx.xxx.0/24",
                    ...
                }
            }
        }
        """
        try:
            attributes = data.get('data', {}).get('attributes', {})

            # Statistik analisis
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            timeout = stats.get('timeout', 0)

            total_vendors = malicious + suspicious + harmless + undetected + timeout

            # Tentukan risk level
            risk_level = self._calculate_risk(malicious, suspicious)

            # Detail per vendor
            analysis_results = attributes.get('last_analysis_results', {})
            vendor_details = []

            for vendor_name, vendor_data in analysis_results.items():
                vendor_details.append({
                    'vendor_name': vendor_name,
                    'category': vendor_data.get('category', 'undetected'),
                    'result': vendor_data.get('result', 'clean'),
                    'method': vendor_data.get('method', 'blacklist')
                })

            # Informasi jaringan
            country = attributes.get('country', '-')
            as_owner = attributes.get('as_owner', '-')
            network = attributes.get('network', '-')

            # WHOIS info
            whois = attributes.get('whois', '')
            reputation = attributes.get('reputation', 0)

            return {
                'success': True,
                'ip_address': ip_address,
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'undetected': undetected,
                'timeout': timeout,
                'total_vendors': total_vendors,
                'risk_level': risk_level,
                'country': country,
                'as_owner': as_owner,
                'network': network,
                'reputation': reputation,
                'vendor_details': vendor_details,
                'raw_response': json.dumps(data, indent=2)
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error parsing response: {str(e)}',
                'error_code': 'PARSE_ERROR'
            }

    def _calculate_risk(self, malicious: int, suspicious: int) -> str:
        """
        Menghitung level risiko berdasarkan deteksi vendor

        Kriteria:
        - HIGH    : malicious >= 5
        - MEDIUM  : malicious >= 1 atau suspicious >= 3
        - SAFE    : malicious = 0 dan suspicious = 0
        """
        if malicious >= Config.RISK_HIGH_THRESHOLD:
            return 'HIGH'
        elif malicious >= Config.RISK_MEDIUM_THRESHOLD or suspicious >= 3:
            return 'MEDIUM'
        else:
            return 'SAFE'

    def check_api_key(self) -> bool:
        """Verifikasi apakah API key valid"""
        if self.api_key == 'YOUR_API_KEY_HERE' or not self.api_key:
            return False

        try:
            url = f"{self.base_url}/ip_addresses/8.8.8.8"
            response = requests.get(
                url,
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False