import nmap
import requests
from datetime import datetime
from config import Config
import time

vulnerabilitiesRec = Config.vulnerabilities_collection

def get_cves_for_service(service_name):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": service_name,
        "resultsPerPage": 5
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve_info = item.get("cve", {})
            cve_id = cve_info.get("id", "N/A")
            description = cve_info.get("descriptions", [{}])[0].get("value", "")

            metrics = cve_info.get("metrics", {})
            cvss_data = None
            score = None

            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})

            if cvss_data:
                score = cvss_data.get("baseScore", None)

            if score is not None:
                if score >= 7.0:
                    risk = "High"
                elif score >= 4.0:
                    risk = "Medium"
                else:
                    risk = "Low"
            else:
                continue  # Skip unknown risk

            cves.append({
                "id": cve_id,
                "description": description,
                "score": score,
                "risk": risk
            })

        return cves
    except Exception as e:
        print(f"[ERROR] Failed to fetch CVEs for {service_name}: {e}")
        return []

def scan_network(network_range):
    scanner = nmap.PortScanner()
    print(f"Scanning network: {network_range}")

    try:
        scanner.scan(hosts=network_range, arguments='-O -sS -T4')
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        return

    for host in scanner.all_hosts():
        ip_address = host
        os_name = "Unknown"

        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            os_name = scanner[host]['osmatch'][0]['name']

        services_info = []

        if 'tcp' in scanner[host]:
            for port, info in scanner[host]['tcp'].items():
                service = info.get('name', 'unknown')
                state = info.get('state', 'unknown')

                cves = get_cves_for_service(service)

                services_info.append({
                    "port": port,
                    "service": service,
                    "state": state,
                    "cves": cves
                })

                time.sleep(0.5)

        record = {
            "ip": ip_address,
            "os": os_name,
            "scanned_at": datetime.now(),
            "services": services_info
        }

        try:
            vulnerabilitiesRec.insert_one(record)
            print(f"[+] Inserted {ip_address} into MongoDB")
        except Exception as e:
            print(f"[ERROR] Could not insert {ip_address} into MongoDB: {e}")
