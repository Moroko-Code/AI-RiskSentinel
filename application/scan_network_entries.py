from config import Config

def get_flattened_vulnerabilities():
    vulnerabilitiesRec = Config.vulnerabilities_collection
    results = list(vulnerabilitiesRec.find())
    flattened_data = []

    for doc in results:
        ip = doc.get("ip")
        os = doc.get("os")
        scanned_at = doc.get("scanned_at")
        services = doc.get("services", [])

        if not services:
            flattened_data.append({
                "ip": ip,
                "os": os,
                "scanned_at": scanned_at,
                "port": None,
                "service": None,
                "state": None,
                "cve_id": None,
                "description": None,
                "score": None,
                "risk": None
            })

        for service in services:
            port = service.get("port")
            svc = service.get("service")
            state = service.get("state")
            cves = service.get("cves", [])

            if not cves:
                flattened_data.append({
                    "ip": ip,
                    "os": os,
                    "scanned_at": scanned_at,
                    "port": port,
                    "service": svc,
                    "state": state,
                    "cve_id": None,
                    "description": None,
                    "score": None,
                    "risk": None
                })

            for cve in cves:
                flattened_data.append({
                    "ip": ip,
                    "os": os,
                    "scanned_at": scanned_at,
                    "port": port,
                    "service": svc,
                    "state": state,
                    "cve_id": cve.get("id"),
                    "description": cve.get("description"),
                    "score": cve.get("score"),
                    "risk": cve.get("risk")
                })

    return flattened_data
