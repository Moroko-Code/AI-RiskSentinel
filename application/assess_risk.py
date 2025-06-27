
def assess_risk(os_name, open_ports, firewall_present):
    HIGH_RISK_PORTS = {21, 22, 23, 445, 3389}
    MID_RISK_PORTS = {80, 443, 8080, 8443}

    legacy_os = any(x in os_name.lower() for x in ['xp', '2000', 'vista', 'windows 7'])
    no_firewall = not firewall_present
    high_risk_count = len([p for p in open_ports if p in HIGH_RISK_PORTS])
    mid_risk_count = len([p for p in open_ports if p in MID_RISK_PORTS])

    if high_risk_count > 0 or (legacy_os and no_firewall):
        return "High"
    elif mid_risk_count >= 2 or legacy_os or no_firewall:
        return "Mid"
    else:
        return "Low"


