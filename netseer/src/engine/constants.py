"""Risk-model constants (CONCEPTS A5, A14). All scoring constants live in this one module."""

from __future__ import annotations

# A14 device attribution: type → asset criticality (I1, 0–9).
DEVICE_TYPE = {"server": 9, "network": 8, "workstation": 6, "phone": 5, "iot": 5, "guest": 3, "unknown": 5}

DEVICE_TYPE_LABEL = {
    "server": "Server/NAS",
    "network": "Network device (router/switch/AP)",
    "workstation": "Workstation/Laptop",
    "phone": "Phone/Tablet",
    "iot": "IoT (printer/CCTV/smart device)",
    "guest": "Guest device",
    "unknown": "Unknown",
}

# A5.2 likelihood factors (0–9).
L1_PRIORITY = {1: 9, 2: 6, 3: 3, 4: 1}
L1_SIG_SEVERITY = {"Critical": 9, "Major": 7, "Minor": 4, "Informational": 1}   # overrides priority, except Informational
L3_RULE = {"single": 2, "R1": 6, "R2": 5, "R3": 7, "R4": 9}
L4_DIRECTION = {"ext->int": 9, "int->ext": 7, "int->int": 6, "ext->ext": 1}
# L2 = min(9, 3*log10(1+n_alerts));  L5 = max(abuseipdb/100, min(1, vt_malicious/VT_MALICIOUS_FULL))*9,
# counted in the mean only when it raises L (no reports is not evidence of safety)
VT_MALICIOUS_FULL = 5            # VirusTotal engines flagging an IP that count as fully malicious (L5 = 9)

# A5.2 impact factors (0–9).
I2_PORTS_9 = {21, 22, 23, 139, 445, 1433, 3306, 3389, 5432, 5900}
I2_PORTS_6 = {80, 443, 8080, 8443}
I2_OTHER = 4
I3_CLASSTYPE = {
    9: ["trojan-activity", "command-and-control", "successful-admin", "successful-user"],
    8: ["attempted-admin", "shellcode-detect", "exploit-kit"],
    7: ["attempted-user", "web-application-attack"],
    6: ["attempted-dos", "denial-of-service", "default-login-attempt", "credential-theft"],
    3: ["attempted-recon", "network-scan", "successful-recon-limited"],
    2: ["policy-violation", "misc-activity"],
    1: ["not-suspicious"],
}
I3_OTHER = 4
# L = mean(L1..L5 present);  I = I3*(0.5+0.5*I2/9)

# A5.3 levels and the OWASP matrix; key = (L level, I level).
LEVEL_CUTS = (3.0, 6.0)          # <3 Low, <6 Medium, else High
MATRIX = {("Low", "Low"): "Note", ("Low", "Medium"): "Low", ("Low", "High"): "Medium",
          ("Medium", "Low"): "Low", ("Medium", "Medium"): "Medium", ("Medium", "High"): "High",
          ("High", "Low"): "Medium", ("High", "Medium"): "High", ("High", "High"): "Critical"}
FACTOR_NAMES = {
    "L1": "Detection confidence", "L2": "Activity volume", "L3": "Correlation strength", "L4": "Exposure",
    "L5": "Threat reputation", "I1": "Asset criticality", "I2": "Service sensitivity", "I3": "Technical impact",
}
BANDS = ("Critical", "High", "Medium", "Low", "Note")      # sort order, worst first
# score R = 10*(L/9)*(I/9); sort by band then R

# A5.4 roll-up (rank-damped union).  p_i = R_i/10 * 0.5**(age/half_life), Note excluded
# D(x sorted desc) = 1 - prod_k(1 - x_k / k**DAMPING_P);  P(d) = D(p_i of incidents with d)
# P(N) = D(w_d*P(d), w_d = I1/9; no-device incidents use Unknown weight);  health = round(100*(1-P(N)))
DAMPING_P = 1.5                  # NetSeer heuristic, checked by split stability (CONCEPTS A5.4)
RISK_CUTS = ((90, "Critical"), (70, "High"), (40, "Medium"), (0, "Low"))   # device risk %, same as R x10

# A4 correlation thresholds.
SWEEP_MIN_HOSTS = 5              # R2: one source → at least this many destinations, same SID
FAN_IN_MIN_SOURCES = 5           # R3: at least this many sources → one destination, same SID

# MITRE ATT&CK enterprise tactics in kill-chain order (titles; R4 needs a step forward in this order).
MITRE_TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}
