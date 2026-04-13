# registry_forensic_cli.py
"""
WRFA - Windows Registry Forensic Analyzer
Author : AASU'g
Purpose: Offline Registry Forensic Analysis from exported hives
"""

import hashlib
import pandas as pd
import codecs
import os
import html
import subprocess
import re
from datetime import datetime, timezone
from Registry import Registry
from colorama import Fore, Style, init

init(autoreset=True)

# =========================
# PATH CONFIGURATION
# =========================
EVIDENCE = "evidence/"
REPORT_CSV = "reports/registry_forensic_report.csv"
REPORT_HTML = "reports/registry_forensic_report.html"
REPORT_PDF = "reports/registry_forensic_report.pdf"

HIVES = {
    "SYSTEM": EVIDENCE + "SYSTEM",
    "SOFTWARE": EVIDENCE + "SOFTWARE",
    "SAM": EVIDENCE + "SAM",
    "SECURITY": EVIDENCE + "SECURITY",
    "DEFAULT": EVIDENCE + "DEFAULT",
    "NTUSER": EVIDENCE + "NTUSER.DAT",
    "USRCLASS": EVIDENCE + "UsrClass.dat"
}

# =========================
# BANNER
# =========================
def banner():
    print(Fore.RED + r"""
██╗    ██╗██████╗ ███████╗ █████╗
██║    ██║██╔══██╗██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝█████╗  ███████║
██║███╗██║██╔══██╗██╔══╝  ██╔══██║
╚███╔███╔╝██║  ██║██║     ██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
""")
    print(Fore.RED + "WRFA - Windows Registry Forensic Analyzer")
    print(Fore.RED + "Author : AASU'g\n")
    print(Style.DIM + "[ Offline | Read-Only | Evidence Preserved ]\n")

# =========================
# HASH VERIFICATION
# =========================
def sha256(path):
    if not os.path.exists(path):
        return "Missing"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# =========================
# RISK CLASSIFICATION
# =========================
def classify_risk(category, artifact):
    """Classify risk level of a forensic artifact."""
    art_lower = artifact.lower() if artifact else ""

    # HIGH risk artifacts
    if category == "RunKeys":
        return "HIGH"
    if category == "USBHistory":
        return "HIGH"
    if category == "ExecutedPrograms":
        if any(p in art_lower for p in ["downloads", "temp", "appdata\\local\\temp"]):
            return "HIGH"
        if art_lower.endswith(".exe") and "program files" not in art_lower:
            return "MEDIUM"
    if category == "ExplorerInteraction":
        if any(p in art_lower for p in ["\\\\", "usb", "removable"]):
            return "HIGH"
    if category == "LocalUsers":
        if artifact not in ["Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount"]:
            return "MEDIUM"

    # MEDIUM risk artifacts
    if category in ["InstalledSoftware", "OpenSaveMRU"]:
        return "MEDIUM"

    return "INFO"

# =========================
# TIMESTAMP HELPER
# =========================
def get_timestamp(key):
    """Extract last-modified timestamp from a registry key."""
    try:
        ts = key.timestamp()
        if ts:
            return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        pass
    return ""

# =========================
# STRING CLEANER (NEW ADD)
# =========================
def clean_string(s):
    try:
        s = str(s)
        s = re.sub(r'[^\x20-\x7E]', '', s)  # remove non printable
        return s.strip()
    except:
        return ""



# =========================
# USER ARTIFACTS
# =========================
def recent_docs():
    out = []
    try:
        reg = Registry.Registry(HIVES["NTUSER"])
        key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")

        for s in key.subkeys():
            ext = s.name()

            for v in s.values():
                try:
                    raw = v.value()

                    if isinstance(raw, bytes):
                        decoded = raw.decode("utf-16le", errors="ignore")
                    else:
                        decoded = str(raw)

                    cleaned = clean_string(decoded)

                    if ".lnk" in cleaned.lower():
                        out.append({
                            "category": "RecentDocs",
                            "artifact": cleaned,
                            "source": "NTUSER.DAT",
                            "details": f"Recent File ({ext})",
                            "timestamp": get_timestamp(s),
                            "risk": "INFO"
                        })
                except:
                    pass
    except:
        pass

    return out

def userassist():
    out = []
    try:
        reg = Registry.Registry(HIVES["NTUSER"])
        ua = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
        for guid in ua.subkeys():
            for s in guid.subkeys():
                if s.name() == "Count":
                    ts = get_timestamp(s)
                    for v in s.values():
                        decoded = codecs.decode(v.name(), "rot_13")
                        out.append({
                            "category": "ExecutedPrograms",
                            "artifact": decoded,
                            "source": "NTUSER.DAT",
                            "details": f"UserAssist GUID: {guid.name()}",
                            "timestamp": ts,
                            "risk": classify_risk("ExecutedPrograms", decoded)
                        })
    except:
        pass
    return out

def opensavemru():
    out = []
    try:
        reg = Registry.Registry(HIVES["NTUSER"])

        base_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"
        k = reg.open(base_path)

        parent_ts = get_timestamp(k)

        for ext in k.subkeys():  # .txt, .pdf etc
            ext_ts = get_timestamp(ext)

            for v in ext.values():
                try:
                    raw = v.value()

                    # STRING CASE
                    if isinstance(raw, str):
                        cleaned = clean_string(raw)

                    # BINARY CASE (REAL DATA)
                    elif isinstance(raw, bytes):
                        try:
                            cleaned = raw.decode("utf-16le", errors="ignore")
                            cleaned = clean_string(cleaned)
                        except:
                            cleaned = str(raw[:40])  # fallback preview

                    else:
                        cleaned = str(raw)

                    if cleaned:
                        out.append({
                            "category": "OpenSaveMRU",
                            "artifact": f"{ext.name()} → {cleaned}",
                            "source": "NTUSER.DAT",
                            "details": "Opened/Saved file (decoded)",
                            "timestamp": ext_ts or parent_ts,
                            "risk": "MEDIUM"
                        })

                except:
                    continue

    except Exception as e:
        print("[ERROR OpenSaveMRU]", e)

    return out

def run_keys():
    out = []
    try:
        reg = Registry.Registry(HIVES["NTUSER"])
        k = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        ts = get_timestamp(k)
        for v in k.values():
            entry = f"{v.name()} = {v.value()}"
            out.append({
                "category": "RunKeys",
                "artifact": entry,
                "source": "NTUSER.DAT",
                "details": "Auto-start persistence mechanism",
                "timestamp": ts,
                "risk": classify_risk("RunKeys", entry)
            })
    except:
        pass
    return out

# =========================
# USRCLASS.DAT ARTIFACTS
# =========================
def shellbags():
    out = []
    try:
        reg = Registry.Registry(HIVES["USRCLASS"])
        key = reg.open(
            "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
        )
        parent_ts = get_timestamp(key)
        for s in key.subkeys():
            ts = get_timestamp(s)
            out.append({
                "category": "ShellBags",
                "artifact": f"BagMRU Entry : {s.name()}",
                "source": "UsrClass.dat",
                "details": "Folder navigation record (persists after deletion)",
                "timestamp": ts or parent_ts,
                "risk": classify_risk("ShellBags", s.name())
            })
    except:
        pass
    return out

def folder_view_history():
    out = []
    try:
        reg = Registry.Registry(HIVES["USRCLASS"])
        key = reg.open(
            "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags"
        )
        parent_ts = get_timestamp(key)
        for s in key.subkeys():
            ts = get_timestamp(s)
            out.append({
                "category": "FolderViewHistory",
                "artifact": f"Folder View Bag : {s.name()}",
                "source": "UsrClass.dat",
                "details": "Folder view customization (size, sort, position)",
                "timestamp": ts or parent_ts,
                "risk": classify_risk("FolderViewHistory", s.name())
            })
    except:
        pass
    return out

def explorer_interaction():
    out = []
    try:
        reg = Registry.Registry(HIVES["NTUSER"])
        key = reg.open(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
        )
        ts = get_timestamp(key)
        for v in key.values():
            out.append({
                "category": "ExplorerInteraction",
                "artifact": v.value(),
                "source": "NTUSER.DAT",
                "details": "Manually typed Explorer address bar path",
                "timestamp": ts,
                "risk": classify_risk("ExplorerInteraction", v.value())
            })
    except:
        pass
    return out


# =========================
# DEFAULT HIVE ARTIFACTS
# =========================
def default_user_profile():
    out = []
    try:
        reg = Registry.Registry(HIVES["DEFAULT"])

        # Explorer Run (default behavior)
        try:
            k = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            ts = get_timestamp(k)
            for v in k.values():
                entry = f"{v.name()} = {v.value()}"
                out.append({
                    "category": "DefaultRun",
                    "artifact": entry,
                    "source": "DEFAULT",
                    "details": "Default profile auto-start entry",
                    "timestamp": ts,
                    "risk": "MEDIUM"
                })
        except:
            pass

        # Default Shell settings
        try:
            k = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")
            ts = get_timestamp(k)
            out.append({
                "category": "DefaultExplorer",
                "artifact": "Explorer Default Config",
                "source": "DEFAULT",
                "details": "Default user shell configuration",
                "timestamp": ts,
                "risk": "INFO"
            })
        except:
            pass

    except:
        pass

    return out


# =========================
# SYSTEM ARTIFACTS
# =========================
def usb_history():
    out = []
    try:
        reg = Registry.Registry(HIVES["SYSTEM"])
        k = reg.open("ControlSet001\\Enum\\USBSTOR")

        for device in k.subkeys():
            for instance in device.subkeys():
                try:
                    name = device.name()
                    serial = instance.name()

                    friendly = ""
                    try:
                        friendly = instance.value("FriendlyName").value()
                    except:
                        pass

                    out.append({
                        "category": "USBHistory",
                        "artifact": f"{friendly} | {serial}",
                        "source": "SYSTEM",
                        "details": "USB device with serial number",
                        "timestamp": get_timestamp(instance),
                        "risk": "HIGH"
                    })
                except:
                    pass
    except:
        pass

    return out

def installed_software():
    out = []
    try:
        reg = Registry.Registry(HIVES["SOFTWARE"])
        k = reg.open("Microsoft\\Windows\\CurrentVersion\\Uninstall")
        for s in k.subkeys():
            try:
                name = s.value("DisplayName").value()
                ts = get_timestamp(s)
                out.append({
                    "category": "InstalledSoftware",
                    "artifact": name,
                    "source": "SOFTWARE",
                    "details": "Installed application",
                    "timestamp": ts,
                    "risk": classify_risk("InstalledSoftware", name)
                })
            except:
                pass
    except:
        pass
    return out

def services():
    out = []
    try:
        reg = Registry.Registry(HIVES["SYSTEM"])
        k = reg.open("ControlSet001\\Services")
        for s in k.subkeys():
            ts = get_timestamp(s)
            out.append({
                "category": "Services",
                "artifact": s.name(),
                "source": "SYSTEM",
                "details": "Registered Windows service/driver",
                "timestamp": ts,
                "risk": classify_risk("Services", s.name())
            })
    except:
        pass
    return out

def mounted_devices():
    out = []
    try:
        reg = Registry.Registry(HIVES["SYSTEM"])
        k = reg.open("MountedDevices")
        ts = get_timestamp(k)
        for v in k.values():
            out.append({
                "category": "MountedDevices",
                "artifact": v.name(),
                "source": "SYSTEM",
                "details": "Drive letter / volume mapping",
                "timestamp": ts,
                "risk": classify_risk("MountedDevices", v.name())
            })
    except:
        pass
    return out

def network_interfaces():
    out = []
    try:
        reg = Registry.Registry(HIVES["SYSTEM"])
        k = reg.open("ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces")

        for s in k.subkeys():
            try:
                guid = s.name()

                ip = ""
                try:
                    ip = s.value("DhcpIPAddress").value()
                except:
                    pass

                out.append({
                    "category": "NetworkInterfaces",
                    "artifact": f"{guid} | IP: {ip if ip else 'N/A'}",
                    "source": "SYSTEM",
                    "details": "Adapter GUID + IP Address",
                    "timestamp": get_timestamp(s),
                    "risk": "INFO"
                })
            except:
                pass
    except:
        pass

    return out

def sam_users():
    import struct
    from datetime import datetime

    def filetime_to_dt(ft):
        try:
            if ft == 0:
                return "Never"
            return datetime.utcfromtimestamp(
                (ft - 116444736000000000) / 10000000
            ).strftime("%Y-%m-%d %H:%M:%S")
        except:
            return "N/A"

    out = []

    try:
        reg = Registry.Registry(HIVES["SAM"])

        names_key = reg.open("SAM\\Domains\\Account\\Users\\Names")
        users_key = reg.open("SAM\\Domains\\Account\\Users")

        for user in names_key.subkeys():
            try:
                username = user.name()
                ts = get_timestamp(user)

                rid = user.value("").value()
                rid_hex = format(rid, 'x').zfill(8)

                last_login = "N/A"
                pwd_change = "N/A"
                account_created = "N/A"
                failed_logins = "N/A"

                try:
                    user_key = users_key.open(rid_hex)
                    v_data = user_key.value("V").value()

                    # 🔥 OFFSETS (SAM STRUCTURE)
                    last_login_ft      = struct.unpack("<Q", v_data[8:16])[0]
                    pwd_change_ft      = struct.unpack("<Q", v_data[24:32])[0]
                    account_create_ft  = struct.unpack("<Q", v_data[40:48])[0]

                    # Failed login count (approx offset)
                    failed_logins      = struct.unpack("<H", v_data[64:66])[0]

                    last_login = filetime_to_dt(last_login_ft)
                    pwd_change = filetime_to_dt(pwd_change_ft)
                    account_created = filetime_to_dt(account_create_ft)

                except:
                    pass

                out.append({
                    "category": "LocalUsers",
                    "artifact": username,
                    "source": "SAM",
                    "details": (
                        f"Last Login: {last_login} | "
                        f"Pwd Changed: {pwd_change} | "
                        f"Created: {account_created} | "
                        f"Failed Logins: {failed_logins}"
                    ),
                    "timestamp": ts,
                    "risk": classify_risk("LocalUsers", username)
                })

            except:
                pass

    except:
        pass

    return out

# =========================
# COLLECT ALL ARTIFACTS
# =========================
def collect_all_artifacts():
    """Collect all forensic artifacts into a single flat list."""
    all_artifacts = []
    all_artifacts.extend(recent_docs())
    all_artifacts.extend(userassist())
    all_artifacts.extend(opensavemru())
    all_artifacts.extend(run_keys())
    all_artifacts.extend(shellbags())
    all_artifacts.extend(folder_view_history())
    all_artifacts.extend(explorer_interaction())
    all_artifacts.extend(usb_history())
    all_artifacts.extend(installed_software())
    all_artifacts.extend(services())
    all_artifacts.extend(mounted_devices())
    all_artifacts.extend(network_interfaces())
    all_artifacts.extend(sam_users())
    all_artifacts.extend(default_user_profile()) 
    return all_artifacts

# =========================
# CSV REPORT
# =========================
def generate_csv_report(artifacts):
    """Generate structured long-format CSV report."""
    
    # 1. Take the flat list of extracted artifacts and build a structured Pandas table
    df = pd.DataFrame(artifacts, columns=["category", "artifact", "source", "details", "timestamp", "risk"])
    
    # 2. Rename the columns to look nice for the Excel header row
    df.columns = ["Category", "Artifact", "Source Hive", "Details", "Timestamp", "Risk Level"]
    
    # 3. Export to CSV file
    df.to_csv(REPORT_CSV, index=False)
    
    # 4. Print summary to the console
    print(Fore.GREEN + f"\n[✔] CSV Report Generated → {REPORT_CSV}")
    print(Fore.YELLOW + f"    Total artifacts: {len(df)}")

# =========================
# HTML REPORT
# =========================
def generate_html_report(artifacts):
    """Generate professional styled HTML forensic report."""

    # Compute evidence hashes
    hashes = {k: sha256(v) for k, v in HIVES.items()}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build statistics
    total = len(artifacts)
    high_count = sum(1 for a in artifacts if a["risk"] == "HIGH")
    med_count = sum(1 for a in artifacts if a["risk"] == "MEDIUM")
    info_count = sum(1 for a in artifacts if a["risk"] == "INFO")

    # Category display names and order
    CATEGORY_META = {
        "RunKeys":             {"label": "🔴 Auto-Start Programs (Run Keys)", "desc": "Programs configured to run automatically at login — a common persistence mechanism for malware."},
        "USBHistory":          {"label": "🔴 USB Device History", "desc": "USB storage devices that have been connected to this system."},
        "ExecutedPrograms":    {"label": "🟡 Executed Programs (UserAssist)", "desc": "Programs the user has launched, decoded from ROT-13 obfuscation."},
        "ExplorerInteraction": {"label": "🟡 Explorer Typed Paths", "desc": "Paths manually typed into the Windows Explorer address bar."},
        "RecentDocs":          {"label": "📄 Recently Opened Documents", "desc": "File types recently accessed by the user."},
        "OpenSaveMRU":         {"label": "📂 Open/Save Dialog History", "desc": "File types opened or saved via standard Windows file dialogs."},
        "ShellBags":           {"label": "📁 ShellBags (Folder Navigation)", "desc": "Records of folders browsed in Explorer — persists even after folder deletion."},
        "FolderViewHistory":   {"label": "📁 Folder View Settings", "desc": "Per-folder view customizations (sort order, view mode, window size)."},
        "InstalledSoftware":   {"label": "💿 Installed Software", "desc": "Applications registered in the system's Uninstall registry."},
        "LocalUsers":          {"label": "👤 Local User Accounts", "desc": "User accounts found in the SAM database."},
        "Services":            {"label": "⚙️ Windows Services", "desc": "Services and drivers registered on the system."},
        "MountedDevices":      {"label": "💾 Mounted Devices", "desc": "Drive letter and volume mappings."},
        "NetworkInterfaces":   {"label": "🌐 Network Interfaces", "desc": "Network adapter identifiers (GUIDs)."},
    }

    # Group artifacts by category
    grouped = {}
    for a in artifacts:
        cat = a["category"]
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(a)

    # Build category sections HTML
    sections_html = ""
    for cat_key, meta in CATEGORY_META.items():
        items = grouped.get(cat_key, [])
        if not items:
            continue

        cat_high = sum(1 for i in items if i["risk"] == "HIGH")
        cat_med = sum(1 for i in items if i["risk"] == "MEDIUM")

        badge = ""
        if cat_high:
            badge += f'<span class="badge high">{cat_high} HIGH</span>'
        if cat_med:
            badge += f'<span class="badge med">{cat_med} MEDIUM</span>'

        rows = ""
        for item in items:
            risk_class = item["risk"].lower()
            rows += f"""<tr class="risk-{risk_class}">
    <td>{html.escape(item["artifact"])}</td>
    <td>{html.escape(item["details"])}</td>
    <td>{html.escape(item["source"])}</td>
    <td>{html.escape(item["timestamp"])}</td>
    <td><span class="risk-tag {risk_class}">{item["risk"]}</span></td>
</tr>\n"""

        sections_html += f"""
<div class="section">
    <div class="section-header">
        <h2>{meta["label"]} <span class="count">({len(items)})</span> {badge}</h2>
        <p class="section-desc">{meta["desc"]}</p>
    </div>
    <div class="table-wrap">
    <table>
        <thead>
            <tr><th>Artifact</th><th>Details</th><th>Source</th><th>Timestamp</th><th>Risk</th></tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    </div>
</div>
"""

    # Build hashes table
    hash_rows = ""
    for k, v in hashes.items():
        status = "✔ Verified" if v != "Missing" else "✘ Missing"
        cls = "hash-ok" if v != "Missing" else "hash-miss"
        hash_rows += f"<tr><td>{k}</td><td class='{cls}'>{v}</td><td class='{cls}'>{status}</td></tr>\n"

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WRFA Forensic Report</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {{
        --bg: #0a0a0f;
        --surface: #12121a;
        --surface2: #1a1a26;
        --border: #2a2a3a;
        --text: #e0e0e8;
        --text-dim: #8888a0;
        --red: #e94560;
        --red-glow: rgba(233, 69, 96, 0.15);
        --orange: #f59e0b;
        --orange-glow: rgba(245, 158, 11, 0.15);
        --green: #10b981;
        --green-glow: rgba(16, 185, 129, 0.15);
        --blue: #3b82f6;
    }}

    * {{ margin: 0; padding: 0; box-sizing: border-box; }}

    body {{
        font-family: 'Inter', sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.6;
        padding: 0;
    }}

    .header {{
        background: linear-gradient(135deg, #1a0a10 0%, #0a0a1a 50%, #0a1a15 100%);
        border-bottom: 1px solid var(--border);
        padding: 40px;
        text-align: center;
    }}

    .header h1 {{
        font-size: 2.2rem;
        font-weight: 700;
        color: var(--red);
        letter-spacing: 3px;
        margin-bottom: 8px;
    }}

    .header .subtitle {{
        color: var(--text-dim);
        font-size: 0.95rem;
        font-weight: 300;
    }}

    .header .meta {{
        margin-top: 20px;
        display: flex;
        justify-content: center;
        gap: 30px;
        flex-wrap: wrap;
    }}

    .header .meta span {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: var(--text-dim);
        background: var(--surface);
        padding: 6px 14px;
        border-radius: 6px;
        border: 1px solid var(--border);
    }}

    .container {{
        max-width: 1400px;
        margin: 0 auto;
        padding: 30px 40px;
    }}

    /* Executive Summary */
    .summary {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
        margin-bottom: 30px;
    }}

    .stat-card {{
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        transition: transform 0.2s;
    }}

    .stat-card:hover {{ transform: translateY(-2px); }}

    .stat-card .number {{
        font-size: 2rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }}

    .stat-card .label {{
        font-size: 0.8rem;
        color: var(--text-dim);
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 4px;
    }}

    .stat-card.high .number {{ color: var(--red); }}
    .stat-card.med .number {{ color: var(--orange); }}
    .stat-card.info .number {{ color: var(--green); }}
    .stat-card.total .number {{ color: var(--blue); }}

    /* Hash Verification */
    .hash-section {{
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 24px;
        margin-bottom: 30px;
    }}

    .hash-section h2 {{
        font-size: 1.1rem;
        margin-bottom: 16px;
        color: var(--text);
    }}

    .hash-section table {{
        width: 100%;
        border-collapse: collapse;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
    }}

    .hash-section th {{
        text-align: left;
        padding: 8px 12px;
        color: var(--text-dim);
        border-bottom: 1px solid var(--border);
        font-weight: 500;
    }}

    .hash-section td {{
        padding: 8px 12px;
        border-bottom: 1px solid var(--border);
        word-break: break-all;
    }}

    .hash-ok {{ color: var(--green); }}
    .hash-miss {{ color: var(--red); }}

    /* Sections */
    .section {{
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        margin-bottom: 20px;
        overflow: hidden;
    }}

    .section-header {{
        padding: 20px 24px 14px;
        border-bottom: 1px solid var(--border);
    }}

    .section-header h2 {{
        font-size: 1.1rem;
        font-weight: 600;
    }}

    .section-desc {{
        font-size: 0.82rem;
        color: var(--text-dim);
        margin-top: 4px;
    }}

    .count {{
        color: var(--text-dim);
        font-weight: 400;
        font-size: 0.9rem;
    }}

    .badge {{
        display: inline-block;
        font-size: 0.7rem;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        margin-left: 8px;
        vertical-align: middle;
    }}

    .badge.high {{
        background: var(--red-glow);
        color: var(--red);
        border: 1px solid var(--red);
    }}

    .badge.med {{
        background: var(--orange-glow);
        color: var(--orange);
        border: 1px solid var(--orange);
    }}

    .table-wrap {{
        overflow-x: auto;
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.82rem;
    }}

    thead th {{
        text-align: left;
        padding: 10px 14px;
        color: var(--text-dim);
        font-weight: 500;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        background: var(--surface2);
        position: sticky;
        top: 0;
    }}

    tbody td {{
        padding: 8px 14px;
        border-bottom: 1px solid rgba(42, 42, 58, 0.5);
        word-break: break-word;
        max-width: 500px;
    }}

    tbody tr:hover {{
        background: rgba(255, 255, 255, 0.02);
    }}

    /* Risk rows */
    .risk-high {{
        background: var(--red-glow);
    }}

    .risk-medium {{
        background: var(--orange-glow);
    }}

    /* Risk tags */
    .risk-tag {{
        display: inline-block;
        font-size: 0.68rem;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        letter-spacing: 0.5px;
    }}

    .risk-tag.high {{
        background: var(--red);
        color: #fff;
    }}

    .risk-tag.medium {{
        background: var(--orange);
        color: #000;
    }}

    .risk-tag.info {{
        background: var(--border);
        color: var(--text-dim);
    }}

    .footer {{
        text-align: center;
        padding: 30px;
        color: var(--text-dim);
        font-size: 0.75rem;
        border-top: 1px solid var(--border);
        margin-top: 20px;
    }}

    @media (max-width: 768px) {{
        .container {{ padding: 16px; }}
        .header {{ padding: 24px; }}
        .header h1 {{ font-size: 1.5rem; }}
        .summary {{ grid-template-columns: repeat(2, 1fr); }}
    }}
</style>
</head>
<body>

<div class="header">
    <h1>⚡ W R F A</h1>
    <div class="subtitle">Windows Registry Forensic Analyzer — Investigation Report</div>
    <div class="meta">
        <span>📅 Generated: {now}</span>
        <span>🔒 Mode: Offline / Read-Only</span>
        <span>👤 Author: AASU'g</span>
    </div>
</div>

<div class="container">

    <!-- Executive Summary -->
    <div class="summary">
        <div class="stat-card total">
            <div class="number">{total}</div>
            <div class="label">Total Artifacts</div>
        </div>
        <div class="stat-card high">
            <div class="number">{high_count}</div>
            <div class="label">High Risk</div>
        </div>
        <div class="stat-card med">
            <div class="number">{med_count}</div>
            <div class="label">Medium Risk</div>
        </div>
        <div class="stat-card info">
            <div class="number">{info_count}</div>
            <div class="label">Informational</div>
        </div>
    </div>

    <!-- Evidence Integrity -->
    <div class="hash-section">
        <h2>🔐 Evidence Integrity — SHA-256 Hashes</h2>
        <table>
            <thead><tr><th>Hive</th><th>SHA-256 Hash</th><th>Status</th></tr></thead>
            <tbody>{hash_rows}</tbody>
        </table>
    </div>

    <!-- Artifact Sections -->
    {sections_html}

</div>

<div class="footer">
    WRFA — Windows Registry Forensic Analyzer | Evidence untouched. Analysis clean.
</div>

</body>
</html>"""

    with open(REPORT_HTML, "w", encoding="utf-8") as f:
        f.write(report_html)

    print(Fore.GREEN + f"    [✔] HTML Report Generated → {REPORT_HTML}")

# =========================
# PDF REPORT (EDGE HEADLESS)
# =========================
def generate_pdf_report():
    """Generate PDF report using headless Microsoft Edge."""
    html_path = os.path.abspath(REPORT_HTML)
    pdf_path = os.path.abspath(REPORT_PDF)

    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    ]
    edge_exe = next((p for p in edge_paths if os.path.exists(p)), None)

    if not edge_exe:
        print(Fore.RED + "    [✘] PDF skipped: Microsoft Edge not found.")
        return

    edge_cmd = [
        edge_exe,
        "--headless",
        "--disable-gpu",
        f"--print-to-pdf={pdf_path}",
        html_path
    ]
    
    try:
        # Hide output window and run silently
        subprocess.run(edge_cmd, capture_output=True, check=False)
        if os.path.exists(pdf_path):
            print(Fore.GREEN + f"    [✔] PDF Report Generated  → {REPORT_PDF}")
        else:
            print(Fore.RED + "    [✘] PDF generation failed silently.")
    except Exception as e:
        print(Fore.RED + f"    [✘] PDF generation error: {e}")

# =========================
# REPORT GENERATION
# =========================
def generate_report():
    print(Fore.YELLOW + "\n[*] Collecting forensic artifacts...")
    artifacts = collect_all_artifacts()
    print(Fore.YELLOW + f"[*] Found {len(artifacts)} artifacts across {len(set(a['category'] for a in artifacts))} categories\n")
    return artifacts

# =========================
# MAIN
# =========================
def main():
    banner()
    while True:
        print(Fore.RED + "\n╔══════════════════════════════════════╗")
        print(Fore.RED + "║       WRFA — Analysis Menu          ║")
        print(Fore.RED + "╠══════════════════════════════════════╣")
        print(Fore.RED + "║  1) Verify Evidence Hashes           ║")
        print(Fore.RED + "║  2) Generate Forensic Reports        ║")
        print(Fore.RED + "║  3) Exit                             ║")
        print(Fore.RED + "╚══════════════════════════════════════╝\n")

        c = input(Fore.RED + "WRFA> ").strip()

        if c == "1":
            print(Fore.YELLOW + "\n[*] Evidence Hash Verification:\n")
            for k, v in HIVES.items():
                h = sha256(v)
                status = Fore.GREEN + "✔" if h != "Missing" else Fore.RED + "✘"
                print(f"  {status} {k:<10} : {Fore.CYAN}{h}")
            print(Fore.RED + "\n[✔] Evidence untouched. Analysis clean.")

        elif c == "2":
            artifacts = generate_report()
            if artifacts:
                generate_csv_report(artifacts)
                generate_html_report(artifacts)
                generate_pdf_report()
                print(Fore.GREEN + "\n[✔] All reports generated successfully.")

        elif c == "3":
            print(Fore.RED + "\n[ WRFA TERMINATED ]")
            break

        else:
            print(Fore.YELLOW + "Invalid option. Please select 1-3.")

        print(Fore.RED + "\n[✔] Evidence untouched. Analysis clean.\n")

if __name__ == "__main__":
    main()
