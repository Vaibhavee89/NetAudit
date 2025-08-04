import streamlit as st
import nmap
import psutil
import dns.resolver
import socket
import json
from datetime import datetime
import pandas as pd

from fpdf import FPDF
import io
from fpdf import FPDF  # <-- Add this import
import subprocess
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

# ========================
# Utility Functions
# ========================

def scan_network(subnet):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments='-sn')
    live_hosts = []
    for host in scanner.all_hosts():
        mac = scanner[host]['addresses'].get('mac', "N/A")
        live_hosts.append({
            'ip': host,
            'mac': mac,
            'status': scanner[host].state()
        })
    return live_hosts

def port_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-sV -p 1-65535 -T4')
    if ip not in scanner.all_hosts():
        return {"error": f"No scan results for {ip}. Host may be unreachable."}
    ports = []
    for proto in scanner[ip].all_protocols():
        for port in scanner[ip][proto].keys():
            ports.append({
                'port': port,
                'service': scanner[ip][proto][port]['name'],
                'state': scanner[ip][proto][port]['state'],
                'product': scanner[ip][proto][port].get('product', ''),
                'version': scanner[ip][proto][port].get('version', '')
            })
    return ports

def os_detect(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-O')
    if ip not in scanner.all_hosts():
        return "No scan results. Host may be unreachable."
    return scanner[ip]['osmatch'][0]['name'] if scanner[ip]['osmatch'] else "Unknown"

def dns_audit(domain):
    try:
        records = dns.resolver.resolve(domain, 'A')
        return [r.to_text() for r in records]
    except Exception as e:
        return [f"DNS lookup failed: {str(e)}"]

def traffic_stats():
    net = psutil.net_io_counters()
    return {'sent': net.bytes_sent, 'recv': net.bytes_recv}

# def vulnerability_scan(ip):
#     import nmap
#     scanner = nmap.PortScanner()

#     vuln_scripts = [
#         'smb-vuln-ms17-010',
#         'smb2-vuln-uptime',
#         'smb-vuln-cve2009-3103',
#         'smb-vuln-ms08-067',
#         'rdp-vuln-ms12-020',  # for port 3389
#         'http-vuln-cve2017-5638',  # for web if 80/443 open
#         'ssl-ccs-injection',       # SSL vuln
#     ]

#     target_ports = '135,139,445,3389,593,1025,1433,5357'
#     results = []

#     for script in vuln_scripts:
#         try:
#             scanner.scan(hosts=ip, arguments=f'-Pn -p {target_ports} --script {script}')
#             host_data = scanner[ip]
#             hostscripts = host_data.get('hostscript', [])
#             for vuln in hostscripts:
#                 results.append({
#                     'script': vuln.get('id', script),
#                     'output': vuln.get('output', 'No output provided')
#                 })
#         except Exception as e:
#             results.append({
#                 'script': script,
#                 'error': str(e)
#             })

#     return {
#         'vulnerabilities': results
#     } if results else {
#         "message": "No known vulnerabilities detected with specific scripts.",
#         "note": f"Ports scanned: {target_ports}. Target may be patched or need deeper scans."
#     }

# def vulnerability_scan(ip):
#     scanner = nmap.PortScanner()
#     scanner.scan(hosts=ip, arguments='--script vuln')
#     return scanner[ip].get('hostscript', [])

# def run_combined_vuln_scan(target_ip):
#     # Step 1: Load vulnerability patterns
#     with open("vuln_data.json", "r") as f:
#         vuln_data = json.load(f)

#     suspicious_ports = vuln_data.get("vuln_ports", [])
#     suspicious_vendors = vuln_data.get("suspicious_vendors", [])
#     suspicious_hostnames = vuln_data.get("suspicious_hostnames", [])
#     vuln_rules = vuln_data.get("vuln_rules", [])

#     # Step 2: Run Nmap vulnerability scan with scripts
#     scanner = nmap.PortScanner()
#     try:
#         scanner.scan(target_ip, arguments="-sV --script vuln")
#     except Exception as e:
#         return {"error": f"Scan failed: {e}"}

#     result = {"target": target_ip, "vulnerabilities": []}

#     if target_ip in scanner.all_hosts():
#         host_info = scanner[target_ip]

#         # Check open ports and matched ports
#         for port in host_info.get("tcp", {}):
#             port_info = host_info["tcp"][port]
#             port_data = {
#                 "port": port,
#                 "name": port_info.get("name", ""),
#                 "product": port_info.get("product", ""),
#                 "version": port_info.get("version", ""),
#                 "script_output": port_info.get("script", {})
#             }

#             if port in suspicious_ports:
#                 port_data["matched"] = "Matched Suspicious Port"
#             result["vulnerabilities"].append(port_data)

#         # Vendor and hostname checks
#         vendor = host_info.get("vendor", {}).get(host_info.get("addresses", {}).get("mac", ""), "")
#         hostname = host_info.get("hostnames", [{}])[0].get("name", "")

#         if vendor in suspicious_vendors:
#             result["vulnerabilities"].append({"type": "Vendor Match", "vendor": vendor})
#         if hostname in suspicious_hostnames:
#             result["vulnerabilities"].append({"type": "Suspicious Hostname", "hostname": hostname})
        
#         # Vuln rule matching (basic string match in script output)
#         for port in result["vulnerabilities"]:
#             scripts = port.get("script_output", {})
#             if isinstance(scripts, dict):
#                 for script_name, output in scripts.items():
#                     for rule in vuln_rules:
#                         if rule.lower() in output.lower():
#                             result["vulnerabilities"].append({
#                                 "type": "Matched Vulnerability Rule",
#                                 "port": port.get("port"),
#                                 "rule": rule,
#                                 "script": script_name,
#                                 "output": output
#                             })
#     return result

# def load_vuln_data_from_csv(file_path="vuln_data.csv"):
#     df = pd.read_csv(file_path)
#     vuln_data = {
#         "vuln_ports": [],
#         "suspicious_vendors": [],
#         "suspicious_hostnames": [],
#         "rules": []
#     }

#     for _, row in df.iterrows():
#         if row['match_type'] == 'vuln_port':
#             vuln_data['vuln_ports'].append(int(row['value']))
#         elif row['match_type'] == 'suspicious_vendor':
#             vuln_data['suspicious_vendors'].append(row['value'].lower())
#         elif row['match_type'] == 'suspicious_hostname':
#             vuln_data['suspicious_hostnames'].append(row['value'].lower())

#         vuln_data['rules'].append({
#             "type": row['vuln_type'],
#             "value": row['value'],
#             "description": row['description']
#         })

#     return vuln_data

# Load vulnerability database
def load_vuln_db():
    with open('vuln_db.json', 'r') as f:
        return json.load(f)

# Run Nmap script on a target IP and port
def run_nmap_script(ip, script, port=None):
    nm = nmap.PortScanner()
    args = f"--script={script}"
    if port:
        args += f" -p {port}"
    nm.scan(hosts=ip, arguments=args)
    return nm[ip]

# Auto vulnerability scan
def run_auto_vuln_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments="-O -sS")
    
    os_match = nm[ip].get('osmatch', [])
    ports = [int(p) for p in nm[ip]['tcp'].keys()] if 'tcp' in nm[ip] else []

    detected_os = os_match[0]['name'].lower() if os_match else "unknown"
    if "linux" in detected_os:
        detected_os = "linux"
    elif "windows" in detected_os:
        detected_os = "windows"
    else:
        detected_os = "unknown"

    vuln_db = load_vuln_db()

    results = []

    for entry in vuln_db:
        if any(p in ports for p in entry['ports']) and detected_os in entry['os']:
            for port in entry['ports']:
                result = run_nmap_script(ip, entry['nmap_script'], port)
                results.append({ "vuln": entry['name'], "result": result })

    return results

# Custom vulnerability scan
def run_custom_vuln_scan(ip, keyword):
    vuln_db = load_vuln_db()
    for entry in vuln_db:
        if keyword.lower() in entry['name'].lower():
            for port in entry['ports']:
                result = run_nmap_script(ip, entry['nmap_script'], port)
                return { "vuln": entry['name'], "result": result }
    return { "error": "No matching vulnerability found." }

# def run_nmap_vuln_scan(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-sV --script vuln')
    
    detected = []
    host_info = scanner[target_ip]
    vuln_data = load_vuln_data_from_csv()

    for proto in host_info.all_protocols():
        for port in host_info[proto].keys():
            # Port Vulnerability Check
            if port in vuln_data['vuln_ports']:
                detected.append({
                    "ip": target_ip,
                    "type": "Open Vulnerable Port",
                    "port": port,
                    "description": f"Port {port} is marked as vulnerable"
                })

    # Hostname & Vendor (You can pass this info from scan_network function)
    hostname = host_info.hostname().lower()
    vendor = host_info['addresses'].get('mac_vendor', 'unknown').lower()

    if hostname in vuln_data['suspicious_hostnames']:
        detected.append({
            "ip": target_ip,
            "type": "Suspicious Hostname",
            "value": hostname,
            "description": "Hostname matches a suspicious pattern"
        })

    if vendor in vuln_data['suspicious_vendors']:
        detected.append({
            "ip": target_ip,
            "type": "Suspicious Vendor",
            "value": vendor,
            "description": "Vendor matches a flagged manufacturer"
        })

    return detected


def save_report(data, name='scan_report.json'):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    json_filename = f'report_{timestamp}.json'
    pdf_filename = f'report_{timestamp}.pdf'
    # Save JSON
    with open(json_filename, 'w') as f:
        json.dump(data, f, indent=2)
    # Save PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, "Network Audit Report", ln=True, align="C")
    pdf.ln(10)
    for key, value in data.items():
        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(0, 10, f"{key}:", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 10, json.dumps(value, indent=2))
        pdf.ln(2)
    pdf.output(pdf_filename)
    return json_filename, pdf_filename

def firewall_test(ip, ports=[22, 80, 443]):
    results = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
            results[port] = "Open"
        except Exception:
            results[port] = "Blocked/Filtered"
        finally:
            sock.close()
    return results

def download_report_ui():
    import glob
    reports = sorted(glob.glob("report_*.pdf"), reverse=True)
    if reports:
        latest_report = reports[0]
        with open(latest_report, "rb") as f:
            st.download_button(
                label="Download Latest Report (PDF)",
                data=f.read(),
                file_name=latest_report,
                mime="application/pdf"
            )
    else:
        st.info("No PDF reports found.")

def generate_pdf(report_data, title="Scan Report"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=title, ln=True, align="C")
    pdf.ln(10)

    if isinstance(report_data, list):
        for item in report_data:
            pdf.multi_cell(0, 10, txt=json.dumps(item, indent=2))
            pdf.ln()
    elif isinstance(report_data, dict):
        pdf.multi_cell(0, 10, txt=json.dumps(report_data, indent=2))
    else:
        pdf.multi_cell(0, 10, txt=str(report_data))

    # Get PDF as byte string
    pdf_bytes = pdf.output(dest='S').encode('latin-1')  # 'S' = return as string
    return io.BytesIO(pdf_bytes)

def get_firewall_rules():
    # Run the netsh command and capture output
    output = subprocess.getoutput('netsh advfirewall firewall show rule name=all')
    rules = []
    current_rule = {}
    for line in output.splitlines():
        if line.startswith("Rule Name:"):
            if current_rule:
                rules.append(current_rule)
                current_rule = {}
            current_rule['name'] = line.split(":", 1)[1].strip()
        elif line.startswith("LocalPort:"):
            current_rule['port'] = line.split(":", 1)[1].strip()
        elif line.startswith("Protocol:"):
            current_rule['protocol'] = line.split(":", 1)[1].strip()
    if current_rule:
        rules.append(current_rule)
    return rules

def firewall_test_all_rules():
    rules = get_firewall_rules()
    results = []
    for rule in rules:
        port = rule.get('port')
        protocol = rule.get('protocol', 'TCP')
        name = rule.get('name')
        if port and port.isdigit():
            sock_type = socket.SOCK_STREAM if protocol.upper() == 'TCP' else socket.SOCK_DGRAM
            sock = socket.socket(socket.AF_INET, sock_type)
            sock.settimeout(1)
            try:
                sock.connect(('127.0.0.1', int(port)))
                status = "Open"
            except Exception:
                status = "Blocked/Filtered"
            finally:
                sock.close()
            results.append({'rule': name, 'port': port, 'protocol': protocol, 'status': status})
    return results

def map_network_topology(subnet):
    hosts = scan_network(subnet)
    G = nx.Graph()
    for host in hosts:
        ip = host['ip']
        mac = host['mac']
        G.add_node(ip, label=f"{ip}\n{mac}")
    net = Network(height="500px", width="100%", bgcolor="#222222", font_color="white")
    net.from_nx(G)
    net.show("topology.html", notebook=False)  # <-- Fix here
    with open("topology.html", "r", encoding="utf-8") as f:
        html = f.read()
    return html

def check_for_intrusion(scanned_hosts, genuine_hosts):
 scanned_ips = {host['ip'] for host in scanned_hosts}
 genuine_ips = {host['ip'] for host in genuine_hosts}
 intrusive_ips = scanned_ips - genuine_ips
 return [host for host in scanned_hosts if host['ip'] in intrusive_ips]

# def check_for_intrusion(scanned_hosts, genuine_hosts):
#     scanned_ips = {host['ip'] for host in scanned_hosts}
#     genuine_ip_map = {host['ip']: host.get('mac', '') for host in genuine_hosts}
    
#     intrusions = []

#     for host in scanned_hosts:
#         ip = host['ip']
#         mac = host['mac']
#         status = host['status']
        
#         if ip not in genuine_ip_map:
#             intrusions.append({
#                 'ip': ip,
#                 'mac': mac,
#                 'status': status,
#                 'issue': "Unknown IP - Not in genuine list"
#             })
#         elif mac != genuine_ip_map[ip] and mac != "N/A":
#             intrusions.append({
#                 'ip': ip,
#                 'mac': mac,
#                 'expected_mac': genuine_ip_map[ip],
#                 'status': status,
#                 'issue': "MAC address mismatch"
#             })

#     return intrusions



# ========================
# Streamlit UI
# ========================

st.set_page_config(page_title="NetAudit - Network Auditing Tool", layout="wide")
st.title("🛡️ NetAudit – Network Auditing Tool (Backend Prototype)")

st.sidebar.header("📝 Audit Scope & Objectives")
scope = st.sidebar.text_input("Define Scope (e.g. 192.168.1.0/24, example.com)", "")
objectives = st.sidebar.text_area("Define Objectives (e.g. Find open ports, check OS, audit DNS)", "")

# Store scope/objectives for use in reports
user_scope = scope if scope else "Not specified"
user_objectives = objectives if objectives else "Not specified"

st.sidebar.header("🔍 Audit Options")
scan_type = st.sidebar.selectbox("Choose Action", [
 "Intrusion Detection",
    "Network Scan",
    "Port & Service Scan",
    "OS Detection",
    "DNS Audit",
    "Traffic Stats",
    "Vulnerability Scan",
    "Firewall Test",
    "Map Network Topology"  # <-- Add this
])

if scan_type == "Intrusion Detection":
    st.header("Intrusion Detection")
    subnet = st.text_input("Enter Subnet to Scan (e.g. 192.168.1.0/24)", "192.168.1.0/24")
    genuine_hosts_input = st.text_area("Enter Genuine Hosts (one IP per line)", "192.168.1.1\n192.168.1.100")
    genuine_hosts = [{"ip": ip.strip()} for ip in genuine_hosts_input.splitlines() if ip.strip()]

    permission = st.checkbox("I have permission to scan this network and understand the risks.")
    if st.button("Check for Intrusions") and permission:
        st.info(f"Scanning subnet {subnet} to check for intrusions...")
        scanned_hosts = scan_network(subnet)
        intrusions = check_for_intrusion(scanned_hosts, genuine_hosts)
        
        if intrusions:
            st.error("Potential Intrusions Detected:")
            st.json(intrusions)
        else:
            st.success("No intrusions detected based on the genuine hosts list.")

        pdf = generate_pdf(intrusions, title=f"Intrusion Detection Report ({subnet})")
        st.download_button("📥 Download PDF Report", pdf, file_name="intrusion_detection_report.pdf", mime="application/pdf")

# if scan_type == "Intrusion Detection":
#     st.header("📡 Advanced Intrusion Detection")

#     subnet = st.text_input("Enter Subnet to Scan (e.g. 192.168.1.0/24)", "192.168.1.0/24")
    
#     st.markdown("### 🧾 Known (Genuine) Hosts")
#     genuine_hosts_input = st.text_area("Enter Genuine Hosts (Format: IP[,MAC])", "192.168.1.1,AA:BB:CC:DD:EE:FF\n192.168.1.100")
#     genuine_hosts = []
#     for line in genuine_hosts_input.splitlines():
#         parts = line.strip().split(',')
#         if len(parts) == 2:
#             genuine_hosts.append({'ip': parts[0].strip(), 'mac': parts[1].strip().lower()})
#         elif len(parts) == 1:
#             genuine_hosts.append({'ip': parts[0].strip(), 'mac': ''})

#     permission = st.checkbox("✅ I have permission to scan this network and understand the risks.")

#     if st.button("🔍 Check for Intrusions") and permission:
#         st.info(f"Scanning subnet `{subnet}` to check for intrusions...")
#         scanned_hosts = scan_network(subnet)
#         intrusions = check_for_intrusion(scanned_hosts, genuine_hosts)

#         if intrusions:
#             st.error(f"⚠️ {len(intrusions)} Potential Intrusions Detected!")
#             for intr in intrusions:
#                 st.json(intr)
#         else:
#             st.success("✅ No intrusions detected based on the known hosts.")

#         pdf = generate_pdf(intrusions, title=f"Intrusion Detection Report ({subnet})")
#         st.download_button("📥 Download PDF Report", pdf, file_name="intrusion_detection_report.pdf", mime="application/pdf")

elif scan_type == "Network Scan":
    subnet = st.text_input("Enter Subnet (e.g. 192.168.1.0/24)", "192.168.1.0/24")
    permission = st.checkbox("I have permission to scan this network and understand the risks.")
    if st.button("Scan Network", key="scan_network") and permission:
        result = scan_network(subnet)
        st.success(f"Found {len(result)} live hosts.")
        st.json(result)
        save_report({
            "scope": user_scope,
            "objectives": user_objectives,
            "hosts": result
        })
        pdf = generate_pdf(result, title=f"Network Scan Report ({subnet})")
        st.download_button("📥 Download PDF Report", pdf, file_name="network_scan_report.pdf", mime="application/pdf")
    elif st.button("Scan Network", key="scan_network_no_permission") and not permission:
        st.error("You must confirm you have permission before scanning.")

elif scan_type == "Port & Service Scan":
    ip = st.text_input("Target IP", "192.168.1.1")
    if st.button("Scan Ports"):
        result = port_scan(ip)
        st.json(result)
        save_report({"ip": ip, "ports": result})

        pdf = generate_pdf(result, title=f"Port & Service Scan Report ({ip})")
        st.download_button("📥 Download PDF Report", pdf, file_name="port_service_report.pdf", mime="application/pdf")

elif scan_type == "OS Detection":
    ip = st.text_input("Target IP for OS detection", "192.168.1.1")
    if st.button("Detect OS"):
        os = os_detect(ip)
        st.success(f"Detected OS: {os}")
        save_report({"ip": ip, "os": os})

        pdf = generate_pdf({"ip": ip, "os": os}, title=f"OS Detection Report ({ip})")
        st.download_button("📥 Download PDF Report", pdf, file_name="os_detection_report.pdf", mime="application/pdf")

elif scan_type == "DNS Audit":
    domain = st.text_input("Enter Domain", "example.com")
    if st.button("Run DNS Audit"):
        result = dns_audit(domain)
        st.json(result)
        save_report({"domain": domain, "dns": result})

        pdf = generate_pdf(result, title=f"DNS Audit Report ({domain})")
        st.download_button("📥 Download PDF Report", pdf, file_name="dns_audit_report.pdf", mime="application/pdf")

elif scan_type == "Traffic Stats":
    stats = traffic_stats()
    st.metric("Bytes Sent", stats['sent'])
    st.metric("Bytes Received", stats['recv'])

    pdf = generate_pdf(stats, title="Traffic Stats Report")
    st.download_button("📥 Download PDF Report", pdf, file_name="traffic_stats_report.pdf", mime="application/pdf")

# elif scan_type == "Vulnerability Scan":
#     ip = st.text_input("Target IP for Vulnerability Scan", "192.168.1.1")
#     if st.button("Scan Vulnerabilities"):
#         result = vulnerability_scan(ip)
#         st.json(result)
#         save_report({"ip": ip, "vulnerabilities": result})

#         pdf = generate_pdf(result, title=f"Vulnerability Report ({ip})")
#         st.download_button("📥 Download PDF Report", pdf, file_name="vulnerability_report.pdf", mime="application/pdf")

# elif scan_type == "Vulnerability Scan":
#     st.header("🔍 Vulnerability Scan")
#     target_ip = st.text_input("Enter Target IP", "192.168.1.1")
#     permission = st.checkbox("I have permission to scan this IP and understand the risks.")

#     if st.button("Scan for Vulnerabilities") and permission:
#         st.info(f"Scanning {target_ip} for known vulnerabilities...")
#         result = run_combined_vuln_scan(target_ip)

#         if "error" in result:
#             st.error(result["error"])
#         elif result["vulnerabilities"]:
#             st.error("⚠️ Potential Vulnerabilities Found:")
#             st.json(result)
#         else:
#             st.success("✅ No known vulnerabilities found.")

#         # Generate PDF report (optional, if you already have generate_pdf())
#         pdf = generate_pdf(result, title=f"Vulnerability Scan Report - {target_ip}")
#         st.download_button("📥 Download PDF Report", pdf, file_name="vulnerability_scan_report.pdf", mime="application/pdf")

# elif scan_type == "Vulnerability Scan":
#     st.header("🔍 Vulnerability Scan")
#     target_ip = st.text_input("Enter Target IP", "192.168.1.5")
#     upload = st.file_uploader("Upload Vulnerability CSV", type=["csv"])
#     permission = st.checkbox("I have permission to scan this target")

#     if st.button("Run Vulnerability Scan") and permission and upload:
#         # Save uploaded file temporarily
#         with open("vuln_data.csv", "wb") as f:
#             f.write(upload.getvalue())

#         st.info("Running Nmap vulnerability scan...")
#         result = run_nmap_vuln_scan(target_ip)

#         if result:
#             st.error("⚠️ Vulnerabilities Detected:")
#             st.json(result)
#         else:
#             st.success("✅ No known vulnerabilities found!")

#         pdf = generate_pdf(result, title=f"Vulnerability Report - {target_ip}")
#         st.download_button("📥 Download PDF Report", pdf, file_name="vulnerability_report.pdf", mime="application/pdf")

elif scan_type == "Vulnerability Scan":
    st.header("🔍 Vulnerability Scan")
    target_ip = st.text_input("Enter Target IP", "192.168.1.5")
    scan_mode = st.radio("Select Scan Mode", ["Auto Scan", "Custom Scan"])
    permission = st.checkbox("I have permission to scan this target")

    if scan_mode == "Auto Scan" and st.button("Run Auto Vulnerability Scan") and permission:
        result = run_auto_vuln_scan(target_ip)
        st.json(result)

        # Optionally allow download
        pdf = generate_pdf(result, title=f"Auto Vulnerability Report - {target_ip}")
        st.download_button("📥 Download PDF Report", pdf, file_name="auto_vulnerability_report.pdf", mime="application/pdf")

    elif scan_mode == "Custom Scan":
        keyword = st.text_input("Enter Vulnerability Keyword")
        if st.button("Run Custom Vulnerability Scan") and permission:
            result = run_custom_vuln_scan(target_ip, keyword)
            st.json(result)

            pdf = generate_pdf(result, title=f"Custom Vulnerability Report - {target_ip}")
            st.download_button("📥 Download PDF Report", pdf, file_name="custom_vulnerability_report.pdf", mime="application/pdf")


elif scan_type == "Firewall Test":
    if st.button("Test All Firewall Rules"):
        result = firewall_test_all_rules()
        st.json(result)
        save_report({"firewall_rules": result})
        pdf = generate_pdf(result, title="Firewall Rules Test Report")
        st.download_button("📥 Download PDF Report", pdf, file_name="firewall_rules_report.pdf", mime="application/pdf")

elif scan_type =="Check for Intrusion":
    st.header("Intrusion Detection")
    if st.button("Test For Intrusion Detection"):
        result = check_for_intrusion()
        st.json(result)
        save_report({"intrusions": result})

elif scan_type == "Map Network Topology":
    subnet = st.text_input("Enter Subnet for Topology Mapping", "192.168.1.0/24")
    permission = st.checkbox("I have permission to scan this network and understand the risks.")
    if st.button("Map Topology", key="map_topology") and permission:
        st.info("Scanning and mapping network topology...")
        html = map_network_topology(subnet)
        components.html(html, height=550, scrolling=True)
    elif st.button("Map Topology", key="map_topology_no_permission") and not permission:
        st.error("You must confirm you have permission before mapping topology.")

st.sidebar.markdown("---")
st.sidebar.write("📄 Reports are saved locally as JSON and PDF.")
download_report_ui()

# Print Nmap version
st.sidebar.header("🔧 Nmap Version")
nmap_version = subprocess.getoutput("nmap --version")
st.sidebar.text_area("Nmap Version Info", nmap_version, height=300)

st.sidebar.markdown("---")
st.sidebar.write("📄 Reports are saved locally as JSON and downloadable as PDF.")