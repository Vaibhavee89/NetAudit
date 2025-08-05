import streamlit as st
import nmap
import psutil
import dns.resolver
import socket
import json
from datetime import datetime
import pandas as pd
import io
from fpdf import FPDF 
import subprocess
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


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

def capture_packets(count=50):
    packets = sniff(count=count, timeout=10)
    summary = []
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

    for pkt in packets:
        proto = "Other"
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            size = len(pkt)
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                proto = pkt.lastlayer().name

            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            summary.append({
                "Source": src,
                "Destination": dst,
                "Protocol": proto,
                "Size": size
            })

    return summary, protocol_counts

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
    st.header("📊 Real-Time Traffic Analysis")
    packet_count = st.slider("Number of Packets to Capture", 10, 200, 50)
    if st.button("Capture Packets"):
        with st.spinner("Capturing packets..."):
            captured, proto_stats = capture_packets(packet_count)
            st.success(f"Captured {len(captured)} packets.")

            # Show protocol distribution
            st.subheader("Protocol Distribution")
            st.json(proto_stats)

            # Show captured packet summary
            st.subheader("Packet Details")
            st.dataframe(captured)

            # Save as PDF
            pdf = generate_pdf(captured, title="Live Packet Capture Report")
            st.download_button("📥 Download PDF Report", pdf, file_name="packet_capture_report.pdf", mime="application/pdf")


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