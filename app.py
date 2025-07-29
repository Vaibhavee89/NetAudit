import streamlit as st
import nmap
import psutil
import dns.resolver
import socket
import json
from datetime import datetime
from fpdf import FPDF  # <-- Add this import

# ========================
# Utility Functions
# ========================

def scan_network(subnet):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments='-sn')  # Ping scan
    live_hosts = []
    for host in scanner.all_hosts():
        if 'mac' in scanner[host]['addresses']:
            mac = scanner[host]['addresses']['mac']
        else:
            mac = "N/A"
        live_hosts.append({
            'ip': host,
            'mac': mac,
            'status': scanner[host].state()
        })
    return live_hosts

def port_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-sV')
    if ip not in scanner.all_hosts():
        return {"error": f"No scan results for {ip}. Host may be unreachable."}
    ports = []
    for proto in scanner[ip].all_protocols():
        lport = scanner[ip][proto].keys()
        for port in lport:
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

def vulnerability_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='--script vuln')
    return scanner[ip].get('hostscript', [])

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

# ========================
# Streamlit UI
# ========================

st.set_page_config(page_title="NetAudit - Network Auditing Tool", layout="wide")
st.title("🛡️ NetAudit – Network Auditing Tool (Backend Prototype)")

st.sidebar.header("🔍 Audit Options")
scan_type = st.sidebar.selectbox("Choose Action", [
    "Network Scan",
    "Port & Service Scan",
    "OS Detection",
    "DNS Audit",
    "Traffic Stats",
    "Vulnerability Scan",
    "Firewall Test"
])

if scan_type == "Network Scan":
    subnet = st.text_input("Enter Subnet (e.g. 192.168.1.0/24)", "192.168.1.0/24")
    if st.button("Scan Network"):
        result = scan_network(subnet)
        st.success(f"Found {len(result)} live hosts.")
        st.json(result)
        save_report({"subnet": subnet, "results": result})

elif scan_type == "Port & Service Scan":
    ip = st.text_input("Target IP", "192.168.1.1")
    if st.button("Scan Ports"):
        result = port_scan(ip)
        st.json(result)
        save_report({"ip": ip, "ports": result})

elif scan_type == "OS Detection":
    ip = st.text_input("Target IP for OS detection", "192.168.1.1")
    if st.button("Detect OS"):
        os = os_detect(ip)
        st.success(f"Detected OS: {os}")
        save_report({"ip": ip, "os": os})

elif scan_type == "DNS Audit":
    domain = st.text_input("Enter Domain", "example.com")
    if st.button("Run DNS Audit"):
        result = dns_audit(domain)
        st.json(result)
        save_report({"domain": domain, "dns": result})

elif scan_type == "Traffic Stats":
    stats = traffic_stats()
    st.metric("Bytes Sent", stats['sent'])
    st.metric("Bytes Received", stats['recv'])

elif scan_type == "Vulnerability Scan":
    ip = st.text_input("Target IP for Vulnerability Scan", "192.168.1.1")
    if st.button("Scan Vulnerabilities"):
        result = vulnerability_scan(ip)
        st.json(result)
        save_report({"ip": ip, "vulnerabilities": result})

elif scan_type == "Firewall Test":
    ip = st.text_input("Target IP for Firewall Test", "192.168.1.1")
    if st.button("Test Firewall"):
        result = firewall_test(ip)
        st.json(result)
        save_report({"ip": ip, "firewall": result})

st.sidebar.markdown("---")
st.sidebar.write("📄 Reports are saved locally as JSON and PDF.")
download_report_ui()

