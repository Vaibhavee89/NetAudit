import streamlit as st
import nmap
import psutil
import dns.resolver
import socket
import json
from datetime import datetime

from fpdf import FPDF
import io
from fpdf import FPDF  # <-- Add this import
import subprocess

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
    scanner.scan(hosts=ip, arguments='-sV')
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

        pdf = generate_pdf(result, title=f"Network Scan Report ({subnet})")
        st.download_button("📥 Download PDF Report", pdf, file_name="network_scan_report.pdf", mime="application/pdf")

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

elif scan_type == "Vulnerability Scan":
    ip = st.text_input("Target IP for Vulnerability Scan", "192.168.1.1")
    if st.button("Scan Vulnerabilities"):
        result = vulnerability_scan(ip)
        st.json(result)
        save_report({"ip": ip, "vulnerabilities": result})

        pdf = generate_pdf(result, title=f"Vulnerability Report ({ip})")
        st.download_button("📥 Download PDF Report", pdf, file_name="vulnerability_report.pdf", mime="application/pdf")

elif scan_type == "Firewall Test":
    if st.button("Test All Firewall Rules"):
        result = firewall_test_all_rules()
        st.json(result)
        save_report({"firewall_rules": result})
        pdf = generate_pdf(result, title="Firewall Rules Test Report")
        st.download_button("📥 Download PDF Report", pdf, file_name="firewall_rules_report.pdf", mime="application/pdf")

st.sidebar.markdown("---")
st.sidebar.write("📄 Reports are saved locally as JSON and PDF.")
download_report_ui()

# Print Nmap version
st.sidebar.header("🔧 Nmap Version")
nmap_version = subprocess.getoutput("nmap --version")
st.sidebar.text_area("Nmap Version Info", nmap_version, height=300)

st.sidebar.markdown("---")
st.sidebar.write("📄 Reports are saved locally as JSON and downloadable as PDF.")
