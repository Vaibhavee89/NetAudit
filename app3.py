import streamlit as st
import nmap
import psutil
import dns.resolver
import json
import csv
from datetime import datetime
from manuf import manuf
from fpdf import FPDF
import io

# ========== Security databases from Code 1 ==========

trusted_macs = {"E0:2B:E9:40:00:51"}
blocked_macs = {"00:11:22:33:44:55"}
outdated_os_keywords = [
    "windows xp", "windows 7", "windows 2000", "server 2003",
    "ubuntu 12", "ubuntu 14", "centos 6", "debian 8"
]
suspicious_vendors = ["unknown", "zte", "huawei", "generic", "china"]
suspicious_hostnames = ["unknown", "localhost", "test", "temp", "user-pc"]
vuln_ports = {
    21: "FTP port open – may allow anonymous login",
    23: "Telnet port open – unencrypted communication",
    80: "HTTP open – data transmitted unencrypted",
    139: "NetBIOS open – susceptible to SMB attacks",
    445: "SMB open – vulnerable to EternalBlue exploit",
    3389: "RDP open – risk of brute-force attack",
    3306: "MySQL port open – potential for DB exposure",
    5900: "VNC port open – unsecured remote desktop",
    53: "DNS port open – DNS amplification attack possible"
}
VULN_RULES = {
    "DNS port open – DNS amplification attack possible": {
        "firewall": "Block inbound UDP traffic on port 53 from untrusted IPs",
        "nids": "Enable signature: 'DNS Amplification Attack Detection'"
    },
    "HTTP open – data transmitted unencrypted": {
        "firewall": "Allow HTTP only from internal networks; redirect to HTTPS",
        "nids": "Enable signature: 'Cleartext HTTP Credential Leak'"
    },
    "SMB open – vulnerable to EternalBlue exploit": {
        "firewall": "Block ports 445 & 139 from external traffic",
        "nids": "Enable signature: 'MS17-010 EternalBlue Exploit Attempt'"
    },
    "NetBIOS open – susceptible to SMB attacks": {
        "firewall": "Block NetBIOS ports (137-139, 445) on public interfaces",
        "nids": "Enable rule: 'Suspicious NetBIOS Scan'"
    },
    "MySQL port open – potential for DB exposure": {
        "firewall": "Restrict MySQL port (3306) to known application servers",
        "nids": "Enable rule: 'MySQL Unauthorized Access Attempt'"
    },
    "MAC address not found – possible stealth device": {
        "firewall": "Log and monitor all connections from unknown MACs",
        "nids": "Enable anomaly-based detection for unknown devices"
    },
    "Suspicious vendor: Unknown": {
        "firewall": "Isolate and monitor device in separate VLAN",
        "nids": "Enable rule: 'Unidentified Device Communication Alert'"
    }
}

# ========== Utility and scan functions ==========

def scan_network_basic(subnet):
    """ Streamlit's simple live host discovery """
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

def audit_subnet(subnet):
    """ Core logic from Code 1: OS, MAC, vendor, port + vulnerability inference """
    scanner = nmap.PortScanner()
    parser = manuf.MacParser()
    audit_results = []
    scanner.scan(hosts=subnet, arguments='-T4 -F -O -sV')
    for host in scanner.all_hosts():
        info = {}
        vulnerabilities = []
        info['ip'] = host
        info['state'] = scanner[host].state()
        # MAC & vendor
        mac = scanner[host]['addresses'].get('mac', 'Not found')
        info['mac'] = mac
        info['vendor'] = parser.get_manuf(mac) if mac != 'Not found' else 'Unknown'
        # Hostname
        hostname = scanner[host].hostname()
        info['hostname'] = hostname if hostname else 'Unknown'
        # OS detection
        osmatch = scanner[host].get('osmatch', [])
        os = osmatch[0]['name'].lower() if osmatch else 'unknown'
        info['os'] = os
        # Ports
        ports = []
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                port_info = scanner[host][proto][port]
                ports.append({
                    'port': port,
                    'service': port_info.get('name', 'unknown'),
                    'state': port_info.get('state', 'unknown'),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', '')
                })
                if port in vuln_ports:
                    vulnerabilities.append(vuln_ports[port])
        info['ports'] = ports
        # MAC-based vulnerability
        if mac in blocked_macs:
            vulnerabilities.append("MAC address is in blocked list")
        elif mac == 'Not found':
            vulnerabilities.append("MAC address not found – possible stealth device")
        # OS check
        for bad_os in outdated_os_keywords:
            if bad_os in os:
                vulnerabilities.append(f"Outdated OS detected: {bad_os}")
                break
        # Vendor check
        vendor_lower = str(info.get('vendor', '')).lower()
        if any(v in vendor_lower for v in suspicious_vendors):
            vulnerabilities.append(f"Suspicious vendor: {info['vendor'] or 'Unknown'}")
        # Hostname
        host_lower = hostname.lower() if hostname else ''
        if any(bad in host_lower for bad in suspicious_hostnames):
            vulnerabilities.append(f"Suspicious hostname: {hostname}")
        # Trust Check
        info['trusted'] = mac in trusted_macs
        info['vulnerabilities'] = vulnerabilities
        audit_results.append(info)
    return audit_results

# ---- Streamlit's simple functional blocks ----

def port_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-sV')
    ports = []
    for proto in scanner[ip].all_protocols():
        for port in scanner[ip][proto]:
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

# PDF & report utility
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
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    return io.BytesIO(pdf_bytes)

def gen_csv_bytes(devices):
    output = io.StringIO()
    fieldnames = ['ip', 'state', 'mac', 'vendor', 'hostname', 'os', 'trusted', 'vulnerabilities']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for d in devices:
        row = {key: d.get(key, '') for key in fieldnames}
        row['vulnerabilities'] = "; ".join(d['vulnerabilities'])
        writer.writerow(row)
    return io.BytesIO(output.getvalue().encode())

# ========== Streamlit UI ==========

st.set_page_config(page_title="NetAudit - Network Auditing Tool", layout="wide")
st.title("🛡️ NetAudit – Network Auditing Tool")

st.sidebar.header("🔍 Audit Options")
scan_type = st.sidebar.selectbox("Choose Action", [
    "Simple Network Scan",
    "Audit Subnet With Vuln/Trust Logic",
    "Port & Service Scan",
    "OS Detection",
    "DNS Audit",
    "Traffic Stats",
    "Vulnerability Scan"
])

if scan_type == "Simple Network Scan":
    subnet = st.text_input("Enter Subnet (e.g. 192.168.1.0/24)", "192.168.1.0/24")
    if st.button("Scan Network"):
        result = scan_network_basic(subnet)
        st.success(f"Found {len(result)} live hosts.")
        st.json(result)
        pdf = generate_pdf(result, title=f"Network Scan Report ({subnet})")
        st.download_button("📥 Download PDF Report", pdf, file_name="network_scan_report.pdf", mime="application/pdf")

elif scan_type == "Audit Subnet With Vuln/Trust Logic":
    subnet = st.text_input("Subnet to audit", "192.168.1.0/24")
    if st.button("Audit Subnet"):
        devices = audit_subnet(subnet)
        st.success(f"Audited {len(devices)} hosts. See details below.")
        for info in devices:
            st.write(f"### {info['ip']} ({info['hostname']})")
            st.write(f"- MAC: {info['mac']} | Vendor: {info['vendor']} | OS: {info['os']} | Trusted: {'Yes' if info['trusted'] else 'No'}")
            ports_str = ', '.join(f"{p['port']}/{p['service']}" for p in info['ports']) if info['ports'] else 'None'
            st.write(f"- Ports: {ports_str}")
            if info['vulnerabilities']:
                st.error("Vulnerabilities:")
                for v in info['vulnerabilities']:
                    st.write(f"- {v}")
                    if v in VULN_RULES:
                        st.warning(f"FireWall: {VULN_RULES[v]['firewall']}")
                        st.warning(f"NIDS: {VULN_RULES[v]['nids']}")
        st.json(devices)
        # CSV/JSON/PDF export!
        csv_bytes = gen_csv_bytes(devices)
        st.download_button("⬇️ Download CSV", csv_bytes, file_name="network_audit.csv", mime="text/csv")
        pdf = generate_pdf(devices, title=f"Network Audit Report ({subnet})")
        st.download_button("⬇️ Download PDF", pdf, file_name="network_audit.pdf", mime="application/pdf")
        st.download_button("⬇️ Download JSON", io.BytesIO(json.dumps(devices, indent=2).encode()), file_name="network_audit.json", mime="application/json")

elif scan_type == "Port & Service Scan":
    ip = st.text_input("Target IP", "192.168.1.1")
    if st.button("Scan Ports"):
        result = port_scan(ip)
        st.json(result)
        pdf = generate_pdf(result, title=f"Port & Service Scan ({ip})")
        st.download_button("📥 Download PDF Report", pdf, file_name="port_service_report.pdf", mime="application/pdf")

elif scan_type == "OS Detection":
    ip = st.text_input("Target IP for OS detection", "192.168.1.1")
    if st.button("Detect OS"):
        os = os_detect(ip)
        st.success(f"Detected OS: {os}")
        pdf = generate_pdf({"ip": ip, "os": os}, title=f"OS Detection Report ({ip})")
        st.download_button("📥 Download PDF Report", pdf, file_name="os_detection_report.pdf", mime="application/pdf")

elif scan_type == "DNS Audit":
    domain = st.text_input("Enter Domain", "example.com")
    if st.button("Run DNS Audit"):
        result = dns_audit(domain)
        st.json(result)
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
        pdf = generate_pdf(result, title=f"Vulnerability Report ({ip})")
        st.download_button("📥 Download PDF Report", pdf, file_name="vulnerability_report.pdf", mime="application/pdf")

st.sidebar.markdown("---")
st.sidebar.write("📄 Reports can be exported as CSV, JSON, and PDF.")

