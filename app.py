import streamlit as st
import nmap
import psutil
import dns.resolver
import socket
import json
from datetime import datetime

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
    with open(f'report_{timestamp}.json', 'w') as f:
        json.dump(data, f, indent=2)

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
    "Vulnerability Scan"
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

st.sidebar.markdown("---")
st.sidebar.write("📄 Reports are saved locally as JSON.")

