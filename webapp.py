from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
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
import os
import glob
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this in production

# ========================
# Utility Functions (from Streamlit app)
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

def load_vuln_db():
    try:
        with open('vuln_db.json', 'r') as f:
            content = f.read().strip()
            if not content:
                return []
            return json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def run_nmap_script(ip, script, port=None):
    nm = nmap.PortScanner()
    args = f"--script={script}"
    if port:
        args += f" -p {port}"
    nm.scan(hosts=ip, arguments=args)
    return nm[ip] if ip in nm.all_hosts() else {}

def run_auto_vuln_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments="-O -sS")
    
    os_match = nm[ip].get('osmatch', []) if ip in nm.all_hosts() else []
    ports = [int(p) for p in nm[ip]['tcp'].keys()] if ip in nm.all_hosts() and 'tcp' in nm[ip] else []

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

def run_custom_vuln_scan(ip, keyword):
    vuln_db = load_vuln_db()
    for entry in vuln_db:
        if keyword.lower() in entry['name'].lower():
            for port in entry['ports']:
                result = run_nmap_script(ip, entry['nmap_script'], port)
                return { "vuln": entry['name'], "result": result }
    return { "error": "No matching vulnerability found." }

def save_report(data, name='scan_report'):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    json_filename = f'reports/report_{timestamp}.json'
    pdf_filename = f'reports/report_{timestamp}.pdf'
    
    # Create reports directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)
    
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
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    return io.BytesIO(pdf_bytes)

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

def get_firewall_rules():
    try:
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
    except Exception as e:
        return [{"error": f"Failed to get firewall rules: {str(e)}"}]

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
        G.add_node(ip, label=f"{ip}\\n{mac}")
    
    net = Network(height="500px", width="100%", bgcolor="#222222", font_color="white")
    net.from_nx(G)
    
    # Save to static directory
    os.makedirs('static', exist_ok=True)
    net.show("static/topology.html", notebook=False)
    
    with open("static/topology.html", "r", encoding="utf-8") as f:
        html = f.read()
    return html

def check_for_intrusion(scanned_hosts, genuine_hosts):
    scanned_ips = {host['ip'] for host in scanned_hosts}
    genuine_ips = {host['ip'] for host in genuine_hosts}
    intrusive_ips = scanned_ips - genuine_ips
    return [host for host in scanned_hosts if host['ip'] in intrusive_ips]

# ========================
# Flask Routes
# ========================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/network_scan')
def network_scan_page():
    return render_template('network_scan.html')

@app.route('/port_scan')
def port_scan_page():
    return render_template('port_scan.html')

@app.route('/os_detection')
def os_detection_page():
    return render_template('os_detection.html')

@app.route('/dns_audit')
def dns_audit_page():
    return render_template('dns_audit.html')

@app.route('/traffic_stats')
def traffic_stats_page():
    return render_template('traffic_stats.html')

@app.route('/vulnerability_scan')
def vulnerability_scan_page():
    return render_template('vulnerability_scan.html')

@app.route('/firewall_test')
def firewall_test_page():
    return render_template('firewall_test.html')

@app.route('/network_topology')
def network_topology_page():
    return render_template('network_topology.html')

@app.route('/intrusion_detection')
def intrusion_detection_page():
    return render_template('intrusion_detection.html')

# API Routes
@app.route('/api/scan_network', methods=['POST'])
def api_scan_network():
    data = request.get_json()
    subnet = data.get('subnet', '192.168.1.0/24')
    
    try:
        result = scan_network(subnet)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/port_scan', methods=['POST'])
def api_port_scan():
    data = request.get_json()
    ip = data.get('ip')
    
    try:
        result = port_scan(ip)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/os_detect', methods=['POST'])
def api_os_detect():
    data = request.get_json()
    ip = data.get('ip')
    
    try:
        result = os_detect(ip)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/dns_audit', methods=['POST'])
def api_dns_audit():
    data = request.get_json()
    domain = data.get('domain')
    
    try:
        result = dns_audit(domain)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/capture_packets', methods=['POST'])
def api_capture_packets():
    data = request.get_json()
    count = data.get('count', 50)
    
    try:
        captured, proto_stats = capture_packets(count)
        return jsonify({'success': True, 'data': {'packets': captured, 'stats': proto_stats}})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/vulnerability_scan', methods=['POST'])
def api_vulnerability_scan():
    data = request.get_json()
    ip = data.get('ip')
    scan_mode = data.get('mode', 'auto')
    keyword = data.get('keyword', '')
    
    try:
        if scan_mode == 'auto':
            result = run_auto_vuln_scan(ip)
        else:
            result = run_custom_vuln_scan(ip, keyword)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/firewall_test', methods=['POST'])
def api_firewall_test():
    try:
        result = firewall_test_all_rules()
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/network_topology', methods=['POST'])
def api_network_topology():
    data = request.get_json()
    subnet = data.get('subnet', '192.168.1.0/24')
    
    try:
        html_content = map_network_topology(subnet)
        return jsonify({'success': True, 'data': html_content})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/intrusion_detection', methods=['POST'])
def api_intrusion_detection():
    data = request.get_json()
    subnet = data.get('subnet', '192.168.1.0/24')
    genuine_hosts_list = data.get('genuine_hosts', [])
    genuine_hosts = [{"ip": ip.strip()} for ip in genuine_hosts_list if ip.strip()]
    
    try:
        scanned_hosts = scan_network(subnet)
        intrusions = check_for_intrusion(scanned_hosts, genuine_hosts)
        return jsonify({'success': True, 'data': intrusions})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download_report', methods=['POST'])
def api_download_report():
    data = request.get_json()
    report_data = data.get('data')
    title = data.get('title', 'Network Audit Report')
    filename = data.get('filename', 'report.pdf')
    
    try:
        pdf_buffer = generate_pdf(report_data, title)
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/reports')
def list_reports():
    try:
        reports = sorted(glob.glob("reports/report_*.pdf"), reverse=True)
        report_list = []
        for report in reports:
            filename = os.path.basename(report)
            timestamp = filename.replace('report_', '').replace('.pdf', '')
            report_list.append({
                'filename': filename,
                'timestamp': timestamp,
                'path': report
            })
        return render_template('reports.html', reports=report_list)
    except Exception as e:
        flash(f'Error loading reports: {str(e)}', 'error')
        return render_template('reports.html', reports=[])

@app.route('/download_report/<filename>')
def download_report(filename):
    try:
        return send_file(f'reports/{filename}', as_attachment=True)
    except Exception as e:
        flash(f'Error downloading report: {str(e)}', 'error')
        return redirect(url_for('list_reports'))

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('reports', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Create empty vuln_db.json if it doesn't exist
    if not os.path.exists('vuln_db.json'):
        with open('vuln_db.json', 'w') as f:
            json.dump([], f)
    
    app.run(debug=True, host='0.0.0.0', port=5000) 