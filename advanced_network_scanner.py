import sys
import socket
import ipaddress
import concurrent.futures
import platform
import subprocess
import re
import argparse
import urllib.request
import time
import ssl
import struct
import csv
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
}

_SYSTEM_ARP_CACHE = {}
_SPOOFED_PORTS = set()  # Global tracking set for wildcard port spoofing detection

def print_app_name():
    print("""
     .-') _   _ .-') _    .-')               .-')        .-') _             
    ( OO ) )_(  OO) (  OO) )   ( OO ).            ( OO ).-.    ( OO ) )            
,--./ ,--,'(,------./     '._ (_)---\_)   .-----.  / . --. /,--./ ,--,'            
|   \ |  |\ |  .---'|'--...__)/    _ |   '  .--./  | \-.  \ |   \ |  |\            
|    \|  | )|  |    '--.  .--'\  :` `.   |  |('-..-'-'   |  ||    \|  | )           
|  .     |/(|  '--.    |  |    '..`''.) /_) |OO  )\| |_.'  ||  .     |/            
|  |\    |  |  .--'    |  |   .-._)   \ ||  |`-'|  |  .-.  ||  |\    |              
|  | \   |  |  `---.   |  |   \       /(_'  '--'\  |  | |  ||  | \   |              
`--'  `--'  `------'   `--'    `-----'    `-----'  `--' `--'`--'  `--'              
    """)
    print(f"{' Developed by ARIP ':=^175}")
    print(f" > Purpose: Advanced Asset Triage, Port Ranges, Real-time Visual Telemetry")
    print(f" > Portfolio/GitHub: github.com/arip-dhar") 
    print(f" > For any queries Gmail Id: aripdhar80@gmail.com") 
    print("=" * 175)
    print("\n[+] Initializing advanced visual port service mapping diagnostics...\n")

def get_local_ip_and_mask():
    system = platform.system().lower()
    if system == 'windows':
        try:
            output = subprocess.check_output("ipconfig", universal_newlines=True)
            ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)
            mask_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)
            if ip_match and mask_match:
                return ip_match.group(1), mask_match.group(1)
        except Exception:
            pass
    else:
        try:
            output = subprocess.check_output("ifconfig", shell=True, universal_newlines=True)
            ip_match = re.search(r'inet ([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
            if ip_match:
                return ip_match.group(1), ip_match.group(2)
        except Exception:
            pass
    return '127.0.0.1', '255.255.255.0'

def mask_to_cidr(mask):
    return sum(bin(int(x)).count('1') for x in mask.split('.'))

def parse_network(arg=None):
    if not arg:
        ip, mask = get_local_ip_and_mask()
        cidr = mask_to_cidr(mask)
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/32', strict=False)
    else:
        raise ValueError("Invalid target network segment syntax layout.")

def parse_port_ranges(port_arg):
    """Natively normalizes hybrid range formats into sanitized integer listings."""
    ports = set()
    if not port_arg:
        return list(COMMON_SERVICES.keys())
        
    chunks = port_arg.split(',')
    for chunk in chunks:
        chunk = chunk.strip()
        if '-' in chunk:
            try:
                start, end = map(int, chunk.split('-'))
                if 0 <= start <= 65535 and 0 <= end <= 65535:
                    ports.update(range(min(start, end), max(start, end) + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(chunk)
                if 0 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(list(ports))

def draw_progress_bar(current, total):
    """Renders a dynamic, inline terminal progress track calculation."""
    if total <= 0:
        return
    bar_length = 40
    fraction = current / total
    filled_length = int(round(bar_length * fraction))
    percent = round(fraction * 100, 1)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    sys.stdout.write(f"\r[-] Analysis Execution Progress: [{bar}] {percent}% Complete")
    sys.stdout.flush()

def detect_wildcard_port_spoofing(network, target_ports):
    global _SPOOFED_PORTS
    dummy_ip = str(list(network.hosts())[-2]) if network.num_addresses > 4 else None
    if not dummy_ip:
        return

    # Check up to 5 ports to avoid slowdown if range is vast
    check_ports = target_ports[:5]
    for port in check_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((dummy_ip, port)) == 0:
                _SPOOFED_PORTS.add(port)

def trigger_system_arp_discovery(ip):
    ip_str = str(ip)
    system = platform.system().lower()
    if system == "windows":
        subprocess.run(["ping", "-n", "1", "-w", "75", ip_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["ping", "-c", "1", "-W", "1", ip_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def populate_arp_table():
    global _SYSTEM_ARP_CACHE
    system = platform.system().lower()
    try:
        if system == "windows":
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            matches = re.findall(r"([\d.]+)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})", output, re.IGNORECASE)
            for ip, mac in matches:
                _SYSTEM_ARP_CACHE[ip] = mac.replace("-", ":").upper()
        else:
            output = subprocess.check_output("arp -n", shell=True, text=True, stderr=subprocess.DEVNULL)
            matches = re.findall(r"([\d.]+)\s+\S+\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", output, re.IGNORECASE)
            for ip, mac in matches:
                _SYSTEM_ARP_CACHE[ip] = mac.upper()
    except Exception:
        pass

def advanced_os_fingerprint(ttl, open_ports):
    if ttl is None:
        return "Unknown / Protected Stack"
    try:
        ttl_val = int(ttl)
        if ttl_val <= 64:
            if 22 in open_ports or 80 in open_ports:
                return "Linux / Embedded IoT"
            elif 23 in open_ports:
                return "Embedded Network Hardware"
            return "Linux / macOS / Android"
        elif ttl_val <= 128:
            if 445 in open_ports or 139 in open_ports:
                return "Windows Workstation/Server"
            elif 3389 in open_ports:
                return "Windows OS (RDP Core)"
            return "Windows Ecosystem"
        else:
            return "Cisco / Core Infrastructure"
    except Exception:
        return "Generic Network OS"

def lookup_service_cves(port, banner):
    cve_tags = []
    banner_upper = banner.upper()
    
    if port == 22 and "DROPBEAR" in banner_upper:
        match = re.search(r'DROPBEAR_0\.(\d+)', banner_upper)
        if match and int(match.group(1)) <= 50:
            cve_tags.append("CVE-2012-0920")
    elif port == 23:
        cve_tags.append("CVE-1999-0619")
    elif port == 80 or port == 8080:
        if "BOA" in banner_upper:
            cve_tags.append("CVE-2017-9833")
    elif port == 445 and "SMBV1" in banner_upper:
        cve_tags.append("CVE-2017-0144")
    elif port == 443 and ("TLSV1.0" in banner_upper or "TLSV1.1" in banner_upper):
        cve_tags.append("CVE-2014-3566")
        
    return f" CVEs: [{', '.join(cve_tags)}]" if cve_tags else ""

def assess_service_vulnerabilities(port, banner):
    findings = []
    banner_upper = banner.upper()
    
    if port == 21:
        findings.append("[High: Plaintext Auth]")
        if "LOCALHOST" in banner_upper:
            findings.append("[Med: Default Configuration Leaked]")
    elif port == 22:
        if "DROPBEAR" in banner_upper:
            match = re.search(r'DROPBEAR_0\.(\d+)', banner_upper)
            if match and int(match.group(1)) <= 50:
                findings.append("[High: Legacy Dropbear SSH Build]")
    elif port == 23:
        findings.append("[Critical: Completely Unencrypted Management Protocol]")
    elif port == 80 or port == 8080:
        if "BOA" in banner_upper:
            findings.append("[High: Obsolete BOA Daemon - Vulnerable to Memory Leakage]")
    elif port == 445:
        if "SMBV1" in banner_upper:
            findings.append("[Critical: Remote Code Execution / EternalBlue Exposure]")
    elif port == 443:
        if "TLSV1.0" in banner_upper or "TLSV1.1" in banner_upper:
            findings.append("[High: Obsolete Cryptographic Standards Allowed]")
            
    return " ".join(findings) if findings else ""

def calculate_asset_risk_score(open_ports, service_strings):
    score = 0.0
    combined_meta = " ".join(service_strings).upper()
    
    if "[CRITICAL:" in combined_meta: score += 5.0
    elif "[HIGH:" in combined_meta: score += 3.0
    if "[MED:" in combined_meta: score += 1.5

    if 23 in open_ports: score += 2.0  
    if 21 in open_ports: score += 1.5  
    if 445 in open_ports: score += 1.0 

    score += (len(open_ports) * 0.4)
    return min(10.0, round(score, 1))

def detect_web_technologies(http_response):
    tech_stack = []
    response_upper = http_response.upper()

    if "X-POWERED-BY: PHP" in response_upper or ".PHP" in response_upper:
        tech_stack.append("PHP")
    if "X-POWERED-BY: ASP.NET" in response_upper or "ASPX" in response_upper:
        tech_stack.append("ASP.NET")
    if "SERVER: COYOTE" in response_upper or "TOMCAT" in response_upper:
        tech_stack.append("Java/Tomcat")
    if "WP-CONTENT" in response_upper or "WP-INCLUDES" in response_upper:
        tech_stack.append("WordPress CMS")
    if "BOOTSTRAP" in response_upper:
        tech_stack.append("Bootstrap CSS")
    if "JQUERY" in response_upper:
        tech_stack.append("jQuery JS")

    security_missing = []
    if "X-FRAME-OPTIONS" not in response_upper:
        security_missing.append("Clickjacking")
    if "STRICT-TRANSPORT-SECURITY" not in response_upper:
        security_missing.append("HSTS Missing")
        
    tech_string = ""
    if tech_stack:
        tech_string += f" Tech: [{', '.join(tech_stack)}]"
    if security_missing:
        tech_string += f" Sec-Defects: [{', '.join(security_missing)}]"
        
    return tech_string

def detect_smb_version(ip):
    smb_negotiate_packet = (
        b'\x00\x00\x00\x54\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x20\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xff'
        b'\x00\x29\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
        b'\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x31\x30\x30\x00'
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((ip, 445))
            s.sendall(smb_negotiate_packet)
            response = s.recv(256)
            if len(response) >= 9:
                if response[4:8] == b'\xfe\x53\x4d\x42':
                    dialect = response[68:70]
                    if dialect == b'\x02\x02': return "SMBv2.02"
                    elif dialect == b'\x10\x02': return "SMBv2.10"
                    elif dialect == b'\x00\x03': return "SMBv3.00"
                    elif dialect == b'\x11\x03': return "SMBv3.1.1 (Secure)"
                    return "SMBv2/v3 Managed"
                elif response[4:8] == b'\xff\x53\x4d\x42':
                    return "SMBv1 (VULNERABLE - Legacy)"
    except Exception:
        pass
    return "SMB (Version Unknown)"

def scan_ssl_tls_properties(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            ssock.connect((ip, port))
            cipher_info = ssock.cipher()
            return f"{cipher_info[1]} Cipher:({cipher_info[0]})"
    except Exception as e:
        return f"SSL Handshake Failed ({str(e).split(':')[-1].strip()})"

def grab_service_banner(ip, s, port):
    try:
        if port == 445:
            return detect_smb_version(ip), ""
        elif port == 443:
            crypto_banner = scan_ssl_tls_properties(ip, port)
            return crypto_banner, ""
        elif port in [80, 8080]:
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            raw_response = s.recv(1024).decode('utf-8', errors='ignore')
            server_match = re.search(r"Server:\s*(.*)", raw_response, re.IGNORECASE)
            banner = f"HTTP ({server_match.group(1).strip()})" if server_match else "HTTP Web Service"
            web_tech_data = detect_web_technologies(raw_response)
            return banner, web_tech_data
        else:
            banner = s.recv(64).decode('utf-8', errors='ignore').strip()
            clean_banner = "".join(c for c in banner if 32 <= ord(c) < 127)[:30] if banner else "Unknown Service"
            return clean_banner, ""
    except Exception:
        pass
    return "Unknown Service", ""

def scan_target_ports(ip, target_ports):
    open_ports_list = []
    open_services = []
    for port in target_ports:
        if port in _SPOOFED_PORTS:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.35) 
            if s.connect_ex((ip, port)) == 0:
                open_ports_list.append(port)
                detailed_banner, web_technologies = grab_service_banner(ip, s, port)
                
                vuln_alerts = assess_service_vulnerabilities(port, detailed_banner)
                cve_listings = lookup_service_cves(port, detailed_banner)
                
                display_string = f"{port}[{detailed_banner}]"
                if web_technologies:
                    display_string += f"{web_technologies}"
                if cve_listings:
                    display_string += f"{cve_listings}"
                if vuln_alerts:
                    display_string += f" {vuln_alerts}"
                    
                open_services.append(display_string)
    return open_ports_list, open_services

def get_mac_vendor(mac):
    if mac in ["00:00:00:00:00:00", "UNKNOWN / GATEWAY"]:
        return "Network Infrastructure Node"
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.0) as response:
            return response.read().decode('utf-8')
    except Exception:
        return "Unknown Manufacturer"

def lookup_reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "No PTR Record"

def capture_live_traffic_sample(duration=3):
    print(f"[-] Initializing native packet capture subsystem telemetry ({duration}s runtime)...")
    system = platform.system().lower()
    
    if system == "windows":
        print("[!] Info: Native Layer-3 RAW sockets streaming requires administrative interface binding locks on Windows. Skipping telemetry pass.")
        return []
        
    captured_logs = []
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sniffer.settimeout(1.0)
        end_time = time.time() + duration
        
        while time.time() < end_time:
            try:
                raw_packet, _ = sniffer.recvfrom(65565)
                ip_header = raw_packet[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                s_ip = socket.inet_ntoa(iph[8])
                d_ip = socket.inet_ntoa(iph[9])
                
                log_entry = f"Protocol: TCP | Origin: {s_ip} -> Ingress: {d_ip} | Fragment Size: {len(raw_packet)} Bytes"
                if log_entry not in captured_logs:
                    captured_logs.append(log_entry)
            except socket.timeout:
                continue
    except PermissionError:
        print("[!] Privileges Error: Root authority (`sudo`) missing. Unable to lock packet capture socket binds.")
    except Exception as e:
        print(f"[!] Traffic Engine Exception: {e}")
        
    return captured_logs

def generate_ascii_topology_map(devices):
    if not devices:
        return
    print("\n" + "=" * 55 + " LOGICAL NETWORK TOPOLOGY MAP " + "=" * 55 + "\n")
    
    gateway = None
    endpoints = []
    for d in devices:
        if d['ip'].endswith(".1") or "GATEWAY" in d['mac']:
            gateway = d
        else:
            endpoints.append(d)
            
    print("[ WAN / INTERNET ]")
    print("       │")
    
    if gateway:
        print(f"┌─[ Core Router/Gateway ] ── ({gateway['ip']}) - Risk Rating: [{gateway['risk']}/10] Vendor: {gateway['vendor']}")
        print(f"│   ├── Hostname: {gateway['hostname']}")
        print(f"│   └── Active Interfaces: {gateway['services'] if gateway['services'] else 'None Listed'}")
    else:
        print("┌─[ Gateway Node Missing / Non-Standard Setup ]")
    
    print("│")
    
    for i, ep in enumerate(endpoints):
        is_last = (i == len(endpoints) - 1)
        connector = "└──" if is_last else "├──"
        pipe = "   " if is_last else "│  "
        
        print(f"{connector} [ Host Node ] ── ({ep['ip']}) - Risk: [{ep['risk']}/10] Latency: {ep['latency']}")
        print(f"{pipe} ├── Name: {ep['hostname']}")
        print(f"{pipe} ├── Architecture Profile: {ep['os']}")
        print(f"{pipe} └── Exposed Ports: {ep['services'] if ep['services'] else 'No Management Access Open'}")
        if not is_last:
            print("│")
            
    print("\n" + "=" * 140)

def inspect_host(ip, target_ports):
    ip = str(ip)
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", "-w", "500", ip] if system == "windows" else ["ping", "-c", "1", "-W", "1", ip]
    
    is_alive = False
    detected_ttl = None
    
    start_rtt = time.perf_counter()
    
    mac_cached = _SYSTEM_ARP_CACHE.get(ip)
    if mac_cached and mac_cached != "00:00:00:00:00:00":
        is_alive = True
        
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.0)
        ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
        if ttl_match:
            is_alive = True
            detected_ttl = int(ttl_match.group(1))
    except Exception:
        pass
        
    rtt_ms = (time.perf_counter() - start_rtt) * 1000
    
    open_ports_list, discovered_services = scan_target_ports(ip, target_ports)
        
    if discovered_services and not is_alive:
        is_alive = True
        
    if is_alive and discovered_services:
        mac = mac_cached if mac_cached else ("UNKNOWN / GATEWAY" if ip.endswith(".1") else "UNKNOWN")
        vendor = get_mac_vendor(mac)
        services_string = ", ".join(discovered_services)
        hostname = lookup_reverse_dns(ip)
        os_environment = advanced_os_fingerprint(detected_ttl, open_ports_list)
        latency_string = f"{rtt_ms:.2f} ms"
        
        risk_score = calculate_asset_risk_score(open_ports_list, discovered_services)
        
        return {
            "ip": ip, "hostname": hostname, "mac": mac, "latency": latency_string,
            "os": os_environment, "vendor": vendor, "services": services_string, "risk": risk_score
        }
        
    return None

def scan_network(network, target_ports):
    print(f"[*] Assessment Scope     : {network}")
    print(f"[*] Address Pool Count    : {network.num_addresses}")
    print(f"[-] Running wildcard diagnostic mapping sequences...")
    
    detect_wildcard_port_spoofing(network, target_ports)
    
    print(f"[-] Launching active multi-threaded ARP discovery sweep...")
    workers = min(64, max(1, network.num_addresses))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as sweep_executor:
        sweep_executor.map(trigger_system_arp_discovery, network.hosts())
        
    print(f"[-] Synchronizing system ARP interface mapping pools...")
    populate_arp_table()
    
    print("\n[-] Commencing multi-threaded matrix scanning sequences...\n")
    
    discovered_devices = []
    hosts = list(network.hosts())
    total_hosts = len(hosts)
    completed_hosts = 0
    
    # Render the initial frame state
    draw_progress_bar(completed_hosts, total_hosts)
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(inspect_host, ip, target_ports): ip for ip in hosts}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    discovered_devices.append(res)
                
                completed_hosts += 1
                draw_progress_bar(completed_hosts, total_hosts)
    except KeyboardInterrupt:
        print("\n[!] Scan prematurely aborted by operator.")
        
    print("\n\n" + "-" * 195)
    print(f"{'IP ADDRESS':<15} | {'RISK':<5} | {'HOSTNAME / DOMAIN':<22} | {'LATENCY':<10} | {'MAC ADDRESS':<18} | {'OS ENVIRONMENT':<28} | {'SERVICES, THREAT ALERTS & CVSS METRICS'}")
    print("-" * 195)
    for res in discovered_devices:
        print(f"{res['ip']:<15} | {res['risk']:<5} | {res['hostname']:<22} | {res['latency']:<10} | {res['mac']:<18} | {res['os']:<28} | {res['services']}")
        
    return discovered_devices

def export_to_csv(filename, devices):
    """Saves completed dictionary results out to a structured CSV audit sheet."""
    fields = ["ip", "risk", "hostname", "latency", "mac", "os", "vendor", "services"]
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for dev in devices:
                # Filter dictionary storage fields matching standard structure
                row = {k: dev.get(k, "") for k in fields}
                writer.writerow(row)
        print(f"\n[+] Audit results successfully cataloged to: {filename}")
    except Exception as e:
        print(f"\n[-] File Export IO Matrix Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Professional Network Diagnostic Analyzer Matrix.")
    parser.add_argument("target", nargs="?", help="Subnet target designation range.")
    parser.add_argument("-p", "--ports", help="Target selection (e.g., '22,80' or range '20-100' or combined '21-25,443').")
    parser.add_argument("-o", "--export", help="Output destination path filename for generated CSV records.")
    args = parser.parse_args()
    
    print_app_name()
    
    # Process range string arrays cleanly via the new regex expansion filter
    port_targets = parse_port_ranges(args.ports)

    try:
        network = parse_network(args.target)
    except Exception as e:
        print(f"[-] Input Parser Matrix Error: {e}")
        return

    start_time = datetime.now()
    
    traffic_feed = capture_live_traffic_sample(duration=2)
    if traffic_feed:
        print("\n" + "." * 30 + " NETWORK TRAFFIC REAL-TIME CAPTURE STREAM " + "." * 30)
        for flow in traffic_feed[:5]:  
            print(f" [Captured Frame] {flow}")
        print("." * 102 + "\n")

    results = scan_network(network, port_targets)
    generate_ascii_topology_map(results)
    
    # Optional execution pass of the CSV sheet mapping function
    if args.export:
        export_to_csv(args.export, results)
        
    print(f"[*] Audit Complete. {len(results)} active endpoints evaluated in {datetime.now() - start_time}\n")

if __name__ == "__main__":
    main()