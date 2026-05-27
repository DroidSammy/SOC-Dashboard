import argparse
import sys
import os
import time
import requests

try:
    from scapy.all import sniff, IP, UDP, DNS, DNSQR
except ImportError:
    print("Error: scapy is not installed. Run: pip install scapy")
    sys.exit(1)

# List of simulated phishing keywords for the demo
PHISHING_KEYWORDS = ['paypal', 'secure-login', 'verify-account', 'free-crypto', 'update-password', 'bank-alert', 'hianime', 'torrent', 'movie-free']

def check_domain(domain):
    """Simple rule-based check for phishing indicators in the domain"""
    domain_lower = domain.lower()
    for keyword in PHISHING_KEYWORDS:
        if keyword in domain_lower:
            return True
    return False

def report_to_backend(ip, domain):
    """Sends the malicious request to the SOC Dashboard backend"""
    url = "http://localhost:4000/api/students/track-dns"
    payload = {
        "ip": ip,
        "domain": domain
    }
    try:
        response = requests.post(url, json=payload, timeout=2)
        if response.status_code == 200:
            print(f"[!] Reported {domain} from {ip} to SOC Backend -> Triggered UEBA Alert")
        else:
            print(f"[x] Failed to report to backend: HTTP {response.status_code}")
    except Exception as e:
        print(f"[x] Error reporting to backend: {e}")

def dns_callback(packet):
    """Callback function for each intercepted packet."""
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode('utf-8').strip('.')
        src_ip = packet[IP].src
        
        # We only care about devices on the local network requesting external domains
        # Wait, for a simple demo we'll just log and check all
        
        is_phishy = check_domain(query)
        
        if is_phishy:
            print(f"[{time.strftime('%H:%M:%S')}] 🚨 MALICIOUS DNS QUERY DETECTED: {src_ip} -> {query}")
            report_to_backend(src_ip, query)
        else:
            # Uncomment below to see all DNS queries
            # print(f"[{time.strftime('%H:%M:%S')}] Safe DNS Query: {src_ip} -> {query}")
            pass

def start_sniffing(interface=None):
    print(f"[*] Starting live DNS sniffing on interface: {interface if interface else 'Default'}")
    print("[*] Note: This requires Administrator/Root privileges.")
    print("="*60)
    print("Waiting for DNS queries (Try visiting 'http://paypal-verify-account.tk')...")
    
    try:
        # Sniff UDP port 53 (DNS)
        sniff(filter="udp port 53", iface=interface, prn=dns_callback, store=False)
    except PermissionError:
        print("\n[!] PERMISSION DENIED: You must run this script as Administrator/Root to hook into the network adapter.")
    except Exception as e:
        print(f"\n[!] An error occurred during sniffing: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live DNS Sniffer for UEBA Analysis")
    parser.add_argument("-i", "--interface", default=None, help="Specific network interface to sniff on")
    args = parser.parse_args()
    
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[WARNING] Not running as Administrator. Packet sniffing will likely fail.")
            
    start_sniffing(args.interface)
