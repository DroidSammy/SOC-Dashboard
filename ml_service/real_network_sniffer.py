import argparse
import sys
import os
import time

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("Error: scapy is not installed. Run: pip install scapy")
    sys.exit(1)

def packet_callback(packet):
    """Callback function for each intercepted packet."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"
        port = "N/A"
        
        if TCP in packet:
            protocol = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            port = packet[UDP].dport
            
        print(f"[{time.strftime('%H:%M:%S')}] {protocol} Packet: {src_ip} -> {dst_ip} (Port: {port})")

def start_sniffing(interface=None, packet_count=50):
    """
    Performs live packet sniffing on the host network adapter.
    Requires administrator/root privileges.
    """
    print(f"[*] Starting live network sniff on interface: {interface if interface else 'Default'}")
    print(f"[*] Capturing {packet_count} packets...")
    print("[*] Note: This requires Administrator/Root privileges.")
    print("="*60)
    
    try:
        # Sniff packets
        sniff(iface=interface, prn=packet_callback, count=packet_count, store=False)
        print("="*60)
        print("[*] Sniffing completed successfully.")
        
    except PermissionError:
        print("\n[!] PERMISSION DENIED: You must run this script as Administrator/Root to hook into the network adapter.")
    except Exception as e:
        print(f"\n[!] An error occurred during sniffing: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real Live Network Sniffer for SOC Dashboard")
    parser.add_argument("-i", "--interface", default=None, help="Specific network interface to sniff on (e.g., 'Ethernet', 'Wi-Fi')")
    parser.add_argument("-c", "--count", type=int, default=50, help="Number of packets to capture")
    args = parser.parse_args()
    
    # Needs root check
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[WARNING] Not running as Administrator. Packet sniffing will likely fail.")
            
    start_sniffing(args.interface, args.count)
