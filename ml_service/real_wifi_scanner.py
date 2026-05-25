import argparse
import sys
import os

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    print("Error: scapy is not installed. Run: pip install scapy")
    sys.exit(1)

def scan_wifi(target_ip):
    """
    Performs a real ARP sweep on the specified IP range to find active devices.
    Requires root/administrator privileges to execute correctly.
    """
    print(f"[*] Starting real Wi-Fi network sweep on {target_ip}...")
    print("[*] Note: This requires Administrator/Root privileges.")
    
    try:
        # Create an ARP packet
        arp = ARP(pdst=target_ip)
        # Create an Ethernet frame
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Stack them
        packet = ether/arp

        # Send the packet and receive responses
        result = srp(packet, timeout=3, verbose=0)[0]

        clients = []
        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("\n" + "="*40)
        print("Discovered Live Network Endpoints:")
        print("="*40)
        print("IP Address\t\tMAC Address")
        print("-" * 40)
        
        if not clients:
            print("No devices found. Ensure you are running as Administrator.")
            
        for client in clients:
            print(f"{client['ip']}\t\t{client['mac']}")
            
        print("="*40)
        print(f"Total devices found: {len(clients)}")

    except PermissionError:
        print("\n[!] PERMISSION DENIED: You must run this script as Administrator/Root to craft raw packets.")
    except Exception as e:
        print(f"\n[!] An error occurred during scan: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real Wi-Fi Subnet Scanner for SOC Dashboard")
    parser.add_argument("-t", "--target", default="192.168.1.1/24", help="Target IP range (e.g., 192.168.1.1/24)")
    args = parser.parse_args()
    
    # Needs root check
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[WARNING] Not running as Administrator. ARP scanning may fail.")
            
    scan_wifi(args.target)
