import sys
import subprocess
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def block_ip(ip_address):
    print(f"[*] Engaging Firewall... Blocking internet access for {ip_address}")
    rule_name = f"Block_Hotspot_{ip_address}"
    
    # First, ensure no duplicate rules exist
    subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, capture_output=True)
    
    # Add new inbound block rule
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if "Ok." in result.stdout:
        print(f"[+] SUCCESS! {ip_address} has been disconnected from the internet.")
        print("[*] (Their Wi-Fi icon is still connected, but no pages will load)")
    else:
        print(f"[-] Failed to block {ip_address}. Error: {result.stdout}")

def unblock_ip(ip_address):
    print(f"[*] Removing Firewall Block... Restoring internet for {ip_address}")
    rule_name = f"Block_Hotspot_{ip_address}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if "Ok." in result.stdout or "No rules match" in result.stdout:
        print(f"[+] SUCCESS! {ip_address} internet access has been restored.")
    else:
        print(f"[-] Failed to unblock {ip_address}. Error: {result.stdout}")

if __name__ == "__main__":
    if not is_admin():
        print("[!] ERROR: PERMISSION DENIED.")
        print("    You MUST run this script in an Administrator Command Prompt.")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("Usage: python hotspot_blocker.py <block|unblock> <ip_address>")
        print("Example: python hotspot_blocker.py block 192.168.137.5")
        sys.exit(1)

    action = sys.argv[1].lower()
    ip = sys.argv[2]

    if action == "block":
        block_ip(ip)
    elif action == "unblock":
        unblock_ip(ip)
    else:
        print("Invalid action. Use 'block' or 'unblock'.")
