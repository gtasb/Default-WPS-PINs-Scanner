import re
import time
import platform
import argparse
import subprocess
import scanner as sc
import os
from urllib import parse

def scan_wifi():
    system_platform = platform.system().lower()

    if system_platform == "windows":
        return scan_wifi_windows()
    elif system_platform == "linux":
        return scan_wifi_linux()
    elif system_platform == "darwin":
        return scan_wifi_mac()
    else:
        print("Unsupported platform for Wi-Fi scanning.")
        return []


def scan_wifi_windows():
    try:
        subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, text=True, shell=True, timeout=3)
        time.sleep(3)
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, text=True, shell=True, timeout=3
        )
        if result.returncode != 0:
            print("Error: Unable to scan networks. Make sure Wi-Fi is enabled.")
            return []

        output = result.stdout
        if not output.strip():
            print("No Wi-Fi networks found.")
            return []

        #print(f"Scanned WiFi Networks:{output}")
        return parse_networks_windows(output)
    except Exception as e:
        print(f"Error: {e}")
        return []


""" 
def scan_wifi_linux():
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print("Error: Unable to scan networks. Make sure Wi-Fi is enabled.")
            return []

        output = result.stdout
        if not output.strip():
            print("No Wi-Fi networks found.")
            return []

        return parse_networks_linux(output)
    except Exception as e:
        print(f"Error: {e}")
        return [] 
"""

def scan_wifi_linux():
    try:
        result = subprocess.run(
            ["iw", "dev", "wlan0", "scan"],
            capture_output=True, text=True, check=True, 
            timeout=15
        )
        return parse_iw_scan(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Scan failed: {e}")
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []

def parse_iw_scan(output):
    networks = []
    current_network = {}
    lines = output.splitlines()

    for line in lines:
        line = line.strip()
        if line.startswith("BSS ") and "on" in line:
            bssid_part = line[4:].split('(', 1)[0].strip()
            if current_network and "BSSID" in current_network:
                networks.append(current_network)
            current_network = {"BSSID": bssid_part}
        elif line.startswith("SSID:"):
            # ssid = line[5:].strip()[1:]  ❌ 错误：丢失首字母
            ssid = line[5:].strip()     # ✅ 修复：去掉 [1:]
            try:
                ssid = bytes(ssid.encode('latin1')).decode('utf-8')
            except:
                pass
            current_network["SSID"] = ssid
        elif "signal:" in line:
            signal = line.split(":", 1)[1].strip().split(" ")[0]
            current_network["Signal"] = signal
        elif "Authentication suites" in line:
            auth = line.split(":", 1)[1].strip()
            current_network["Authentication"] = auth
        elif "Pairwise ciphers" in line or "Group cipher" in line:
            encryption = line.split(":", 1)[1].strip()
            current_network["Encryption"] = encryption

    if current_network and "BSSID" in current_network:
        networks.append(current_network)

    return networks


def scan_wifi_mac():
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print("Error: Unable to scan networks. Make sure Wi-Fi is enabled.")
            return []

        output = result.stdout
        if not output.strip():
            print("No Wi-Fi networks found.")
            return []

        return parse_networks_mac(output)
    except Exception as e:
        print(f"Error: {e}")
        return []


def parse_networks_windows(output):
    ssid_pattern = re.compile(r"SSID \d+ : (.+)")
    bssid_pattern = re.compile(r"BSSID \d+[\s\d]*:\s*([a-fA-F0-9:-]+)")
    signal_pattern = re.compile(r"信号\s+:\s+(\d+)%")
    auth_pattern = re.compile(r"身份验证\s+:\s+(.+)")
    encryption_pattern = re.compile(r"加密\s+:\s+(.+)")
    channel_pattern = re.compile(r"频道\s+:\s+(\d+)")
    band_pattern = re.compile(r"波段\s+:\s+(.+)")

    lines = output.splitlines()
    networks = []
    current_network = {}

    for line in lines:
        ssid_match = ssid_pattern.search(line)
        if ssid_match:
            if current_network:
                networks.append(current_network)
            current_network = {'SSID': ssid_match.group(1)}
        
        # 只有当字段尚未存在时才设置
        if bssid_match := bssid_pattern.search(line):
            if 'BSSID' not in current_network:
                current_network['BSSID'] = bssid_match.group(1)

        if signal_match := signal_pattern.search(line):
            if 'Signal' not in current_network:
                current_network['Signal'] = signal_match.group(1)

        if auth_match := auth_pattern.search(line):
            if 'Authentication' not in current_network:
                current_network['Authentication'] = auth_match.group(1)

        if encryption_match := encryption_pattern.search(line):
            if 'Encryption' not in current_network:
                current_network['Encryption'] = encryption_match.group(1)

        if channel_match := channel_pattern.search(line):
            if 'Channel' not in current_network:
                current_network['Channel'] = channel_match.group(1)

        if band_match := band_pattern.search(line):
            if 'Band' not in current_network:
                current_network['Band'] = band_match.group(1)

    if current_network:
        networks.append(current_network)

    return networks


def parse_networks_linux(output):
    networks = []
    lines = output.strip().splitlines()
    for line in lines:
        ssid, signal, security = line.split(":")
        networks.append({
            "SSID": ssid.strip(),
            "Signal": signal.strip(),
            "Authentication": security.strip(),
            "Encryption": security.strip()
        })
    return networks


def parse_networks_mac(output):
    networks = []
    lines = output.strip().splitlines()
    for line in lines[1:]:
        parts = line.split()
        ssid = " ".join(parts[:-3])
        signal = parts[-3]
        networks.append({
            "SSID": ssid.strip(),
            "Signal": signal.strip(),
            "Authentication": "Unknown",
            "Encryption": "Unknown"
        })
    return networks


def parse_networks(output):
    ssid_pattern = re.compile(r"SSID \d+ : (.+)")
    signal_pattern = re.compile(r"Signal\s+:\s+(\d+)%")
    auth_pattern = re.compile(r"Authentication\s+:\s+(.+)")
    encryption_pattern = re.compile(r"Encryption\s+:\s+(.+)")
    channel_pattern = re.compile(r"Channel\s+:\s+(\d+)")
    band_pattern = re.compile(r"Band\s+:\s+(.+)")

    lines = output.splitlines()
    networks = []
    current_network = {}

    for line in lines:
        ssid_match = ssid_pattern.search(line)
        if ssid_match:
            if current_network:
                networks.append(current_network)
            current_network = {'SSID': ssid_match.group(1)}
        
        if signal_match := signal_pattern.search(line):
            current_network['Signal'] = signal_match.group(1)

        if auth_match := auth_pattern.search(line):
            current_network['Authentication'] = auth_match.group(1)

        if encryption_match := encryption_pattern.search(line):
            current_network['Encryption'] = encryption_match.group(1)

        if channel_match := channel_pattern.search(line):
            current_network['Channel'] = channel_match.group(1)

        if band_match := band_pattern.search(line):
            current_network['Band'] = band_match.group(1)

    if current_network:
        networks.append(current_network)

    return networks


def parse_arguments():
    parser = argparse.ArgumentParser(description="Wi-Fi Network Scanner Tool")
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Timeout duration between scans in seconds')
    parser.add_argument('-r', '--retries', type=int, default=1,
                        help='Number of retries for scanning')
    parser.add_argument('-i', '--interface', type=str, default='wlan0',
                        help='Network interface name')
    parser.add_argument('--all', action='store_true',
                        help='Show all networks (default: only show networks with matching PIN)')
    return parser.parse_args()

def resevere_bssid(bssid):
    s = bssid.encode('unicode_escape')
    ss = s.decode('utf-8').replace('\\x', '%')
    un = parse.unquote(ss)
    return un

def main():
    args = parse_arguments()

    pin_db = sc.load_pin_database(csv_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pins.csv'))

    for retry in range(args.retries):
        print(f"Scan attempt {retry + 1}/{args.retries}")
        networks = scan_wifi()
        if networks:
            print("Available Wi-Fi Networks:")
            for network in networks:
                print(f"\nSSID: {resevere_bssid(network.get('SSID', 'N/A'))}")
                #print(f"\nSSID: {network.get('SSID', 'N/A')}")
                #print(f"  Signal Strength: {network.get('Signal', 'N/A')}%")
                #print(f"  Authentication: {network.get('Authentication', 'N/A')}")
                #print(f"  Encryption: {network.get('Encryption', 'N/A')}")
                #print(f"  Channel: {network.get('Channel', 'N/A')}")
                #print(f"  Band: {network.get('Band', 'N/A')}")
                print(f"  MAC: {network.get('BSSID', 'N/A')}")
                #print("\n")
                pins = sc.find_pin(network.get('BSSID', 'N/A'), pin_db)
                #if platform.system().lower() == "linux":
                #    sc.cf_pins(pins, args.interface)
                
#        else:
#            print("No networks found.")
        time.sleep(args.timeout)

    print("Scanning completed!")

if __name__ == "__main__":
    main()