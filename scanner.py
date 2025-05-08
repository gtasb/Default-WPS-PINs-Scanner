import subprocess

def normalize_bssid(bssid):
    """统一格式化 BSSID 并提取 OUI 部分"""
    return ':'.join(bssid.upper().split(':')[:3])  # 如 'F0:2F:74:C5:42:CC' → 'F0:2F:74'

def load_pin_database(csv_file='pins.csv'):
    """加载 CSV 数据为 OUI -> PIN 字典"""
    import pandas as pd
    pin_db = {}
    try:
        df = pd.read_csv(csv_file, encoding='utf-8')
        print(f"Loaded {len(df)} records from CSV")

    except Exception as e:
        print(f"Error loading CSV: {e}")

    return df

def find_pin(bssid, pin_db):
    df = pin_db
    oui = normalize_bssid(bssid)
    pins = []
    matches = df[df['OUI'] == oui]
    if not matches.empty:
        for index, match in matches.iterrows():
            pins.append(match['PIN'])
            print(f"→ PIN: {match['PIN']}")
    else:
        print("No matching PIN found.")
    return pins

def cf_pins(pins, interface):
    try:
        # reaver -i wlan0mon -b E0:3F:49:6A:57:78 -v
        result = subprocess.run(
            ["reaver", "-i", "{interface}", "-b", "{pins}", "-v"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print("Error: Unable to scan networks. Make sure Wi-Fi is enabled.")
            return []

        output = result.stdout
        return 
    except Exception as e:
        print(f"Error: {e}")
    return 

