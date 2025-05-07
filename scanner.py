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
        print(f"{df}")

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
    oui = normalize_bssid(bssid)
    pin = pin_db.get(oui, "Not found")
    print(f"可能的PIN: {pin}") 

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
            print(f"Matched OUI: {match['OUI']} → PIN: {match['PIN']}")
    else:
        print("No matching PIN found.")
