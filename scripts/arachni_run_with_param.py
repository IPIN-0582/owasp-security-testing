import subprocess, os, shlex, re
import xml.etree.ElementTree as ET

# ====== Cấu hình =======
OUT_DIR = "../data/arachni/"
BENCHMARK_XML = "../BenchmarkJava/data/benchmark-crawler-http.xml"
ARACHNI_PATH = "/home/huy/arachni-1.6.1.3-0.6.1.1/bin/arachni"
ARACHNI_REPORTER_PATH = "/home/huy/arachni-1.6.1.3-0.6.1.1/bin/arachni_reporter"
REAL_HOST = "192.168.6.149"
os.makedirs(OUT_DIR, exist_ok=True)

def extract_benchmark_name(url: str) -> str:
    match = re.search(r"(BenchmarkTest\d+)", url)
    return match.group(1) if match else "Unknown"

def load_urls_and_params(xml_file):
    """Parse benchmark-crawler-http.xml để lấy URL và param"""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    url_map = []
    for test in root.findall(".//benchmarkTest"):
        url = test.get('URL')  # Lấy URL từ attribute 'URL'
        if not url:
            continue
        url = url.replace("localhost", REAL_HOST)
        benchmark_name = extract_benchmark_name(url)
        # Lấy param từ getparam và formparam
        get_params = '&'.join([f"{p.get('name')}={p.get('value')}" for p in test.findall('./getparam') if p.get('name') and p.get('value')])
        form_params = '&'.join([f"{p.get('name')}={p.get('value')}" for p in test.findall('./formparam') if p.get('name') and p.get('value')])
        params = '&'.join(filter(None, [get_params, form_params]))
        url_map.append((url, benchmark_name, params))
    return url_map

# ====== Thực thi =======
url_map = load_urls_and_params(BENCHMARK_XML)

if not url_map:
    print("⚠️ Không tìm thấy testcase nào có URL trong benchmark-crawler-http.xml!")
else:
    for url, benchmark_name, params in url_map:
        afr = os.path.join(OUT_DIR, f"{benchmark_name}.afr")
        xml_ = os.path.join(OUT_DIR, f"{benchmark_name}.xml")
        
        full_url = url
        if params:
            separator = '&' if '?' in url else '?'
            full_url = f"{url}{separator}{params}"
        
        print(f"[+] Scanning {full_url}")
        cmd_scan = f"{ARACHNI_PATH} {shlex.quote(full_url)} --report-save={shlex.quote(afr)}"
        result = subprocess.run(cmd_scan, shell=True)
        if result.returncode != 0:
            print(f"    ! Scan error for {benchmark_name}, bỏ qua")
            continue
        
        cmd_rep = f"{ARACHNI_REPORTER_PATH} {shlex.quote(afr)} --reporter=xml:outfile={shlex.quote(xml_)}"
        subprocess.run(cmd_rep, shell=True)

    print("\n✅ Hoàn tất scan bằng Arachni lưu tại /data/arachni/")
