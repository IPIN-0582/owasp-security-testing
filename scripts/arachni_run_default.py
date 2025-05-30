import subprocess, os, hashlib, shlex
import re

URL_FILE   = "../data/owasp/urls.txt"
OUT_DIR    = "../data/arachni/"
os.makedirs(OUT_DIR, exist_ok=True)

ARACHNI_PATH = r"/home/huy/arachni-1.6.1.3-0.6.1.1/bin/arachni"
ARACHNI_REPORTER_PATH = r"/home/huy/arachni-1.6.1.3-0.6.1.1/bin/arachni_reporter"

def extract_benchmark_name(url: str) -> str:
    """Trích xuất BenchmarkTestXXXXXX từ URL."""
    match = re.search(r"(BenchmarkTest\d+)", url)
    return match.group(1) if match else "Unknown"

with open(URL_FILE, encoding="utf-8") as f:
    for url in map(str.strip, f):
        if not url:
            continue
        # Chỉ lấy tên BenchmarkTestXXXXXX làm tên file
        benchmark_name = extract_benchmark_name(url)
        afr = os.path.join(OUT_DIR, f"{benchmark_name}.afr")
        xml_ = os.path.join(OUT_DIR, f"{benchmark_name}.xml")

        print(f"[+] Scanning {url}")
        cmd_scan = f"{ARACHNI_PATH} {shlex.quote(url)} --report-save={shlex.quote(afr)}"
        if subprocess.run(cmd_scan, shell=True).returncode != 0:
            print("    ! Scan error, bỏ qua"); continue

        cmd_rep = f"{ARACHNI_REPORTER_PATH} {shlex.quote(afr)} --reporter=xml:outfile={shlex.quote(xml_)}"
        subprocess.run(cmd_rep, shell=True)

print("\n✅ Hoàn tất scan bằng Arachni lưu tại /data/arachni/")
