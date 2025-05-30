import xml.etree.ElementTree as ET
import csv
import glob
import os

# Thư mục chứa file XML kết quả quét
input_dir = '../data/arachni'
output_csv = '../data/arachni/arachni_report.csv'

# Tạo danh sách file XML cần quét
xml_files = glob.glob(os.path.join(input_dir, '*.xml'))

# Danh sách kết quả
results = []

for file in xml_files:
    tree = ET.parse(file)
    root = tree.getroot()
    
    url = root.find('./options/url').text if root.find('./options/url') is not None else 'N/A'
    
    for issue in root.findall('./issues/issue'):
        issue_name = issue.find('name').text if issue.find('name') is not None else 'N/A'
        severity = issue.find('severity').text if issue.find('severity') is not None else 'N/A'
        vector = issue.find('./vector/url').text if issue.find('./vector/url') is not None else url
        results.append({
            'File': os.path.basename(file),
            'URL': vector,
            'Issue': issue_name,
            'Severity': severity
        })

# Ghi ra file CSV
with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['File', 'URL', 'Issue', 'Severity']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for row in results:
        writer.writerow(row)

print(f"Tổng hợp {len(results)} dòng từ {len(xml_files)} file và ghi vào {output_csv}")
