import json
import csv

json_file_path = '../data/sonarqube/sonarqube_report.json'
csv_file_path = '../data/sonarqube/sonarqube_report.csv'

# Đọc từng dòng, bỏ qua dòng rác
valid_lines = []
with open(json_file_path, 'r', encoding='utf-8') as file:
    for line in file:
        line = line.strip()
        if line and line not in [',', ']', '[']:  # Bỏ qua dòng chỉ có , hoặc ]
            valid_lines.append(line.rstrip(','))  # Bỏ dấu , cuối dòng nếu có

# Nối các dòng thành chuỗi JSON array
json_content = '[' + ','.join(valid_lines) + ']'

# Parse JSON
try:
    data = json.loads(json_content)
except json.JSONDecodeError as e:
    print(f"❌ Lỗi parse JSON toàn bộ nội dung: {e}")
    data = []

# Tạo header CSV
headers = [
    "key", "rule", "severity", "component", "project", "line", "message", "effort",
    "debt", "author", "tags", "creationDate", "updateDate", "type", "scope", "status"
]

# Ghi dữ liệu ra CSV
with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    writer.writeheader()
    for item in data:
        row = {key: item.get(key, "") for key in headers}
        row['tags'] = ', '.join(item.get('tags', []))
        writer.writerow(row)

print(f"✅ Đã xuất file CSV tại: {csv_file_path}")