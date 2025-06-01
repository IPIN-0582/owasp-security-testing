import json
import csv

# Đọc dữ liệu JSON từ file
with open('../data/semgrep/semgrep_report.json', 'r', encoding='utf-8') as json_file:
    data = json.load(json_file)

# Chuẩn bị dữ liệu cho CSV
results = data.get('results', [])

# Xác định các trường CSV cần xuất
csv_fields = [
    'check_id', 'path', 'start_line', 'start_col', 'end_line', 'end_col'
]

# Tạo danh sách dữ liệu để viết vào CSV
csv_rows = []
for result in results:
    row = {
        'check_id': result.get('check_id', ''),
        'path': result.get('path', ''),
        'start_line': result.get('start', {}).get('line', ''),
        'start_col': result.get('start', {}).get('col', ''),
        'end_line': result.get('end', {}).get('line', ''),
        'end_col': result.get('end', {}).get('col', ''),
    }
    csv_rows.append(row)

# Ghi dữ liệu vào file CSV
output_csv_file = '../data/semgrep/semgrep_report.csv'
with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
    writer.writeheader()
    writer.writerows(csv_rows)

print(f'File CSV đã được tạo: {output_csv_file}')
