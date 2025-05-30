import xml.etree.ElementTree as ET
import csv

# Đường dẫn file XML ZAP
input_file = '../data/zap/zap_report.xml'
# Đường dẫn file CSV đầu ra
output_file = '../data/zap/zap_report.csv'

# Parse XML
tree = ET.parse(input_file)
root = tree.getroot()

# Tạo list để lưu dữ liệu
data = []

# Lặp qua các 'alertitem'
for site in root.findall('.//site'):
    for alertitem in site.findall('.//alertitem'):
        pluginid = alertitem.find('pluginid').text if alertitem.find('pluginid') is not None else ''
        alert = alertitem.find('alert').text if alertitem.find('alert') is not None else ''
        riskcode = alertitem.find('riskcode').text if alertitem.find('riskcode') is not None else ''
        riskdesc = alertitem.find('riskdesc').text if alertitem.find('riskdesc') is not None else ''
        
        # Lặp qua các 'instance' của alertitem
        for instance in alertitem.findall('instances/instance'):
            uri = instance.find('uri').text if instance.find('uri') is not None else ''
            method = instance.find('method').text if instance.find('method') is not None else ''
            param = instance.find('param').text if instance.find('param') is not None else ''
            attack = instance.find('attack').text if instance.find('attack') is not None else ''
            evidence = instance.find('evidence').text if instance.find('evidence') is not None else ''
            
            # Thêm vào danh sách dữ liệu
            data.append([pluginid, alert, riskcode, riskdesc, uri, method, param, attack, evidence])

# Viết dữ liệu vào file CSV
with open(output_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    # Header
    writer.writerow(['pluginid', 'alert', 'riskcode', 'riskdesc', 'uri', 'method', 'param', 'attack', 'evidence'])
    # Ghi từng dòng dữ liệu
    writer.writerows(data)

print(f'Dữ liệu đã được xuất ra file CSV: {output_file}')
