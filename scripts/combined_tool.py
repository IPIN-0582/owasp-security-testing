import pandas as pd
from functools import reduce

# Bước 1: Đọc kết quả từ các file CSV định dạng chuẩn
files = {
    'semgrep': '../data/semgrep/semgrep_results_format.csv',
    'sonarqube': '../data/sonarqube/sonarqube_results_format.csv',
    'zap': '../data/zap/zap_results_format.csv',
    'arachni': '../data/arachni/arachni_results_format.csv',
    'fsb': '../data/fsb/fsb_results_format.csv'
}

dfs = {tool: pd.read_csv(path) for tool, path in files.items()}

# Bước 2: Merge theo TestCase và CWE
merged_df = reduce(lambda left, right: pd.merge(left, right, on=['TestCase', 'CWE'], suffixes=('', '_{}'.format(right.columns[-1]))), dfs.values())

# Bước 3: Xử lý theo công thức 1ooN (logic 2-tools combination, mở rộng n-tools)
def combine_row(row):
    expected = row['Expected']
    detect_cols = [col for col in row.index if col.startswith('Detected')]
    detected_tools = [row[col] for col in detect_cols]
    
    if expected:  # Positive case
        if any(detected_tools):
            return 'TP'
        else:
            return 'FN'
    else:  # Negative case
        if any(detected_tools):
            return 'FP'
        else:
            return 'TN'

merged_df['Evaluation'] = merged_df.apply(combine_row, axis=1)

# Bước 4: Tóm tắt TP, FP, FN, TN
summary = merged_df['Evaluation'].value_counts().reindex(['TP', 'FP', 'FN', 'TN'], fill_value=0).reset_index()
summary.columns = ['Metric', 'Count']
print("\n📊 Summary:\n", summary)

# Bước 5: Tính các chỉ số
TP = summary.loc[summary['Metric'] == 'TP', 'Count'].values[0]
FP = summary.loc[summary['Metric'] == 'FP', 'Count'].values[0]
FN = summary.loc[summary['Metric'] == 'FN', 'Count'].values[0]
TN = summary.loc[summary['Metric'] == 'TN', 'Count'].values[0]

recall = TP / (TP + FN) if TP + FN else 0
precision = TP / (TP + FP) if TP + FP else 0
fpr = FP / (FP + TN) if FP + TN else 0
fbeta = lambda b: (1 + b**2) * precision * recall / (b**2 * precision + recall) if (precision + recall) else 0
f1, f05, f15 = fbeta(1), fbeta(0.5), fbeta(1.5)
print(f"\n✅ Recall: {recall:.4f}, Precision: {precision:.4f}, FPR: {fpr:.4f}, F1: {f1:.4f}")

# Bước 6: Xuất kết quả tổng hợp
merged_df.to_csv('../data/combined/combined_n_tools_results.csv', index=False)
print("\n✅ File tổng hợp đã lưu: combined_n_tools_results.csv")

# Bước 7: Xem merged_df.head()
print("\n🔎 Preview merged_df:")
print(merged_df.head())
