import pandas as pd
import re
import math
import matplotlib.pyplot as plt

# 1. Đọc benchmark
benchmark_df = pd.read_csv('../data/owasp/expected_results_320.csv')
benchmark_df = benchmark_df.rename(columns=lambda x: x.strip())
benchmark_df = benchmark_df.rename(columns={
    '# test name': 'testcase',
    'real vulnerability': 'real_vulnerability',
    'category': 'category'
})
benchmark_df['category'] = benchmark_df['category'].str.lower()
benchmark_df['testcase'] = benchmark_df['testcase'].str.strip()
benchmark_df = benchmark_df.drop(['Benchmark version: 1.2', '2016-06-1'], axis=1)

print("\n🔎 Preview benchmark_df:")
print(benchmark_df.head())


# 2. Đọc Semgrep từ CSV
semgrep_df = pd.read_csv('../data/semgrep/semgrep_report.csv')
semgrep_df = semgrep_df[semgrep_df['path'].str.contains(r'BenchmarkTest\d+', regex=True, na=False)]
semgrep_df['testcase'] = semgrep_df['path'].str.extract(r'(BenchmarkTest\d+)')

# 3. Mapping check_id → category (chuẩn 11 loại benchmark)
checkid2category = {
    'java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal': 'pathtraver',
    'java.servlets.security.httpservlet-path-traversal.httpservlet-path-traversal': 'pathtraver',
    'java.servlets.security.httpservlet-path-traversal-deepsemgrep.httpservlet-path-traversal-deepsemgrep': 'pathtraver',
    'java.lang.security.audit.xss.no-direct-response-writer.no-direct-response-writer': 'xss',
    'java.lang.security.audit.crypto.des-is-deprecated.des-is-deprecated': 'crypto',
    'java.lang.security.audit.crypto.desede-is-deprecated.desede-is-deprecated': 'crypto',
    'java.lang.security.audit.tainted-cmd-from-http-request.tainted-cmd-from-http-request': 'cmdi',
    'java.servlets.security.tainted-cmd-from-http-request.tainted-cmd-from-http-request': 'cmdi',
    'java.servlets.security.tainted-cmd-from-http-request-deepsemgrep.tainted-cmd-from-http-request-deepsemgrep': 'cmdi',
    'java.lang.security.audit.sqli.tainted-sql-from-http-request.tainted-sql-from-http-request': 'sqli',
    'java.lang.security.audit.tainted-ldapi-from-http-request.tainted-ldapi-from-http-request': 'ldapi',
    'java.servlets.security.tainted-ldapi-from-http-request.tainted-ldapi-from-http-request': 'ldapi',
    'java.servlets.security.tainted-ldapi-from-http-request-deepsemgrep.tainted-ldapi-from-http-request-deepsemgrep': 'ldapi',
    'java.servlets.security.servletresponse-writer-xss.servletresponse-writer-xss': 'xss',
    'java.servlets.security.servletresponse-writer-xss-deepsemgrep.servletresponse-writer-xss-deepsemgrep': 'xss',
    'java.lang.security.audit.crypto.use-of-md5.use-of-md5': 'crypto',
    'java.lang.security.audit.crypto.use-of-sha1.use-of-sha1': 'crypto',
    'java.servlets.security.audit.cookie-secure-flag-false.cookie-secure-flag-false': 'cookiesecure',
    'java.servlets.security.tainted-xpath-from-http-request-deepsemgrep.tainted-xpath-from-http-request-deepsemgrep': 'xpathi',
    'java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request': 'xpathi',
    'java.servlets.security.tainted-xpath-from-http-request.tainted-xpath-from-http-request': 'xpathi'
}

semgrep_df['category_semgrep'] = semgrep_df['check_id'].map(checkid2category)
semgrep_df_filtered = semgrep_df[semgrep_df['category_semgrep'].notna()]
semgrep_grouped = semgrep_df_filtered.groupby('testcase')['category_semgrep'].apply(set).reset_index()

print("\n🔎 Preview semgrep_df:")
print(semgrep_df.head())

# 4. Ghép với benchmark
merged_df = benchmark_df.merge(semgrep_grouped, on='testcase', how='left')
merged_df['category_semgrep'] = merged_df['category_semgrep'].apply(lambda x: x if isinstance(x, set) else set())

# 5. Hàm đánh giá TP, FP, FN, TN
def evaluate(row):
    category_benchmark = row['category']
    category_semgrep_set = row['category_semgrep']
    real_vuln = row['real_vulnerability']
    if real_vuln:
        return 'TP' if category_benchmark in category_semgrep_set else 'FN'
    else:
        return 'FP' if category_benchmark in category_semgrep_set else 'TN'

merged_df['Evaluation'] = merged_df.apply(evaluate, axis=1)
print("\n🔎 Preview merged_df:")
print(merged_df.head(10))

# 6. Tạo file CSV chuẩn từ merged_df (format chuẩn để so sánh multi-tool)
semgrep_output_df = pd.DataFrame([{
    'TestCase': row['testcase'],
    'CWE': row['category'],
    'Expected': bool(row['real_vulnerability']),
    'Detected': row['category'] in row['category_semgrep']
} for _, row in merged_df.iterrows()])
semgrep_output_df.to_csv('../data/semgrep/semgrep_results_format.csv', index=False)

print("\n✅ Đã xuất file Semgrep chuẩn từ merged_df: semgrep_results_format.csv")
print(semgrep_output_df.head())

# 7. Tóm tắt
summary = merged_df['Evaluation'].value_counts().reindex(['TP', 'FP', 'FN', 'TN'], fill_value=0).reset_index()
summary.columns = ['Metric', 'Count']
TP = summary.loc[summary['Metric'] == 'TP', 'Count'].values[0]
FP = summary.loc[summary['Metric'] == 'FP', 'Count'].values[0]
FN = summary.loc[summary['Metric'] == 'FN', 'Count'].values[0]
TN = summary.loc[summary['Metric'] == 'TN', 'Count'].values[0]

# 8. Tính chỉ số
def metrics_paper(tp, fp, fn, tn):
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    fpr = fp / (tn + fp) if tn + fp else 0.0

    # F–scores (β = 1, 0.5, 1.5)
    fbeta = lambda b: (1 + b**2) * prec * rec / (b**2 * prec + rec) if (prec + rec) else 0.0
    f1, f05, f15 = fbeta(1), fbeta(0.5), fbeta(1.5)

    # Markedness (TPR+TNR centered)
    denom_mark = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mark = ((tp * tn) - (fp * fn)) / denom_mark if denom_mark else 0.0
    
    # Informedness (Youden J)
    inf = rec - fpr

    results = {
        "Rec":  rec,
        "FPR":  fpr,
        "Prec": prec,
        "F-Mes": f1,
        "F0.5": f05,
        "F1.5": f15,
        "Mark": mark,
        "Inf":  inf,
    }

    print("\n=== KẾT QUẢ ===")
    for metric, value in results.items():
        print(f"{metric}: {value:.4f}")

    return results

metrics = metrics_paper(TP, FP, FN, TN)

# 9. Vẽ biểu đồ
labels, values = list(metrics.keys()), list(metrics.values())
fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.bar(labels, values, color='skyblue')
for bar in bars:
    height = bar.get_height()
    ax.annotate(f'{height:.2f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3), textcoords="offset points", ha='center', va='bottom')
ax.set_ylim(0, 1.1)
ax.set_ylabel('Giá trị')
ax.set_title('Biểu đồ các chỉ số đánh giá (SEMGREP-SAST)')
plt.tight_layout()
plt.show()
