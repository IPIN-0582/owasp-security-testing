import xml.etree.ElementTree as ET
import pandas as pd

# --- Đường dẫn ---
XML_PATH = "../data/fsb/fsb_report.xml"    # file .xml do FindSecurityBugs sinh ra
CSV_PATH = "../data/fsb/fsb_report.csv"        # file đích .csv

# --- Đọc & phân tích XML ---
tree = ET.parse(XML_PATH)
root = tree.getroot()

records = []
for bug in root.findall(".//BugInstance"):
    rec = {
        "bug_type"  : bug.get("type"),
        "category"  : bug.get("category"),
        "priority"  : bug.get("priority"),
        "message"   : bug.findtext("LongMessage") or bug.findtext("ShortMessage")
    }
    cls = bug.find("Class")
    if cls is not None:
        rec["class"] = cls.get("classname")

    src = bug.find(".//SourceLine")
    if src is not None:
        rec["source_path"] = src.get("sourcepath")
        rec["start_line"]  = src.get("start")
        rec["end_line"]    = src.get("end")

    records.append(rec)

# --- Xuất CSV ---
pd.DataFrame(records).to_csv(CSV_PATH, index=False, encoding="utf-8")
print(f"Đã xuất {len(records)} dòng → {CSV_PATH}")
