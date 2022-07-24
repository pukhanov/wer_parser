import argparse
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


# based on https://stackoverflow.com/a/22238613
def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def from_filetime(filetime: int):
    return datetime(1601, 1, 1).replace(tzinfo=timezone.utc) + timedelta(microseconds=filetime/10)

def parse_wer_file(filepath: Path):
    if filepath.exists() and filepath.name.lower() == "report.wer":
        wer_report = {}
        with filepath.open("r", encoding="utf-16") as f:
            last_key_name = ""
            for line in f:
                line = line.strip()
                sl = line.split("=", 1)
                if "[" in sl[0] and "]" in sl[0]:
                    if "." in sl[0]:
                        field_name = sl[0].split("[", 1)[0]
                        if field_name not in wer_report:
                            wer_report[field_name] = {}

                        if ".Name" in sl[0] or ".Key" in sl[0]:
                            wer_report[field_name][sl[1].replace(" ", "")] = ""
                            last_key_name = sl[1].replace(" ", "")
                        else:
                            wer_report[field_name][last_key_name] = sl[1]
                    else:
                        field_name = sl[0].split("[", 1)[0]
                        field_value = sl[1]
                        if field_name == "LoadedModule":
                            field_value = field_value.lower()
                        if field_name in wer_report:
                            wer_report[field_name].append(field_value)
                        else:
                            wer_report[field_name] = [field_value]
                elif "." in sl[0]:
                    field_name = sl[0].split(".", 1)
                    if field_name[0] not in wer_report:
                        wer_report[field_name[0]] = {field_name[1]: sl[1]}
                    else:
                        wer_report[field_name[0]][field_name[1]] = sl[1]
                else:
                    wer_report[sl[0]] = sl[1]

        # Parse out SHA1 of executable. Same format as hash in AmCache. Only first 31,457,280 bytes of file get hashed
        if "TargetAppId" in wer_report and wer_report["TargetAppId"].startswith("W:"):
            tai_split = wer_report["TargetAppId"].split("!")
            if tai_split[1].startswith("0000"):
                wer_report["SHA1"] = tai_split[1][4:]

        if "EventTime" in wer_report:
            wer_report["EventTime"] = from_filetime(int(wer_report["EventTime"]))
        if "UploadTime" in wer_report:
            wer_report["UploadTime"] = from_filetime(int(wer_report["UploadTime"]))
        
        return wer_report
    else:
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-dir", type=Path, help="Path to ReportArchive folder to process")
    args = parser.parse_args()
    if args.dir:
        wer_dir = args.dir
    else:
        wer_dir = Path("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive")

    wer_results = []
    if wer_dir.exists():
        for item in wer_dir.iterdir():
            if item.is_dir():
                report_path = Path(item, "Report.wer")
                try:
                    if report_path.exists():
                        result = parse_wer_file(report_path)                
                        if result:
                            try:
                                wer_results.append(result)
                            except Exception as e:
                                print(f"Error parsing file {report_path}. {e}")
                except PermissionError as e:
                    print(f"Permission denied to {report_path}")

    if wer_results:
        with Path(f"wer_results.csv").open("w", newline='') as csv_file:
            csv_writer = csv.DictWriter(csv_file, fieldnames=["AppPath", "EventTime", "SHA1", "AppName", "NsAppName", "OriginalFilename", "EventType", "FriendlyEventName", "ReportType"], extrasaction="ignore")
            csv_writer.writeheader()
            csv_writer.writerows(wer_results)

        with Path(f"wer_results.jsonl").open("w") as json_file:
            for item in wer_results:
                json_file.write(json.dumps(item, default=json_serial) + "\n")
