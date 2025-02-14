import json
from collections import namedtuple

# nampedtuple is used to replicate the functionality of the Finding class inside models.
Test = namedtuple("Test", [])


class AnchoreEngineParser:
    def get_scan_types(self):
        return ["Anchore Engine Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Anchore Engine Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Anchore-CLI JSON vulnerability report format."

    def get_findings(self, filename, test):
        dupes = {}

        with open(filename, encoding="utf-8") as file:
            data = json.load(file)

        metadata = data.get("metadata", {})

        details = f"**Image hash**: {metadata.get('imageDigest', metadata.get('image_digest', 'None'))} \n\n"

        for item in data.get("securityEvaluation", []):
            vulnerability_id = item.get("vulnerabilityId", "Unknown")

            title = f"{vulnerability_id} - {item.get('package', 'Unknown')} ({item.get('packageType', 'Unknown')})"

            details += f"**Package**: {item.get('package', 'Unknown')}\n\n"
            details += f"**Package path**: {item.get('path', 'Unknown')}\n\n"
            details += f"**Package type**: {item.get('packageType', 'Unknown')}\n\n"

            severity = item.get("severity", "Unknown")
            if severity.lower() in ["negligible", "unknown"]:
                severity = "Info"

            mitigation = "No fix available."
            if item.get("fixAvailable") and item["fixAvailable"] != "None":
                mitigation = f"Upgrade to: {' or '.join(item['fixAvailable'].split(','))}\n\n"
                mitigation += f"URL: {item.get('link', 'None')}"

            cvssv3_base_score = item.get("nvdCvssBaseScore")

            if isinstance(cvssv3_base_score, str) and cvssv3_base_score.replace(".", "", 1).isdigit():
                cvssv3_base_score = float(cvssv3_base_score)
            elif not isinstance(cvssv3_base_score, int | float):
                cvssv3_base_score = None

            references = item.get("link")

            dupe_key = "|".join(
                [
                    item.get("cves", "None"),
                    item.get("package", "None"),
                    item.get("packageType", "None"),
                    item.get("path", "None"),
                    item.get("severity", "None"),
                ],
            )

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                find = {
                    "title": title,
                    "cve": item.get("cves"),
                    "cvssv3_score": cvssv3_base_score,
                    "date": item.get("detectedAt"),
                    "description": details,
                    "severity": severity,
                    "mitigation": mitigation,
                    "references": references,
                    "file_path": item.get("path"),
                    "component_name": item.get("package"),
                    "url": item.get("link"),
                    "static_finding": True,
                    "dynamic_finding": False,
                    "vulnerability_id": vulnerability_id,
                }

                dupes[dupe_key] = find

        return list(dupes.values())


# parser = AnchoreEngineParser()
# json_file_path = "~/Vulnerability_Report_2025-01-13T10_09_59.971Z.json"

# findings = parser.get_findings(json_file_path, Test())
