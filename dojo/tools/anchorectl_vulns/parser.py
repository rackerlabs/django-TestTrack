import json
from dojo.models import Finding


class AnchoreCTLVulnsParser:
    def get_scan_types(self):
        return ["AnchoreCTL Vuln Report"]

    def get_label_for_scan_types(self, scan_type):
        return "AnchoreCTL Vuln Report"

    def get_description_for_scan_types(self, scan_type):
        return "AnchoreCTLs JSON vulnerability report format."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}

        metadata = data.get("metadata", {})
        image_digest = metadata.get("imageDigest", "None")
        vulnerabilities = data.get("securityEvaluation", data)

        for vuln in vulnerabilities:
            vulnerability_id = vuln.get("vulnerabilityId", vuln.get("vuln"))
            title = f"{vulnerability_id} - {vuln['package']} ({vuln['packageType']})"

            findingdetail = f"**Image hash**: {image_digest}\n\n"
            findingdetail += f"**Package**: {vuln['package']}\n\n"
            findingdetail += f"**Package path**: {vuln.get('path', vuln.get('packagePath', 'N/A'))}\n\n"
            findingdetail += f"**Package type**: {vuln['packageType']}\n\n"
            findingdetail += f"**Feed**: {vuln.get('feed', 'N/A')}/{vuln.get('feedGroup', 'N/A')}\n\n"
            findingdetail += f"**CPE**: {vuln.get('packageCpe', 'N/A')}\n\n"
            findingdetail += f"**Description**: {vuln.get('description', '<None>')}\n\n"

            sev = vuln["severity"]
            if sev in ["Negligible", "Unknown"]:
                sev = "Info"

            mitigation = f"Upgrade to {vuln.get('fix', vuln.get('fixAvailable', 'No fix available'))}\n"
            mitigation += f"URL: {vuln.get('url', vuln.get('link', 'N/A'))}\n"

            cvss_base_score = None
            if vuln.get("feed") in ["nvdv2", "vulnerabilities"]:
                if vuln.get("nvdData"):
                    cvss_base_score = vuln["nvdData"][0].get("cvssV3", {}).get("baseScore")
            else:
                for vendor in vuln.get("vendorData", []):
                    if vendor.get("cvssV3", {}).get("baseScore", -1) != -1:
                        cvss_base_score = vendor["cvssV3"]["baseScore"]
                        break

            references = vuln.get("url", vuln.get("link", "N/A"))

            dupe_key = "|".join([
                image_digest,
                vulnerability_id,
                vuln["package"],
                vuln.get("path", vuln.get("packagePath", "N/A")),
            ])

            if dupe_key not in dupes:
                find = Finding(
                    title=title,
                    test=test,
                    cvssv3_score=cvss_base_score,
                    description=findingdetail,
                    severity=sev,
                    mitigation=mitigation,
                    references=references,
                    file_path=vuln.get("path", vuln.get("packagePath", "N/A")),
                    component_name=vuln["package"],
                    component_version=vuln.get("packageVersion", "Unknown"),
                    url=vuln.get("url", vuln.get("link")),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=vulnerability_id,
                )
                if vulnerability_id:
                    find.unsaved_vulnerability_ids = [vulnerability_id]
                dupes[dupe_key] = find

        return list(dupes.values())
