import json
from datetime import datetime

from html2text import html2text

from dojo.models import Endpoint, Finding


class RapplexParser:

    """Rapplex - Web Application Security Scanner"""

    def get_scan_types(self):
        return ["Rapplex Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Rapplex Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import Rapplex JSON report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        severities = ["Information", "Low", "Medium", "High", "Critical"]

        for severity in severities:
            current_severity = data.get("Severities", {}).get(severity)
            if not current_severity:
                continue

            main_issue_groups = current_severity.get("IssueGroups", [])
            for main_issue_group in main_issue_groups:
                issues = main_issue_group.get("Issues", [])

                for issue in issues:
                    formatted_date = datetime.strptime(data.get("StartedDate", ""), "%d/%m/%Y %H:%M:%S").strftime("%Y-%m-%d")
                    severity_level = current_severity.get("Name", "")
                    title = issue.get("Title", "")
                    url = issue.get("Url", "")
                    req = issue.get("HttpRequest", "")
                    res = issue.get("HttpResponse", "")
                    issue_definition = main_issue_group.get("Definition", {})

                    cwe_val = None
                    for classification in issue_definition.get("Classifications", []):
                        if classification.get("Foundation") == "CWE":
                            cwe_val = classification.get("Value")
                            break

                    issue_sections = issue_definition.get("Sections", {})
                    ref = html2text(issue_sections.get("References", ""))
                    rem = issue_sections.get("Remediation", "")
                    summary = issue_sections.get("Summary", "")

                    finding = Finding(
                        title=title,
                        test=test,
                        severity=severity_level,
                        date=formatted_date,
                        description=summary,
                        mitigation=rem,
                        cwe=cwe_val,
                        references=ref,
                        active=True,
                    )

                    finding.unsaved_request = req
                    finding.unsaved_response = res

                    endpoint = Endpoint.from_uri(url)
                    finding.unsaved_endpoints.append(endpoint)

                    findings.append(finding)
        return findings
