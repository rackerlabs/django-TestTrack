import csv
import io
import json
from datetime import datetime

from cvss import parser as cvss_parser
from dateutil import parser
from django.conf import settings
from django.utils import timezone

from dojo.models import Finding
from dojo.utils import first_elem


class VeracodeScaParser:
    vc_severity_mapping = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    def get_scan_types(self):
        return ["Veracode SourceClear Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Veracode SourceClear Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Veracode SourceClear CSV or JSON report format"

    def get_findings(self, file, test):
        if file is None:
            return ()

        if file.name.strip().lower().endswith(".json"):
            return self._get_findings_json(file, test)

        return self.get_findings_csv(file, test)

    def _get_findings_json(self, file, test):
        """Load a Veracode SCA file in JSON format"""
        data = json.load(file)

        embedded = data.get("_embedded")
        findings = []
        if not embedded:
            return findings

        for issue in embedded.get("issues", []):
            if issue.get("issue_type") != "vulnerability":
                continue

            # Get the date based on the first_seen setting
            try:
                if settings.USE_FIRST_SEEN:
                    date = parser.parse(issue.get("created_date"))
                else:
                    date = parser.parse(issue.get("created_date"))
            except Exception:
                date = None

            library = issue.get("library")
            component_name = library.get("name")
            if library.get("id") and library.get("id").startswith("maven:"):
                component_name = library.get("id").split(":")[2]
            component_version = library.get("version")

            vulnerability = issue.get("vulnerability")
            vuln_id = vulnerability.get("cve")
            if vuln_id and not (
                vuln_id.startswith(("cve", "CVE"))
            ):
                vuln_id = "CVE-" + vuln_id
            cvss_score = issue.get("severity")
            if vulnerability.get("cvss3_score"):
                cvss_score = vulnerability.get("cvss3_score")
            severity = self.__cvss_to_severity(cvss_score)

            description = (
                "Project name: {}\n"
                "Title: \n>{}"
                "\n\n-----\n\n".format(
                    issue.get("project_name"), vulnerability.get("title"),
                )
            )

            finding = Finding(
                test=test,
                title=f"{component_name}:{component_version} | {vuln_id}",
                description=description,
                severity=severity,
                component_name=component_name,
                component_version=component_version,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=issue.get("id"),
                date=date,
                nb_occurences=1,
            )

            if vuln_id:
                finding.unsaved_vulnerability_ids = [vuln_id]

            if vulnerability.get("cvss3_vector"):
                cvssv3_vector = vulnerability.get("cvss3_vector")
                if not cvssv3_vector.startswith("CVSS:3.1/"):
                    cvssv3_vector = "CVSS:3.1/" + cvssv3_vector
                vectors = cvss_parser.parse_cvss_from_text(cvssv3_vector)
                if len(vectors) > 0:
                    finding.cvssv3 = vectors[0].clean_vector()

            if vulnerability.get("cwe_id"):
                cwe = vulnerability.get("cwe_id")
                if cwe:
                    if cwe.startswith(("CWE-", "cwe-")):
                        cwe = cwe[4:]
                    if cwe.isdigit():
                        finding.cwe = int(cwe)

            finding.references = "\n\n" + issue.get("_links").get("html").get(
                "href",
            )
            status = issue.get("issue_status")
            if (
                (issue.get("Ignored")
                and issue.get("Ignored").capitalize() == "True")
                or (status
                and (
                    status.capitalize() == "Resolved"
                    or status.capitalize() == "Fixed"
                ))
            ):
                finding.is_mitigated = True
                finding.mitigated = timezone.now()
                finding.active = False

            findings.append(finding)

        return findings

    def get_findings_csv(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(
            io.StringIO(content), delimiter=",", quotechar='"',
        )
        csvarray = []

        for row in reader:
            csvarray.append(row)

        findings = []
        for row in csvarray:
            if row.get("Issue type") != "Vulnerability":
                continue

            issueId = row.get("Issue ID", None)
            if not issueId:
                # Workaround for possible encoding issue
                issueId = first_elem(row.values())
            library = row.get("Library", None)
            if row.get("Package manager") == "MAVEN" and row.get(
                "Coordinate 2",
            ):
                library = row.get("Coordinate 2")
            version = row.get("Version in use", None)
            vuln_id = row.get("CVE", None)
            if vuln_id and not (
                vuln_id.startswith(("cve", "CVE"))
            ):
                vuln_id = "CVE-" + vuln_id

            severity = self.fix_severity(row.get("Severity", None))
            cvss_score = float(row.get("CVSS score", 0))
            # Get the date based on the first_seen setting
            try:
                if settings.USE_FIRST_SEEN:
                    date = datetime.strptime(
                        row.get("Issue opened: Scan date"), "%d %b %Y %H:%M%p %Z",
                    )
                else:
                    date = datetime.strptime(
                        row.get("Issue opened: Scan date"), "%d %b %Y %H:%M%p %Z",
                    )
            except Exception:
                date = None

            description = (
                "Project name: {}\n"
                "Title: \n>{}"
                "\n\n-----\n\n".format(row.get("Project"), row.get("Title"))
            )

            finding = Finding(
                test=test,
                title=f"{library}:{version} | {vuln_id}",
                description=description,
                severity=severity,
                component_name=library,
                component_version=version,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=issueId,
                date=date,
                nb_occurences=1,
            )

            finding.unsaved_vulnerability_ids = [vuln_id]
            if cvss_score:
                finding.cvssv3_score = cvss_score

            if (
                (row.get("Ignored")
                and row.get("Ignored").capitalize() == "True")
                or (row.get("Status")
                and row.get("Status").capitalize() == "Resolved")
            ):
                finding.is_mitigated = True
                finding.mitigated = timezone.now()
                finding.active = False

            findings.append(finding)

        return findings

    def fix_severity(self, severity):
        severity = severity.capitalize()
        if severity is None:
            severity = "Medium"
        elif severity == "Unknown" or severity == "None":
            severity = "Info"
        return severity

    @classmethod
    def __cvss_to_severity(cls, cvss):
        if cvss >= 9:
            return cls.vc_severity_mapping.get(5)
        if cvss >= 7:
            return cls.vc_severity_mapping.get(4)
        if cvss >= 4:
            return cls.vc_severity_mapping.get(3)
        if cvss > 0:
            return cls.vc_severity_mapping.get(2)
        return cls.vc_severity_mapping.get(1)
