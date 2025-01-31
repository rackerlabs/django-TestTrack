import csv
import hashlib
import io

from cvss import parser as cvss_parser
from dateutil.parser import parse

from dojo.models import Endpoint, Finding


class GenericCSVParser:
    ID = "Generic Findings Import"

    def _get_findings_csv(self, filename):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(
            io.StringIO(content), delimiter=",", quotechar='"',
        )

        dupes = {}
        for row in reader:
            finding = Finding(
                title=row["Title"],
                description=row["Description"],
                date=parse(row["Date"]).date(),
                severity=self.get_severity(row["Severity"]),
                duplicate=self._convert_bool(
                    row.get("Duplicate", "FALSE"),
                ),  # bool False by default
                nb_occurences=1,
            )
            # manage active
            if "Active" in row:
                finding.active = self._convert_bool(row.get("Active"))
            # manage mitigation
            if "Mitigation" in row:
                finding.mitigation = row["Mitigation"]
            # manage impact
            if "Impact" in row:
                finding.impact = row["Impact"]
            # manage impact
            if "References" in row:
                finding.references = row["References"]
            # manage verified
            if "Verified" in row:
                finding.verified = self._convert_bool(row.get("Verified"))
            # manage false positives
            if "FalsePositive" in row:
                finding.false_p = self._convert_bool(row.get("FalsePositive"))
            # manage CVE
            if "CVE" in row and [row["CVE"]]:
                finding.unsaved_vulnerability_ids = [row["CVE"]]
            # manage Vulnerability Id
            if row.get("Vulnerability Id"):
                if finding.unsaved_vulnerability_ids:
                    finding.unsaved_vulnerability_ids.append(
                        row["Vulnerability Id"],
                    )
                else:
                    finding.unsaved_vulnerability_ids = [
                        row["Vulnerability Id"],
                    ]
            # manage CWE
            if "CweId" in row:
                finding.cwe = int(row["CweId"])

            if "epss_score" in row:
                finding.epss_score = float(row["epss_score"])

            if "epss_percentile" in row:
                finding.epss_percentile = float(row["epss_percentile"])

            if "CVSSV3" in row:
                cvss_objects = cvss_parser.parse_cvss_from_text(row["CVSSV3"])
                if len(cvss_objects) > 0:
                    finding.cvssv3 = cvss_objects[0].clean_vector()

            # manage endpoints
            if "Url" in row:
                finding.unsaved_endpoints = [
                    Endpoint.from_uri(row["Url"])
                    if "://" in row["Url"]
                    else Endpoint.from_uri("//" + row["Url"]),
                ]

            # manage internal de-duplication
            key = hashlib.sha256(
                f"{finding.severity}|{finding.title}|{finding.description}".encode(),
            ).hexdigest()
            if key in dupes:
                find = dupes[key]
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                if find.unsaved_vulnerability_ids:
                    find.unsaved_vulnerability_ids.extend(
                        finding.unsaved_vulnerability_ids,
                    )
                else:
                    find.unsaved_vulnerability_ids = (
                        finding.unsaved_vulnerability_ids
                    )
                find.nb_occurences += 1
            else:
                dupes[key] = finding
        return list(dupes.values())

    def _convert_bool(self, val):
        return val.lower()[0:1] == "t"  # bool False by default

    def get_severity(self, severity_input):
        if severity_input in ["Info", "Low", "Medium", "High", "Critical"]:
            return severity_input
        return "Info"
