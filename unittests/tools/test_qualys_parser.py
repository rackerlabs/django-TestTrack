import datetime

from django.test import override_settings

from dojo.models import Test
from dojo.tools.qualys.parser import QualysParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQualysParser(DojoTestCase):

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_no_vuln_has_no_findings_first_seen(self):
        self.parse_file_with_no_vuln_has_no_findings()

    def test_parse_file_with_no_vuln_has_no_findings(self):
        self.parse_file_with_no_vuln_has_no_findings()

    def parse_file_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("qualys") / "empty.xml", encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_multiple_vuln_has_multiple_findings_first_seen(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings()
        self.assertEqual(datetime.datetime(2019, 7, 31).date(), finding.date)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings()
        self.assertEqual(datetime.datetime(2019, 7, 31).date(), finding.date)

    def parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(
            get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml", encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(301, len(findings))

            finding = findings[0]
            self.assertEqual(
                finding.title, "QID-6 | DNS Host Name",
            )
            self.assertEqual(
                finding.severity, "Informational",
            )
            self.assertEqual(
                finding.unsaved_endpoints[0].host, "demo13.s02.sjc01.qualys.com",
            )
            for finding in findings:
                if finding.unsaved_endpoints[0].host == "demo14.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_cvssv3_score = finding
                if finding.unsaved_endpoints[0].host == "demo13.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_cvssv3_vector = finding
            self.assertEqual(
                # CVSS_FINAL is defined without a cvssv3 vector
                finding_cvssv3_score.cvssv3, None,
            )
            self.assertEqual(
                finding_cvssv3_score.severity, "High",
            )
            self.assertEqual(finding_cvssv3_vector.cvssv3,
                            "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H")
            self.assertEqual(
                finding_cvssv3_vector.severity, "High",
            )
            return finding

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_no_vuln_has_no_findings_csv_first_seen(self):
        self.parse_file_with_no_vuln_has_no_findings_csv()

    def test_parse_file_with_no_vuln_has_no_findings_csv(self):
        self.parse_file_with_no_vuln_has_no_findings_csv()

    def parse_file_with_no_vuln_has_no_findings_csv(self):
        with open(
            get_unit_tests_scans_path("qualys") / "empty.csv", encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_multiple_vuln_has_multiple_findings_csv_first_seen(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings_csv()
        self.assertEqual(datetime.datetime(2021, 5, 13).date(), finding.date)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_csv(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings_csv()
        self.assertEqual(datetime.datetime(2021, 5, 25).date(), finding.date)

    def parse_file_with_multiple_vuln_has_multiple_findings_csv(self):
        with open(
            get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.csv", encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))

            finding = findings[0]
            self.assertEqual(
                finding.title,
                "QID-105971 | EOL/Obsolete Software: Microsoft ASP.NET 1.0 Detected")
            self.assertEqual(
                finding.severity, "Critical",
            )
            self.assertEqual(
                finding.unsaved_endpoints[0].host, "ip-10-98-57-180.eu-west-1.compute.internal",
            )

            for finding in findings:
                if finding.unsaved_endpoints[0].host == "ip-10-98-57-180.eu-west-1.compute.internal" and finding.title == "QID-105971 | EOL/Obsolete Software: Microsoft ASP.NET 1.0 Detected":

                    self.assertEqual(
                        finding.severity, "Critical",
                    )
                    self.assertEqual(
                        finding.cvssv3,
                        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:U/RC:C")
                    self.assertEqual(
                        finding.severity, "Critical",
                    )

            return findings[0]

    def test_parse_file_monthly_pci_issue6932(self):
        with open(
            get_unit_tests_scans_path("qualys") / "monthly_pci_issue6932.csv", encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_cvss_values_and_scores(self):
        with open(
            get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml", encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                if finding.unsaved_endpoints[0].host == "demo14.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_cvssv3_score = finding
                if finding.unsaved_endpoints[0].host == "demo13.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_no_cvssv3_at_detection = finding
                if finding.unsaved_endpoints[0].host == "demo14.s02.sjc01.qualys.com" and finding.title == 'QID-121695 | NTP "monlist"  Feature Denial of Service Vulnerability':
                    finding_no_cvssv3 = finding
            # The CVSS Vector is not used from the Knowledgebase
            self.assertEqual(
                # CVSS_FINAL is defined without a cvssv3 vector
                finding_cvssv3_score.cvssv3, None,
            )
            # Nevertheless the CVSSv3 Score should be set
            self.assertEqual(
                finding_cvssv3_score.cvssv3_score, 8.2,
            )
            # If no cvss information is present in detection and not in knowledgebase values should be empty
            self.assertEqual(
                finding_no_cvssv3.cvssv3, None,
            )
            self.assertEqual(
                finding_no_cvssv3.cvssv3_score, None,
            )
            # No CVSS Values available in detection and it uses the knowledgebase then
            self.assertEqual(finding_no_cvssv3_at_detection.cvssv3,
                            "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H")
            self.assertEqual(
                finding_no_cvssv3_at_detection.cvssv3_score, 9.0,
            )

    def test_get_severity_legacy(self):
        with open(get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml", encoding="utf-8") as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            counts = {}
            for finding in findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
            expected_counts = {
                "Informational": 177,
                "Low": 65,
                "Medium": 46,
                "High": 6,
                "Critical": 7,
            }

            self.assertEqual(expected_counts, counts)

    @override_settings(USE_QUALYS_LEGACY_SEVERITY_PARSING=False)
    def test_get_severity(self):
        with open(get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml", encoding="utf-8") as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            counts = {}
            for finding in findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
            expected_counts = {
                "Low": 242,
                "Medium": 46,
                "High": 13,
            }

            self.assertEqual(expected_counts, counts)
