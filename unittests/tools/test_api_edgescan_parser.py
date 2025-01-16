from dojo.models import Test
from dojo.tools.api_edgescan.parser import ApiEdgescanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestApiEdgescanParser(DojoTestCase):

    def test_get_scan_types(self):
        parser = ApiEdgescanParser()
        self.assertEqual(parser.get_scan_types(), ["Edgescan Scan"])

    def test_get_label_for_scan_types(self):
        scan_type = "Edgescan Scan"
        parser = ApiEdgescanParser()
        self.assertEqual(parser.get_label_for_scan_types(scan_type), "Edgescan Scan")

    def get_description_for_scan_types(self):
        scan_type = "Edgescan Scan"
        parser = ApiEdgescanParser()
        self.assertEqual(
            parser.get_description_for_scan_types(scan_type),
            "Edgescan findings can be imported by API or JSON file.",
        )

    def test_requires_file(self):
        parser = ApiEdgescanParser()
        self.assertEqual(parser.requires_file("scan_type"), False)

    def test_requires_tool_type(self):
        parser = ApiEdgescanParser()
        self.assertEqual(parser.requires_tool_type("scan_type"), "Edgescan")

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("api_edgescan") / "no_vuln.json", encoding="utf-8") as testfile:
            parser = ApiEdgescanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("api_edgescan") / "one_vuln.json", encoding="utf-8") as testfile:
            parser = ApiEdgescanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "Cross-site scripting (reflected)")
            self.assertEqual(finding.date, "2014-12-05")
            self.assertEqual(finding.cwe, 75)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "CVE-2021-5300")
            self.assertEqual(finding.cvssv3, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N")
            self.assertEqual(finding.url, "192.168.1.1")
            self.assertEqual(finding.severity, "High")
            self.assertEqual(finding.description, "Description Text")
            self.assertEqual(finding.mitigation, "Remediation Text")
            self.assertEqual(finding.active, True)
            self.assertEqual(finding.tags, ["APPROVED", "Demo-Asset", "ABC Corporate", "test"])
            self.assertEqual(finding.unique_id_from_tool, 21581)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            self.assertEqual(finding.unsaved_endpoints[0].host, "192.168.1.1")
            self.assertEqual(finding.unsaved_endpoints[0].protocol, None)

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("api_edgescan") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = ApiEdgescanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding_1 = findings[0]
            finding_2 = findings[1]
            self.assertEqual(finding_1.title, "Cross-site scripting (reflected)")
            self.assertEqual(finding_1.date, "2014-12-05")
            self.assertEqual(finding_1.cwe, 75)
            self.assertEqual(1, len(finding_1.unsaved_vulnerability_ids))
            self.assertEqual(finding_1.unsaved_vulnerability_ids[0], "CVE-2021-5300")
            self.assertEqual(finding_1.cvssv3, None)
            self.assertEqual(finding_1.url, "https://test.example.com")
            self.assertEqual(finding_1.severity, "High")
            self.assertEqual(finding_1.description, "Description Text")
            self.assertEqual(finding_1.mitigation, "Remediation Text")
            self.assertEqual(finding_1.active, True)
            self.assertEqual(finding_1.tags, ["APPROVED", "Demo-Asset"])
            self.assertEqual(finding_1.unique_id_from_tool, 21581)
            self.assertEqual(1, len(finding_1.unsaved_endpoints))
            self.assertEqual(finding_1.unsaved_endpoints[0].host, "test.example.com")
            self.assertEqual(finding_1.unsaved_endpoints[0].protocol, "https")
            self.assertEqual(finding_2.title, "Directory listing")
            self.assertEqual(finding_2.date, "2014-09-05")
            self.assertEqual(finding_2.cwe, 77)
            self.assertEqual(1, len(finding_2.unsaved_vulnerability_ids))
            self.assertEqual(finding_2.unsaved_vulnerability_ids[0], "CVE-2021-4008")
            self.assertEqual(finding_2.cvssv3, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N")
            self.assertEqual(finding_2.url, "example.test.com")
            self.assertEqual(finding_2.severity, "Low")
            self.assertEqual(finding_2.description, "Description Text 2")
            self.assertEqual(finding_2.mitigation, "Remediation Text 2")
            self.assertEqual(finding_2.active, False)
            self.assertEqual(finding_2.tags, [])
            self.assertEqual(finding_2.unique_id_from_tool, 21583)
            self.assertEqual(1, len(finding_2.unsaved_endpoints))
            self.assertEqual(finding_2.unsaved_endpoints[0].host, "example.test.com")
            self.assertEqual(finding_2.unsaved_endpoints[0].protocol, None)
