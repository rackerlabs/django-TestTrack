from dojo.models import Test
from dojo.tools.api_vulners.parser import ApiVulnersParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestApiVulnersParser(DojoTestCase):

    def test_parse_many_findings(self):
        with open(get_unit_tests_scans_path("api_vulners") / "report_many_vulns.json", encoding="utf-8") as testfile:
            parser = ApiVulnersParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            finding = findings[2]
            self.assertEqual("High", finding.severity)
            self.assertEqual("223.234.234.123", finding.unsaved_endpoints[0].host)
            self.assertEqual("VNS/CESA-2021:0348", finding.vuln_id_from_tool)
            self.assertEqual("**CentOS Errata and Security Advisory** CESA-2021:0348", finding.description)
            self.assertEqual(4, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", finding.cvssv3)

    def test_parse_one_finding(self):
        with open(get_unit_tests_scans_path("api_vulners") / "report_one_vuln.json", encoding="utf-8") as testfile:
            parser = ApiVulnersParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("12.34.56.78", finding.unsaved_endpoints[0].host)
            self.assertEqual("VNS/RHSA-2018:2285", finding.vuln_id_from_tool)
            self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)

    def test_parse_no_finding(self):
        with open(get_unit_tests_scans_path("api_vulners") / "report_no_vulns.json", encoding="utf-8") as testfile:
            parser = ApiVulnersParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_no_description(self):
        with open(get_unit_tests_scans_path("api_vulners") / "report_no_description.json", encoding="utf-8") as testfile:
            parser = ApiVulnersParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("12.34.56.78", finding.unsaved_endpoints[0].host)
            self.assertEqual("VNS/RHSA-2018:2285", finding.vuln_id_from_tool)
            self.assertEqual(finding.title, finding.description)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
