from dojo.models import Test
from dojo.tools.wazuh.parser import WazuhParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWazuhParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("wazuh") / "no_findings.json", encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with open(get_unit_tests_scans_path("wazuh") / "one_finding.json", encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CVE-1234-123123", finding.unsaved_vulnerability_ids)
            self.assertEqual("asdf", finding.component_name)
            self.assertEqual("4.3.1", finding.component_version)
            self.assertEqual(5.5, finding.cvssv3_score)

    def test_parse_many_finding(self):
        with open(get_unit_tests_scans_path("wazuh") / "many_findings.json", encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(6, len(findings))
            self.assertEqual("2023-02-08", finding.date)

    def test_parse_one_finding_with_endpoint(self):
        with open(get_unit_tests_scans_path("wazuh") / "one_finding_with_endpoint.json", encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CVE-1234-1234", finding.unsaved_vulnerability_ids)
            self.assertEqual(6.5, finding.cvssv3_score)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("agent-1", endpoint.host)
            self.assertEqual("asdf", finding.component_name)
            self.assertEqual("1", finding.component_version)
            self.assertEqual("2023-12-13", finding.date)
