
from dojo.models import Test
from dojo.tools.burp.parser import BurpParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBurpParser(DojoTestCase):

    def test_burp_with_one_vuln_has_one_finding(self):
        with open(get_unit_tests_scans_path() / "burp/one_finding.xml", encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(1, len(findings))
            self.assertEqual("1049088", findings[0].vuln_id_from_tool)
            self.assertEqual(3, len(findings[0].unsaved_endpoints))

    def test_burp_with_multiple_vulns_has_multiple_findings(self):
        with open(get_unit_tests_scans_path() / "burp/seven_findings.xml", encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(7, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("5245344", finding.vuln_id_from_tool)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Frameable response (potential Clickjacking)", finding.title)

    def test_burp_with_one_vuln_with_blank_response(self):
        with open(get_unit_tests_scans_path() / "burp/one_finding_with_blank_response.xml", encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(1, len(findings))

            self.assertEqual("7121655797013284864", findings[0].unique_id_from_tool)
            self.assertEqual("1049088", findings[0].vuln_id_from_tool)
            self.assertEqual("SQL injection", findings[0].title)
            self.assertEqual(1, len(findings[0].unsaved_endpoints))
            self.assertEqual("High", findings[0].severity)

    def test_burp_with_one_vuln_with_cwe(self):
        with open(get_unit_tests_scans_path() / "burp/one_finding_with_cwe.xml", encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(1, len(findings))

            self.assertEqual("456437653765735", findings[0].unique_id_from_tool)
            self.assertEqual("7340288", findings[0].vuln_id_from_tool)
            self.assertEqual("Cacheable HTTPS response", findings[0].title)
            self.assertEqual(524, findings[0].cwe)
            self.assertEqual("Info", findings[0].severity)

    def test_burp_issue4399(self):
        with open(get_unit_tests_scans_path() / "burp/issue4399.xml", encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(20, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("4060931308708695040", finding.unique_id_from_tool)
                self.assertEqual("16777728", finding.vuln_id_from_tool)
                self.assertEqual("Unencrypted communications", finding.title)
                self.assertEqual(326, finding.cwe)
                self.assertEqual("Low", finding.severity)
            with self.subTest(i=10):
                finding = findings[10]
                self.assertEqual("3648136005422773248", finding.unique_id_from_tool)
                self.assertEqual("4197376", finding.vuln_id_from_tool)
                self.assertEqual("Input returned in response (reflected)", finding.title)
                self.assertEqual(20, finding.cwe)
                self.assertEqual("Info", finding.severity)
            with self.subTest(i=19):
                finding = findings[19]
                self.assertEqual("5394761637085678592", finding.unique_id_from_tool)
                self.assertEqual("3146256", finding.vuln_id_from_tool)
                self.assertEqual("External service interaction (HTTP)", finding.title)
                self.assertEqual(918, finding.cwe)
                self.assertEqual("High", finding.severity)
