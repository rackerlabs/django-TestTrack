from dojo.models import Test
from dojo.tools.drheader.parser import DrHeaderParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDrHeaderParser(DojoTestCase):

    def test_parse_file_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path("drheader") / "no_vulns.json", encoding="utf-8")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open(get_unit_tests_scans_path("drheader") / "scan.json", encoding="utf-8")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_has_many_finding_one_tool2(self):
        testfile = open(get_unit_tests_scans_path("drheader") / "scan2.json", encoding="utf-8")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_has_many_finding_one_tool3(self):
        testfile = open(get_unit_tests_scans_path("drheader") / "scan3.json", encoding="utf-8")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(11, len(findings))

    def test_parse_file_has_many_finding_multiple_urls(self):
        testfile = open(get_unit_tests_scans_path("drheader") / "multiple_urls.json", encoding="utf-8")
        parser = DrHeaderParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        testfile.close()
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(443, endpoint.port)
            self.assertEqual("example.com", endpoint.host)
