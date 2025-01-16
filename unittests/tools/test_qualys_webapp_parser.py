from dojo.models import Test
from dojo.tools.qualys_webapp.parser import QualysWebAppParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQualysWebAppParser(DojoTestCase):

    def test_qualys_webapp_parser_with_no_vuln_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path("qualys_webapp") / "qualys_webapp_no_vuln.xml", encoding="utf-8")
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 6 non-info findings, 17 total
        self.assertEqual(0, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(17, len(findings))

    def test_qualys_webapp_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open(get_unit_tests_scans_path("qualys_webapp") / "qualys_webapp_one_vuln.xml", encoding="utf-8")
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 8 non-info findings, 14 total
        self.assertEqual(1, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(14, len(findings))

    def test_qualys_webapp_parser_with_many_vuln_has_many_findings(self):
        testfile = open(
            get_unit_tests_scans_path("qualys_webapp") / "qualys_webapp_many_vuln.xml", encoding="utf-8",
        )
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 3 non-info findings, 21 total
        self.assertEqual(3, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(21, len(findings))

    def test_qualys_webapp_parser_info_is_vuln(self):
        testfile = open(
            get_unit_tests_scans_path("qualys_webapp") / "qualys_webapp_many_vuln.xml", encoding="utf-8",
        )
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test(), enable_weakness=True)
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 21 non-info findings, 21 total
        self.assertEqual(21, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(21, len(findings))

    def test_discussion_10239(self):
        testfile = open(
            get_unit_tests_scans_path("qualys_webapp") / "discussion_10239.xml", encoding="utf-8",
        )
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test(), enable_weakness=True)
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(finding.unsaved_req_resp[0].get("req"), "POST: https://example.com/vulnerable/path\nReferer:  https://example.com/\n\nHost:  www.example.com\n\nUser-Agent:  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15\n\nAccept:  */*\n\nContent-Length:  39\n\nContent-Type:  application/x-www-form-urlencoded REQUEST_ONE\n\nBODY: post_param=malicious_code_here\n")
