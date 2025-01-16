
from dojo.models import Engagement, Finding, Product, Test
from dojo.tools.appspider.parser import AppSpiderParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAppSpiderParser(DojoTestCase):
    def test_appspider_parser_has_one_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        testfile = open(get_unit_tests_scans_path() / "appspider/one_vuln.xml", encoding="utf-8")
        parser = AppSpiderParser()
        findings = parser.get_findings(testfile, test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        testfile.close()
        self.assertEqual(1, len(findings))
        item = findings[0]
        with self.subTest(item=0):
            self.assertEqual(525, item.cwe)

    def convert_severity(self):
        with self.subTest(val="0-Safe"):
            self.assertIn(Finding.SEVERITIES, AppSpiderParser.convert_severity("0-Safe"))
