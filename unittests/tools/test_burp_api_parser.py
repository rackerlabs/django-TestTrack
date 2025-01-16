from dojo.models import Test
from dojo.tools.burp_api.parser import BurpApiParser, convert_confidence, convert_severity
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestParser(DojoTestCase):

    def test_example_report(self):
        testfile = get_unit_tests_scans_path() / "/burp_api/example.json"
        with open(testfile, encoding="utf-8") as f:
            parser = BurpApiParser()
            findings = parser.get_findings(f, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
        self.assertEqual(5, len(findings))
        with self.subTest(i=0):
            item = findings[0]
            self.assertEqual("Info", item.severity)
            self.assertEqual("TLS cookie without secure flag set", item.title)
            self.assertEqual("5605602767570803712", item.unique_id_from_tool)
            self.assertEqual("5243392", item.vuln_id_from_tool)
            self.assertGreater(3, item.scanner_confidence)
            self.assertIsNotNone(item.impact)

    def test_validate_more(self):
        testfile = get_unit_tests_scans_path() / "/burp_api/many_vulns.json"
        with open(testfile, encoding="utf-8") as f:
            parser = BurpApiParser()
            findings = parser.get_findings(f, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            for item in findings:
                self.assertIsNotNone(item.impact)

    def test_convert_severity(self):
        with self.subTest(severity="high"):
            self.assertEqual("High", convert_severity({"severity": "high"}))
        with self.subTest(severity="medium"):
            self.assertEqual("Medium", convert_severity({"severity": "medium"}))
        with self.subTest(severity="low"):
            self.assertEqual("Low", convert_severity({"severity": "low"}))
            self.assertEqual("Low", convert_severity({"severity": "LOW"}))
        with self.subTest(severity="undefined"):
            self.assertEqual("Info", convert_severity({"severity": "undefined"}))
        with self.subTest(severity=None):
            self.assertEqual("Info", convert_severity({}))

    def test_convert_confidence(self):
        with self.subTest(confidence="certain"):
            self.assertGreater(3, convert_confidence({"confidence": "certain"}))
        with self.subTest(confidence="firm"):
            self.assertLess(2, convert_confidence({"confidence": "firm"}))
            self.assertGreater(6, convert_confidence({"confidence": "firm"}))
        with self.subTest(confidence="tentative"):
            self.assertLess(5, convert_confidence({"confidence": "tentative"}))
        with self.subTest(confidence="undefined"):
            self.assertIsNone(convert_confidence({"confidence": "undefined"}))
        with self.subTest(confidence=None):
            self.assertIsNone(convert_confidence({}))

    def test_fix_issue_9128(self):
        testfile = get_unit_tests_scans_path() / "/burp_api/fix_issue_9128.json"
        with open(testfile, encoding="utf-8") as f:
            parser = BurpApiParser()
            findings = parser.get_findings(f, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            for item in findings:
                self.assertIsNotNone(item.impact)
