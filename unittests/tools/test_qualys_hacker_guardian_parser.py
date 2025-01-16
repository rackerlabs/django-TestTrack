
from dojo.models import Test
from dojo.tools.qualys_hacker_guardian.parser import QualysHackerGuardianParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQualysHackerGuardianParser(DojoTestCase):

    def test_qualys_hacker_guardian_parser_with_no_findings(self):
        with open(get_unit_tests_scans_path() / "qualys_hacker_guardian/zero_finding.csv", encoding="utf-8") as testfile:
            parser = QualysHackerGuardianParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_qualys_hacker_guardian_parser_with_one_findings(self):
        with open(get_unit_tests_scans_path() / "qualys_hacker_guardian/one_finding.csv", encoding="utf-8") as testfile:
            parser = QualysHackerGuardianParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("Reference to Windows file path is present in HTML", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual(len(finding.unsaved_endpoints), 2)

    def test_qualys_hacker_guardian_parser_with_many_findings(self):
        with open(get_unit_tests_scans_path() / "qualys_hacker_guardian/many_finding.csv", encoding="utf-8") as testfile:
            parser = QualysHackerGuardianParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("Reference to Windows file path is present in HTML", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual(len(finding.unsaved_endpoints), 2)
            finding = findings[1]
            self.assertEqual("HTTP Security Header Not Detected", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertEqual(len(finding.unsaved_endpoints), 1)
            finding = findings[2]
            self.assertEqual("Predictable Resource Location Via Forced Browsing", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertEqual(len(finding.unsaved_endpoints), 1)
