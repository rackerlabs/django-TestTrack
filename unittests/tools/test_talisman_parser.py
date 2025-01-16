from dojo.models import Test
from dojo.tools.talisman.parser import TalismanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTalismanParser(DojoTestCase):
    def test_parse_empty(self):
        with open(get_unit_tests_scans_path("talisman") / "no_finding.json", encoding="utf-8") as testfile:
            parser = TalismanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with open(get_unit_tests_scans_path("talisman") / "one_finding.json", encoding="utf-8") as testfile:
            parser = TalismanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("password.html", finding.file_path)
            self.assertEqual("Secret pattern found in password.html file", finding.title)
            self.assertIsNotNone(finding.description)

    def test_parse_many_finding(self):
        with open(get_unit_tests_scans_path("talisman") / "many_findings.json", encoding="utf-8") as testfile:
            parser = TalismanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual(
                "talisman_report/talisman_reports/data/report.json", finding.file_path,
            )
            self.assertEqual(
                "Secret pattern found in talisman_report/talisman_reports/data/report.json file",
                finding.title,
            )
            self.assertIsNotNone(finding.description)
            finding = findings[1]
            self.assertEqual("README.md", finding.file_path)
            self.assertEqual("Secret pattern found in README.md file", finding.title)
            self.assertIsNotNone(finding.description)
