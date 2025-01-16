from dojo.models import Test
from dojo.tools.ggshield.parser import GgshieldParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGgshieldParser(DojoTestCase):

    def test_parse_empty(self):
        with open(get_unit_tests_scans_path("ggshield") / "no_finding.json", encoding="utf-8") as testfile:
            parser = GgshieldParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with open(get_unit_tests_scans_path("ggshield") / "one_finding.json", encoding="utf-8") as testfile:
            parser = GgshieldParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("wapf/settings.py", finding.file_path)
            self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual("2021-07-05", finding.date)

    def test_parse_many_finding(self):
        with open(get_unit_tests_scans_path("ggshield") / "many_findings.json", encoding="utf-8") as testfile:
            parser = GgshieldParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding = findings[0]
            self.assertEqual("wapf/settings.py", finding.file_path)
            self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual("2021-03-13", finding.date)
            finding = findings[1]
            self.assertEqual("wapf/settings.py", finding.file_path)
            self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual("2021-07-05", finding.date)
