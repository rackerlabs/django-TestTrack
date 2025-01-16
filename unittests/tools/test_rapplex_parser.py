
from dojo.models import Test
from dojo.tools.rapplex.parser import RapplexParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRapplexParser(DojoTestCase):

    def test_rapplex_parser_with_no_findings(self):
        with open(get_unit_tests_scans_path() / "rapplex/rapplex_zero_vul.json", encoding="utf-8") as testfile:
            parser = RapplexParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_rapplex_parser_with_one_findings(self):
        with open(get_unit_tests_scans_path() / "rapplex/rapplex_one_vul.json", encoding="utf-8") as testfile:
            parser = RapplexParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("89", finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)

    def test_rapplex_parser_with_many_findings(self):
        with open(get_unit_tests_scans_path() / "rapplex/rapplex_many_vul.json", encoding="utf-8") as testfile:
            parser = RapplexParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(8, len(findings))
            finding = findings[0]
            self.assertEqual("Application Disclosure", finding.title)
            self.assertEqual("Information", finding.severity)
            self.assertEqual("200", finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)
            finding = findings[4]
            self.assertEqual("Missing X-Frame-Options Header", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("693", finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)
            finding = findings[6]
            self.assertEqual("Cross-site Scripting (Reflected)", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("79", finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)
            finding = findings[7]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("89", finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)
