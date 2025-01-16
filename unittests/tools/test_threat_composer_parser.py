

from dojo.models import Test
from dojo.tools.threat_composer.parser import ThreatComposerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name: str):
    return get_unit_tests_scans_path("threat_composer") / file_name


class TestThreatComposerParser(DojoTestCase):

    def test_threat_composer_parser_with_no_threat_has_no_findings(self):
        with open(sample_path("threat_composer_zero_threats.json"), encoding="utf-8") as testfile:
            parser = ThreatComposerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_threat_composer_parser_with_one_threat_has_one_finding(self):
        with open(sample_path("threat_composer_one_threat.json"), encoding="utf-8") as testfile:
            parser = ThreatComposerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("lorem ipsum", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertIn("Assumption", str(finding.description))
                self.assertIsNotNone(finding.mitigation)
                self.assertIn("Assumption", str(finding.mitigation))
                self.assertIsNotNone(finding.impact)
                self.assertEqual("46db1eb4-a451-4d05-afe1-c695491e2387", finding.unique_id_from_tool)
                self.assertEqual(23, finding.vuln_id_from_tool)
                self.assertFalse(finding.false_p)
                self.assertFalse(finding.verified)

    def test_threat_composer_parser_with_many_threats_has_many_findings(self):
        with open(sample_path("threat_composer_many_threats.json"), encoding="utf-8") as testfile:
            parser = ThreatComposerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(21, len(findings))

    def test_threat_composer_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context:
            with open(sample_path("threat_composer_no_threats_with_error.json"), encoding="utf-8") as testfile:
                parser = ThreatComposerParser()
                parser.get_findings(testfile, Test())

        self.assertNotIn("No threats found in the JSON file", str(context.exception))

    def test_threat_composer_parser_with_one_threat_has_not_assumptions(self):
        with open(sample_path("threat_composer_broken_assumptions.json"), encoding="utf-8") as testfile:
            parser = ThreatComposerParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]
            self.assertNotIn("Assumption", str(finding.description))

    def test_threat_composer_parser_with_one_threat_has_not_mitigations(self):
        with open(sample_path("threat_composer_broken_mitigations.json"), encoding="utf-8") as testfile:
            parser = ThreatComposerParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]
            self.assertNotIn("Mitigation", str(finding.mitigation))
