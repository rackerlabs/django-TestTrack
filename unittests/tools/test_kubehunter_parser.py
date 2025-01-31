from django.test import TestCase

from dojo.models import Test
from dojo.tools.kubehunter.parser import KubeHunterParser
from unittests.dojo_test_case import get_unit_tests_scans_path


class TestKubeHunterParser(TestCase):

    def test_kubehunter_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("kubehunter") / "kubehunter_zero_vul.json", encoding="utf-8") as testfile:
            parser = KubeHunterParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_kubehunter_parser_with_one_criticle_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("kubehunter") / "kubehunter_one_vul.json", encoding="utf-8") as testfile:
            parser = KubeHunterParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            self.assertEqual("KHV044", findings[0].vuln_id_from_tool)
            self.assertEqual("Privileged Container", findings[0].title)
            self.assertEqual(True, finding.active)

            self.assertEqual(False, finding.duplicate)
            self.assertEqual(finding.severity, "High")

    def test_kubehunter_parser_with_many_vuln_has_many_findings(self):
        with open(get_unit_tests_scans_path("kubehunter") / "kubehunter_many_vul.json", encoding="utf-8") as testfile:
            parser = KubeHunterParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(8, len(findings))

    def test_kubehunter_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context, \
           open(get_unit_tests_scans_path("kubehunter") / "empty.json", encoding="utf-8") as testfile:
            parser = KubeHunterParser()
            parser.get_findings(testfile, Test())

        self.assertEqual(
            "Expecting value: line 1 column 1 (char 0)", str(context.exception),
        )

    def test_kubehunter_parser_dupe(self):
        with open(get_unit_tests_scans_path("kubehunter") / "dupe.json", encoding="utf-8") as testfile:
            parser = KubeHunterParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
