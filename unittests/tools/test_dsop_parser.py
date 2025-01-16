from dojo.models import Test
from dojo.tools.dsop.parser import DsopParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDsopParser(DojoTestCase):
    def test_zero_findings(self):
        with open(get_unit_tests_scans_path("dsop") / "zero_vuln.xlsx", "rb") as testfile:
            parser = DsopParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_many_findings(self):
        with open(get_unit_tests_scans_path("dsop") / "many_vuln.xlsx", "rb") as testfile:
            parser = DsopParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 4)
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-15587", finding.unsaved_vulnerability_ids[0])
