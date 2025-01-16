from dojo.models import Test
from dojo.tools.skf.parser import SKFParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSkfParser(DojoTestCase):

    def test_single_has_no_finding(self):
        with open(get_unit_tests_scans_path("skf") / "export.csv", encoding="utf-8") as testfile:
            parser = SKFParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(27, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("Authentication Verification Requirements : Verify that user set passwords are at least 12 characters in length. (C6)", finding.title)
            self.assertEqual("Info", finding.severity)
