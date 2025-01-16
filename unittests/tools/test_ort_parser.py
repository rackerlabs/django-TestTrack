from dojo.models import Test
from dojo.tools.ort.parser import OrtParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOrtParser(DojoTestCase):
    def test_parse_without_file_has_no_finding(self):
        parser = OrtParser()
        findings = parser.get_findings(None, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_has_many_finding_one_tool(self):
        testfile = open(
            get_unit_tests_scans_path("ort") / "evaluated-model-reporter-test-output.json", encoding="utf-8",
        )
        parser = OrtParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
