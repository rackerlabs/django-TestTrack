from dojo.models import Test
from dojo.tools.whitehat_sentinel.parser import WhiteHatSentinelParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWhiteHatSentinelParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with self.assertRaises(ValueError):
            with open(get_unit_tests_scans_path("whitehat_sentinel") / "empty_file.json", encoding="utf-8") as testfile:
                parser = WhiteHatSentinelParser()
                parser.get_findings(testfile, Test())

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("whitehat_sentinel") / "one_vuln.json", encoding="utf-8") as testfile:
            parser = WhiteHatSentinelParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("whitehat_sentinel") / "many_vuln.json", encoding="utf-8") as testfile:
            parser = WhiteHatSentinelParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_parse_file_with_invalid_data(self):
        with self.assertRaises(ValueError):
            with open(get_unit_tests_scans_path("whitehat_sentinel") / "invalid_data.txt", encoding="utf-8") as testfile:
                parser = WhiteHatSentinelParser()
                parser.get_findings(testfile, Test())
