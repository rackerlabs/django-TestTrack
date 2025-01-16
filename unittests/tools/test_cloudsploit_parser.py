from dojo.models import Test
from dojo.tools.cloudsploit.parser import CloudsploitParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCloudsploitParser(DojoTestCase):

    def test_cloudsploit_parser_with_no_vuln_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path("cloudsploit") / "cloudsploit_zero_vul.json", encoding="utf-8")
        parser = CloudsploitParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_cloudsploit_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open(get_unit_tests_scans_path("cloudsploit") / "cloudsploit_one_vul.json", encoding="utf-8")
        parser = CloudsploitParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_cloudsploit_parser_with_many_vuln_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path("cloudsploit") / "cloudsploit_many_vul.json", encoding="utf-8")
        parser = CloudsploitParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))
