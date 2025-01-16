
from dojo.models import Test
from dojo.tools.trufflehog.parser import TruffleHogParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name):
    return get_unit_tests_scans_path("trufflehog") / file_name


class TestTruffleHogParser(DojoTestCase):

    def test_many_vulns_v2(self):
        with open(sample_path("v2_many_vulns.json"), encoding="utf-8") as test_file:
            parser = TruffleHogParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 18)
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("test_all.py", finding.file_path)

    def test_many_vulns_git_v3(self):
        with open(sample_path("v3_git.json"), encoding="utf-8") as test_file:
            parser = TruffleHogParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 3)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("keys", finding.file_path)

    def test_many_vulns_github_v3(self):
        with open(sample_path("v3_github.json"), encoding="utf-8") as test_file:
            parser = TruffleHogParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 3)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("keys", finding.file_path)
