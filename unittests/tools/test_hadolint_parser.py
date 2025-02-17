from dojo.models import Test
from dojo.tools.hadolint.parser import HadolintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TesthadolintParser(DojoTestCase):

    def test_parse_file_with_one_dockerfile(self):
        testfile = open(get_unit_tests_scans_path("hadolint") / "one_dockerfile.json", encoding="utf-8")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        finding = findings[0]
        self.assertEqual(finding.line, 9)
        self.assertEqual(finding.file_path, "django-DefectDojo\\Dockerfile.django")

    def test_parse_file_with_many_dockerfile(self):
        testfile = open(get_unit_tests_scans_path("hadolint") / "many_dockerfile.json", encoding="utf-8")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(12, len(findings))
