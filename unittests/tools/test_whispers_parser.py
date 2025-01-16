from dojo.models import Test
from dojo.tools.whispers.parser import WhispersParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWhispersParser(DojoTestCase):

    def test_whispers_parser_severity_map(self):
        fixtures = [
            get_unit_tests_scans_path("whispers") / "whispers_one_vul.json",  # v2.1 format
            get_unit_tests_scans_path("whispers") / "whispers_one_vul_v2.2.json",  # v2.2 format
        ]
        expected_severity = "High"

        for fixture in fixtures:
            testfile = open(fixture, encoding="utf-8")
            parser = WhispersParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(expected_severity, findings[0].severity)

    def test_whispers_parser_with_no_vuln_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path("whispers") / "whispers_zero_vul.json", encoding="utf-8")
        parser = WhispersParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_whispers_parser_with_one_critical_vuln_has_one_findings(self):
        testfile = open(get_unit_tests_scans_path("whispers") / "whispers_one_vul.json", encoding="utf-8")
        parser = WhispersParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("src/pip.conf", findings[0].file_path)
        self.assertEqual(2, findings[0].line)
        self.assertEqual("pip.conf Password", findings[0].vuln_id_from_tool)

    def test_whispers_parser_with_many_vuln_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path("whispers") / "whispers_many_vul.json", encoding="utf-8")
        parser = WhispersParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
