
from dojo.models import SEVERITIES, Test
from dojo.tools.api_blackduck.parser import ApiBlackduckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestApiBlackduckParser(DojoTestCase):

    def test_bandit_parser_has_many_findings(self):
        with open(get_unit_tests_scans_path("api_blackduck") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = ApiBlackduckParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                finding.clean()
                self.assertIn(finding.severity, SEVERITIES)
            self.assertEqual(43, len(findings))
            with self.subTest(i=0):
                item = findings[0]
                self.assertEqual("BDSA-2021-2909 in cdr/code-server:3.3.0-rc.27", item.title)
                self.assertEqual("Medium", item.severity)
                self.assertEqual("cdr/code-server", item.component_name)
                self.assertEqual("3.3.0-rc.27", item.component_version)
                self.assertEqual(400, item.cwe)
                self.assertEqual("BDSA-2021-2909", item.unique_id_from_tool)
            with self.subTest(i=20):
                item = findings[20]
                self.assertEqual("BDSA-2019-2252 in LibreOffice:6.0.0.3", item.title)
                self.assertEqual("High", item.severity)
                self.assertEqual("LibreOffice", item.component_name)
                self.assertEqual("6.0.0.3", item.component_version)
                self.assertEqual(749, item.cwe)
                self.assertEqual("BDSA-2019-2252", item.unique_id_from_tool)
            with self.subTest(i=42):
                item = findings[42]
                self.assertEqual("BDSA-2020-3620 in y18n:5.0.1", item.title)
                self.assertEqual("Medium", item.severity)
                self.assertEqual("y18n", item.component_name)
                self.assertEqual("5.0.1", item.component_version)
                self.assertEqual(668, item.cwe)
                self.assertEqual("BDSA-2020-3620", item.unique_id_from_tool)
