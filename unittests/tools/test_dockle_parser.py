from dojo.models import Test
from dojo.tools.dockle.parser import DockleParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDockleParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("dockle") / "no_findings.json", encoding="utf-8") as testfile:
            parser = DockleParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with open(get_unit_tests_scans_path("dockle") / "many_findings.json", encoding="utf-8") as testfile:
            parser = DockleParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("CIS-DI-0001: Create a user for the container", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.static_finding)
                self.assertFalse(finding.dynamic_finding)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual("CIS-DI-0001", finding.vuln_id_from_tool)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("CIS-DI-0005: Enable Content trust for Docker", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.static_finding)
                self.assertFalse(finding.dynamic_finding)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual("CIS-DI-0005", finding.vuln_id_from_tool)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("CIS-DI-0008: Confirm safety of setuid/setgid files", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.static_finding)
                self.assertFalse(finding.dynamic_finding)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual("CIS-DI-0008", finding.vuln_id_from_tool)
