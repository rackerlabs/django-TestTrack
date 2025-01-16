from dojo.models import Test
from dojo.tools.nsp.parser import NspParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNspParser(DojoTestCase):
    def test_parse_none(self):
        parser = NspParser()
        with open(get_unit_tests_scans_path("nsp") / "none.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(0, len(findings))

    def test_parse_ok(self):
        parser = NspParser()
        with open(get_unit_tests_scans_path("nsp") / "scan.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(9, len(findings))

        # Count each type of finding to check afterwards
        codeExec = 0
        dos = 0

        for finding in findings:
            if finding.title.startswith("Remote Code Execution"):
                self.assertEqual(findings[0].severity, "High")
                self.assertEqual(findings[0].references, "https://nodesecurity.io/advisories/521")
                codeExec += 1
            elif finding.title.startswith("Regular Expression Denial of Service"):
                self.assertEqual(findings[0].severity, "High")
                self.assertIn(finding.references, [
                    "https://nodesecurity.io/advisories/106",
                    "https://nodesecurity.io/advisories/526",
                    "https://nodesecurity.io/advisories/534",
                    "https://nodesecurity.io/advisories/535",
                ])
                dos += 1
            else:
                self.fail("Unexpected NSP finding.")

        self.assertEqual(codeExec, 1)
        self.assertEqual(dos, 8)
