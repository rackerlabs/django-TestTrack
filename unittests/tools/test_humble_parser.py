from dojo.models import Test
from dojo.tools.humble.parser import HumbleParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHumbleParser(DojoTestCase):
    def test_humble_parser_with_many_findings(self):
        with open(get_unit_tests_scans_path("humble") / "many_findings.json", encoding="utf-8") as testfile:
            parser = HumbleParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(9, len(findings))
            finding = findings[0]
            self.assertEqual(finding.unsaved_endpoints[0].host, "asdf.asf.hs")
            self.assertEqual("Missing header: Clear-Site-Data", finding.title)
            finding = findings[7]
            self.assertEqual("Deprecated header: Strict-Transport-Security (Recommended Values)", finding.title)

    def test_humble_parser_with_many_findings2(self):
        with open(get_unit_tests_scans_path("humble") / "many_findings2.json", encoding="utf-8") as testfile:
            parser = HumbleParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(16, len(findings))
            finding = findings[0]
            self.assertEqual(finding.unsaved_endpoints[0].host, "testestset.com")
            self.assertEqual("Missing header: Clear-Site-Data", finding.title)
            finding = findings[7]
            self.assertEqual("Missing header: Referrer-Policy", finding.title)
            self.assertEqual("This security Header is missing: Referrer-Policy", finding.description)
