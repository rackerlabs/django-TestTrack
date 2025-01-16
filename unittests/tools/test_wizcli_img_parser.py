from dojo.models import Test
from dojo.tools.wizcli_img.parser import WizcliImgParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWizcliImgParser(DojoTestCase):
    def test_no_findings(self):
        with open(get_unit_tests_scans_path("wizcli_img") / "wizcli_img_zero_vul.json", encoding="utf-8") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with open(get_unit_tests_scans_path("wizcli_img") / "wizcli_img_one_vul.json", encoding="utf-8") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(
                "Secret: Password in URL (postgresql://postgres:---REDACTED---@localhost:5432/postgres?)", finding.title,
            )
            self.assertEqual("High", finding.severity)
            self.assertEqual("/app/testing.go", finding.file_path)
            self.assertIn(
                "**Secret ID**: None\n"
                "**Description**: Password in URL (postgresql://postgres:---REDACTED---@localhost:5432/postgres?)\n"
                "**File Name**: /app/testing.go\n"
                "**Line Number**: 35\n"
                "**Match Content**: PASSWORD\n",
                finding.description,
            )

    def test_multiple_findings(self):
        with open(get_unit_tests_scans_path("wizcli_img") / "wizcli_img_many_vul.json", encoding="utf-8") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            finding = findings[0]
            self.assertEqual("libcrypto3 - CVE-2024-5535", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(None, finding.file_path)
            self.assertIn(
                "**OS Package Name**: libcrypto3\n"
                "**OS Package Version**: 3.3.1-r0\n"
                "**Vulnerability Name**: CVE-2024-5535\n"
                "**Fixed Version**: 3.3.1-r1\n"
                "**Source**: https://security.alpinelinux.org/vuln/CVE-2024-5535\n"
                "**Description**: None\n"
                "**Score**: None\n"
                "**Exploitability Score**: None\n"
                "**Has Exploit**: False\n"
                "**Has CISA KEV Exploit**: False\n",
                finding.description,
            )

            finding = findings[1]
            self.assertEqual("libssl3 - CVE-2024-5535", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(None, finding.file_path)
            self.assertEqual(None, finding.line)
            self.assertIn(
                "**OS Package Name**: libssl3\n"
                "**OS Package Version**: 3.3.1-r0\n"
                "**Vulnerability Name**: CVE-2024-5535\n"
                "**Fixed Version**: 3.3.1-r1\n"
                "**Source**: https://security.alpinelinux.org/vuln/CVE-2024-5535\n"
                "**Description**: None\n"
                "**Score**: None\n"
                "**Exploitability Score**: None\n"
                "**Has Exploit**: False\n"
                "**Has CISA KEV Exploit**: False\n",
                finding.description,
            )
