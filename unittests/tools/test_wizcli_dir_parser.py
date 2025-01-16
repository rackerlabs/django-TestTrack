from dojo.models import Test
from dojo.tools.wizcli_dir.parser import WizcliDirParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWizcliDirParser(DojoTestCase):
    def test_no_findings(self):
        with open(get_unit_tests_scans_path("wizcli_dir") / "wizcli_dir_zero_vul.json", encoding="utf-8") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with open(get_unit_tests_scans_path("wizcli_dir") / "wizcli_dir_one_vul.json", encoding="utf-8") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("google.golang.org/protobuf - CVE-2024-24786", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/grpc/proto/go.mod", finding.file_path)
            self.assertIn(
                "**Library Name**: google.golang.org/protobuf\n"
                "**Library Version**: 1.28.1\n"
                "**Library Path**: /grpc/proto/go.mod\n"
                "**Vulnerability Name**: CVE-2024-24786\n"
                "**Fixed Version**: 1.33.0\n"
                "**Source**: https://github.com/advisories/GHSA-8r3f-844c-mc37\n"
                "**Description**: None\n"
                "**Score**: None\n"
                "**Exploitability Score**: None\n"
                "**Has Exploit**: False\n"
                "**Has CISA KEV Exploit**: False\n",
                finding.description,
            )

    def test_multiple_findings(self):
        with open(get_unit_tests_scans_path("wizcli_dir") / "wizcli_dir_many_vul.json", encoding="utf-8") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            finding = findings[0]
            self.assertEqual("golang.org/x/net - CVE-2023-44487", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/grpc/proto/go.mod", finding.file_path)
            self.assertIn(
                "**Library Name**: golang.org/x/net\n"
                "**Library Version**: 0.14.0\n"
                "**Library Path**: /grpc/proto/go.mod\n"
                "**Vulnerability Name**: CVE-2023-44487\n"
                "**Fixed Version**: 0.17.0\n"
                "**Source**: https://github.com/advisories/GHSA-qppj-fm5r-hxr3\n"
                "**Description**: None\n"
                "**Score**: 7.5\n"
                "**Exploitability Score**: 3.9\n"
                "**Has Exploit**: True\n"
                "**Has CISA KEV Exploit**: True\n",
                finding.description,
            )

            finding = findings[1]
            self.assertEqual("golang.org/x/net - CVE-2023-45288", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/grpc/proto/go.mod", finding.file_path)
            self.assertEqual(None, finding.line)
            self.assertIn(
                "**Library Name**: golang.org/x/net\n"
                "**Library Version**: 0.14.0\n"
                "**Library Path**: /grpc/proto/go.mod\n"
                "**Vulnerability Name**: CVE-2023-45288\n"
                "**Fixed Version**: 0.23.0\n"
                "**Source**: https://github.com/advisories/GHSA-4v7x-pqxf-cx7m\n"
                "**Description**: None\n"
                "**Score**: None\n"
                "**Exploitability Score**: None\n"
                "**Has Exploit**: False\n"
                "**Has CISA KEV Exploit**: False\n",
                finding.description,
            )
