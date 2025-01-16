from collections import Counter

from dojo.models import Test
from dojo.tools.aqua.parser import AquaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAquaParser(DojoTestCase):
    def test_aqua_parser_has_no_finding(self):
        with open(get_unit_tests_scans_path("aqua") / "no_vuln.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_aqua_parser_has_one_finding(self):
        with open(get_unit_tests_scans_path("aqua") / "one_vuln.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2019-14697 - musl (1.1.20-r4) ", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
            self.assertEqual("musl libc through 1.1.23 has an x87 floating-point stack adjustment imbalance, related to the math/i386/ directory. In some cases, use of this library could introduce out-of-bounds writes that are not present in an application's source code.", finding.description)
            self.assertEqual("1.1.20-r5", finding.mitigation)
            self.assertEqual("\nhttps://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-14697", finding.references)
            self.assertEqual("musl", finding.component_name)
            self.assertEqual("1.1.20-r4", finding.component_version)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-14697", finding.unsaved_vulnerability_ids[0])

    def test_aqua_parser_has_many_findings(self):
        with open(get_unit_tests_scans_path("aqua") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(24, len(findings))

    def test_aqua_parser_v2_has_one_finding(self):
        with open(get_unit_tests_scans_path("aqua") / "one_v2.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2019-15601: curl", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CURL before 7.68.0 lacks proper input validation, which allows users to create a `FILE:` URL that can make the client access a remote file using SMB (Windows-only issue).", finding.description)
            self.assertEqual("Upgrade to curl 7.68.0", finding.mitigation)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-15601", finding.unsaved_vulnerability_ids[0])

    def test_aqua_parser_v2_has_many_findings(self):
        with open(get_unit_tests_scans_path("aqua") / "many_v2.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_aqua_parser_cvssv3_has_no_finding(self):
        with open(get_unit_tests_scans_path("aqua") / "many_v2.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nb_cvssv3 = 0
            for finding in findings:
                if finding.cvssv3 is not None:
                    nb_cvssv3 = nb_cvssv3 + 1

            self.assertEqual(0, nb_cvssv3)

    def test_aqua_parser_cvssv3_has_many_findings(self):
        with open(get_unit_tests_scans_path("aqua") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nb_cvssv3 = 0
            for finding in findings:
                if finding.cvssv3 is not None:
                    nb_cvssv3 = nb_cvssv3 + 1

            self.assertEqual(16, nb_cvssv3)

    def test_aqua_parser_for_aqua_severity(self):
        with open(get_unit_tests_scans_path("aqua") / "vulns_with_aqua_severity.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            sevs = []

            for finding in findings:
                sevs.append(finding.severity)

            d = Counter(sevs)
            self.assertEqual(1, d["Critical"])
            self.assertEqual(1, d["High"])
            self.assertEqual(2, d["Medium"])
            self.assertEqual(2, d["Low"])
            self.assertEqual(7, d["Info"])

    def test_aqua_parser_issue_10585(self):
        with open(get_unit_tests_scans_path("aqua") / "issue_10585.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_aqua_parser_aqua_devops_issue_10611(self):
        with open(get_unit_tests_scans_path("aqua") / "aqua_devops_issue_10611.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(101, len(findings))
            self.assertEqual("server.key - server.key (/juice-shop/node_modules/node-gyp/test/fixtures/server.key) ", findings[83].title)

    def test_aqua_parser_aqua_devops_issue_10849(self):
        with open(get_unit_tests_scans_path("aqua") / "issue_10849.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0.0006, findings[0].epss_score)
            self.assertEqual(0.23474, findings[0].epss_percentile)

    def test_aqua_parser_aqua_devops_empty(self):
        with open(get_unit_tests_scans_path("aqua") / "empty_aquadevops.json", encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))
