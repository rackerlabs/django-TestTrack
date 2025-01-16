from datetime import datetime

from dojo.models import Test
from dojo.tools.gitlab_container_scan.parser import GitlabContainerScanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGitlabContainerScanParser(DojoTestCase):
    def test_gitlab_container_scan_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("gitlab_container_scan") / "gl-container-scanning-report-0-vuln.json", encoding="utf-8") as testfile:
            parser = GitlabContainerScanParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_gitlab_container_scan_parser_with_one_vuln_has_one_findings_v14(self):
        with open(get_unit_tests_scans_path("gitlab_container_scan") / "gl-container-scanning-report-1-vuln_v14.json", encoding="utf-8") as testfile:
            parser = GitlabContainerScanParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        first_finding = findings[0]
        self.assertEqual(datetime(2021, 4, 14, 19, 46, 18), first_finding.date)
        self.assertEqual("CVE-2019-3462 in apt-1.4.8", first_finding.title)
        self.assertEqual("apt", first_finding.component_name)
        self.assertEqual("1.4.8", first_finding.component_version)
        self.assertEqual(1, len(first_finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-3462", first_finding.unsaved_vulnerability_ids[0])
        self.assertEqual("High", first_finding.severity)
        self.assertEqual("Upgrade apt from 1.4.8 to 1.4.9", first_finding.mitigation)
        self.assertEqual("df52bc8ce9a2ae56bbcb0c4ecda62123fbd6f69b", first_finding.unique_id_from_tool)

    def test_gitlab_container_scan_parser_with_one_vuln_has_one_findings_v15(self):
        with open(get_unit_tests_scans_path("gitlab_container_scan") / "gl-container-scanning-report-1-vuln_v15.json", encoding="utf-8") as testfile:
            parser = GitlabContainerScanParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        first_finding = findings[0]
        self.assertEqual(datetime(2021, 4, 14, 19, 46, 18), first_finding.date)
        self.assertEqual("CVE-2019-3462 in apt-1.4.8", first_finding.title)
        self.assertEqual("apt", first_finding.component_name)
        self.assertEqual("1.4.8", first_finding.component_version)
        self.assertEqual(1, len(first_finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-3462", first_finding.unsaved_vulnerability_ids[0])
        self.assertEqual("High", first_finding.severity)
        self.assertEqual("Upgrade apt from 1.4.8 to 1.4.9", first_finding.mitigation)
        self.assertEqual("df52bc8ce9a2ae56bbcb0c4ecda62123fbd6f69b", first_finding.unique_id_from_tool)

    def test_gitlab_container_scan_parser_with_five_vuln_has_five_findings_v14(self):
        with open(get_unit_tests_scans_path("gitlab_container_scan") / "gl-container-scanning-report-5-vuln_v14.json", encoding="utf-8") as testfile:
            parser = GitlabContainerScanParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))

    def test_gitlab_container_scan_parser_with_five_vuln_has_five_findings_v15(self):
        with open(get_unit_tests_scans_path("gitlab_container_scan") / "gl-container-scanning-report-5-vuln_v15.json", encoding="utf-8") as testfile:
            parser = GitlabContainerScanParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))

    def test_gitlab_container_scan_parser_with_fless_data_v14(self):
        with open(get_unit_tests_scans_path("gitlab_container_scan") / "issue6639_v14.json", encoding="utf-8") as testfile:
            parser = GitlabContainerScanParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(98, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertIsNone(finding.date)
            self.assertEqual("busybox: remote attackers may execute arbitrary code if netstat is used", finding.title)
            self.assertEqual("busybox", finding.component_name)
            self.assertEqual("1.34.1-r4", finding.component_version)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-28391", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("Upgrade busybox to 1.34.1-r5", finding.mitigation)
            self.assertEqual("CVE-2022-28391", finding.unique_id_from_tool)

        with self.subTest(i=50):
            finding = findings[50]
            self.assertIsNone(finding.date)
            self.assertEqual(
                "openssl: Infinite loop in BN_mod_sqrt() reachable when parsing certificates", finding.title,
            )
            self.assertEqual("libretls", finding.component_name)
            self.assertEqual("3.3.4-r2", finding.component_version)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-0778", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("High", finding.severity)
            self.assertEqual("Upgrade libretls to 3.3.4-r3", finding.mitigation)
            self.assertEqual("CVE-2022-0778", finding.unique_id_from_tool)

    def test_gitlab_container_scan_parser_with_fless_data_v15(self):
        with open(get_unit_tests_scans_path("gitlab_container_scan") / "issue6639_v15.json", encoding="utf-8") as testfile:
            parser = GitlabContainerScanParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(98, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertIsNone(finding.date)
            self.assertEqual("CVE-2022-28391 in busybox-1.34.1-r4", finding.title)
            self.assertEqual("busybox", finding.component_name)
            self.assertEqual("1.34.1-r4", finding.component_version)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-28391", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("Upgrade busybox to 1.34.1-r5", finding.mitigation)
            self.assertEqual("CVE-2022-28391", finding.unique_id_from_tool)

        with self.subTest(i=50):
            finding = findings[50]
            self.assertIsNone(finding.date)
            self.assertEqual("CVE-2022-0778 in libretls-3.3.4-r2", finding.title)
            self.assertEqual("libretls", finding.component_name)
            self.assertEqual("3.3.4-r2", finding.component_version)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-0778", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("High", finding.severity)
            self.assertEqual("Upgrade libretls to 3.3.4-r3", finding.mitigation)
            self.assertEqual("CVE-2022-0778", finding.unique_id_from_tool)
