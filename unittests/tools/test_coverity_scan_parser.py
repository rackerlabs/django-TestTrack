from dojo.models import Test
from dojo.tools.coverity_scan.parser import CoverityScanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

SCANS_PATH = get_unit_tests_scans_path("coverity_scan")


class TestCoverityScanParser(DojoTestCase):
    def test_parse_no_findings(self):
        with open(SCANS_PATH / "no_vuln.json", encoding="utf-8") as testfile:
            parser = CoverityScanParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with open(SCANS_PATH / "one_vuln.json", encoding="utf-8") as testfile:
            parser = CoverityScanParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("IadeFt-IGhxEGm.yml", finding.file_path)
        self.assertEqual(5, finding.line)
        self.assertEqual(552, finding.cwe)
        self.assertEqual("SIGMA.container_filesystem_write/docker_compose", finding.vuln_id_from_tool)
        self.assertEqual(
            "The docker service container is configured to permit writing to the root filesystem. This makes some security attack vectors such as privilege escalation, denial-of-service or authorization bypass possible since the container instance's filesystem can be tampered with.",
            finding.description,
        )

    def test_parse_many_findings(self):
        with open(SCANS_PATH / "many_vulns.json", encoding="utf-8") as testfile:
            parser = CoverityScanParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(10, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("QeCQIf-GrViGYz.yml", finding.file_path)
            self.assertEqual(5, finding.line)
            self.assertEqual(552, finding.cwe)
            self.assertEqual("SIGMA.container_filesystem_write/docker_compose", finding.vuln_id_from_tool)

        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("High", finding.severity)
            self.assertEqual("JJNYRH-eAmbjhM.yml", finding.file_path)
            self.assertEqual(19, finding.line)
            self.assertEqual(269, finding.cwe)
            self.assertEqual("SIGMA.container_requesting_net_raw/docker_compose", finding.vuln_id_from_tool)

        with self.subTest(i=7):
            finding = findings[7]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("kTYTFN-lPQekQM.yml", finding.file_path)
            self.assertEqual(5, finding.line)
            self.assertEqual(284, finding.cwe)
            self.assertEqual("SIGMA.least_privilege_violation/docker_compose", finding.vuln_id_from_tool)
