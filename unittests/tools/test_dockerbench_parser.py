from dojo.models import Test
from dojo.tools.dockerbench.parser import DockerBenchParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDockerBenchParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("dockerbench") / "docker-bench-report-zero-vulns.json", encoding="utf-8",
        ) as testfile:
            parser = DockerBenchParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(
            get_unit_tests_scans_path("dockerbench") / "docker-bench-report-single-vuln.json", encoding="utf-8",
        ) as testfile:
            parser = DockerBenchParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("2.11", finding.unique_id_from_tool)
            self.assertIn("2.11 -", finding.title)
            self.assertIn("some kind of remediation could be here", finding.mitigation)
            self.assertIn("Ensure base device size is not changed until needed", finding.description)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(
            get_unit_tests_scans_path("dockerbench") / "docker-bench-report-many-vulns.json", encoding="utf-8",
        ) as testfile:
            parser = DockerBenchParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 50)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "CRITICAL"), 0)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "HIGH"), 32)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "LOW"), 16)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "INFO"), 2)

            finding = findings[3]
            self.assertEqual("High", finding.severity)
            self.assertEqual("1.1.4", finding.unique_id_from_tool)
            self.assertIn("1.1.4 -", finding.title)
            self.assertIn("Ensure auditing is configured for Docker files and directories -/run/containerd (Automated)", finding.description)
            self.assertIn("Install auditd. Add -a exit,always -F path=/run/containerd -F perm=war -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.", finding.mitigation)
            self.assertIn("Audit can generate large log files. So you need to make sure that they are rotated and archived periodically. Create a separate partition for audit logs to avoid filling up other critical partitions.", finding.mitigation)

            finding = findings[27]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("2.18", finding.unique_id_from_tool)
            self.assertIn("2.18 -", finding.title)
            self.assertIn("Ensure that experimental features are not implemented in production (Scored)", finding.description)
            self.assertIn("You should not pass --experimental as a runtime parameter to the Docker daemon on production systems.", finding.mitigation)
            self.assertIn("mitigation impact: None.", finding.mitigation)

            finding = findings[39]
            self.assertEqual("Info", finding.severity)
            self.assertEqual("4.5", finding.unique_id_from_tool)
            self.assertIn("4.5 -", finding.title)
            self.assertIn("Ensure Content trust for Docker is Enabled (Automated)", finding.description)
            self.assertIn("Add DOCKER_CONTENT_TRUST variable to the /etc/environment file using command echo DOCKER_CONTENT_TRUST=1 | sudo tee -a /etc/environment.", finding.mitigation)
            self.assertIn("This prevents users from working with tagged images unless they contain a signature.", finding.mitigation)
