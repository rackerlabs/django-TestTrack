
from dojo.models import Test
from dojo.tools.trivy_operator.parser import TrivyOperatorParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name):
    return get_unit_tests_scans_path("trivy_operator") / file_name


class TestTrivyOperatorParser(DojoTestCase):

    def test_configauditreport_no_vuln(self):
        with open(sample_path("configauditreport_no_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 0)

    def test_configauditreport_single_vulns(self):
        with open(sample_path("configauditreport_single_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("AVD-KSV-0014", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("KSV014 - Root file system is not read-only", finding.title)

    def test_configauditreport_many_vulns(self):
        with open(sample_path("configauditreport_many.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 13)
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("AVD-KSV-0014", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("KSV014 - Root file system is not read-only", finding.title)
            finding = findings[1]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("AVD-KSV-0016", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("KSV016 - Memory requests not specified", finding.title)

    def test_vulnerabilityreport_no_vuln(self):
        with open(sample_path("vulnerabilityreport_no_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 0)

    def test_vulnerabilityreport_single_vulns(self):
        with open(sample_path("vulnerabilityreport_single_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2023-23914", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-2023-23914 curl 7.87.0-r1", finding.title)
            self.assertEqual("7.87.0-r2", finding.mitigation)
            self.assertEqual(4.2, finding.cvssv3_score)

    def test_vulnerabilityreport_many(self):
        with open(sample_path("vulnerabilityreport_many.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 41)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2023-23914", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-2023-23914 curl 7.87.0-r1", finding.title)
            self.assertEqual("7.87.0-r2", finding.mitigation)
            self.assertEqual(4.2, finding.cvssv3_score)
            finding = findings[1]
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2023-23916", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-2023-23916 curl 7.87.0-r1", finding.title)
            self.assertEqual("7.87.0-r2", finding.mitigation)
            self.assertEqual(6.5, finding.cvssv3_score)

    def test_exposedsecretreport_no_vuln(self):
        with open(sample_path("exposedsecretreport_no_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 0)

    def test_exposedsecretreport_single_vulns(self):
        with open(sample_path("exposedsecretreport_single_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("aws-secret-access-key", finding.references)
            self.assertEqual("root/aws_secret.txt", finding.file_path)
            self.assertEqual("Secret detected in root/aws_secret.txt - AWS Secret Access Key", finding.title)

    def test_exposedsecretreport_many(self):
        with open(sample_path("exposedsecretreport_many.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 2)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("aws-secret-access-key", finding.references)
            self.assertEqual("root/aws_secret.txt", finding.file_path)
            self.assertEqual("Secret detected in root/aws_secret.txt - AWS Secret Access Key", finding.title)
            finding = findings[1]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("github-pat", finding.references)
            self.assertEqual("root/github_secret.txt", finding.file_path)
            self.assertEqual("Secret detected in root/github_secret.txt - GitHub Personal Access Token", finding.title)

    def test_vulnerabilityreport_extended(self):
        with open(sample_path("vulnerabilityreport_extended.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 5)
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2024-0553", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-2024-0553 libgnutls30 3.6.13-2ubuntu1.9", finding.title)
            self.assertEqual("3.6.13-2ubuntu1.10", finding.mitigation)
            self.assertEqual(5.9, finding.cvssv3_score)
            self.assertEqual("ubuntu:20.04 (ubuntu 20.04)", finding.file_path)
            self.assertEqual("lbc, os-pkgs, ubuntu", str(finding.tags))

    def test_cis_benchmark(self):
        with open(sample_path("cis_benchmark.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 795)
            finding = findings[0]
            self.assertEqual("5.1.2 AVD-KSV-0041 /clusterrole-admin", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("AVD-KSV-0041", finding.unsaved_vulnerability_ids[0])
            finding = findings[40]
            self.assertEqual("5.2.2 AVD-KSV-0017 kube-system/daemonset-csi-azuredisk-node", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("AVD-KSV-0017", finding.unsaved_vulnerability_ids[0])
            finding = findings[150]
            self.assertEqual("5.2.7 AVD-KSV-0012 opentelemetry-demo/replicaset-opentelemetry-demo-frauddetectionservice-6c6c4b7994", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("AVD-KSV-0012", finding.unsaved_vulnerability_ids[0])

    def test_findings_in_list(self):
        with open(sample_path("findings_in_list.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 18)

    def test_findings_all_reports_in_dict(self):
        with open(sample_path("all_reports_in_dict.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 43)

    def test_findings_clustercompliancereport(self):
        with open(sample_path("clustercompliancereport.json"), encoding="utf-8") as test_file:
            parser = TrivyOperatorParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 2)
