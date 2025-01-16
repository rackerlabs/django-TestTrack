

from dojo.models import Test
from dojo.tools.awssecurityhub.parser import AwsSecurityHubParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name: str):
    return get_unit_tests_scans_path("awssecurityhub") / file_name


class TestAwsSecurityHubParser(DojoTestCase):

    def test_one_finding(self):
        with open(sample_path("config_one_finding.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Informational", finding.severity)
            self.assertTrue(finding.is_mitigated)
            self.assertFalse(finding.active)
            self.assertEqual("https://docs.aws.amazon.com/console/securityhub/IAM.5/remediation", finding.references)

    def test_one_finding_active(self):
        with open(sample_path("config_one_finding_active.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.is_mitigated)
            self.assertTrue(finding.active)

    def test_many_findings(self):
        with open(sample_path("config_many_findings.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual(finding.component_name, "AwsAccount")
            self.assertEqual("This is a Security Hub Finding \nThis AWS control checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password.\n**AWS Finding ARN:** arn:aws:securityhub:us-east-1:012345678912:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.5/finding/de861909-2d26-4e45-bd86-19d2ab6ceef1\n**Resource IDs:** AWS::::Account:012345678912\n**AwsAccountId:** 012345678912\n**Generator ID:** aws-foundational-security-best-practices/v/1.0.0/IAM.5\n", finding.description)

    def test_repeated_findings(self):
        with open(sample_path("config_repeated_findings.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))

    def test_unique_id(self):
        with open(sample_path("config_one_finding.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(
                "arn:aws:securityhub:us-east-1:012345678912:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.5/finding/de861909-2d26-4e45-bd86-19d2ab6ceef1",
                findings[0].unique_id_from_tool,
            )

    def test_inspector_ec2(self):
        with open(sample_path("inspector_ec2_cve.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(5, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2022-3643 - kernel - Resource: i-11111111111111111", finding.title)
            self.assertEqual("Resource: i-11111111111111111", finding.impact)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-3643", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("- Update kernel-4.14.301\n\t- yum update kernel\n", finding.mitigation)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("AwsEc2Instance arn:aws:ec2:us-east-1:XXXXXXXXXXXX:i-11111111111111111", endpoint.host)

    def test_inspector_ec2_with_no_vulnerabilities(self):
        with open(sample_path("inspector_ec2_cve_no_vulnerabilities.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(finding.component_name, "AwsEc2Instance")

    def test_inspector_ec2_ghsa(self):
        with open(sample_path("inspector_ec2_ghsa.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.is_mitigated)
            self.assertTrue(finding.active)
            self.assertIn("GHSA-p98r-538v-jgw5", finding.title)
            self.assertSetEqual({"CVE-2023-34256", "GHSA-p98r-538v-jgw5"}, set(finding.unsaved_vulnerability_ids))
            self.assertEqual("https://github.com/bottlerocket-os/bottlerocket/security/advisories/GHSA-p98r-538v-jgw5", finding.references)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("AwsEc2Instance arn:aws:ec2:eu-central-1:012345678912:instance/i-07c11cc535d830123", endpoint.host)

    def test_inspector_ecr(self):
        with open(sample_path("inspector_ecr.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(7, len(findings))

            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertFalse(finding.is_mitigated)
            self.assertTrue(finding.active)
            self.assertEqual("CVE-2023-2650 - openssl - Image: repo-os/sha256:af965ef68c78374a5f987fce98c0ddfa45801df2395bf012c50b863e65978d74", finding.title)
            self.assertIn("repo-os/sha256:af965ef68c78374a5f987fce98c0ddfa45801df2395bf012c50b863e65978d74", finding.impact)
            self.assertIn("Repository: repo-os", finding.impact)
            self.assertEqual(0.0014, finding.epss_score)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("AwsEcrContainerImage arn:aws:ecr:eu-central-1:123456789012:repository/repo-os/sha256:af965ef68c78374a5f987fce98c0ddfa45801df2395bf012c50b863e65978d74", endpoint.host)

    def test_guardduty(self):
        with open(sample_path("guardduty.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(4, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.active)
            finding = findings[3]
            self.assertEqual("Low", finding.severity)
            self.assertTrue(finding.active)
            self.assertEqual("User AssumedRole : 123123123 is anomalously invoking APIs commonly used in Discovery tactics. - Resource: 123123123", finding.title)
            self.assertEqual("TTPs/Discovery/IAMUser-AnomalousBehavior\n[https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)", finding.mitigation)
            endpoint = findings[0].unsaved_endpoints[0]
            self.assertEqual("AwsEc2Instance arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890", endpoint.host)
            self.assertEqual("This is a GuardDuty Finding\nAPIs commonly used in Discovery tactics were invoked by user AssumedRole : 123123123, under anomalous circumstances. Such activity is not typically seen from this user.\n**AWS Finding ARN:** arn:aws:guardduty:us-east-1:123456789012:detector/123456789/finding/2123123123123\n**SourceURL:** [https://us-east-1.console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?macros=current&fId=2123123123123](https://us-east-1.console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?macros=current&fId=2123123123123)\n**AwsAccountId:** 123456789012\n**Region:** us-east-1\n**Generator ID:** arn:aws:guardduty:us-east-1:123456789012:detector/123456789\n", finding.description)

    def test_issue_10956(self):
        with open(sample_path("issue_10956.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("0.00239", finding.epss_score)

    def test_missing_account_id(self):
        with open(sample_path("missing_account_id.json"), encoding="utf-8") as test_file:
            parser = AwsSecurityHubParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
