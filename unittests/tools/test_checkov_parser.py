from dojo.models import Test
from dojo.tools.checkov.parser import CheckovParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCheckovParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("checkov") / "checkov-report-0-vuln.json", encoding="utf-8") as testfile:
            parser = CheckovParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_no_vuln_has_no_findings_v2(self):
        with open(get_unit_tests_scans_path("checkov") / "checkov2-report-0-vuln.json", encoding="utf-8") as testfile:
            parser = CheckovParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(get_unit_tests_scans_path("checkov") / "checkov-report-1-vuln.json", encoding="utf-8") as testfile:
            parser = CheckovParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(get_unit_tests_scans_path("checkov") / "checkov-report-many-vuln.json", encoding="utf-8") as testfile:
            parser = CheckovParser()
            findings = parser.get_findings(testfile, Test())
            self.assertGreater(len(findings), 2)

    def test_parse_file_with_multiple_check_type_has_multiple_check_type(self):
        with open(get_unit_tests_scans_path("checkov") / "checkov-report-multiple-check_type.json", encoding="utf-8") as testfile:
            parser = CheckovParser()
            findings = parser.get_findings(testfile, Test())

            # Number of findings
            self.assertEqual(13, len(findings))
            terraform_findings_amount = 0
            dockerfile_findings_amount = 0
            for finding in findings:
                if "Check Type: terraform" in finding.description:
                    terraform_findings_amount += 1
                elif "Check Type: dockerfile" in finding.description:
                    dockerfile_findings_amount += 1
            self.assertEqual(11, terraform_findings_amount)
            self.assertEqual(2, dockerfile_findings_amount)

            # Terraform
            first_terraform_finding = findings[0]
            self.assertEqual("Medium", first_terraform_finding.severity)
            self.assertEqual(
                "Check Type: terraform\n"
                "Check Id: CKV_AWS_161\n"
                "Ensure RDS database has IAM authentication enabled\n",
                first_terraform_finding.description,
            )
            self.assertEqual("/aws/db-app.tf", first_terraform_finding.file_path)
            self.assertEqual(1, first_terraform_finding.line)
            self.assertEqual("aws_db_instance.default", first_terraform_finding.component_name)
            self.assertEqual("", first_terraform_finding.mitigation)
            self.assertEqual("", first_terraform_finding.references)

            # Dockerfile
            first_dockerfile_finding = findings[11]
            self.assertEqual("Medium", first_dockerfile_finding.severity)
            self.assertEqual(
                "Check Type: dockerfile\n"
                "Check Id: CKV_DOCKER_3\n"
                "Ensure that a user for the container has been created\n",
                first_dockerfile_finding.description,
            )
            self.assertEqual("/aws/resources/Dockerfile", first_dockerfile_finding.file_path)
            self.assertEqual(0, first_dockerfile_finding.line)
            self.assertEqual("/aws/resources/Dockerfile.", first_dockerfile_finding.component_name)
            self.assertEqual("", first_dockerfile_finding.mitigation)
            self.assertEqual(
                "https://docs.bridgecrew.io/docs/ensure-that-a-user-for-the-container-has-been-created",
                first_dockerfile_finding.references,
            )

    def test_parse_file_with_specified_severity(self):
        with open(get_unit_tests_scans_path("checkov") / "checkov-report-severity.json", encoding="utf-8") as testfile:
            parser = CheckovParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            self.assertEqual("Medium", findings[0].severity)
            self.assertEqual("Medium", findings[1].severity)
            self.assertEqual("Low", findings[2].severity)
            self.assertEqual("High", findings[3].severity)
