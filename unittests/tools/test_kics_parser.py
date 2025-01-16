from dojo.models import Test
from dojo.tools.kics.parser import KICSParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKICSParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("kics") / "no_findings.json", encoding="utf-8") as testfile:
            parser = KICSParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with open(get_unit_tests_scans_path("kics") / "many_findings.json", encoding="utf-8") as testfile:
            parser = KICSParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(18, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Secret Management: Passwords And Secrets In Infrastructure Code", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("Hardcoded secret key should not appear in source", finding.mitigation)
                self.assertEqual("test/charts/example/terraform/main.tf", finding.file_path)
                self.assertEqual(25, finding.line)
                self.assertEqual("Common", finding.component_name)
                description = """Query to find passwords and secrets in infrastructure code.
**Platform:** Common
**Category:** Secret Management
**Issue type:** RedundantAttribute"""
                self.assertEqual(description, finding.description)
                self.assertEqual("https://kics.io/", finding.references)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Access Control: S3 Bucket Access to Any Principal", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("aws_s3_bucket_policy[this].policy.Principal is not equal to, nor does it contain '*'", finding.mitigation)
                self.assertEqual("test/charts/example/terraform/s3.tf", finding.file_path)
                self.assertEqual(36, finding.line)
                self.assertEqual("Terraform", finding.component_name)
                description = """S3 Buckets must not allow Actions From All Principals, as to prevent leaking private information to the entire internet or allow unauthorized data tampering / deletion. This means the 'Effect' must not be 'Allow' when there are All Principals
**Platform:** Terraform
**Category:** Access Control
**Issue type:** IncorrectValue
**Actual value:** aws_s3_bucket_policy[this].policy.Principal is equal to or contains \'*\'"""
                self.assertEqual(description, finding.description)
                self.assertEqual("https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy", finding.references)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Access Control: S3 Bucket Allows Get Action From All Principals", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("aws_s3_bucket_policy[this].policy.Action is not a 'Get' action", finding.mitigation)
                self.assertEqual("test/charts/example/terraform/s3.tf", finding.file_path)
                self.assertEqual(43, finding.line)
                self.assertEqual("Terraform", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("Encryption: S3 Bucket Without Server-side-encryption", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("'aws_s3_bucket.server_side_encryption_configuration' exists", finding.mitigation)
                self.assertEqual("test/charts/example/terraform/s3.tf", finding.file_path)
                self.assertEqual(5, finding.line)
                self.assertEqual("Terraform", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=4):
                finding = findings[4]
                self.assertEqual("Insecure Configurations: S3 Static Website Host Enabled", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("resource.aws_s3_bucket[this].website doesn't have static websites inside", finding.mitigation)
                self.assertEqual("test/charts/example/terraform/s3.tf", finding.file_path)
                self.assertEqual(19, finding.line)
                self.assertEqual("Terraform", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=5):
                finding = findings[5]
                self.assertEqual("Resource Management: CPU Limits Not Set", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("spec.template.spec.containers.name=example has CPU limits", finding.mitigation)
                self.assertEqual("test/charts/example/templates/example.yaml", finding.file_path)
                self.assertEqual(62, finding.line)
                self.assertEqual("Kubernetes", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=6):
                finding = findings[6]
                self.assertEqual("Availability: Liveness Probe Is Not Defined", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("metadata.name={{example}}.spec.containers.name={{example}}.livenessProbe is defined", finding.mitigation)
                self.assertEqual("test/charts/example/templates/example.yaml", finding.file_path)
                self.assertEqual(62, finding.line)
                self.assertEqual("Kubernetes", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=7):
                finding = findings[7]
                self.assertEqual("Observability: S3 Bucket Without Versioning", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("'versioning' is equal 'true'", finding.mitigation)
                self.assertEqual("test/charts/example/terraform/s3.tf", finding.file_path)
                self.assertEqual(5, finding.line)
                self.assertEqual("Terraform", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=8):
                finding = findings[8]
                self.assertEqual("Insecure Configurations: Seccomp Profile Is Not Configured", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("'spec.template.metadata.annotations' is set", finding.mitigation)
                self.assertEqual("test/charts/example/templates/example.yaml", finding.file_path)
                self.assertEqual(19, finding.line)
                self.assertEqual("Kubernetes", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=9):
                finding = findings[9]
                self.assertEqual("Insecure Defaults: Service Account Token Automount Not Disabled", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("'spec.template.spec.automountServiceAccountToken' is false", finding.mitigation)
                self.assertEqual("test/charts/example/templates/example.yaml", finding.file_path)
                self.assertEqual(22, finding.line)
                self.assertEqual("Kubernetes", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=10):
                finding = findings[10]
                self.assertEqual("Best Practices: No Drop Capabilities for Containers", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("metadata.name={{example}}.spec.containers.name=example.securityContext is set", finding.mitigation)
                self.assertEqual("test/charts/example/templates/example.yaml", finding.file_path)
                self.assertEqual(62, finding.line)
                self.assertEqual("Kubernetes", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=11):
                finding = findings[11]
                self.assertEqual("Access Control: Permissive Access to Create Pods", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("metadata.name=example.rules.verbs should not contain a wildcard value when metadata.name=example.rules.resources contains a wildcard value", finding.mitigation)
                self.assertEqual("test/charts/example/templates/rbac.yaml", finding.file_path)
                self.assertEqual(20, finding.line)
                self.assertEqual("Kubernetes", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=12):
                finding = findings[12]
                self.assertEqual("Insecure Configurations: Pod or Container Without Security Context", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("spec.template.spec.containers.name=example has a security context", finding.mitigation)
                self.assertEqual("test/charts/example/templates/example.yaml", finding.file_path)
                self.assertEqual(62, finding.line)
                self.assertEqual("Kubernetes", finding.component_name)
                self.assertIsNotNone(finding.description)
                self.assertEqual(1, finding.nb_occurences)
