from dojo.models import Test
from dojo.tools.tfsec.parser import TFSecParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTFSecParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("tfsec") / "no_findings.json", encoding="utf-8") as testfile:
            parser = TFSecParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding_legacy(self):
        with open(get_unit_tests_scans_path("tfsec") / "one_finding_legacy.json", encoding="utf-8") as testfile:
            parser = TFSecParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Potentially sensitive data stored in block attribute.", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.active)
                self.assertEqual("Don't include sensitive data in blocks", finding.mitigation)
                self.assertEqual("Block attribute could be leaking secrets", finding.impact)
                self.assertEqual("tfsec-test/identity.tf", finding.file_path)
                self.assertEqual(226, finding.line)
                self.assertEqual("GEN003", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

    def test_parse_many_findings_legacy(self):
        with open(get_unit_tests_scans_path("tfsec") / "many_findings_legacy.json", encoding="utf-8") as testfile:
            parser = TFSecParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Pod security policy enforcement not defined.", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.active)
                self.assertEqual("Use security policies for pods to restrict permissions to those needed to be effective", finding.mitigation)
                self.assertEqual("Pods could be operating with more permissions than required to be effective", finding.impact)
                self.assertEqual("tfsec-test/cluster.tf", finding.file_path)
                self.assertEqual(52, finding.line)
                self.assertEqual("GCP009", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Shielded GKE nodes not enabled.", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.active)
                self.assertEqual("Enable node shielding", finding.mitigation)
                self.assertEqual("Node identity and integrity can't be verified without shielded GKE nodes", finding.impact)
                self.assertEqual("tfsec-test/cluster.tf", finding.file_path)
                self.assertEqual(52, finding.line)
                self.assertEqual("GCP010", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Potentially sensitive data stored in block attribute.", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.active)
                self.assertEqual("Don't include sensitive data in blocks", finding.mitigation)
                self.assertEqual("Block attribute could be leaking secrets", finding.impact)
                self.assertEqual("tfsec-test/identity.tf", finding.file_path)
                self.assertEqual(226, finding.line)
                self.assertEqual("GEN003", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

    def test_parse_many_findings_current(self):
        with open(get_unit_tests_scans_path("tfsec") / "many_findings_current.json", encoding="utf-8") as testfile:
            parser = TFSecParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(13, len(findings))

            finding = findings[0]
            self.assertEqual("An ingress Network ACL rule allows ALL ports.", finding.title)
            self.assertEqual("Critical", finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertTrue(finding.active)
            self.assertEqual("Set specific allowed ports", finding.mitigation)
            self.assertEqual("All ports exposed for egressing data", finding.impact)
            self.assertEqual("/tmp/aws-eks/modules/vpc-subnets/resources.tf", finding.file_path)
            self.assertEqual(155, finding.line)
            self.assertEqual("aws-vpc-no-excessive-port-access", finding.vuln_id_from_tool)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.references)

            severities = {}
            for finding in findings:
                if severities.get(finding.severity):
                    numSeverity = severities.get(finding.severity)
                    numSeverity += 1
                    severities[finding.severity] = numSeverity
                else:
                    severities[finding.severity] = 1
            self.assertEqual(8, severities.get("Critical"))
            self.assertEqual(3, severities.get("High"))
            self.assertEqual(1, severities.get("Medium"))
            self.assertEqual(1, severities.get("Low"))
