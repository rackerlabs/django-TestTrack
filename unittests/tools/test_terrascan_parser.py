from dojo.models import Test
from dojo.tools.terrascan.parser import TerrascanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTerrascanParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("terrascan") / "no_findings.json", encoding="utf-8") as testfile:
            parser = TerrascanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with open(get_unit_tests_scans_path("terrascan") / "many_findings.json", encoding="utf-8") as testfile:
            parser = TerrascanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Infrastructure Security: gkeControlPlaneNotPublic", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("cluster.tf", finding.file_path)
                self.assertEqual(52, finding.line)
                self.assertEqual("google_container_cluster/k8s_cluster", finding.component_name)
                self.assertEqual("accurics.gcp.NS.109", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Security Best Practices: autoNodeRepairEnabled", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("cluster.tf", finding.file_path)
                self.assertEqual(14, finding.line)
                self.assertEqual("google_container_node_pool/k8s_cluster_node_pool", finding.component_name)
                self.assertEqual("accurics.gcp.OPS.144", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Infrastructure Security: checkRequireSSLEnabled", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("db.tf", finding.file_path)
                self.assertEqual(5, finding.line)
                self.assertEqual("google_sql_database_instance/master", finding.component_name)
                self.assertEqual("accurics.gcp.EKM.141", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("Logging and Monitoring: stackDriverLoggingEnabled", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("cluster.tf", finding.file_path)
                self.assertEqual(52, finding.line)
                self.assertEqual("google_container_cluster/k8s_cluster", finding.component_name)
                self.assertEqual("accurics.gcp.LOG.100", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=4):
                finding = findings[4]
                self.assertEqual("Logging and Monitoring: stackDriverMonitoringEnabled", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("cluster.tf", finding.file_path)
                self.assertEqual(52, finding.line)
                self.assertEqual("google_container_cluster/k8s_cluster", finding.component_name)
                self.assertEqual("accurics.gcp.MON.143", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=5):
                finding = findings[5]
                self.assertEqual("Security Best Practices: checkRotation365Days", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("vault.tf", finding.file_path)
                self.assertEqual(18, finding.line)
                self.assertEqual("google_kms_crypto_key/crypto_key", finding.component_name)
                self.assertEqual("accurics.gcp.EKM.007", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=6):
                finding = findings[6]
                self.assertEqual("Infrastructure Security: networkPolicyEnabled", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("cluster.tf", finding.file_path)
                self.assertEqual(52, finding.line)
                self.assertEqual("google_container_cluster/k8s_cluster", finding.component_name)
                self.assertEqual("accurics.gcp.NS.103", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=7):
                finding = findings[7]
                self.assertEqual("Security Best Practices: checkRotation90Days", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("vault.tf", finding.file_path)
                self.assertEqual(18, finding.line)
                self.assertEqual("google_kms_crypto_key/crypto_key", finding.component_name)
                self.assertEqual("accurics.gcp.EKM.139", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)

            with self.subTest(i=8):
                finding = findings[8]
                self.assertEqual("Security Best Practices: autoNodeUpgradeEnabled", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual("cluster.tf", finding.file_path)
                self.assertEqual(14, finding.line)
                self.assertEqual("google_container_node_pool/k8s_cluster_node_pool", finding.component_name)
                self.assertEqual("accurics.gcp.OPS.101", finding.vuln_id_from_tool)
                self.assertEqual(1, finding.nb_occurences)
