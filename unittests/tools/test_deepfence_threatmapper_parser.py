from dojo.models import Test
from dojo.tools.deepfence_threatmapper.parser import DeepfenceThreatmapperParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDeepfenceThreatmapperParser(DojoTestCase):

    def test_parse_file_compliance_report(self):
        with open(get_unit_tests_scans_path("deepfence_threatmapper") / "compliance_report.xlsx", "rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            self.assertEqual(findings[0].title, "Threatmapper_Compliance_Report-gdpr_3.6")
            self.assertEqual(findings[0].severity, "Info")

    def test_parse_file_malware_report(self):
        with open(get_unit_tests_scans_path("deepfence_threatmapper") / "malware_report.xlsx", "rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            self.assertEqual(findings[0].title, "MD5_Constants")
            self.assertEqual(findings[0].severity, "Low")
            self.assertEqual(findings[0].file_path, "/tmp/Deepfence/YaraHunter/df_db09257b02e615049e0aecc05be2dc2401735e67db4ab74225df777c62c39753/usr/sbin/mkfs.cramfs")

    def test_parse_file_secret_report(self):
        with open(get_unit_tests_scans_path("deepfence_threatmapper") / "secret_report.xlsx", "rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            self.assertEqual(findings[0].title, "Username and password in URI")
            self.assertEqual(findings[0].severity, "High")
            self.assertEqual(findings[0].file_path, "usr/share/doc/curl-8.3.0/TheArtOfHttpScripting.md")

    def test_parse_file_vulnerability_report(self):
        with open(get_unit_tests_scans_path("deepfence_threatmapper") / "vulnerability_report.xlsx", "rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            self.assertEqual(findings[0].title, "Threatmapper_Vuln_Report-CVE-2021-36084")
            self.assertEqual(findings[0].severity, "Low")
            self.assertEqual(findings[0].mitigation, "2.5-10.amzn2.0.1")
            self.assertEqual(findings[0].cve, "CVE-2021-36084")
