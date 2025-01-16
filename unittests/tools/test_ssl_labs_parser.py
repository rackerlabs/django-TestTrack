from dojo.models import Test
from dojo.tools.ssl_labs.parser import SslLabsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSslLabsParser(DojoTestCase):
    def test_parse_none(self):
        parser = SslLabsParser()
        with open(get_unit_tests_scans_path("ssl_labs") / "none.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(0, len(findings))

    def test_parse_ok(self):
        parser = SslLabsParser()
        with open(get_unit_tests_scans_path("ssl_labs") / "ssl_labs_ok_v1.5.0.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'A+' for defectdojo.mevitae.com")
        self.assertEqual(findings[0].unsaved_endpoints[0].host, "defectdojo.mevitae.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Info")
        self.assertIn("TLS", findings[0].description)

    def test_parse_dh1024(self):
        parser = SslLabsParser()
        with open(get_unit_tests_scans_path("ssl_labs") / "ssl_labs_dh1024_v1.5.0.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'B' for dh1024.badssl.com")
        self.assertEqual(len(findings[0].unsaved_endpoints), 3)
        self.assertEqual(findings[0].unsaved_endpoints[0].host, "dh1024.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Medium")
        self.assertIn("TLS", findings[0].description)

    def test_parse_3des(self):
        parser = SslLabsParser()
        with open(get_unit_tests_scans_path("ssl_labs") / "ssl_labs_3des_v1.5.0.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'C' for 3des.badssl.com")
        self.assertEqual(len(findings[0].unsaved_endpoints), 3)
        self.assertEqual(findings[0].unsaved_endpoints[0].host, "3des.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "High")
        self.assertIn("TLS", findings[0].description)

    def test_parse_revoked(self):
        parser = SslLabsParser()
        with open(get_unit_tests_scans_path("ssl_labs") / "ssl_labs_revoked_v1.5.0.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'T' for revoked.badssl.com")
        self.assertEqual(len(findings[0].unsaved_endpoints), 3)
        self.assertEqual(findings[0].unsaved_endpoints[0].host, "revoked.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Critical")
        self.assertIn("TLS", findings[0].description)

    def test_parse_multiple(self):
        parser = SslLabsParser()
        with open(get_unit_tests_scans_path("ssl_labs") / "ssl_labs_multiple_v1.5.0.json", encoding="utf-8") as test_file:
            findings = parser.get_findings(test_file, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))

        # Track the results we've found
        foundInfo = False
        foundMedium = False
        foundCritical = False

        for finding in findings:
            self.assertIn("TLS", finding.description)
            self.assertEqual(finding.cwe, 310)
            if finding.severity == "Info":
                self.assertEqual(finding.title, "TLS Grade 'A+' for defectdojo.mevitae.com")
                self.assertEqual(len(finding.unsaved_endpoints), 4)
                self.assertEqual(finding.unsaved_endpoints[0].host, "defectdojo.mevitae.com")
                foundInfo = True
            elif finding.severity == "Medium":
                self.assertEqual(finding.title, "TLS Grade 'B' for dh1024.badssl.com")
                self.assertEqual(len(finding.unsaved_endpoints), 3)
                self.assertEqual(finding.unsaved_endpoints[0].host, "dh1024.badssl.com")
                foundMedium = True
            elif finding.severity == "Critical":
                self.assertEqual(finding.title, "TLS Grade 'T' for revoked.badssl.com")
                self.assertEqual(len(finding.unsaved_endpoints), 3)
                self.assertEqual(finding.unsaved_endpoints[0].host, "revoked.badssl.com")
                foundCritical = True
            else:
                self.fail("unexpected finding result")

        self.assertTrue(foundInfo and foundMedium and foundCritical)
