
from dojo.models import Test
from dojo.tools.osv_scanner.parser import OSVScannerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOSVScannerParser(DojoTestCase):
    def test_no_findings(self):
        with open(get_unit_tests_scans_path("osv_scanner") / "no_findings.json", encoding="utf-8") as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_some_findings(self):
        with open(get_unit_tests_scans_path("osv_scanner") / "some_findings.json", encoding="utf-8") as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(finding.cwe, "CWE-506")
            self.assertEqual(finding.title, "MAL-2023-1035_flot-axis")
            self.assertEqual(finding.cve, None)
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "MAL-2023-1035")
            self.assertEqual(finding.severity, "Low")

    def test_many_findings(self):
        with open(get_unit_tests_scans_path("osv_scanner") / "many_findings.json", encoding="utf-8") as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(66, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "GHSA-25mq-v84q-4j7r_guzzlehttp/guzzle")
            self.assertEqual(finding.cve, None)
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "GHSA-25mq-v84q-4j7r")
            self.assertEqual(finding.severity, "High")
            finding = findings[3]
            self.assertEqual(finding.static_finding, True)
            self.assertEqual(finding.title, "GHSA-q559-8m2m-g699_guzzlehttp/guzzle")
            self.assertEqual(finding.file_path, "/tmpcardmarket-api/composer.lock")
            self.assertEqual(finding.component_name, "guzzlehttp/guzzle")
            finding = findings[17]
            self.assertEqual(finding.references, "https://nvd.nist.gov/vuln/detail/CVE-2021-45115\nhttps://docs.djangoproject.com/en/4.0/releases/security\nhttps://github.com/django/django\nhttps://groups.google.com/forum/#!forum/django-announce\nhttps://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV\nhttps://security.netapp.com/advisory/ntap-20220121-0005\nhttps://www.djangoproject.com/weblog/2022/jan/04/security-releases\n")
            self.assertEqual(finding.title, "GHSA-53qw-q765-4fww_django")
            self.assertEqual(finding.mitigation, "Upgrade to version: 2.2.26")
