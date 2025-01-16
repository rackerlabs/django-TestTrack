from dojo.models import Test
from dojo.tools.gitleaks.parser import GitleaksParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGitleaksParser(DojoTestCase):

    def test_parse_file_legacy_with_no_findings(self):
        with open(get_unit_tests_scans_path("gitleaks") / "no_findings.json", encoding="utf-8") as testfile:
            parser = GitleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_legacy_with_one_finding(self):
        with open(get_unit_tests_scans_path("gitleaks") / "data_one.json", encoding="utf-8") as testfile:
            parser = GitleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Hard Coded Asymmetric Private Key", finding.title)
                self.assertEqual("cert-key.pem", finding.file_path)
                self.assertIsNone(finding.line)  # some old version don't have this data
                self.assertIn("AsymmetricPrivateKey", finding.unsaved_tags)

    def test_parse_file_legacy_with_multiple_finding(self):
        with open(get_unit_tests_scans_path("gitleaks") / "data_many.json", encoding="utf-8") as testfile:
            parser = GitleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Hard Coded Github", finding.title)
                self.assertEqual(".bashrc", finding.file_path)
                self.assertIsNone(finding.line)  # some old version don't have this data
                self.assertIn("Github", finding.unsaved_tags)

    def test_parse_file_legacy_with_multiple_redacted_finding(self):
        with open(get_unit_tests_scans_path("gitleaks") / "redacted_data_many.json", encoding="utf-8") as testfile:
            parser = GitleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

    def test_parse_file_legacy_from_issue4336(self):
        with open(get_unit_tests_scans_path("gitleaks") / "issue4336.json", encoding="utf-8") as testfile:
            parser = GitleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Hard Coded Twitter Client ID", finding.title)
                self.assertEqual("README.md", finding.file_path)
                self.assertEqual(23, finding.line)

    def test_parse_file_from_version_7_5_0(self):
        with open(get_unit_tests_scans_path("gitleaks") / "version_7.5.0.json", encoding="utf-8") as testfile:
            parser = GitleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Hard Coded AWS Access Key", finding.title)
                self.assertEqual("dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_1_vuln.json", finding.file_path)
                self.assertEqual(13, finding.line)
                self.assertIn("key", finding.unsaved_tags)
                self.assertIn("AWS", finding.unsaved_tags)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Hard Coded Asymmetric Private Key", finding.title)
                self.assertEqual("dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln.json", finding.file_path)
                self.assertEqual(13, finding.line)
                self.assertIn("AsymmetricPrivateKey", finding.unsaved_tags)
            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Hard Coded AWS Access Key", finding.title)
                self.assertEqual("dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln.json", finding.file_path)
                self.assertEqual(44, finding.line)
                self.assertIn("AWS", finding.unsaved_tags)
            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("Hard Coded AWS Access Key", finding.title)
                self.assertEqual("dojo/unittests/tools/test_gitlab_secret_detection_report_parser.py", finding.file_path)
                self.assertEqual(37, finding.line)
                self.assertIn("AWS", finding.unsaved_tags)

    def test_parse_file_from_version_8(self):
        with open(get_unit_tests_scans_path("gitleaks") / "gitleaks8_many.json", encoding="utf-8") as testfile:
            parser = GitleaksParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Hard coded AWS found in /conf/aws.tf", finding.title)
                self.assertEqual("/conf/aws.tf", finding.file_path)
                self.assertEqual(2, finding.line)
                self.assertIn("74d53286c550630f80847d37f68aa3065554ac813544072ccd1278da71fafe31", finding.description)
                self.assertIn("9619c91b3fd2998be5d9ce198833d7ac9489d9bc378ad7cd28963d5a967f8699", finding.description)
                self.assertIn("\n**Commit message:** Lorem ipsum dolor sit amet, consetetur sadipscing elitr", finding.description)
                self.assertEqual(2, finding.nb_occurences)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Hard coded RSA private key found in conf/rsa.pk", finding.title)
                description = """**Secret:** -----BEGIN RSA PRIVATE KEY-----
**Match:** -----BEGIN RSA PRIVATE KEY-----
**Rule Id:** RSA-PK"""
                self.assertEqual(description, finding.description)
                self.assertIn("tag1", finding.unsaved_tags)
                self.assertIn("tag2", finding.unsaved_tags)
            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Hard coded Generic API Key found in tests/api.py", finding.title)
                description = """**Secret:** dfjksdjfs3294dfjlsdaf213
**Match:** apikey = "dfjksdjfs3294dfjlsdaf213"
**Commit message:**
```
Lorem ipsum dolor sit amet,
consetetur sadipscing elitr,
sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat,
sed diam voluptua.
```
**Commit hash:** 69235ea9ea4d59e18e2cc3c295526de46aa1365c1f0c7a95a22ff1537acdf517
**Commit date:** 2016-09-16T18:17:59Z
**Rule Id:** generic-api-key"""
                self.assertEqual(description, finding.description)
