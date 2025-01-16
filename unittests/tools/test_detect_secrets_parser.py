import datetime

from dateutil.tz import tzlocal

from dojo.models import Test
from dojo.tools.detect_secrets.parser import DetectSecretsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDetectSecretsParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("detect_secrets") / "no_findings.json", encoding="utf-8") as testfile:
            parser = DetectSecretsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with open(get_unit_tests_scans_path("detect_secrets") / "many_findings.json", encoding="utf-8") as testfile:
            parser = DetectSecretsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Secret Keyword", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(datetime.datetime(2021, 5, 19, 10, 40, 18, tzinfo=tzlocal()), finding.date)
                self.assertFalse(finding.verified)
                self.assertEqual("modules_images", finding.file_path)
                self.assertEqual(151, finding.line)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(798, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertFalse(finding.false_p)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Secret Keyword", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(datetime.datetime(2021, 5, 19, 10, 40, 18, tzinfo=tzlocal()), finding.date)
                self.assertFalse(finding.verified)
                self.assertEqual("modules_images", finding.file_path)
                self.assertEqual(156, finding.line)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(798, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertFalse(finding.false_p)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Secret Keyword", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(datetime.datetime(2021, 5, 19, 10, 40, 18, tzinfo=tzlocal()), finding.date)
                self.assertFalse(finding.verified)
                self.assertEqual("example/pkg/docker_registry_watcher/docker_config.go", finding.file_path)
                self.assertEqual(109, finding.line)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(798, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertFalse(finding.false_p)

            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("Secret Keyword", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(datetime.datetime(2021, 5, 19, 10, 40, 18, tzinfo=tzlocal()), finding.date)
                self.assertFalse(finding.verified)
                self.assertEqual("example/pkg/docker_registry_watcher/docker_registry_watcher.go", finding.file_path)
                self.assertEqual(112, finding.line)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(798, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertTrue(finding.false_p)
