from dojo.models import Test
from dojo.tools.retirejs.parser import RetireJsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRetireJsParser(DojoTestCase):
    def test_parse(self):
        with open(get_unit_tests_scans_path("retirejs") / "latest.json", encoding="utf-8") as testfile:
            parser = RetireJsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(23, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual(
                    "Quoteless attributes in templates can lead to XSS (handlebars, 3.0.0)",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("handlebars", finding.component_name)
                self.assertEqual("3.0.0", finding.component_version)
                self.assertEqual("/home/damien/dd/.venv/report/scout2-report/inc-handlebars/handlebars-v3.0.0.js", finding.file_path)
            with self.subTest(i=10):
                finding = findings[10]
                self.assertEqual(
                    "XSS in data-container property of tooltip (bootstrap, 3.0.3)",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("bootstrap", finding.component_name)
                self.assertEqual("3.0.3", finding.component_version)
                self.assertEqual("/home/damien/dd/.venv/report/scout2-report/inc-bootstrap/js/bootstrap.min.js", finding.file_path)
            with self.subTest(i=22):
                finding = findings[22]
                self.assertEqual(
                    "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS (jquery, 1.8.0)",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("jquery", finding.component_name)
                self.assertEqual("1.8.0", finding.component_version)
                self.assertEqual("/home/damien/dd/.venv/lib/python3.9/site-packages/tastypie_swagger/static/tastypie_swagger/js/lib/jquery-1.8.0.min.js", finding.file_path)
