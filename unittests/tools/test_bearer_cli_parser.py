from django.test import TestCase

from dojo.models import Test
from dojo.tools.bearer_cli.parser import BearerCLIParser, get_unit_tests_scans_path


class TestBearerParser(TestCase):

    def test_bearer_parser_with_one_vuln_has_one_findings(self):
        testfile = open(get_unit_tests_scans_path("bearer_cli") / "bearer_cli_one_vul.json", encoding="utf-8")
        parser = BearerCLIParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)
        self.assertEqual("79", findings[0].cwe)
        self.assertEqual("Unsanitized user input in dynamic HTML insertion (XSS) in js/adminer/editing.js:581", findings[0].title)
        self.assertEqual("javascript_lang_dangerous_insert_html", findings[0].vuln_id_from_tool)
        self.assertEqual("https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html", findings[0].references)
        self.assertEqual("js/adminer/editing.js", findings[0].file_path)
        self.assertEqual(581, findings[0].line)

    def test_bearer_parser_with_many_vuln_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path("bearer_cli") / "bearer_cli_many_vul.json", encoding="utf-8")
        parser = BearerCLIParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
