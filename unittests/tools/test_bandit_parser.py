import datetime

from dateutil.tz import tzlocal

from dojo.models import Test
from dojo.tools.bandit.parser import BanditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBanditParser(DojoTestCase):
    def test_bandit_parser_has_no_finding(self):
        with open(get_unit_tests_scans_path("bandit") / "no_vuln.json", encoding="utf-8") as testfile:
            parser = BanditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_bandit_parser_has_one_finding(self):
        with open(get_unit_tests_scans_path("bandit") / "one_vuln.json", encoding="utf-8") as testfile:
            parser = BanditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                item = findings[0]
                self.assertEqual(
                    "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
                    item.title,
                )
                self.assertEqual(datetime.datetime(2020, 12, 30, 10, 3, 39, tzinfo=tzlocal()), item.date)
                self.assertEqual("Low", item.severity)
                self.assertEqual("one/one.py", item.file_path)
                self.assertEqual("assert_used:B101", item.vuln_id_from_tool)
                self.assertEqual("Certain", item.get_scanner_confidence_text())
                self.assertIn("https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html", item.references)

    def test_bandit_parser_has_many_findings(self):
        with open(get_unit_tests_scans_path("bandit") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = BanditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(214, len(findings))
            with self.subTest(i=0):
                item = findings[0]
                self.assertEqual("Try, Except, Pass detected.", item.title)
                self.assertEqual(datetime.datetime(2020, 12, 30, 9, 35, 48, tzinfo=tzlocal()), item.date)
                self.assertEqual("Low", item.severity)
                self.assertEqual("dojo/benchmark\\views.py", item.file_path)
                self.assertEqual("try_except_pass:B110", item.vuln_id_from_tool)
                self.assertEqual("Certain", item.get_scanner_confidence_text())
                self.assertIn("https://bandit.readthedocs.io/en/latest/plugins/b110_try_except_pass.html", item.references)

    def test_bandit_parser_has_many_findings_recent(self):
        with open(get_unit_tests_scans_path("bandit") / "dd.json", encoding="utf-8") as testfile:
            parser = BanditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(47, len(findings))
            with self.subTest(i=0):
                item = findings[0]
                self.assertEqual("Use of insecure MD2, MD4, MD5, or SHA1 hash function.", item.title)
                self.assertEqual(datetime.datetime(2021, 3, 30, 18, 23, 12, tzinfo=tzlocal()), item.date)
                self.assertEqual("Medium", item.severity)
                self.assertEqual("dojo/tools/acunetix/parser.py", item.file_path)
                self.assertEqual("blacklist:B303", item.vuln_id_from_tool)
                self.assertEqual("Certain", item.get_scanner_confidence_text())

    def test_bandit_parser_has_many_findings_recent2(self):
        with open(get_unit_tests_scans_path("bandit") / "dd2.json", encoding="utf-8") as testfile:
            parser = BanditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(165, len(findings))
            with self.subTest(i=0):
                item = findings[0]
                self.assertEqual("Try, Except, Pass detected.", item.title)
                self.assertEqual(datetime.datetime(2021, 10, 3, 12, 53, 18, tzinfo=tzlocal()), item.date)
                self.assertEqual("Low", item.severity)
                self.assertEqual("dojo/benchmark/views.py", item.file_path)
                self.assertEqual("try_except_pass:B110", item.vuln_id_from_tool)
                self.assertEqual("Certain", item.get_scanner_confidence_text())
            with self.subTest(i=50):
                item = findings[50]
                self.assertEqual(
                    "Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.", item.title,
                )
                self.assertEqual(datetime.datetime(2021, 10, 3, 12, 53, 18, tzinfo=tzlocal()), item.date)
                self.assertEqual("Medium", item.severity)
                self.assertEqual("dojo/reports/widgets.py", item.file_path)
                self.assertEqual("blacklist:B308", item.vuln_id_from_tool)
                self.assertEqual("Certain", item.get_scanner_confidence_text())
            with self.subTest(i=100):
                item = findings[100]
                self.assertEqual("Potential XSS on mark_safe function.", item.title)
                self.assertEqual(datetime.datetime(2021, 10, 3, 12, 53, 18, tzinfo=tzlocal()), item.date)
                self.assertEqual("Medium", item.severity)
                self.assertEqual("dojo/templatetags/display_tags.py", item.file_path)
                self.assertEqual("django_mark_safe:B703", item.vuln_id_from_tool)
                self.assertEqual("Certain", item.get_scanner_confidence_text())
            with self.subTest(i=164):
                item = findings[164]
                self.assertEqual("Possible binding to all interfaces.", item.title)
                self.assertEqual(datetime.datetime(2021, 10, 3, 12, 53, 18, tzinfo=tzlocal()), item.date)
                self.assertEqual("Medium", item.severity)
                self.assertEqual("dojo/wsgi.py", item.file_path)
                self.assertEqual("hardcoded_bind_all_interfaces:B104", item.vuln_id_from_tool)
                self.assertEqual("Firm", item.get_scanner_confidence_text())
