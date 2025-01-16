from dojo.models import Test
from dojo.tools.rubocop.parser import RubocopParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRubocopParser(DojoTestCase):
    def test_parser_empty(self):
        testfile = open(get_unit_tests_scans_path("rubocop") / "empty.json", encoding="utf-8")
        parser = RubocopParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parser_zero_findings(self):
        testfile = open(get_unit_tests_scans_path("rubocop") / "zero_vulns.json", encoding="utf-8")
        parser = RubocopParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parser_one_vuln(self):
        testfile = open(get_unit_tests_scans_path("rubocop") / "one_finding.json", encoding="utf-8")
        parser = RubocopParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Avoid using `Marshal.load`.", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("app/controllers/password_resets_controller.rb", finding.file_path)
            self.assertEqual(6, finding.line)
            self.assertEqual("Security/MarshalLoad", finding.vuln_id_from_tool)

    def test_parser_many_vulns(self):
        testfile = open(get_unit_tests_scans_path("rubocop") / "many_vulns.json", encoding="utf-8")
        parser = RubocopParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(7, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("`File.read` is safer than `IO.read`.", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("fake_app_unsecure/app/main.rb", finding.file_path)
            self.assertEqual(12, finding.line)
            self.assertEqual("Security/IoMethods", finding.vuln_id_from_tool)
        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("fake_app_unsecure/app/main.rb", finding.file_path)
            self.assertEqual(13, finding.line)
            self.assertEqual("Security/IoMethods", finding.vuln_id_from_tool)
        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("fake_app_unsecure/app/main.rb", finding.file_path)
            self.assertEqual(19, finding.line)
            self.assertEqual("Security/JSONLoad", finding.vuln_id_from_tool)
        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("Prefer using `YAML.safe_load` over `YAML.load`.", finding.title)
            self.assertEqual("Medium", finding.severity)
        with self.subTest(i=4):
            finding = findings[4]
            self.assertEqual("The use of `Kernel#open` is a serious security risk.", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("Security/Open", finding.vuln_id_from_tool)
        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("The use of `Kernel#open` is a serious security risk.", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("Security/Open", finding.vuln_id_from_tool)
        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("The use of `URI.open` is a serious security risk.", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("Security/Open", finding.vuln_id_from_tool)
