from dojo.models import Test
from dojo.tools.php_symfony_security_check.parser import PhpSymfonySecurityCheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPhpSymfonySecurityCheckerParser(DojoTestCase):

    def test_php_symfony_security_check_parser_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_scans_path("php_symfony_security_check") / "php_symfony_no_vuln.json", encoding="utf-8",
        )
        parser = PhpSymfonySecurityCheckParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        items = findings
        self.assertEqual(0, len(items))

    def test_php_symfony_security_check_parser_with_one_criticle_vuln_has_one_findings(
        self,
    ):
        testfile = open(
            get_unit_tests_scans_path("php_symfony_security_check") / "php_symfony_one_vuln.json", encoding="utf-8",
        )
        parser = PhpSymfonySecurityCheckParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_php_symfony_security_check_parser_with_many_vuln_has_many_findings(self):
        testfile = open(
            get_unit_tests_scans_path("php_symfony_security_check") / "php_symfony_many_vuln.json", encoding="utf-8",
        )
        parser = PhpSymfonySecurityCheckParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        items = findings
        self.assertEqual(8, len(items))
        self.assertEqual("symfony/cache", items[0].component_name)
        self.assertEqual("3.4.16", items[0].component_version)
        self.assertEqual(1, len(items[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-10912", items[0].unsaved_vulnerability_ids[0])
