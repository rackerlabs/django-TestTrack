from dojo.models import Test
from dojo.tools.php_security_audit_v2.parser import PhpSecurityAuditV2Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPhpSecurityAuditV2ParserParser(DojoTestCase):

    def test_php_symfony_security_check_parser_with_no_vuln_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path("php_security_audit_v2") / "php_security_audit_v2.0.0_unformatted.json", encoding="utf-8")
        parser = PhpSecurityAuditV2Parser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        items = findings
        self.assertEqual(2, len(items))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("/Applications/MAMP/htdocs/wordpress/wp-content/themes/twentyseventeen/inc/icon-functions.php", finding.file_path)
        self.assertEqual(19, finding.line)
        finding = findings[1]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("/Applications/MAMP/htdocs/wordpress/wp-content/themes/twentyseventeen/index.php", finding.file_path)
        self.assertEqual(35, finding.line)

    def test_php_symfony_security_check_parser_with_many_vuln(self):
        """New report with latest version"""
        testfile = open(get_unit_tests_scans_path("php_security_audit_v2") / "many_vulns.json", encoding="utf-8")
        parser = PhpSecurityAuditV2Parser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        items = findings
        self.assertEqual(908, len(items))
        finding = findings[0]
        self.assertEqual("Security.Misc.TypeJuggle.TypeJuggle", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("/home/xcvb/xfgkfhkhlj/bigbangwp/page-blog-2.php", finding.file_path)
        self.assertEqual(33, finding.line)
        finding = findings[200]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("/home/xcvb/xfgkfhkhlj/bigbangwp/page-blog-6.php", finding.file_path)
        self.assertEqual(53, finding.line)
