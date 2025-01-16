from dojo.models import Test
from dojo.tools.semgrep.parser import SemgrepParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSemgrepParser(DojoTestCase):

    def test_parse_empty(self):
        with open(get_unit_tests_scans_path("semgrep") / "empty.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with open(get_unit_tests_scans_path("semgrep") / "one_finding.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02194.java", finding.file_path)
            self.assertEqual(64, finding.line)
            self.assertEqual(696, finding.cwe)
            self.assertEqual('javax crypto Cipher.getInstance("AES/GCM/NoPadding");', finding.mitigation)
            self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)
            self.assertIn('javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");', finding.description)
            self.assertIn("Using CBC with PKCS5Padding is susceptible to padding orcale attacks", finding.description)

    def test_parse_many_finding(self):
        with open(get_unit_tests_scans_path("semgrep") / "many_findings.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02194.java", finding.file_path)
            self.assertEqual(64, finding.line)
            self.assertEqual(696, finding.cwe)
            self.assertEqual('javax crypto Cipher.getInstance("AES/GCM/NoPadding");', finding.mitigation)
            self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)
            finding = findings[2]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01150.java", finding.file_path)
            self.assertEqual(66, finding.line)
            self.assertEqual(696, finding.cwe)
            self.assertEqual('javax crypto Cipher.getInstance("AES/GCM/NoPadding");', finding.mitigation)
            self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)

    def test_parse_repeated_finding(self):
        with open(get_unit_tests_scans_path("semgrep") / "repeated_findings.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01150.java", finding.file_path)
            self.assertEqual(66, finding.line)
            self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)
            self.assertEqual(696, finding.cwe)
            self.assertEqual('javax crypto Cipher.getInstance("AES/GCM/NoPadding");', finding.mitigation)
            self.assertEqual(2, finding.nb_occurences)

    def test_parse_many_vulns(self):
        with open(get_unit_tests_scans_path("semgrep") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(48, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("tasks.py", finding.file_path)
            self.assertEqual(186, finding.line)
            self.assertIsNone(finding.mitigation)
            self.assertEqual("python.lang.correctness.tempfile.flush.tempfile-without-flush", finding.vuln_id_from_tool)
            finding = findings[2]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("utils.py", finding.file_path)
            self.assertEqual(503, finding.line)
            self.assertEqual("python.lang.maintainability.useless-ifelse.useless-if-conditional", finding.vuln_id_from_tool)
            finding = findings[4]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("tools/sslyze/parser_xml.py", finding.file_path)
            self.assertEqual(124, finding.line)
            self.assertEqual(327, finding.cwe)
            self.assertEqual("python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5", finding.vuln_id_from_tool)
            finding = findings[37]
            self.assertEqual("High", finding.severity)
            self.assertEqual("management/commands/csv_findings_export.py", finding.file_path)
            self.assertEqual(33, finding.line)
            self.assertEqual(1236, finding.cwe)
            self.assertEqual("python.lang.security.unquoted-csv-writer.unquoted-csv-writer", finding.vuln_id_from_tool)

    def test_parse_cwe_list(self):
        with open(get_unit_tests_scans_path("semgrep") / "cwe_list.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("index.js", finding.file_path)
            self.assertEqual(12, finding.line)
            self.assertEqual(352, finding.cwe)
            self.assertEqual("javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage", finding.vuln_id_from_tool)
            self.assertIn("const app = express();", finding.description)
            self.assertIn("A CSRF middleware was not detected in your express application. Ensure you are either using one  such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.", finding.description)

    def test_different_lines_same_fingerprint(self):
        with open(get_unit_tests_scans_path("semgrep") / "semgrep_version_1_30_0_line_26.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings_first = parser.get_findings(testfile, Test())
            with open(get_unit_tests_scans_path("semgrep") / "semgrep_version_1_30_0_line_27.json", encoding="utf-8") as testfile2:
                parser = SemgrepParser()
                findings_second = parser.get_findings(testfile2, Test())
                self.assertEqual(len(findings_first), len(findings_second))
                for first, second in zip(findings_first, findings_second):
                    self.assertEqual(first.unique_id_from_tool, second.unique_id_from_tool)

    def test_parse_issue_8435(self):
        with open(get_unit_tests_scans_path("semgrep") / "issue_8435.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_low_medium_high_severity(self):
        with open(get_unit_tests_scans_path("semgrep") / "high-medium-low-severities.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_parse_sca_deployments_vulns(self):
        with open(get_unit_tests_scans_path("semgrep") / "sca-deployments-vulns.json", encoding="utf-8") as testfile:
            parser = SemgrepParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(18, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("requirements3.txt", finding.file_path)
            self.assertEqual("222", finding.line)
            self.assertEqual(617, finding.cwe)
