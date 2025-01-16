import datetime
import logging

from dojo.models import Test
from dojo.tools.checkmarx_one.parser import CheckmarxOneParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestCheckmarxOneParser(DojoTestCase):

    def test_checkmarx_one_many_vulns(self):
        with open(get_unit_tests_scans_path("checkmarx_one") / "checkmarx_one.json", encoding="utf-8") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(5, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.unique_id_from_tool)
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("Medium", finding_test.severity)
                self.assertEqual("/src/helpers/Constants.ts", finding_test.file_path)

    def test_checkmarx_one_no_findings(self):
        with open(get_unit_tests_scans_path("checkmarx_one") / "no_findings.json", encoding="utf-8") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_checkmarx_one_many_findings(self):
        with open(get_unit_tests_scans_path("checkmarx_one") / "many_findings.json", encoding="utf-8") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.unique_id_from_tool)
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("High", finding_test.severity)
                self.assertEqual("/qe/testharness/Dockerfile", finding_test.file_path)

    def test_checkmarx_one_sca_10770(self):
        with open(get_unit_tests_scans_path("checkmarx_one") / "checkmarx_one_sca_10770.json", encoding="utf-8") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(8, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.unique_id_from_tool)
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("High", finding_test.severity)
                self.assertEqual(89, finding_test.cwe)

    def test_checkmarx_one_no_description(self):
        with open(get_unit_tests_scans_path("checkmarx_one") / "checkmarx_one_format_two.json", encoding="utf-8") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("Low", finding_test.severity)

    def test_checkmarx_vulnerabilities_from_scan_results(self):
        def test_iac_finding(finding):
            self.assertEqual("Dockerfile: Healthcheck Instruction Missing", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("/Dockerfile", finding.file_path)
            self.assertEqual(datetime.datetime(2024, 4, 16, 14, 36, 23), finding.date.replace(tzinfo=None))
            self.assertEqual((
                "**Actual Value**: Dockerfile doesn't contain instruction 'HEALTHCHECK'\n"
                "**Expected Value**: Dockerfile should contain instruction 'HEALTHCHECK'\n"
            ), finding.mitigation)
            self.assertIn((
                "Ensure that HEALTHCHECK is being used. The HEALTHCHECK instruction tells Docker how to test a container to check that it is still working\n\n"
                "**Category**: Insecure Configurations\n"
                "**Issue Type**: MissingAttribute"
            ), finding.description)

        def test_sast_finding(finding):
            self.assertEqual("Go/Go Low Visibility/Deprecated API", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("/scripts/export-csv-full-base/e.go", finding.file_path)
            self.assertEqual(9, finding.line)
            self.assertEqual(datetime.datetime(2024, 4, 16, 14, 39, 59), finding.date.replace(tzinfo=None))
            self.assertEqual((
                "*   Always prefer to use the most updated versions of libraries, packages, and other dependancies.\r\n"
                "*   Do not use or reference any class, method, function, property, or other element that has been declared deprecated.\n\n"
            ), finding.mitigation)
            self.assertEqual((
                "Method @DestinationMethod in @DestinationFile, at line @DestinationLine, calls an obsolete API, @DestinationElement. "
                "This has been deprecated, and should not be used in a modern\xa0codebase.\n\n\n\n"
                "The application references code elements that have been declared as deprecated. This could include classes, functions, "
                "methods, properties, modules, or obsolete library versions that are either out of date by version, or have been entirely "
                "deprecated. It is likely that the code that references the obsolete element was developed before it was declared as obsolete, "
                "and in the meantime the referenced code was updated.\n\n"
                "In Go - preceding code with a comment whose prefix is `// Deprecated: ` will denote it as deprecated."
            ), finding.description)
            self.assertEqual((
                "Referencing deprecated modules can cause an application to be exposed to known vulnerabilities, that have been publicly "
                "reported and already fixed. A common attack technique is to scan applications for these known vulnerabilities, and then "
                "exploit the application through these deprecated versions. However, even if deprecated code is used in a way that is "
                "completely secure, its very use and inclusion in the code base would encourage developers to re-use the deprecated element "
                "in the future, potentially leaving the application vulnerable to attack, which is why deprecated code should be eliminated "
                "from the code-base as a matter of practice.\r\n\r\n"
                "Note that the actual risk involved depends on the specifics of any known vulnerabilities in older versions.\n\n"
            ), finding.impact)
            self.assertEqual((
                "- OWASP ASVS\n"
                "\t- V01 Architecture, Design and Threat Modeling\n"
                "- OWASP Top 10 2021\n"
                "\t- A6-Vulnerable and Outdated Components\n"
            ), finding.references)

        def test_sca_finding(finding):
            # Not implemented yet
            pass

        with open(get_unit_tests_scans_path("checkmarx_one") / "vulnerabilities_from_scan_results.json", encoding="utf-8") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(146, len(findings))
            for index in range(len(findings)):
                logger.debug(f"{index} {findings[index]}")
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
            iac_finding = findings[145]
            test_iac_finding(iac_finding)
            sast_finding = findings[124]
            self.maxDiff = None
            test_sast_finding(sast_finding)
