from datetime import datetime

from dojo.models import Engagement, Product, Test
from dojo.tools.checkmarx_osa.parser import CheckmarxOsaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCheckmarxOsaParser(DojoTestCase):
    # comment out to get full diff with big reports
    # maxDiff = None

    def init(self, report_filename):
        my_file_handle = open(report_filename, encoding="utf-8")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        return my_file_handle, product, engagement, test

    def teardown(self, my_file_handle):
        my_file_handle.close()

    # ----------------------------------------------------------------------------
    # no_finding
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_no_vulnerabilities_has_no_findings(
        self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx_osa") / "no_finding.json",
        )
        parser = CheckmarxOsaParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(0, len(findings))

    # ----------------------------------------------------------------------------
    # single finding (to_verify); check all fields
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_single_vulnerability_has_single_finding(
        self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx_osa") / "single_finding.json",
        )
        parser = CheckmarxOsaParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        # check content
        item = findings[0]
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("2A3E02E74053088617923D6FE19F14E8188B5271", item.unique_id_from_tool)
        self.assertEqual(str, type(item.title))
        self.assertEqual("com.fasterxml.jackson.core:jackson-databind 2.10.2 | CVE-2020-25649", item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(1035, item.cwe)
        self.assertEqual(float, type(item.cvssv3_score))
        self.assertEqual(7.5, item.cvssv3_score)
        self.assertEqual(datetime, type(item.publish_date))
        self.assertEqual(datetime.strptime("2020-12-03T17:15:00", "%Y-%m-%dT%H:%M:%S"), item.publish_date)
        self.assertEqual(str, type(item.component_name))
        self.assertEqual("com.fasterxml.jackson.core:jackson-databind", item.component_name)
        self.assertEqual(str, type(item.component_version))
        self.assertEqual("2.10.2", item.component_version)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.references))
        self.assertEqual("https://nvd.nist.gov/vuln/detail/CVE-2020-25649", item.references)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("Upgrade to 2.10.5.1", item.mitigation)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)
        self.assertEqual(str, type(item.description))
        self.assertEqual("A flaw was found in FasterXML Jackson Databind before 2.6.7.4, 2.7.0 through 2.9.10.6, and 2.10.0 through 2.10.5, where it did not have entity expansion secured properly. This flaw makes it vulnerable to XML external entity (XXE) attacks. The highest threat from this vulnerability is data integrity.", item.description)
        self.assertEqual(int, type(item.scanner_confidence))
        self.assertEqual(1, item.scanner_confidence)
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-25649", item.unsaved_vulnerability_ids[0])

    # ----------------------------------------------------------------------------
    # single finding false positive
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_false_positive_is_false_positive(
        self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx_osa") / "single_finding_false_positive.json",
        )
        parser = CheckmarxOsaParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(True, item.false_p)

    # ----------------------------------------------------------------------------
    # single finding confirmed (should be verified=True)
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_confirmed_is_verified(
        self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx_osa") / "single_finding_confirmed.json",
        )
        parser = CheckmarxOsaParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(True, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)

    # ----------------------------------------------------------------------------
    # multiple findings
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_multiple_findings(
        self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx_osa") / "multiple_findings.json",
        )
        parser = CheckmarxOsaParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(18, len(findings))

    # ----------------------------------------------------------------------------
    # single finding no score
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_no_score(
        self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx_osa") / "single_finding_no_score.json",
        )
        parser = CheckmarxOsaParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertIsNone(item.cvssv3_score)

    # ----------------------------------------------------------------------------
    # single finding no url
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_no_url(
        self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx_osa") / "single_finding_no_url.json",
        )
        parser = CheckmarxOsaParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertIsNone(item.references)

    # ----------------------------------------------------------------------------
    # single finding no libraryId (ValueError)
    # ----------------------------------------------------------------------------
    def test_checkmarx_osa_parse_file_with_no_libraryId_raises_ValueError(
        self,
    ):
        with self.assertRaises(ValueError) as context:
            my_file_handle, _product, _engagement, test = self.init(
                get_unit_tests_scans_path("checkmarx_osa") / "single_finding_no_libraryId.json",
            )
            with my_file_handle:
                parser = CheckmarxOsaParser()
                parser.get_findings(my_file_handle, test)

        self.assertEqual(
            "Invalid format: missing mandatory field libraryId", str(context.exception),
        )
