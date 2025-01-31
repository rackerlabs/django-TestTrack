
from dojo.models import Test
from dojo.tools.anchore_enterprise.parser import AnchoreEnterpriseParser, extract_vulnerability_id, search_filepath
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAnchoreEnterpriseParser(DojoTestCase):
    def test_anchore_policy_check_parser_has_no_findings(self):
        with open(get_unit_tests_scans_path("anchore_enterprise") / "no_checks.json", encoding="utf-8") as testfile:
            parser = AnchoreEnterpriseParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_anchore_policy_check_parser_has_one_finding(self):
        with open(get_unit_tests_scans_path("anchore_enterprise") / "one_check.json", encoding="utf-8") as testfile:
            parser = AnchoreEnterpriseParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_anchore_policy_check_parser_has_multiple_findings(self):
        with open(get_unit_tests_scans_path("anchore_enterprise") / "many_checks.json", encoding="utf-8") as testfile:
            parser = AnchoreEnterpriseParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(57, len(findings))
            finding = findings[1]
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2015-2992", finding.unsaved_vulnerability_ids[0])

    def test_anchore_policy_check_parser_invalid_format(self):
        with open(get_unit_tests_scans_path("anchore_enterprise") / "invalid_checks_format.json", encoding="utf-8") as testfile, \
          self.assertRaises(Exception):
            parser = AnchoreEnterpriseParser()
            parser.get_findings(testfile, Test())

    def test_anchore_policy_check_extract_vulnerability_id(self):
        vulnerability_id = extract_vulnerability_id("CVE-2019-14540+openapi-generator-cli-4.0.0.jar:jackson-databind")
        self.assertEqual("CVE-2019-14540", vulnerability_id)
        vulnerability_id = extract_vulnerability_id("RHSA-2020:0227+sqlite")
        self.assertEqual(None, vulnerability_id)
        vulnerability_id = extract_vulnerability_id("41cb7cdf04850e33a11f80c42bf660b3")
        self.assertEqual(None, vulnerability_id)
        vulnerability_id = extract_vulnerability_id("")
        self.assertEqual(None, vulnerability_id)

    def test_anchore_policy_check_parser_search_filepath(self):
        file_path = search_filepath(
            "MEDIUM Vulnerability found in non-os package type (python) - /usr/lib64/python2.7/lib-dynload/Python (CVE-2014-4616 - https://nvd.nist.gov/vuln/detail/CVE-2014-4616)",
        )
        self.assertEqual("/usr/lib64/python2.7/lib-dynload/Python", file_path)
        file_path = search_filepath(
            "HIGH Vulnerability found in non-os package type (java) - /root/.m2/repository/org/apache/struts/struts-core/1.3.8/struts-core-1.3.8.jar (CVE-2015-0899 - https://nvd.nist.gov/vuln/detail/CVE-2015-0899)",
        )
        self.assertEqual(
            "/root/.m2/repository/org/apache/struts/struts-core/1.3.8/struts-core-1.3.8.jar",
            file_path,
        )
        file_path = search_filepath(
            "test /usr/local/bin/ag package type (java) - /root/.m2/repository/org/apache/struts/struts-core/1.3.8/struts-core-1.3.8.jar (CVE-2015-0899 - https://nvd.nist.gov/vuln/detail/CVE-2015-0899)",
        )
        self.assertEqual("/usr/local/bin/ag", file_path)
        file_path = search_filepath(
            "HIGH Vulnerability found in os package type (rpm) - kernel-headers (RHSA-2017:0372 - https://access.redhat.com/errata/RHSA-2017:0372)",
        )
        self.assertEqual("", file_path)
        file_path = search_filepath("test")
        self.assertEqual("", file_path)
