import hashlib

from dojo.models import Test
from dojo.tools.jfrog_xray_api_summary_artifact.parser import (
    JFrogXrayApiSummaryArtifactParser,
)
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestJFrogXrayApiSummaryArtifactParser(DojoTestCase):
    def test_parse_file_with_no_vuln(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_api_summary_artifact") / "no_vuln.json", encoding="utf-8")
        parser = JFrogXrayApiSummaryArtifactParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_api_summary_artifact") / "one_vuln.json", encoding="utf-8")
        parser = JFrogXrayApiSummaryArtifactParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual("OpenSSL crypto", item.title[:14])
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("XRAY-124116", item.unsaved_vulnerability_ids[0])
        self.assertEqual("Critical", item.severity)
        self.assertEqual(
            "3.12:openssl:1.1.1k-r0 -> OpenSSL contains an overflow",
            item.description[:54],
        )
        self.assertEqual(" code.", item.description[-6:])
        self.assertIsNone(item.mitigation)
        self.assertEqual("artifact1", item.component_name)
        self.assertIsNotNone(item.tags)
        self.assertEqual("1.0", item.component_version)
        self.assertEqual("artifact_path/artifact1/1.0/", item.file_path[:28])
        self.assertIsNone(item.severity_justification)
        self.assertIsNone(item.references)
        self.assertIsNone(item.impact)
        self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", item.cvssv3)
        result = hashlib.sha256()
        unique_id = (
            "eaab06c0a28618bfb65481bf31bce7d6dd3a15dac528297690111c202a1cd468"
            + "3.12:openssl"
            + "1.1.1k-r0"
            + "XRAY-124116"
        )
        result.update(unique_id.encode())
        self.assertEqual(result.hexdigest(), item.unique_id_from_tool)

    def test_parse_file_with_many_vulns(self):
        testfile = open(
            get_unit_tests_scans_path("jfrog_xray_api_summary_artifact") / "many_vulns.json", encoding="utf-8",
        )
        parser = JFrogXrayApiSummaryArtifactParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(15, len(findings))
        finding = findings[0]
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2021-42385", finding.unsaved_vulnerability_ids[0])

    def test_parse_file_with_malformed_cvssv3_score(self):
        testfile = open(
            get_unit_tests_scans_path("jfrog_xray_api_summary_artifact") / "malformed_cvssv3.json", encoding="utf-8",
        )
        parser = JFrogXrayApiSummaryArtifactParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertIsNone(finding.cvssv3)
        self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("XRAY-523195", finding.unsaved_vulnerability_ids[1])
