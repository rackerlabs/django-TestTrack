from dojo.models import Test
from dojo.tools.jfrogxray.parser import JFrogXrayParser, decode_cwe_number
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestJfrogJFrogXrayParser(DojoTestCase):

    def test_parse_file_with_one_vuln(self):
        testfile = open(get_unit_tests_scans_path("jfrogxray") / "one_vuln.json", encoding="utf-8")
        parser = JFrogXrayParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual("debian:stretch:libx11", item.component_name)
        self.assertEqual("2:1.6.4-3", item.component_version)
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2018-14600", item.unsaved_vulnerability_ids[0])
        self.assertEqual(787, item.cwe)

    def test_parse_file_with_many_vulns(self):
        testfile = open(get_unit_tests_scans_path("jfrogxray") / "many_vulns.json", encoding="utf-8")
        parser = JFrogXrayParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_parse_file_with_many_vulns2(self):
        testfile = open(get_unit_tests_scans_path("jfrogxray") / "many_vulns2.json", encoding="utf-8")
        parser = JFrogXrayParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))

        item = findings[0]
        self.assertEqual("No CVE - pip:9.0.1", item.title)
        description = """pip PyPI (Python Packaging Index) PipXmlrpcTransport._download_http_url() Function Content-Disposition Header Path Traversal Arbitrary File Write Weakness
**Provider:** JFrog"""
        self.assertEqual(description, item.description)
        self.assertEqual("High", item.severity)
        self.assertEqual("pip", item.component_name)
        self.assertEqual("9.0.1", item.component_version)
        self.assertIsNone(item.unsaved_vulnerability_ids)
        self.assertIsNone(item.cwe)
        self.assertEqual("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", item.cvssv3)

        item = findings[1]
        self.assertEqual("CVE-2020-14386 - ubuntu:bionic:linux:4.15.0-88.88", item.title)
        description = """A flaw was found in the Linux kernel before 5.9-rc4. Memory corruption can be exploited to gain root privileges from unprivileged processes. The highest threat from this vulnerability is to data confidentiality and integrity.
**Versions that are vulnerable:**
< 4.15.0-117.118
**Provider:** JFrog"""
        self.assertEqual(description, item.description)
        self.assertEqual("High", item.severity)
        self.assertEqual("ubuntu:bionic:linux", item.component_name)
        self.assertEqual("4.15.0-88.88", item.component_version)
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-14386", item.unsaved_vulnerability_ids[0])
        self.assertEqual(787, item.cwe)
        self.assertEqual("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", item.cvssv3)

    def test_decode_cwe_number(self):
        with self.subTest(val="CWE-1234"):
            self.assertEqual(1234, decode_cwe_number("CWE-1234"))
        with self.subTest(val=""):
            self.assertEqual(0, decode_cwe_number(""))
        with self.subTest(val="cwe-1"):
            self.assertEqual(1, decode_cwe_number("cwe-1"))
