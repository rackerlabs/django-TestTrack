from dojo.models import Test
from dojo.tools.cargo_audit.parser import CargoAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCargoAuditParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("cargo_audit") / "no_findings.json", encoding="utf-8") as testfile:
            parser = CargoAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with open(get_unit_tests_scans_path("cargo_audit") / "many_findings.json", encoding="utf-8") as testfile:
            parser = CargoAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("[arc-swap 0.4.7] Dangling reference in `access::Map` with Constant", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual(["dangling reference"], finding.tags)
                self.assertEqual("arc-swap", finding.component_name)
                self.assertEqual("0.4.7", finding.component_version)
                self.assertEqual("RUSTSEC-2020-0091", finding.vuln_id_from_tool)
                self.assertEqual("2020-12-10", finding.publish_date)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("RUSTSEC-2020-0091", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("CVE-2020-35711", finding.unsaved_vulnerability_ids[1])

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("[hyper 0.13.9] Multiple Transfer-Encoding headers misinterprets request payload", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual(["http", "request-smuggling"], finding.tags)
                self.assertEqual("hyper", finding.component_name)
                self.assertEqual("0.13.9", finding.component_version)
                self.assertEqual("RUSTSEC-2021-0020", finding.vuln_id_from_tool)
                self.assertEqual("2021-02-05", finding.publish_date)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("RUSTSEC-2021-0020", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("CVE-2021-21299", finding.unsaved_vulnerability_ids[1])

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("[smallvec 0.6.13] Buffer overflow in SmallVec::insert_many", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual(["buffer-overflow", "heap-overflow", "unsound"], finding.tags)
                self.assertEqual("smallvec", finding.component_name)
                self.assertEqual("0.6.13", finding.component_version)
                self.assertEqual("RUSTSEC-2021-0003", finding.vuln_id_from_tool)
                self.assertEqual("2021-01-08", finding.publish_date)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("RUSTSEC-2021-0003", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("CVE-2021-25900", finding.unsaved_vulnerability_ids[1])

            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("[smallvec 1.5.0] Buffer overflow in SmallVec::insert_many", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertEqual(["buffer-overflow", "heap-overflow", "unsound"], finding.tags)
                self.assertEqual("smallvec", finding.component_name)
                self.assertEqual("1.5.0", finding.component_version)
                self.assertEqual("RUSTSEC-2021-0003", finding.vuln_id_from_tool)
                self.assertEqual("2021-01-08", finding.publish_date)
                self.assertEqual(1, finding.nb_occurences)
                self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("RUSTSEC-2021-0003", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("CVE-2021-25900", finding.unsaved_vulnerability_ids[1])
