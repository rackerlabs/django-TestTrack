import datetime

from dojo.models import Test
from dojo.tools.coverity_api.parser import CoverityApiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestZapParser(DojoTestCase):
    def test_parse_wrong_file(self):
        with self.assertRaises(ValueError):
            with open(get_unit_tests_scans_path("coverity_api") / "wrong.json", encoding="utf-8") as testfile:
                parser = CoverityApiParser()
                parser.get_findings(testfile, Test())

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("coverity_api") / "empty.json", encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_only_quality(self):
        """This report only have quality findings"""
        with open(get_unit_tests_scans_path("coverity_api") / "only_quality.json", encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        with open(get_unit_tests_scans_path("coverity_api") / "few_findings.json", encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)  # this one is marked as new ("status": "New")
                self.assertEqual("Risky cryptographic hashing function", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(328, finding.cwe)
                self.assertEqual("Ugmeekucai/Axoqomhsti/Ydyvpiogyn/Rpzlfzjvra.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 23), finding.date)
                self.assertEqual(22463, finding.unique_id_from_tool)

    def test_parse_few_findings_triaged_as_bug(self):
        with open(get_unit_tests_scans_path("coverity_api") / "few_findings_triaged_as_bug.json", encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertTrue(finding.active)
                self.assertTrue(finding.verified)
                self.assertEqual("HTTP header injection", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(610, finding.cwe)
                self.assertEqual("Fhfzusraaf/Ktvntamjop/Azkpvexkuw/Mvibflzawx.rs", finding.file_path)
                self.assertEqual(datetime.date(2020, 11, 19), finding.date)
                self.assertEqual(22248, finding.unique_id_from_tool)

    def test_parse_some_findings_mitigated(self):
        with open(get_unit_tests_scans_path("coverity_api") / "few_findings_mitigated.json", encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(20, len(findings))
            with self.subTest(i=0):
                finding = findings[0]  # this one is dismissed as a false positive
                self.assertFalse(finding.active)
                self.assertTrue(finding.verified)
                self.assertTrue(finding.false_p)
                self.assertEqual("Cross-site scripting", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(79, finding.cwe)
                self.assertEqual("Pfozpmtueo/Vtoqmbvmzf/Noxacjclcz/Aymctwefbi.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 26), finding.date)
                self.assertEqual(22486, finding.unique_id_from_tool)
            with self.subTest(i=10):
                finding = findings[10]
                self.assertFalse(finding.active)
                self.assertTrue(finding.verified)
                self.assertEqual("Use of hard-coded password", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(259, finding.cwe)
                self.assertEqual("Hvsilgzkwz/Lhmxrchybr/Edcoanzncg/Oowieyoxvn.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 15), finding.date)
                self.assertEqual(22421, finding.unique_id_from_tool)
            with self.subTest(i=19):
                finding = findings[19]
                self.assertFalse(finding.active)
                self.assertTrue(finding.verified)
                self.assertEqual("Cross-site scripting", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(79, finding.cwe)
                self.assertEqual("Pyqqbarxuc/Eiiecgivyo/Yurhlwgjpa/Fitpbdjidn.rs", finding.file_path)
                self.assertEqual(datetime.date(2020, 1, 22), finding.date)
                self.assertEqual(18828, finding.unique_id_from_tool)
