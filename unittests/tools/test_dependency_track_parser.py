from dojo.models import Test
from dojo.tools.dependency_track.parser import DependencyTrackParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDependencyTrackParser(DojoTestCase):

    def test_dependency_track_parser_with_empty_list_for_findings_key_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_empty_list.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_missing_findings_key_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_missing.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_null_findings_key_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_null.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_has_many_findings(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "many_findings.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            self.assertIsNone(findings[0].unsaved_vulnerability_ids)
            self.assertIsNone(findings[1].unsaved_vulnerability_ids)
            self.assertEqual(1, len(findings[2].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2016-2097", findings[2].unsaved_vulnerability_ids[0])
            self.assertTrue(findings[2].false_p)
            self.assertTrue(findings[2].is_mitigated)
            self.assertFalse(findings[2].active)
            self.assertEqual(1, len(findings[3].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2016-2097", findings[3].unsaved_vulnerability_ids[0])

    def test_dependency_track_parser_has_one_finding(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "one_finding.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_dependency_track_parser_v3_8_0(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "dependency_track_3.8.0_2021-01-18.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            self.assertTrue(all(item.file_path is not None for item in findings))
            self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))

    def test_dependency_track_parser_findings_with_alias(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "many_findings_with_alias.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(12, len(findings))
            self.assertTrue(all(item.file_path is not None for item in findings))
            self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
            self.assertIn("CVE-2022-42004", findings[0].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_empty_alias(self):
        with open(
            get_unit_tests_scans_path("dependency_track") / "many_findings_with_empty_alias.json", encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(12, len(findings))
            self.assertIn("CVE-2022-2053", findings[11].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_cvssV3_score(self):
        with open(get_unit_tests_scans_path() / "/dependency_track/many_findings_with_cvssV3_score.json", encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(12, len(findings))
        self.assertTrue(all(item.file_path is not None for item in findings))
        self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
        self.assertIn("CVE-2022-42004", findings[0].unsaved_vulnerability_ids)
        self.assertEqual(8.3, findings[0].cvssv3_score)

    def test_dependency_track_parser_findings_with_epss_score(self):
        with open(get_unit_tests_scans_path() / "/dependency_track/dependency_track_4.10_2024_02_11.json", encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(0.00043, findings[0].epss_score)
        self.assertEqual(0.07756, findings[0].epss_percentile)
        self.assertEqual(4.2, findings[0].cvssv3_score)
        self.assertIn("CVE-2023-45803", findings[0].unsaved_vulnerability_ids)
