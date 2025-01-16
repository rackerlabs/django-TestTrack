from dojo.models import Test
from dojo.tools.threagile.parser import ThreagileParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestThreAgileParser(DojoTestCase):
    def test_non_threagile_file_raises_error(self):
        with open(get_unit_tests_scans_path("threagile") / "bad_formatted_risks_file.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            with self.assertRaises(TypeError) as exc_context:
                parser.get_findings(testfile, Test())
        exc = exc_context.exception
        self.assertEqual("Invalid ThreAgile risks file", str(exc))

    def test_empty_file_returns_no_findings(self):
        with open(get_unit_tests_scans_path("threagile") / "empty_file_no_risks.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_file_with_vulnerabilities_returns_correct_findings(self):
        with open(get_unit_tests_scans_path("threagile") / "risks.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))
            finding = findings[0]
            self.assertEqual("unguarded-direct-datastore-access", finding.title)
            self.assertEqual("\u003cb\u003eUnguarded Direct Datastore Access\u003c/b\u003e of \u003cb\u003ePoliciesRegoStorage\u003c/b\u003e by \u003cb\u003eEnergon\u003c/b\u003e via \u003cb\u003eEnergonToPolicyRegoFileStorage\u003c/b\u003e", finding.description)
            self.assertEqual("High", finding.severity)
            self.assertEqual("unguarded-direct-datastore-access@energon-ta>energontopolicyregofilestorage@energon-ta@policies-rego-storage-ta", finding.unique_id_from_tool)
            self.assertEqual(501, finding.cwe)
            self.assertEqual("medium", finding.impact)
            self.assertEqual("policies-rego-storage-ta", finding.component_name)

    def test_in_discussion_is_under_review(self):
        with open(get_unit_tests_scans_path("threagile") / "risks.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[1]
            self.assertTrue(finding.under_review)

    def test_accepted_finding_is_accepted(self):
        with open(get_unit_tests_scans_path("threagile") / "risks.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[2]
            self.assertTrue(finding.risk_accepted)

    def test_in_progress_is_verified(self):
        with open(get_unit_tests_scans_path("threagile") / "risks.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[3]
            self.assertTrue(finding.verified)

    def test_mitigated_is_mitigated(self):
        with open(get_unit_tests_scans_path("threagile") / "risks.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[4]
            self.assertTrue(finding.is_mitigated)
            self.assertEqual("some-runtime", finding.component_name)

    def test_false_positive_is_false_positive(self):
        with open(get_unit_tests_scans_path("threagile") / "risks.json", encoding="utf-8") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            finding = findings[5]
            self.assertTrue(finding.false_p)
            self.assertEqual("some-component\u003esome-traffic", finding.component_name)
