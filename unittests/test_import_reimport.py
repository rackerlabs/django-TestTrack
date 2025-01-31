import datetime

# from unittest import skip
import logging

from django.test import override_settings
from django.test.client import Client
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Finding, Test, Test_Type, User

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path
from .test_utils import assertTestImportModelsCreated

logger = logging.getLogger(__name__)


ENGAGEMENT_NAME_DEFAULT = "Engagement 1"
PRODUCT_NAME_DEFAULT = "Product A"
PRODUCT_TYPE_NAME_DEFAULT = "Type type"


# 0_zap_sample.xml: basic file with 4 out of 5 findings reported, zap4 absent
# 1 active
# 2 active
# 3 active
# 4 absent
# 5 active

# 1_zap_sample_0_and_new_absent: based on 0, but zap1 absent, zap4 reported
# 1 absent
# 2 active
# 3 active
# 4 active
# 5 active

# 2_zap_sample_0_and_new_endpoint: bases on 0: just adding an endpoint to zap1
# 1 active, extra endpoint
# 2 active
# 3 active
# 4 absent
# 5 active

# 3_zap_sampl_0_and_different_severities
# 1 active
# 2 active sev medium
# 3 active
# 4 absent
# 5 active sev medium

# test methods to be used both by API Test and UI Test
class ImportReimportMixin:
    def __init__(self, *args, **kwargs):

        self.zap_sample0_filename = get_unit_tests_scans_path("zap") / "0_zap_sample.xml"
        self.zap_sample1_filename = get_unit_tests_scans_path("zap") / "1_zap_sample_0_and_new_absent.xml"
        self.zap_sample2_filename = get_unit_tests_scans_path("zap") / "2_zap_sample_0_and_new_endpoint.xml"
        self.zap_sample3_filename = get_unit_tests_scans_path("zap") / "3_zap_sampl_0_and_different_severities.xml"

        self.anchore_file_name = get_unit_tests_scans_path("anchore_engine") / "one_vuln_many_files.json"
        self.scan_type_anchore = "Anchore Engine Scan"

        self.acunetix_file_name = get_unit_tests_scans_path("acunetix") / "one_finding.xml"
        self.scan_type_acunetix = "Acunetix Scan"

        self.gitlab_dep_scan_components_filename = get_unit_tests_scans_path("gitlab_dep_scan") / "gl-dependency-scanning-report-many-vuln_v15.json"
        self.scan_type_gtlab_dep_scan = "GitLab Dependency Scanning Report"

        self.sonarqube_file_name1 = get_unit_tests_scans_path("sonarqube") / "sonar-6-findings.html"
        self.sonarqube_file_name2 = get_unit_tests_scans_path("sonarqube") / "sonar-6-findings-1-unique_id_changed.html"
        self.scan_type_sonarqube_detailed = "SonarQube Scan detailed"

        self.veracode_many_findings = get_unit_tests_scans_path("veracode") / "many_findings.xml"
        self.veracode_same_hash_code_different_unique_id = get_unit_tests_scans_path("veracode") / "many_findings_same_hash_code_different_unique_id.xml"
        self.veracode_same_unique_id_different_hash_code = get_unit_tests_scans_path("veracode") / "many_findings_same_unique_id_different_hash_code.xml"
        self.veracode_different_hash_code_different_unique_id = get_unit_tests_scans_path("veracode") / "many_findings_different_hash_code_different_unique_id.xml"
        self.veracode_mitigated_findings = get_unit_tests_scans_path("veracode") / "mitigated_finding.xml"
        self.scan_type_veracode = "Veracode Scan"

        self.clair_few_findings = get_unit_tests_scans_path("clair") / "clair_few_vuln.json"
        self.clair_empty = get_unit_tests_scans_path("clair") / "clair_empty.json"
        self.scan_type_clair = "Clair Scan"

        self.scan_type_generic = "Generic Findings Import"
        self.generic_filename_with_file = get_unit_tests_scans_path("generic") / "test_with_image.json"
        self.generic_import_1 = get_unit_tests_scans_path("generic") / "test_import_report1.json"
        self.generic_import_2 = get_unit_tests_scans_path("generic") / "test_import_report2.json"

        self.aws_prowler_file_name = get_unit_tests_scans_path("aws_prowler") / "many_vuln.json"
        self.aws_prowler_file_name_plus_one = get_unit_tests_scans_path("aws_prowler") / "many_vuln_plus_one.json"
        self.scan_type_aws_prowler = "AWS Prowler Scan"

        self.nuclei_empty = get_unit_tests_scans_path("nuclei") / "empty.jsonl"

        self.gitlab_dast_file_name = get_unit_tests_scans_path("gitlab_dast") / "gitlab_dast_one_vul_v15.json"
        self.scan_type_gitlab_dast = "GitLab DAST Report"

        self.anchore_grype_file_name = get_unit_tests_scans_path("anchore_grype") / "check_all_fields.json"
        self.anchore_grype_scan_type = "Anchore Grype"

    # import zap scan, testing:
    # - import
    # - active/verifed = True
    def test_zap_scan_base_active_verified(self):
        logger.debug("importing original zap xml report")
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename)

        # 0_zap_sample.xml: basic file with 4 out of 5 findings reported, zap4 absent
        # 1 active
        # 2 active
        # 3 active
        # 4 absent
        # 5 active

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # imported count must match count in xml report
        self.assert_finding_count_json(4, findings)

        # the zap scan contains 2 endpoints (uris from findings)
        self.assertEqual(endpoint_count_before + 2, self.db_endpoint_count())
        # 4 findings, total 7 endpoint statuses (1 + 2 + 2 + 2)
        # finding 1 have 1 endpoints => 1 status
        # finding 2 have 2 endpoints => 2 status
        # finding 3 have 2 endpoints => 2 status
        # finding 5 have 2 endpoints => 2 status
        self.assertEqual(endpoint_status_count_before_active + 7, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated, self.db_endpoint_status_count(mitigated=True))

        # no notes expected
        self.assertEqual(notes_count_before, self.db_notes_count())

    # import zap scan, testing:
    # - import
    # - active/verifed = False
    def test_zap_scan_base_not_active_not_verified(self):
        logger.debug("importing original zap xml report")
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename, active=False, verified=False)

        # 0_zap_sample.xml: basic file with 4 out of 5 findings reported, zap4 absent
        # 1 inactive
        # 2 inactive
        # 3 inactive
        # 4 absent
        # 5 inactive

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # imported count must match count in xml report
        self.assert_finding_count_json(4, findings)

        # the zap scan contains 2 endpoints (uris from findings)
        self.assertEqual(endpoint_count_before + 2, self.db_endpoint_count())
        # 4 findings, total 7 endpoint statuses (1 + 2 + 2 + 2)
        # finding 1 have 1 endpoints => 1 status
        # finding 2 have 2 endpoints => 2 status
        # finding 3 have 2 endpoints => 2 status
        # finding 5 have 2 endpoints => 2 status
        self.assertEqual(endpoint_status_count_before_active + 7, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated, self.db_endpoint_status_count(mitigated=True))

        # no notes expected
        self.assertEqual(notes_count_before, self.db_notes_count())

    # Test Scan_Date logic for Import. Reimport without a test_id cannot work for UI, so those tests are only in the API class below.

    # import zap scan without dates
    # - import
    # - no scan_date and date not set by parser leads to today as date
    def test_import_default_scan_date_parser_not_sets_date(self):
        logger.debug("importing zap xml report with date set by parser")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename, active=False, verified=False)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, str(timezone.localtime(timezone.now()).date()))

    # import acunetix scan with dates
    # - import
    # - no scan scan_date does not overrides date set by parser
    def test_import_default_scan_date_parser_sets_date(self):
        logger.debug("importing original acunetix xml report")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=1, created=1):
            import0 = self.import_scan_with_params(self.acunetix_file_name, scan_type=self.scan_type_acunetix, active=False, verified=False)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, "2018-09-24")

    # import zap scan without dates
    # - import
    # - set scan_date overrides date not set by parser
    def test_import_set_scan_date_parser_not_sets_date(self):
        logger.debug("importing original zap xml report")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.zap_sample0_filename, active=False, verified=False, scan_date="2006-12-26")

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, "2006-12-26")

    # import acunetix scan with dates
    # - import
    # - set scan_date overrides date set by parser
    def test_import_set_scan_date_parser_sets_date(self):
        logger.debug("importing acunetix xml report with date set by parser")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=1, created=1):
            import0 = self.import_scan_with_params(self.acunetix_file_name, scan_type=self.scan_type_acunetix, active=False, verified=False, scan_date="2006-12-26")

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, "2006-12-26")

    # Test Scan_Date for reimport in UI. UI can only rupload for existing tests, non UI tests are in API class below

    def test_import_reimport_no_scan_date_parser_no_date(self):
        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # reimport report with 1 extra finding
        reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample1_filename)

        test_id = reimport0["test"]

        # 1 new finding imported
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(5, findings)
        # no scan_date, so date should be today
        self.assertEqual(findings["results"][4]["date"], str(timezone.localtime(timezone.now()).date()))

    def test_import_reimport_scan_date_parser_no_date(self):
        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        # reimport report with 1 extra finding
        reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample1_filename, scan_date="2020-02-02")

        test_id = reimport0["test"]

        # 1 new finding imported
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(5, findings)
        # scan_date provided, so date should be equal to that
        self.assertEqual(findings["results"][4]["date"], "2020-02-02")

    def test_import_reimport_no_scan_date_parser_date(self):
        import0 = self.import_scan_with_params(self.aws_prowler_file_name, scan_type=self.scan_type_aws_prowler)

        test_id = import0["test"]

        # reimport report with 1 extra finding
        reimport0 = self.reimport_scan_with_params(test_id, self.aws_prowler_file_name_plus_one, scan_type=self.scan_type_aws_prowler)

        test_id = reimport0["test"]

        # 1 new finding imported
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(5, findings)
        self.log_finding_summary_json_api(findings)
        # no scan_date, so date should be date from parser
        # findings order by priority, third finding is the new one
        self.assertEqual(findings["results"][2]["date"], "2021-08-23")

    def test_import_reimport_scan_date_parser_date(self):
        import0 = self.import_scan_with_params(self.aws_prowler_file_name, scan_type=self.scan_type_aws_prowler)

        test_id = import0["test"]

        # reimport report with 1 extra finding
        reimport0 = self.reimport_scan_with_params(test_id, self.aws_prowler_file_name_plus_one, scan_type=self.scan_type_aws_prowler, scan_date="2020-02-02")

        test_id = reimport0["test"]

        # 1 new finding imported
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(5, findings)
        # scan_date provided, so date should be equal to that overriding that from the parser
        self.log_finding_summary_json_api(findings)
        self.assertEqual(findings["results"][4]["date"], "2020-02-02")

    # Test re-import with unique_id_from_tool algorithm
    # import sonar scan with detailed parser, testing:
    # - import
    # - active/verifed = True
    def test_sonar_detailed_scan_base_active_verified(self):
        logger.debug("importing original sonar report")
        notes_count_before = self.db_notes_count()

        with assertTestImportModelsCreated(self, imports=1, affected_findings=6, created=6):
            import0 = self.import_scan_with_params(self.sonarqube_file_name1, scan_type=self.scan_type_sonarqube_detailed)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # imported count must match count in the report
        self.assert_finding_count_json(6, findings)

        # no notes expected
        self.assertEqual(notes_count_before, self.db_notes_count())

    # Test re-import with unique_id_from_tool_or_hash_code algorithm
    # import veracode scan, testing:
    # - import
    # - active/verifed = True
    def test_veracode_scan_base_active_verified(self):
        logger.debug("importing original veracode report")
        notes_count_before = self.db_notes_count()

        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.veracode_many_findings, scan_type=self.scan_type_veracode)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # imported count must match count in the report
        self.assert_finding_count_json(4, findings)

        # no notes expected
        self.assertEqual(notes_count_before, self.db_notes_count())

    # import veracode and then reimport veracode again
    # - reimport, findings stay the same, stay active
    # - active = True, verified = True
    # - existing findings with verified is true should stay verified
    def test_import_veracode_reimport_veracode_active_verified_mitigated(self):
        logger.debug("reimporting exact same original veracode mitigated xml report again")

        import_veracode_many_findings = self.import_scan_with_params(self.veracode_mitigated_findings, scan_type=self.scan_type_veracode,
                                                                     verified=True, forceActive=True, forceVerified=True)

        test_id = import_veracode_many_findings["test"]

        notes_count_before = self.db_notes_count()

        # reimport exact same report
        with assertTestImportModelsCreated(self, reimports=1, affected_findings=1, created=0, closed=1, reactivated=0, untouched=0):
            reimport_veracode_mitigated_findings = self.reimport_scan_with_params(test_id, self.veracode_mitigated_findings, scan_type=self.scan_type_veracode)

        test_id = reimport_veracode_mitigated_findings["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in veracode report
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(1, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(0, findings)

        # reimporting the exact same scan shouldn't create any notes, but there will be a new mitigated note
        self.assertEqual(notes_count_before, self.db_notes_count() - 1)
        mitigated_findings = self.get_test_findings_api(test_id, is_mitigated=True)
        self.assert_finding_count_json(1, mitigated_findings)

    # import 0 and then reimport 0 again
    # - reimport, findings stay the same, stay active
    # - active = True, verified = Trie
    # - existing findings with verified is true should stay verified
    def test_import_0_reimport_0_active_verified(self):
        logger.debug("reimporting exact same original zap xml report again")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        # reimport exact same report
        with assertTestImportModelsCreated(self, reimports=1, untouched=4):
            reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample0_filename)

        test_id = reimport0["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in xml report
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(4, findings)

        # reimporting the exact same scan shouldn't modify the number of endpoints and statuses
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(endpoint_status_count_before_active, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated, self.db_endpoint_status_count(mitigated=True))

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    # import 0 and then reimport 0 again with verified is false
    # - reimport, findings stay the same, stay active
    # - active = True, verified = False
    # - existing findings with verified is true should stay verified
    def test_import_0_reimport_0_active_not_verified(self):
        logger.debug("reimporting exact same original zap xml report again, verified=False")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]

        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        # reimport exact same report
        with assertTestImportModelsCreated(self, reimports=1, untouched=4):
            reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample0_filename, verified=False)

        test_id = reimport0["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in xml report
        # we set verified=False in this reimport, but currently DD does not update this flag, so it's still True from previous import
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(4, findings)

        # reimporting the exact same scan shouldn't modify the number of endpoints
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(endpoint_status_count_before_active, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated, self.db_endpoint_status_count(mitigated=True))

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    # Test re-import with unique_id_from_tool algorithm
    # import sonar1 and then reimport sonar1 again with verified is false
    # - reimport, findings stay the same, stay active
    # - active = True, verified = False
    # - existing findings with verified is true should stay verified
    def test_import_sonar1_reimport_sonar1_active_not_verified(self):
        logger.debug("reimporting exact same original sonar report again, verified=False")

        importsonar1 = self.import_scan_with_params(self.sonarqube_file_name1, scan_type=self.scan_type_sonarqube_detailed)

        test_id = importsonar1["test"]

        notes_count_before = self.db_notes_count()

        # reimport exact same report
        with assertTestImportModelsCreated(self, reimports=1, untouched=6):
            reimportsonar1 = self.reimport_scan_with_params(test_id, self.sonarqube_file_name1, scan_type=self.scan_type_sonarqube_detailed, verified=False)

        test_id = reimportsonar1["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in sonar report
        # we set verified=False in this reimport but DD keeps true as per the previous import (reimport doesn't "unverify" findings)
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(6, findings)

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    # Test the minimum severity flag
    def test_import_sonar1_measure_minimum_severity_counts(self):
        # Critical
        response_json = self.import_scan_with_params(self.sonarqube_file_name1, scan_type=self.scan_type_sonarqube_detailed, minimum_severity="Critical")
        test_id = response_json["test"]
        # Count all findings
        self.assert_finding_count_json(3, self.get_test_findings_api(test_id))
        self.assert_finding_count_json(3, self.get_test_findings_api(test_id, severity="Critical"))

        # High
        response_json = self.import_scan_with_params(self.sonarqube_file_name1, scan_type=self.scan_type_sonarqube_detailed, minimum_severity="High")
        test_id = response_json["test"]
        # Count all findings
        self.assert_finding_count_json(4, self.get_test_findings_api(test_id))
        self.assert_finding_count_json(1, self.get_test_findings_api(test_id, severity="High"))

        # Low
        response_json = self.import_scan_with_params(self.sonarqube_file_name1, scan_type=self.scan_type_sonarqube_detailed, minimum_severity="Low")
        test_id = response_json["test"]
        # Count all findings
        self.assert_finding_count_json(6, self.get_test_findings_api(test_id))
        self.assert_finding_count_json(2, self.get_test_findings_api(test_id, severity="Low"))

    # Test re-import with unique_id_from_tool_or_hash_code algorithm
    # import veracode_many_findings and then reimport veracode_many_findings again with verified is false
    # - reimport, findings stay the same, stay active
    # - existing findings with verified is true should stay verified
    def test_import_veracode_reimport_veracode_active_not_verified(self):
        logger.debug("reimporting exact same original veracode report again, verified=False")

        import_veracode_many_findings = self.import_scan_with_params(self.veracode_many_findings, scan_type=self.scan_type_veracode)

        test_id = import_veracode_many_findings["test"]

        notes_count_before = self.db_notes_count()

        # reimport exact same report
        with assertTestImportModelsCreated(self, reimports=1, untouched=4):
            reimport_veracode_many_findings = self.reimport_scan_with_params(test_id, self.veracode_many_findings, scan_type=self.scan_type_veracode, verified=False)

        test_id = reimport_veracode_many_findings["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in sonar report
        # we set verified=False in this reimport but DD keeps true as per the previous import (reimport doesn't "unverify" findings)
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(4, findings)

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    # import sonar1 and then reimport sonar2 which has 1 different unique_id_from_tool
    # - 5 findings stay the same and active
    # - 1 finding is mitigated
    # - 1 finding is added
    def test_import_sonar1_reimport_sonar2(self):
        logger.debug("reimporting same findings except one with a different unique_id_from_tool")

        importsonar1 = self.import_scan_with_params(self.sonarqube_file_name1, scan_type=self.scan_type_sonarqube_detailed)

        test_id = importsonar1["test"]

        notes_count_before = self.db_notes_count()

        # reimport other report
        with assertTestImportModelsCreated(self, reimports=1, affected_findings=2, created=1, closed=1, untouched=5):
            reimportsonar1 = self.reimport_scan_with_params(test_id, self.sonarqube_file_name2, scan_type=self.scan_type_sonarqube_detailed, verified=False)

        test_id = reimportsonar1["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in sonar report
        # (reimport doesn't unverify findings that ware previously verified)
        # (the mitigated finding stays verified)
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # one mitigated (the one previously imported which has changed unique_id_from_tool)
        findings = self.get_test_findings_api(test_id, is_mitigated=True)
        self.assert_finding_count_json(1, findings)

        # one verified False (the new one, as reimport was done with verified false)
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(7, findings)

        # one added note for mitigated finding
        self.assertEqual(notes_count_before + 1, self.db_notes_count())

    # Test re-import with unique_id_from_tool_or_hash_code algorithm
    # import veracode_many_findings and then reimport veracode_same_hash_code_different_unique_id with verified is false
    # - reimport, all findings stay the same, stay active
    # - existing findings with verified is true should stay verified
    def test_import_veracode_reimport_veracode_same_hash_code_different_unique_id(self):
        logger.debug("reimporting report with one finding having same hash_code but different unique_id_from_tool, verified=False")

        import_veracode_many_findings = self.import_scan_with_params(self.veracode_many_findings, scan_type=self.scan_type_veracode)

        test_id = import_veracode_many_findings["test"]

        notes_count_before = self.db_notes_count()

        # reimport
        with assertTestImportModelsCreated(self, reimports=1, untouched=4):
            reimport_veracode_many_findings = self.reimport_scan_with_params(test_id, self.veracode_same_hash_code_different_unique_id, scan_type=self.scan_type_veracode, verified=False)

        test_id = reimport_veracode_many_findings["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # we set verified=False in this reimport but DD keeps true as per the previous import (reimport doesn't "unverify" findings)
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(4, findings)

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    # Test re-import with unique_id_from_tool_or_hash_code algorithm
    # import veracode_many_findings and then reimport veracode_same_unique_id_different_hash_code with verified is false
    # - reimport, all findings stay the same, stay active
    # - existing findings with verified is true should stay verified
    def test_import_veracode_reimport_veracode_same_unique_id_different_hash_code(self):
        logger.debug("reimporting report with one finding having same unique_id_from_tool but different hash_code, verified=False")

        import_veracode_many_findings = self.import_scan_with_params(self.veracode_many_findings, scan_type=self.scan_type_veracode)

        test_id = import_veracode_many_findings["test"]

        notes_count_before = self.db_notes_count()

        # reimport
        with assertTestImportModelsCreated(self, reimports=1, untouched=4):
            reimport_veracode_many_findings = self.reimport_scan_with_params(test_id, self.veracode_same_unique_id_different_hash_code, scan_type=self.scan_type_veracode, verified=False)

        test_id = reimport_veracode_many_findings["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # we set verified=False in this reimport but DD keeps true as per the previous import (reimport doesn't "unverify" findings)
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(4, findings)

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    # Test re-import with unique_id_from_tool_or_hash_code algorithm
    # import veracode_many_findings and then reimport veracode_different_hash_code_different_unique_id with verified is false
    # - reimport, existing findings stay active and the same
    # - 1 added finding, 1 mitigated finding
    # - existing findings with verified is true should stay verified
    def test_import_veracode_reimport_veracode_different_hash_code_different_unique_id(self):
        logger.debug("reimporting report with one finding having different hash_code and different unique_id_from_tool, verified=False")

        import_veracode_many_findings = self.import_scan_with_params(self.veracode_many_findings, scan_type=self.scan_type_veracode)

        test_id = import_veracode_many_findings["test"]

        notes_count_before = self.db_notes_count()

        # reimport
        with assertTestImportModelsCreated(self, reimports=1, affected_findings=2, created=1, closed=1, untouched=3):
            reimport_veracode_many_findings = self.reimport_scan_with_params(test_id, self.veracode_different_hash_code_different_unique_id, scan_type=self.scan_type_veracode, verified=False)

        test_id = reimport_veracode_many_findings["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # we set verified=False in this reimport but DD keeps true as per the previous import (reimport doesn't "unverify" findings)
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # The new finding has verified=false
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(5, findings)

        # 1 added note for the migitated finding
        self.assertEqual(notes_count_before + 1, self.db_notes_count())

    # import 0 and then reimport 1 with zap4 as extra finding, zap1 closed.
    # - active findings count should be 4
    # - total  findings count should be 5
    # - zap1 is closed, so endpoints should be mitigated
    # - verified is false, so zap4 should not be verified.
    # - existing findings with verified is true should stay verified
    def test_import_0_reimport_1_active_not_verified(self):
        logger.debug("reimporting updated zap xml report, 1 new finding and 1 no longer present, verified=False")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        finding_count_before = self.db_finding_count()
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        # reimport updated report
        with assertTestImportModelsCreated(self, reimports=1, affected_findings=2, created=1, closed=1, untouched=3):
            reimport1 = self.reimport_scan_with_params(test_id, self.zap_sample1_filename, verified=False)

        test_id = reimport1["test"]
        self.assertEqual(test_id, test_id)

        self.get_test_api(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # active findings must be equal to those in both reports
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(4 + 1, findings)

        # verified findings must be equal to those in report 0
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(5, findings)

        # the updated scan report has
        # - 1 new finding
        self.assertEqual(finding_count_before + 1, self.db_finding_count())
        # zap4 only uses 2 endpoints that already exist
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        # but 2 statuses should be created for those endpoints, 2 statuses for zap1 closed
        self.assertEqual(endpoint_status_count_before_active + 2 - 3, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated + 2, self.db_endpoint_status_count(mitigated=True))

        # - 1 new note for zap1 being closed now
        self.assertEqual(notes_count_before + 1, self.db_notes_count())

    # import 0 and then reimport 1 with zap4 as extra finding, zap1 closed and then reimport 0 again
    # - active findings count should be 4
    # - total  findings count should be 5
    # - zap1 active, zap4 inactive
    def test_import_0_reimport_1_active_verified_reimport_0_active_verified(self):
        logger.debug("reimporting updated zap xml report, 1 new finding and 1 no longer present, verified=True and then 0 again")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        self.db_finding_count()
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        reimport1 = self.reimport_scan_with_params(test_id, self.zap_sample1_filename)

        # zap1 should be closed 2 endpoint statuses less, but 2 extra for zap4
        self.assertEqual(endpoint_status_count_before_active - 3 + 2, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated + 2, self.db_endpoint_status_count(mitigated=True))

        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)

        with assertTestImportModelsCreated(self, reimports=1, affected_findings=2, closed=1, reactivated=1, untouched=3):
            self.reimport_scan_with_params(test_id, self.zap_sample0_filename)

        test_id = reimport1["test"]
        self.assertEqual(test_id, test_id)

        self.get_test_api(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # active findings must be equal to those in both reports
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(4 + 1, findings)

        zap1_ok = False
        zap4_ok = False
        for finding in findings["results"]:
            if "Zap1" in finding["title"]:
                self.assertTrue(finding["active"])
                zap1_ok = True
            if "Zap4" in finding["title"]:
                self.assertFalse(finding["active"])
                zap4_ok = True

        self.assertTrue(zap1_ok)
        self.assertTrue(zap4_ok)

        # verified findings must be equal to those in report 0
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(5, findings)

        self.assertEqual(endpoint_count_before, self.db_endpoint_count())

        # zap4 should be closed again so 2 mitigated eps, zap1 should be open again so 3 active extra
        self.assertEqual(endpoint_status_count_before_active + 3 - 2, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated - 3 + 2, self.db_endpoint_status_count(mitigated=True))

        # zap1 was closed and then opened -> 2 notes
        # zap4 was created and then closed -> only 1 note
        self.assertEqual(notes_count_before + 2 + 1, self.db_notes_count())

    # import 0 and then reimport 2 with an extra endpoint for zap1
    # - extra endpoint should be present in db
    # - reimport doesn't look at endpoints to match against existing findings
    def test_import_0_reimport_2_extra_endpoint(self):
        logger.debug("reimporting exact same original zap xml report again, with an extra endpoint for zap1")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        finding_count_before = self.db_finding_count()
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        with assertTestImportModelsCreated(self, reimports=1, affected_findings=0, untouched=4):
            reimport2 = self.reimport_scan_with_params(test_id, self.zap_sample2_filename)

        test_id = reimport2["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in xml report
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(4, findings)

        self.assertEqual(endpoint_count_before + 1, self.db_endpoint_count())
        self.assertEqual(endpoint_status_count_before_active + 1, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated, self.db_endpoint_status_count(mitigated=True))

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())
        self.assertEqual(finding_count_before, self.db_finding_count())

    # import 0 and then reimport 2 with an extra endpoint for zap1 and then 0 again to remove the extra endpoint again
    # - extra endpoint should no long be present in db
    # - reimport doesn't look at endpoints to match against existing findings
    def test_import_0_reimport_2_extra_endpoint_reimport_0(self):
        logger.debug("reimporting exact same original zap xml report again, with an extra endpoint for zap1")

        # self.log_finding_summary_json_api()

        import0 = self.import_scan_with_params(self.zap_sample0_filename)
        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        with assertTestImportModelsCreated(self, reimports=1, affected_findings=0, untouched=4):
            reimport2 = self.reimport_scan_with_params(test_id, self.zap_sample2_filename)

        test_id = reimport2["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        finding_count_before = self.db_finding_count()
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample0_filename)

        test_id = reimport0["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in xml report
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(4, findings)

        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        # 1 endpoint was marked as mitigated
        self.assertEqual(endpoint_status_count_before_active - 1, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated + 1, self.db_endpoint_status_count(mitigated=True))

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())
        self.assertEqual(finding_count_before, self.db_finding_count())

    # import 0 and then reimport 3 with severities changed for zap1 and zap2
    # - reimport will match on severity, so now should create 2 new findings
    # - and close the 2 old findings because they have a different severity
    # - so zap1 + zap2 closed
    # - 2 new findings zap1' and zap2'
    def test_import_0_reimport_3_active_verified(self):
        logger.debug("reimporting updated zap xml report, with different severities for zap2 and zap5")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        finding_count_before = self.db_finding_count()
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)
        notes_count_before = self.db_notes_count()

        # reimport updated report
        with assertTestImportModelsCreated(self, reimports=1, affected_findings=4, created=2, closed=2, untouched=2):
            reimport1 = self.reimport_scan_with_params(test_id, self.zap_sample3_filename)

        test_id = reimport1["test"]
        self.assertEqual(test_id, test_id)

        self.get_test_api(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        self.assert_finding_count_json(4 + 2, findings)

        zap2_ok = False
        zap5_ok = False
        for finding in findings["results"]:
            if "Zap2" in finding["title"]:
                self.assertTrue(finding["active"] or finding["severity"] == "Low")
                self.assertTrue(not finding["active"] or finding["severity"] == "Medium")
                zap2_ok = True
            if "Zap5" in finding["title"]:
                self.assertTrue(finding["active"] or finding["severity"] == "Low")
                self.assertTrue(not finding["active"] or finding["severity"] == "Medium")
                zap5_ok = True

        self.assertTrue(zap2_ok)
        self.assertTrue(zap5_ok)

        # verified findings must be equal to those in report 0
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0 + 0, findings)

        # unverified findings must be equal to those in report 0
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(4 + 2, findings)

        # the updated scan report has
        # - 2 new findings, 2 new endpoints, 2 + 2 new endpoint statuses active, 3 + 3 endpoint statues mitigated due to zap1+2 closed
        self.assertEqual(finding_count_before + 2, self.db_finding_count())
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(endpoint_status_count_before_active + 3 + 3 - 3 - 3, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated + 2 + 2, self.db_endpoint_status_count(mitigated=True))

        # - zap2 and zap5 closed
        self.assertEqual(notes_count_before + 2, self.db_notes_count())

    # import 1 and then reimport 2 without closing old findings
    # - reimport should not mitigate the zap1
    def test_import_reimport_without_closing_old_findings(self):
        logger.debug("reimporting updated zap xml report and keep old findings open")

        import1 = self.import_scan_with_params(self.zap_sample1_filename)

        test_id = import1["test"]
        findings = self.get_test_findings_api(test_id)
        self.assert_finding_count_json(4, findings)

        with assertTestImportModelsCreated(self, reimports=1, affected_findings=1, created=1, untouched=3):
            reimport1 = self.reimport_scan_with_params(test_id, self.zap_sample2_filename, close_old_findings=False)

        test_id = reimport1["test"]
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(5, findings)

        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        mitigated = 0
        not_mitigated = 0
        for finding in findings["results"]:
            logger.debug(finding)
            if finding["is_mitigated"]:
                mitigated += 1
            else:
                not_mitigated += 1
        self.assertEqual(mitigated, 0)
        self.assertEqual(not_mitigated, 0)

    # some parsers generate 1 finding for each vulnerable file for each vulnerability
    # i.e
    # #: title                     : sev : file_path
    # 1: CVE-2020-1234 jquery      : 1   : /file1.jar
    # 2: CVE-2020-1234 jquery      : 1   : /file2.jar
    #
    # if we don't filter on file_path, we would find 2 existing findings
    # and the logic below will get confused and just create a new finding
    # and close the two existing ones. including and duplicates.
    #
    def test_import_0_reimport_0_anchore_file_path(self):
        import0 = self.import_scan_with_params(self.anchore_file_name, scan_type=self.scan_type_anchore)

        test_id = import0["test"]

        active_findings_before = self.get_test_findings_api(test_id, active=True)
        self.log_finding_summary_json_api(active_findings_before)

        active_findings_count_before = active_findings_before["count"]
        notes_count_before = self.db_notes_count()

        # reimport exact same report
        with assertTestImportModelsCreated(self, reimports=1, affected_findings=0, untouched=4):
            self.reimport_scan_with_params(test_id, self.anchore_file_name, scan_type=self.scan_type_anchore)

        active_findings_after = self.get_test_findings_api(test_id, active=True)
        self.log_finding_summary_json_api(active_findings_after)
        self.assert_finding_count_json(active_findings_count_before, active_findings_after)

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    # import Zap0 with 4 findings
    # set 1 finding to active=False and false_positve=True
    # set 1 finding to active=False and out_of_scope=True
    # set 1 finding to active=False and risk_accepted=True
    # delete 1 finding
    # reimport Zap0 and only 1 finding must be active
    # the other 3 findings manually set to active=False must remain False
    def test_import_reimport_keep_false_positive_and_out_of_scope(self):
        logger.debug("importing zap0 with 4 findings, manually setting 3 findings to active=False, reimporting zap0 must return only 1 finding active=True")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)
        test_id = import0["test"]

        test_api_response = self.get_test_api(test_id)
        product_api_response = self.get_engagement_api(test_api_response["engagement"])
        product_id = product_api_response["product"]

        self.patch_product_api(product_id, {"enable_simple_risk_acceptance": True})

        active_findings_before = self.get_test_findings_api(test_id, active=True)
        self.assert_finding_count_json(4, active_findings_before)

        for finding in active_findings_before["results"]:
            if "Zap1" in finding["title"]:
                self.patch_finding_api(finding["id"], {"active": False,
                                                       "verified": False,
                                                       "false_p": True,
                                                       "out_of_scope": False,
                                                       "risk_accepted": False,
                                                       "is_mitigated": True})
            elif "Zap2" in finding["title"]:
                self.patch_finding_api(finding["id"], {"active": False,
                                                       "verified": False,
                                                       "false_p": False,
                                                       "out_of_scope": True,
                                                       "risk_accepted": False,
                                                       "is_mitigated": True})
            elif "Zap3" in finding["title"]:
                self.patch_finding_api(finding["id"], {"active": False,
                                                       "verified": False,
                                                       "false_p": False,
                                                       "out_of_scope": False,
                                                       "risk_accepted": True,
                                                       "is_mitigated": True})

        active_findings_before = self.get_test_findings_api(test_id, active=True)
        self.assert_finding_count_json(1, active_findings_before)

        for finding in active_findings_before["results"]:
            if "Zap5" in finding["title"]:
                self.delete_finding_api(finding["id"])

        active_findings_before = self.get_test_findings_api(test_id, active=True)
        self.assert_finding_count_json(0, active_findings_before)

        with assertTestImportModelsCreated(self, reimports=1, affected_findings=1, created=1, untouched=1):
            reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample0_filename)

        self.assertEqual(reimport0["test"], test_id)

        active_findings_after = self.get_test_findings_api(test_id, active=True)
        self.assert_finding_count_json(1, active_findings_after)

        active_findings_after = self.get_test_findings_api(test_id, active=False)
        self.assert_finding_count_json(3, active_findings_after)

        for finding in active_findings_after["results"]:
            if "Zap1" in finding["title"]:
                self.assertFalse(finding["active"])
                self.assertFalse(finding["verified"])
                self.assertTrue(finding["false_p"])
                self.assertFalse(finding["out_of_scope"])
                self.assertFalse(finding["risk_accepted"])
                self.assertTrue(finding["is_mitigated"])
            elif "Zap2" in finding["title"]:
                self.assertFalse(finding["active"])
                self.assertFalse(finding["verified"])
                self.assertFalse(finding["false_p"])
                self.assertTrue(finding["out_of_scope"])
                self.assertFalse(finding["risk_accepted"])
                self.assertTrue(finding["is_mitigated"])
            elif "Zap3" in finding["title"]:
                self.assertFalse(finding["active"])
                self.assertFalse(finding["verified"])
                self.assertFalse(finding["false_p"])
                self.assertFalse(finding["out_of_scope"])
                self.assertTrue(finding["risk_accepted"])
                self.assertTrue(finding["is_mitigated"])
            elif "Zap5" in finding["title"]:
                self.assertTrue(finding["active"])
                self.assertTrue(finding["verified"])
                self.assertFalse(finding["false_p"])
                self.assertFalse(finding["out_of_scope"])
                self.assertFalse(finding["risk_accepted"])
                self.assertFalse(finding["is_mitigated"])

    # import gitlab_dep_scan_components_filename with 6 findings
    # findings 1, 2 and 3 have the same component_name (golang.org/x/crypto) and the same CVE (CVE-2020-29652), but different component_version
    # findings 4 and 5 have the same component_name (golang.org/x/text) and the same CVE (CVE-2020-14040), but different component_version
    # finding 6 is different ("unique") from the others
    #
    # reimport gitlab_dep_scan_components_filename and the same 6 finding must be active
    #
    # the previous hashcode calculation for GitLab Dependency Scanning would ignore component_name and component_version,
    # which during the reimport would close findings 2, 3 and 5, because it would only check the finding's title and CVE
    #
    # since a project can have multiples versions (component_version) of the same dependency (component_name),
    # we must consider each finding unique, otherwise we would lose valid information
    def test_import_6_reimport_6_gitlab_dep_scan_component_name_and_version(self):

        import0 = self.import_scan_with_params(self.gitlab_dep_scan_components_filename,
                                               scan_type=self.scan_type_gtlab_dep_scan,
                                               minimum_severity="Info")
        test_id = import0["test"]
        active_findings_before = self.get_test_findings_api(test_id, active=True)
        self.assert_finding_count_json(6, active_findings_before)

        with assertTestImportModelsCreated(self, reimports=1, affected_findings=0, created=0, untouched=6):
            self.reimport_scan_with_params(test_id,
                                                       self.gitlab_dep_scan_components_filename,
                                                       scan_type=self.scan_type_gtlab_dep_scan,
                                                       minimum_severity="Info")

        active_findings_after = self.get_test_findings_api(test_id, active=True)
        self.assert_finding_count_json(6, active_findings_after)

        count = 0
        for finding in active_findings_after["results"]:
            if finding["component_version"] == "v0.0.0-20190219172222-a4c6cb3142f2" or finding["component_version"] == "v0.0.0-20190308221718-c2843e01d9a2" or finding["component_version"] == "v0.0.0-20200302210943-78000ba7a073":
                self.assertEqual("CVE-2020-29652: Nil Pointer Dereference", finding["title"])
                self.assertEqual("CVE-2020-29652", finding["vulnerability_ids"][0]["vulnerability_id"])
                self.assertEqual("golang.org/x/crypto", finding["component_name"])
                count = count + 1
            elif finding["component_version"] == "v0.3.0" or finding["component_version"] == "v0.3.2":
                self.assertEqual("CVE-2020-14040: Loop With Unreachable Exit Condition (Infinite Loop)", finding["title"])
                self.assertEqual("CVE-2020-14040", finding["vulnerability_ids"][0]["vulnerability_id"])
                self.assertEqual("golang.org/x/text", finding["component_name"])
                count = count + 1

        self.assertEqual(5, count)

    # import clair scan, testing:
    # parameter endpoint_to_add: each imported finding should be related to endpoint with id=1
    # close_old_findings functionality: secony (empty) import should close all findings from the first import
    def test_import_param_close_old_findings_with_additional_endpoint(self):
        logger.debug("importing clair report with additional endpoint")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.clair_few_findings, scan_type=self.scan_type_clair, close_old_findings=True, endpoint_to_add=1)

        test_id = import0["test"]
        test = self.get_test(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        # imported count must match count in the report
        self.assert_finding_count_json(4, findings)

        # imported findings should be active in the engagement
        engagement_findings = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False)
        self.assertEqual(engagement_findings.count(), 4)

        # findings should have only one endpoint, added with endpoint_to_add
        for finding in engagement_findings:
            self.assertEqual(finding.endpoints.count(), 1)
            self.assertEqual(finding.endpoints.first().id, 1)

        # reimport empty report
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, closed=4):
            self.import_scan_with_params(self.clair_empty, scan_type=self.scan_type_clair, close_old_findings=True, endpoint_to_add=1)

        # all findings from import0 should be closed now
        engagement_findings_count = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False).count()
        self.assertEqual(engagement_findings_count, 0)

    # close_old_findings functionality: second (empty) import should close all findings from the first import when setting the same service
    def test_import_param_close_old_findings_with_same_service(self):
        logger.debug("importing clair report with same service")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.clair_few_findings, scan_type=self.scan_type_clair, close_old_findings=True, service="service_1")

        test_id = import0["test"]
        test = self.get_test(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        # imported count must match count in the report
        self.assert_finding_count_json(4, findings)

        # imported findings should be active in the engagement
        engagement_findings = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False)
        self.assertEqual(engagement_findings.count(), 4)

        # reimport empty report
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, closed=4):
            self.import_scan_with_params(self.clair_empty, scan_type=self.scan_type_clair, close_old_findings=True, service="service_1")

        # all findings from import0 should be closed now
        engagement_findings_count = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False).count()
        self.assertEqual(engagement_findings_count, 0)

    # close_old_findings functionality: second (empty) import should not close findings from the first import when setting different services
    def test_import_param_close_old_findings_with_different_services(self):
        logger.debug("importing clair report with different services")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.clair_few_findings, scan_type=self.scan_type_clair, close_old_findings=True, service="service_1")

        test_id = import0["test"]
        test = self.get_test(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        # imported count must match count in the report
        self.assert_finding_count_json(4, findings)

        # imported findings should be active in the engagement
        engagement_findings = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False)
        self.assertEqual(engagement_findings.count(), 4)

        # reimport empty report
        with assertTestImportModelsCreated(self, imports=1, affected_findings=0, closed=0):
            self.import_scan_with_params(self.clair_empty, scan_type=self.scan_type_clair, close_old_findings=True, service="service_2")

        # no findings from import0 should be closed now
        engagement_findings_count = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False).count()
        self.assertEqual(engagement_findings_count, 4)

    # close_old_findings functionality: second (empty) import should not close findings from the first import when setting a service in the first import but none in the second import
    def test_import_param_close_old_findings_with_and_without_service_1(self):
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.clair_few_findings, scan_type=self.scan_type_clair, close_old_findings=True, service="service_1")

        test_id = import0["test"]
        test = self.get_test(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        # imported count must match count in the report
        self.assert_finding_count_json(4, findings)

        # imported findings should be active in the engagement
        engagement_findings = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False)
        self.assertEqual(engagement_findings.count(), 4)

        # reimport empty report
        with assertTestImportModelsCreated(self, imports=1, affected_findings=0, closed=0):
            self.import_scan_with_params(self.clair_empty, scan_type=self.scan_type_clair, close_old_findings=True, service=None)

        # no findings from import0 should be closed now
        engagement_findings_count = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False).count()
        self.assertEqual(engagement_findings_count, 4)

    # close_old_findings functionality: second (empty) import should not close findings from the first import when setting no service in the first import but one in the second import
    def test_import_param_close_old_findings_with_and_without_service_2(self):
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.import_scan_with_params(self.clair_few_findings, scan_type=self.scan_type_clair, close_old_findings=True, service=None)

        test_id = import0["test"]
        test = self.get_test(test_id)
        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        # imported count must match count in the report
        self.assert_finding_count_json(4, findings)

        # imported findings should be active in the engagement
        engagement_findings = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False)
        self.assertEqual(engagement_findings.count(), 4)

        # reimport empty report
        with assertTestImportModelsCreated(self, imports=1, affected_findings=0, closed=0):
            self.import_scan_with_params(self.clair_empty, scan_type=self.scan_type_clair, close_old_findings=True, service="service_2")

        # no findings from import0 should be closed now
        engagement_findings_count = Finding.objects.filter(test__engagement_id=1, test__test_type=test.test_type, active=True, is_mitigated=False).count()
        self.assertEqual(engagement_findings_count, 4)

    def test_import_reimport_generic(self):
        """
        This test do a basic import and re-import of a generic JSON report

        This test is useful because some features are only activated in generic JSON format
        """
        import0 = self.import_scan_with_params(self.generic_filename_with_file, scan_type="Generic Findings Import")

        test_id = import0["test"]

        # reimport exact same report
        with assertTestImportModelsCreated(self, reimports=1, untouched=1):
            reimport0 = self.reimport_scan_with_params(test_id, self.generic_filename_with_file, scan_type="Generic Findings Import")

        test_id2 = reimport0["test"]
        self.assertEqual(test_id, test_id2)

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)

        # reimported count must match count in xml report
        # we set verified=False in this reimport, but currently DD does not update this flag, so it's still True from previous import
        findings = self.get_test_findings_api(test_id, verified=True)
        self.assert_finding_count_json(0, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings_api(test_id, verified=False)
        self.assert_finding_count_json(1, findings)

    def test_import_nuclei_emptyc(self):
        """
        This test do a basic import of Nuclei report with no vulnerability

        This test is useful because Nuclei use jsonl for his format so it can generate empty files.
        It tests the condition limit of loading an empty file.
        """
        import0 = self.import_scan_with_params(self.nuclei_empty, scan_type="Nuclei Scan")

        test_id = import0["test"]

        reimport0 = self.reimport_scan_with_params(test_id, self.nuclei_empty, scan_type="Nuclei Scan")

        test_id2 = reimport0["test"]
        self.assertEqual(test_id, test_id2)

    def test_import_reimport_endpoint_where_eps_date_is_different(self):
        endpoint_count_before = self.db_endpoint_count()
        endpoint_status_count_before_active = self.db_endpoint_status_count(mitigated=False)
        endpoint_status_count_before_mitigated = self.db_endpoint_status_count(mitigated=True)

        with assertTestImportModelsCreated(self, imports=1, affected_findings=1, created=1):
            import0 = self.import_scan_with_params(self.gitlab_dast_file_name,
                                                   self.scan_type_gitlab_dast,
                                                   active=True,
                                                   verified=True)

        test_id = import0["test"]

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        self.assert_finding_count_json(1, findings)

        test = self.get_test_api(test_id)["id"]
        finding = Finding.objects.filter(test__engagement_id=1, test=test).first()
        self.assertEqual(finding.status_finding.count(), 1)

        original_date = finding.status_finding.first().date

        self.assertEqual(endpoint_count_before + 1, self.db_endpoint_count())
        self.assertEqual(endpoint_status_count_before_active + 1, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated, self.db_endpoint_status_count(mitigated=True))

        reimport0 = self.reimport_scan_with_params(test_id,
                                                   self.gitlab_dast_file_name,
                                                   scan_type=self.scan_type_gitlab_dast)
        test_id = reimport0["test"]

        findings = self.get_test_findings_api(test_id)
        self.log_finding_summary_json_api(findings)
        self.assert_finding_count_json(1, findings)

        finding = Finding.objects.filter(test__engagement_id=1, test=test).first()
        self.assertEqual(finding.status_finding.count(), 1)

        reimported_date = finding.status_finding.first().date
        self.assertEqual(original_date, reimported_date)

        self.assertEqual(endpoint_count_before + 1, self.db_endpoint_count())
        self.assertEqual(endpoint_status_count_before_active + 1, self.db_endpoint_status_count(mitigated=False))
        self.assertEqual(endpoint_status_count_before_mitigated, self.db_endpoint_status_count(mitigated=True))

    # test handling of vulnerability ids with import
    def test_import_reimport_vulnerability_ids(self):

        import0 = self.import_scan_with_params(self.anchore_grype_file_name, scan_type=self.anchore_grype_scan_type)

        test_id = import0["test"]
        test = Test.objects.get(id=test_id)
        findings = Finding.objects.filter(test=test)
        self.assertEqual(4, len(findings))
        self.assertEqual("GHSA-v6rh-hp5x-86rv", findings[3].cve)
        self.assertEqual(2, len(findings[3].vulnerability_ids))
        self.assertEqual("GHSA-v6rh-hp5x-86rv", findings[3].vulnerability_ids[0])
        self.assertEqual("CVE-2021-44420", findings[3].vulnerability_ids[1])

        test_type = Test_Type.objects.get(name=self.anchore_grype_scan_type)
        reimport_test = Test(
            engagement=test.engagement,
            test_type=test_type,
            scan_type=self.anchore_grype_scan_type,
            target_start=datetime.datetime.now(datetime.UTC),
            target_end=datetime.datetime.now(datetime.UTC),
        )
        reimport_test.save()

        self.reimport_scan_with_params(reimport_test.id, self.anchore_grype_file_name, scan_type=self.anchore_grype_scan_type)
        findings = Finding.objects.filter(test=reimport_test)
        self.assertEqual(4, len(findings))
        self.assertEqual("GHSA-v6rh-hp5x-86rv", findings[3].cve)
        self.assertEqual(2, len(findings[3].vulnerability_ids))
        self.assertEqual("GHSA-v6rh-hp5x-86rv", findings[3].vulnerability_ids[0])
        self.assertEqual("CVE-2021-44420", findings[3].vulnerability_ids[1])

    def test_import_history_reactivated_and_untouched_findings_do_not_mix(self):
        import0 = self.import_scan_with_params(self.generic_import_1, scan_type=self.scan_type_generic)
        test_id = import0["test"]
        # reimport the second report
        self.reimport_scan_with_params(test_id, self.generic_import_2, scan_type=self.scan_type_generic)
        # reimport the first report again
        self.reimport_scan_with_params(test_id, self.generic_import_1, scan_type=self.scan_type_generic)
        # Passing this test means an exception does not occur

    def test_dynamic_parsing_field_set_to_true(self):
        # Test that a generic finding import creates a new test type
        # with the dynamically_generated field set to True
        import0 = self.import_scan_with_params(self.generic_import_1, scan_type=self.scan_type_generic)
        test_id = import0["test"]
        # Fetch the test from the DB to access the test type
        test = Test.objects.get(id=test_id)
        self.assertTrue(test.test_type.dynamically_generated)

    def test_dynamic_parsing_field_set_to_false(self):
        # Test that a ZAP import does not create a new test type
        # and that the dynamically_generated field set to False
        import0 = self.import_scan_with_params(self.zap_sample0_filename)
        test_id = import0["test"]
        # Fetch the test from the DB to access the test type
        test = Test.objects.get(id=test_id)
        self.assertFalse(test.test_type.dynamically_generated)


class ImportReimportTestAPI(DojoAPITestCase, ImportReimportMixin):
    fixtures = ["dojo_testdata.json"]

    def __init__(self, *args, **kwargs):
        # super(ImportReimportMixin, self).__init__(*args, **kwargs)
        ImportReimportMixin.__init__(self, *args, **kwargs)
        # DojoAPITestCase.__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)

    def setUp(self):
        testuser = User.objects.get(username="admin")
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        # self.url = reverse(self.viewname + '-list')

    # Statistics only available in API Response
    # One testcase covering intial import, closing during reimport and reactivating during reimport

    # import 0 and then reimport 1 with zap4 as extra finding, zap1 closed and then reimport 0 again
    # - active findings count should be 4
    # - total  findings count should be 5
    # - zap1 active, zap4 inactive
    def test_import_0_reimport_1_active_verified_reimport_0_active_verified_statistics(self):
        logger.debug("reimporting updated zap xml report, 1 new finding and 1 no longer present, verified=True and then 0 again")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        self.assertEqual(import0["statistics"], {
            "after": {
                "info": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "low": {"active": 3, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 3},
                "medium": {"active": 1, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 1},
                "high": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "critical": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "total": {"active": 4, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 4},
            },
        })

        test_id = import0["test"]
        reimport1 = self.reimport_scan_with_params(test_id, self.zap_sample1_filename)

        self.assertEqual(reimport1["statistics"], {
            "after": {
                "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "low": {"active": 3, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 4, "verified": 0},
                "medium": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                "total": {"active": 4, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 5, "verified": 0}},
            "before": {
                "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "low": {"active": 3, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 3, "verified": 0},
                "medium": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                "total": {"active": 4, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 4, "verified": 0}},
            "delta": {
                "closed": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                    "medium": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "total": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0}},
                "created": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                    "medium": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "total": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0}},
                "left untouched": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 2, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 2, "verified": 0},
                    "medium": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                    "total": {"active": 3, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 3, "verified": 0}},
                "reactivated": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "medium": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "total": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0}},
            },
        })

        with assertTestImportModelsCreated(self, reimports=1, affected_findings=2, closed=1, reactivated=1, untouched=3):
            reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample0_filename)

        self.assertEqual(reimport0["statistics"], {
            "after": {
                "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "low": {"active": 3, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 4, "verified": 0},
                "medium": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                "total": {"active": 4, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 5, "verified": 0}},
            "before": {
                "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                "low": {"active": 3, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 4, "verified": 0},
                "medium": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                "total": {"active": 4, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 5, "verified": 0}},
            "delta": {
                "closed": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                    "medium": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "total": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 1, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0}},
                "created": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "medium": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "total": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0}},
                "left untouched": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 2, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 2, "verified": 0},
                    "medium": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                    "total": {"active": 3, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 3, "verified": 0}},
                "reactivated": {
                    "critical": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "high": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "info": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "low": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0},
                    "medium": {"active": 0, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 0, "verified": 0},
                    "total": {"active": 1, "duplicate": 0, "false_p": 0, "is_mitigated": 0, "out_of_scope": 0, "risk_accepted": 0, "total": 1, "verified": 0}},
            },
        })

    # without import history, there are no delta statistics
    @override_settings(TRACK_IMPORT_HISTORY=False)
    def test_import_0_reimport_1_active_verified_reimport_0_active_verified_statistics_no_history(self):
        logger.debug("reimporting updated zap xml report, 1 new finding and 1 no longer present, verified=True and then 0 again")

        import0 = self.import_scan_with_params(self.zap_sample0_filename)

        self.assertEqual(import0["statistics"], {
            "after": {
                "info": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "low": {"active": 3, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 3},
                "medium": {"active": 1, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 1},
                "high": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "critical": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "total": {"active": 4, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 4},
            },
        })

        test_id = import0["test"]

        reimport1 = self.reimport_scan_with_params(test_id, self.zap_sample1_filename)

        self.assertEqual(reimport1["statistics"], {
            "before": {
                "info": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "low": {"active": 3, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 3},
                "medium": {"active": 1, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 1},
                "high": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "critical": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "total": {"active": 4, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 4},
            },
            "after": {
                "info": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "low": {"active": 3, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 1, "risk_accepted": 0, "total": 4},
                "medium": {"active": 1, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 1},
                "high": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "critical": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "total": {"active": 4, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 1, "risk_accepted": 0, "total": 5},
            },
        })

        with assertTestImportModelsCreated(self, reimports=0, affected_findings=0, closed=0, reactivated=0, untouched=0):
            reimport0 = self.reimport_scan_with_params(test_id, self.zap_sample0_filename)

        self.assertEqual(reimport0["statistics"], {
            "before": {
                "info": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "low": {"active": 3, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 1, "risk_accepted": 0, "total": 4},
                "medium": {"active": 1, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 1},
                "high": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "critical": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "total": {"active": 4, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 1, "risk_accepted": 0, "total": 5},
            },
            "after": {
                "info": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "low": {"active": 3, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 1, "risk_accepted": 0, "total": 4},
                "medium": {"active": 1, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 1},
                "high": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "critical": {"active": 0, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 0, "risk_accepted": 0, "total": 0},
                "total": {"active": 4, "verified": 0, "duplicate": 0, "false_p": 0, "out_of_scope": 0, "is_mitigated": 1, "risk_accepted": 0, "total": 5},
            },
        })
    # Reimport tests to test Scan_Date logic (usecase not supported on UI)

    # reimport zap scan without dates (non existing test, so import is called inside DD)
    # - reimport
    # - no scan_date overrides date not set by parser
    def test_reimport_default_scan_date_parser_not_sets_date(self):
        logger.debug("importing zap xml report with date set by parser")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.reimport_scan_with_params(None, self.zap_sample0_filename, active=False, verified=False,
                product_name=PRODUCT_NAME_DEFAULT, engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, str(timezone.localtime(timezone.now()).date()))

    # reimport acunetix scan with dates (non existing test, so import is called inside DD)
    # - reimport
    # - deafult scan_date (today) does not overrides date set by parser
    def test_reimport_default_scan_date_parser_sets_date(self):
        logger.debug("importing original acunetix xml report")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=1, created=1):
            import0 = self.reimport_scan_with_params(None, self.acunetix_file_name, scan_type=self.scan_type_acunetix, active=False, verified=False,
                product_name=PRODUCT_NAME_DEFAULT, engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, "2018-09-24")

    # reimport zap scan without dates (non existing test, so import is called inside DD)
    # - reimport
    # - set scan_date overrides date not set by parser
    def test_reimport_set_scan_date_parser_not_sets_date(self):
        logger.debug("importing original zap xml report")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=4, created=4):
            import0 = self.reimport_scan_with_params(None, self.zap_sample0_filename, active=False, verified=False, scan_date="2006-12-26",
                            product_name=PRODUCT_NAME_DEFAULT, engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, "2006-12-26")

    # reimport acunetix scan with dates (non existing test, so import is called inside DD)
    # - reimport
    # - set scan_date overrides date set by parser
    def test_reimport_set_scan_date_parser_sets_date(self):
        logger.debug("importing acunetix xml report with date set by parser")
        with assertTestImportModelsCreated(self, imports=1, affected_findings=1, created=1):
            import0 = self.reimport_scan_with_params(None, self.acunetix_file_name, scan_type=self.scan_type_acunetix, active=False, verified=False, scan_date="2006-12-26",
                            product_name=PRODUCT_NAME_DEFAULT, engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)

        test_id = import0["test"]
        findings = self.get_test_findings_api(test_id, active=False, verified=False)
        self.log_finding_summary_json_api(findings)

        # Get the date
        date = findings["results"][0]["date"]
        self.assertEqual(date, "2006-12-26")


class ImportReimportTestUI(DojoAPITestCase, ImportReimportMixin):
    fixtures = ["dojo_testdata.json"]
    client_ui = Client()

    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        ImportReimportMixin.__init__(self, *args, **kwargs)
        # super(ImportReimportMixin, self).__init__(*args, **kwargs)
        # super(DojoAPITestCase, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)

    def setUp(self):
        # still using the API to verify results
        testuser = User.objects.get(username="admin")
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        # self.url = reverse(self.viewname + '-list')

        self.client_ui = Client()
        self.client_ui.force_login(self.get_test_admin())

    # def remove_non_ui_params(self, kwargs):
    #     for param in ['product_type_name', 'product_name', 'engagement_name', 'test_title', 'auto_create_context', 'engagement']:
    #         if param in kwargs:
    #             kwargs.pop(param)
    #     return kwargs

    # override methods to use UI
    def import_scan_with_params(self, *args, **kwargs):
        return self.import_scan_with_params_ui(*args, **kwargs)

    def reimport_scan_with_params(self, *args, **kwargs):
        return self.reimport_scan_with_params_ui(*args, **kwargs)

    def import_scan_ui(self, engagement, payload):
        logger.debug("import_scan payload %s", payload)
        # response = self.client_ui.post(reverse('import_scan_results', args=(engagement, )), urlencode(payload), content_type='application/x-www-form-urlencoded')
        response = self.client_ui.post(reverse("import_scan_results", args=(engagement, )), payload)

        test = Test.objects.get(id=response.url.split("/")[-1])
        # f = open('response.html', 'w+')
        # f.write(str(response.content, 'utf-8'))
        # f.close()
        self.assertEqual(302, response.status_code, response.content[:1000])
        return {"test": test.id}

    def reimport_scan_ui(self, test, payload):
        response = self.client_ui.post(reverse("re_import_scan_results", args=(test, )), payload)
        self.assertEqual(302, response.status_code, response.content[:1000])
        test = Test.objects.get(id=response.url.split("/")[-1])
        return {"test": test.id}

    def import_scan_with_params_ui(self, filename, scan_type="ZAP Scan", engagement=1, minimum_severity="Low", *, active=True, verified=False,
                                   push_to_jira=None, endpoint_to_add=None, tags=None, close_old_findings=False, scan_date=None, service=None,
                                   forceActive=False, forceVerified=False):

        activePayload = "not_specified"
        if forceActive:
            activePayload = "force_to_true"
        elif not active:
            activePayload = "force_to_false"

        verifiedPayload = "not_specified"
        if forceVerified:
            verifiedPayload = "force_to_true"
        elif not verified:
            verifiedPayload = "force_to_false"

        with open(filename, encoding="utf-8") as testfile:
            payload = {
                    "minimum_severity": minimum_severity,
                    "active": activePayload,
                    "verified": verifiedPayload,
                    "scan_type": scan_type,
                    "file": testfile,
                    "environment": 1,
                    "version": "1.0.1",
                    "close_old_findings": close_old_findings,
            }

            if push_to_jira is not None:
                payload["push_to_jira"] = push_to_jira

            if endpoint_to_add is not None:
                payload["endpoints"] = [endpoint_to_add]

            if tags is not None:
                payload["tags"] = tags

            if scan_date is not None:
                payload["scan_date"] = scan_date

            if service is not None:
                payload["service"] = service

            return self.import_scan_ui(engagement, payload)

    def reimport_scan_with_params_ui(self, test_id, filename, scan_type="ZAP Scan", minimum_severity="Low", *, active=True, verified=False, push_to_jira=None, tags=None, close_old_findings=True, scan_date=None):
        # Mimic old functionality for active/verified to avoid breaking tests
        activePayload = "force_to_true"
        if not active:
            activePayload = "force_to_false"
        verifiedPayload = "force_to_true"
        if not verified:
            verifiedPayload = "force_to_false"

        with open(filename, encoding="utf-8") as testfile:
            payload = {
                    "minimum_severity": minimum_severity,
                    "active": activePayload,
                    "verified": verifiedPayload,
                    "scan_type": scan_type,
                    "file": testfile,
                    "version": "1.0.1",
                    "close_old_findings": close_old_findings,
            }

            if push_to_jira is not None:
                payload["push_to_jira"] = push_to_jira

            if tags is not None:
                payload["tags"] = tags

            if scan_date is not None:
                payload["scan_date"] = scan_date

            return self.reimport_scan_ui(test_id, payload)

# Observations:
# - When reopening a mitigated finding, almost no fields are updated such as title, description, severity, impact, references, ....
# - Basically fields (and req/resp) are only stored on the initial import, reimporting only changes the active/mitigated/verified flags + some dates + notes
# - (Re)Import could provide some more statistics of imported findings (reimport: new, mitigated, reactivated, untouched, ...)
# - Endpoints that are no longer present in the scan that is imported, are still retained by DD, which makes them look "active" in the product view
# - Maybe test severity threshold?
# - Not sure,but I doubt the Endpoint_Status objects are created at all during import/reimport? Or are those not needed?
