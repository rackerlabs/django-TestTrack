# from unittest import skip
import logging

from crum import impersonate
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from vcr import VCR

import dojo.risk_acceptance.helper as ra_helper
from dojo.jira_link import helper as jira_helper
from dojo.models import Finding, Finding_Group, JIRA_Instance, Risk_Acceptance, User

from .dojo_test_case import DojoVCRAPITestCase, get_unit_tests_path, toggle_system_setting_boolean

logger = logging.getLogger(__name__)

# these tests are using vcrpy to record traffic to and from JIRA: https://vcrpy.readthedocs.io/en/latest/usage.html
# after being recorded, the traffic is used for future runs of the tests
# this allows us to locally develop tests, run them, make them work against a real JIRA instance.
# after that we can commit the tests AND the recordings (cassettes).

# the record_mode is set to 'once' by default. this means it will replay responses from the cassette, if there is a cassette.
# otherwise it will create a new cassette and record responses. on the next run the cassette wil be used.

# if changing tests, you can best remove all cassettes before running the tests.
# or you can temporarily set the record_mode to all the make it always go to the real JIRA and record all the traffic.

# when the tests are finished, you'll have to set the assertCassettePlayed method to make it assert
# that all entries in the cassette have been used by the test.

# if you need some credentials for the Defect Dojo JIRA Cloud instance, contact one of the moderators

# some senstive data is filtered out by the filter_headers config option below
# as well as some custom callback functions to filter out cookies.
# please check the recorded files on sensitive data before committing to git


class JIRAImportAndPushTestApi(DojoVCRAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        DojoVCRAPITestCase.__init__(self, *args, **kwargs)

    def assert_cassette_played(self):
        if True:  # set to True when committing. set to False when recording new test cassettes
            self.assertTrue(self.cassette.all_played)

    def _get_vcr(self, **kwargs):
        my_vcr = super()._get_vcr(**kwargs)
        my_vcr.record_mode = "once"
        my_vcr.path_transformer = VCR.ensure_suffix(".yaml")
        my_vcr.filter_headers = ["Authorization", "X-Atlassian-Token"]
        my_vcr.cassette_library_dir = get_unit_tests_path() / "vcr" / "jira"  # TODO: check this
        # filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
        my_vcr.before_record_request = self.before_record_request
        my_vcr.before_record_response = self.before_record_response
        return my_vcr

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.testuser = User.objects.get(username="admin")
        self.testuser.usercontactinfo.block_execution = True
        self.testuser.usercontactinfo.save()
        token = Token.objects.get(user=self.testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.scans_path = "/scans/"
        self.zap_sample5_filename = self.scans_path + "zap/5_zap_sample_one.xml"
        self.npm_groups_sample_filename = self.scans_path + "npm_audit/many_vuln_with_groups.json"
        self.client.force_login(self.get_test_admin())

    def test_import_no_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_with_push_to_jira_is_false(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=False, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_push_to_jira(self):
        # 7 findings, 5 unique component_name+component_version
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        # all findings should be in a group, so no JIRA issues for individual findings
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_push_to_jira_epic_as_issue_type(self):
        jira_instance = JIRA_Instance.objects.get(id=2)
        # we choose issue type Epic and test if it can be created successfully.
        # if yes, it means we have successfully populated the Epic Name custom field which is mandatory in JIRA
        jira_instance.default_issue_type = "Epic"
        jira_instance.save()
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_push_to_jira_is_false_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=False, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_with_push_to_jira_is_false_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=False, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_reimport_no_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_no_push_to_jira_reimport_push_to_jira_false(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=False, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_no_push_to_jira_reimport_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=True, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_reimport_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_reimport_no_push_to_jira_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_reimport_no_push_to_jira_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)

        self.reimport_scan_with_params(test_id, self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_reimport_push_to_jira_is_false_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.get_jira_issue_updated_map(test_id)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=False, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # when sending in identical data to JIRA, JIRA does NOT update the updated timestamp....
        # self.assert_jira_updated_map_changed(test_id, updated_map)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_reimport_push_to_jira_is_false_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        updated_map = self.get_jira_issue_updated_map(test_id)

        self.reimport_scan_with_params(test_id, self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=False, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # when sending in identical data to JIRA, JIRA does NOT update the updated timestamp....
        # self.assert_jira_updated_map_changed(test_id, updated_map)
        self.assert_jira_updated_map_unchanged(test_id, updated_map)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_push_to_jira_reimport_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Get one of the findings from the test
        finding_id = Finding.objects.filter(test__id=test_id).first().id
        self.get_jira_issue_updated(finding_id)
        # re-import and see status change
        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=True, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.get_jira_issue_updated(finding_id)
        # when sending in identical data to JIRA, JIRA does NOT update the updated timestamp....
        # self.assert_jira_updated_change(pre_jira_status, post_jira_status)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_twice_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        import1 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id1 = import1["test"]
        # duplicates shouldn't be sent to JIRA
        self.assert_jira_issue_count_in_test(test_id1, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def add_risk_acceptance(self, eid, data_risk_accceptance, fid=None):
        args = (eid, fid) if fid else (eid,)
        response = self.client.post(reverse("add_risk_acceptance", args=args), data_risk_accceptance)
        self.assertEqual(302, response.status_code, response.content[:1000])
        return response

    def test_import_grouped_reopen_expired_sla(self):
        # steps
        # import scan, make sure they are in grouped JIRA
        # risk acceptance all the grouped findings, make sure they are closed in JIRA
        # expire risk acceptance on all grouped findings, make sure they are open in JIRA
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        findings = self.get_test_findings_api(test_id)
        finding_id = findings["results"][0]["id"]

        ra_data = {
            "name": "Accept: Unit test",
            "accepted_findings": [],
            "recommendation": "A",
            "recommendation_details": "recommendation 1",
            "decision": "A",
            "decision_details": "it has been decided!",
            "accepted_by": "pointy haired boss",
            "owner": 1,
            "expiration_date": "2024-12-31",
            "reactivate_expired": True,
            }

        for finding in findings["results"]:
            ra_data["accepted_findings"].append(finding["id"])

        pre_jira_status = self.get_jira_issue_status(finding_id)

        response = self.add_risk_acceptance(1, data_risk_accceptance=ra_data)
        self.assertEqual("/engagement/1", response.url)

        # We do this to update the JIRA
        for finding in ra_data["accepted_findings"]:
            self.patch_finding_api(finding, {"push_to_jira": True})

        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertNotEqual(pre_jira_status, post_jira_status)

        pre_jira_status = post_jira_status
        ra = Risk_Acceptance.objects.last()
        ra_helper.expire_now(ra)
        # We do this to update the JIRA
        for finding in ra_data["accepted_findings"]:
            self.patch_finding_api(finding, {"push_to_jira": True})

        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertNotEqual(pre_jira_status, post_jira_status)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_with_groups_twice_push_to_jira(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)

        import1 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id1 = import1["test"]
        # duplicates shouldn't be sent to JIRA
        self.assert_jira_issue_count_in_test(test_id1, 0)
        self.assert_jira_group_issue_count_in_test(test_id1, 0)

    def test_import_twice_push_to_jira_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        import1 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id1 = import1["test"]
        # duplicates shouldn't be sent to JIRA
        self.assert_jira_issue_count_in_test(test_id1, 0)
        self.assert_jira_group_issue_count_in_test(test_id1, 0)

    def test_create_edit_update_finding(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding_id = findings["results"][0]["id"]

        # logger.debug('finding_id: %s', finding_id)

        # use existing finding as template, but change some fields to make it not a duplicate
        finding_details = self.get_finding_api(finding_id)
        del finding_details["id"]
        del finding_details["push_to_jira"]

        finding_details["title"] = "jira api test 1"
        self.post_new_finding_api(finding_details)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        finding_details["title"] = "jira api test 2"
        self.post_new_finding_api(finding_details, push_to_jira=True)
        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        finding_details["title"] = "jira api test 3"
        new_finding_json = self.post_new_finding_api(finding_details)
        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.patch_finding_api(new_finding_json["id"], {"push_to_jira": False})
        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True})
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        pre_jira_status = self.get_jira_issue_status(new_finding_json["id"])

        self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True,
                                                        "is_mitigated": True,
                                                        "active": False})
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        post_jira_status = self.get_jira_issue_status(new_finding_json["id"])
        self.assertNotEqual(pre_jira_status, post_jira_status)

        finding_details["title"] = "jira api test 4"
        new_finding_json = self.post_new_finding_api(finding_details)
        new_finding_id = new_finding_json["id"]
        del new_finding_json["id"]

        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.put_finding_api(new_finding_id, new_finding_json, push_to_jira=False)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.put_finding_api(new_finding_id, new_finding_json, push_to_jira=True)
        self.assert_jira_issue_count_in_test(test_id, 3)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.put_finding_api(new_finding_id, new_finding_json, push_to_jira=True)
        self.assert_jira_issue_count_in_test(test_id, 3)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.assert_cassette_played()

    def test_groups_create_edit_update_finding(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id, component_name="negotiator")

        self.assertEqual(len(findings["results"]), 2)

        finding_details = self.get_finding_api(findings["results"][0]["id"])
        finding_group_id = findings["results"][0]["finding_groups"][0]["id"]

        del finding_details["id"]
        del finding_details["push_to_jira"]

        # push a finding should result in pushing the group instead
        self.patch_finding_api(findings["results"][0]["id"], {"push_to_jira": True})

        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 1)

        # push second finding from the same group should not result in a new jira issue

        self.patch_finding_api(findings["results"][1]["id"], {"push_to_jira": True})
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 1)

        pre_jira_status = self.get_jira_issue_status(findings["results"][0]["id"])
        # close both findings
        self.patch_finding_api(findings["results"][0]["id"], {"active": False, "is_mitigated": True, "push_to_jira": True})
        self.patch_finding_api(findings["results"][1]["id"], {"active": False, "is_mitigated": True, "push_to_jira": True})

        post_jira_status = self.get_jira_issue_status(findings["results"][0]["id"])
        # both findings inactive -> should update status in JIRA
        self.assertNotEqual(pre_jira_status, post_jira_status)

        # new finding, not pushed to JIRA

        # use existing finding as template, but change some fields to make it not a duplicate
        self.get_finding_api(findings["results"][0]["id"])

        finding_details["title"] = "jira api test 1"
        self.post_new_finding_api(finding_details)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 1)

        # another new finding, pushed to JIRA
        # same component_name, but not yet in a group, so finding pushed to JIRA

        finding_details["title"] = "jira api test 2"
        new_finding_json = self.post_new_finding_api(finding_details, push_to_jira=True)
        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 1)

        # no way to set finding group easily via API yet
        Finding_Group.objects.get(id=finding_group_id).findings.add(Finding.objects.get(id=new_finding_json["id"]))

        self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True})

        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 1)

        # another new finding, pushed to JIRA, different component_name / different group

        finding_details["title"] = "jira api test 3"
        finding_details["component_name"] = "pg"
        new_finding_json = self.post_new_finding_api(finding_details)
        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 1)

        findings = self.get_test_findings_api(test_id, component_name="pg")

        finding_group_id = findings["results"][0]["finding_groups"][0]["id"]

        # no way to set finding group easily via API yet
        Finding_Group.objects.get(id=finding_group_id).findings.add(Finding.objects.get(id=new_finding_json["id"]))

        self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True})

        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 2)

        self.assert_cassette_played()

    def test_import_with_push_to_jira_add_comment(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding_id = findings["results"][0]["id"]

        self.post_finding_notes_api(finding_id, "testing note. creating it and pushing it to JIRA")
        self.patch_finding_api(finding_id, {"push_to_jira": True})
        # Make sure the number of comments match
        self.assertEqual(len(self.get_jira_comments(finding_id)), 1)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_add_comments_then_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=False, verified=True)
        test_id = import0["test"]

        findings = self.get_test_findings_api(test_id)

        finding_id = findings["results"][0]["id"]

        self.post_finding_notes_api(finding_id, "testing note. creating it and pushing it to JIRA")
        self.post_finding_notes_api(finding_id, "testing second note. creating it and pushing it to JIRA")
        self.patch_finding_api(finding_id, {"push_to_jira": True})

        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Make sure the number of comments match
        self.assertEqual(len(self.get_jira_comments(finding_id)), 2)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_with_push_to_jira_add_tags(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding = Finding.objects.get(id=findings["results"][0]["id"])

        tags = ["tag1", "tag2"]
        self.post_finding_tags_api(finding.id, tags)
        self.patch_finding_api(finding.id, {"push_to_jira": True})

        # Connect to jira to get the new issue
        jira_instance = jira_helper.get_jira_instance(finding)
        jira = jira_helper.get_jira_connection(jira_instance)
        issue = jira.issue(finding.jira_issue.jira_id)

        # Assert that the tags match
        self.assertEqual(issue.fields.labels, tags)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_with_push_to_jira_update_tags(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding = Finding.objects.get(id=findings["results"][0]["id"])

        tags = ["tag1", "tag2"]
        self.post_finding_tags_api(finding.id, tags)
        self.patch_finding_api(finding.id, {"push_to_jira": True})

        # Connect to jira to get the new issue
        jira_instance = jira_helper.get_jira_instance(finding)
        jira = jira_helper.get_jira_connection(jira_instance)
        issue = jira.issue(finding.jira_issue.jira_id)

        # Assert that the tags match
        self.assertEqual(issue.fields.labels, tags)

        tags_new = [*tags, "tag3", "tag4"]
        self.post_finding_tags_api(finding.id, tags_new)
        self.patch_finding_api(finding.id, {"push_to_jira": True})

        # Connect to jira to get the new issue
        jira_instance = jira_helper.get_jira_instance(finding)
        jira = jira_helper.get_jira_connection(jira_instance)
        issue = jira.issue(finding.jira_issue.jira_id)

        # Assert that the tags match
        self.assertEqual(issue.fields.labels, tags_new)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    def test_import_with_push_to_jira_not_verified_with_enforced_verified(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=False)
        test_id = import0["test"]
        # This scan file has two active findings, so we should not push either of them
        self.assert_jira_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    def test_import_with_push_to_jira_not_verified_without_enforced_verified(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=False)
        test_id = import0["test"]
        # This scan file has two active findings, so we should not push both of them
        self.assert_jira_issue_count_in_test(test_id, 2)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_engagement_epic_creation(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=True)
        self.create_engagement_epic(eng)
        self.assertTrue(eng.has_jira_issue)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_enabled_create_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=True)
        self.create_engagement_epic(eng)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 2)
        # Ensure issue are actually in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=True)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_enabled_no_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=True)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 0)
        # Ensure issue are actually not in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=False)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_disabled_create_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=False)
        self.create_engagement_epic(eng)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 0)
        # Ensure issue are actually in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=False)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_disabled_no_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=False)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 0)
        # Ensure issue are actually not in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=False)

        self.assert_cassette_played()

    # creation of epic via the UI is already tested in test_jira_config_engagement_epic, so
    # we take a shortcut here as creating an engagement with epic mapping via the API is not implemented yet
    def create_engagement_epic(self, engagement):
        with impersonate(self.testuser):
            return jira_helper.add_epic(engagement)

    def assert_epic_issue_count(self, engagement, count):
        jira_issues = self.get_epic_issues(engagement)
        self.assertEqual(count, len(jira_issues))
