# from unittest import skip
import logging

from vcr import VCR

from .dojo_test_case import DojoVCRTestCase, get_unit_tests_path
from .test_jira_config_engagement import JIRAConfigEngagementBase

logger = logging.getLogger(__name__)


class JIRAConfigEngagementEpicTest(DojoVCRTestCase, JIRAConfigEngagementBase):
    fixtures = ["dojo_testdata.json"]

    product_id = 999

    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        DojoVCRTestCase.__init__(self, *args, **kwargs)

    def assert_cassette_played(self):
        if True:  # set to True when committing. set to False when recording new test cassettes
            self.assertTrue(self.cassette.all_played)

    def _get_vcr(self, **kwargs):
        my_vcr = super(DojoVCRTestCase, self)._get_vcr(**kwargs)
        my_vcr.record_mode = "once"
        my_vcr.path_transformer = VCR.ensure_suffix(".yaml")
        my_vcr.filter_headers = ["Authorization", "X-Atlassian-Token"]
        my_vcr.cassette_library_dir = str(get_unit_tests_path() / "vcr" / "jira")
        # filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
        my_vcr.before_record_request = self.before_record_request
        my_vcr.before_record_response = self.before_record_response
        return my_vcr

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.user = self.get_test_admin()
        self.client.force_login(self.user)
        self.user.usercontactinfo.block_execution = True
        self.user.usercontactinfo.save()
        # product 3 has no jira project config, double check to make sure someone didn't molest the fixture
        # running this in __init__ throws database access denied error
        self.product_id = 1  # valid JIRA config
        # product = Product.objects.get(id=self.product_id)
        # self.assertIsNone(jira_helper.get_jira_project(product))

    def get_new_engagement_with_jira_project_data_and_epic_mapping(self):
        return {
            "name": "new engagement",
            "description": "new description",
            "lead": 1,
            "product": self.product_id,
            "target_start": "2070-11-27",
            "target_end": "2070-12-04",
            "status": "Not Started",
            "jira-project-form-jira_instance": 2,
            "jira-project-form-project_key": "NTEST",
            "jira-project-form-epic_issue_type_name": "Epic",
            "jira-project-form-enabled": "True",
            "jira-project-form-product_jira_sla_notification": "on",
            "jira-project-form-enable_engagement_epic_mapping": "on",
            "jira-epic-form-push_to_jira": "on",
        }

    def add_engagement_with_jira_project_and_epic_mapping(self, expected_delta_jira_project_db=0, expect_redirect_to=None, *, expect_200=False):
        return self.add_engagement_jira_with_data(self.get_new_engagement_with_jira_project_data_and_epic_mapping(), expected_delta_jira_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def test_add_engagement_with_jira_project_and_epic_mapping(self):
        engagement = self.add_engagement_with_jira_project_and_epic_mapping(expected_delta_jira_project_db=1)
        self.assertIsNotNone(engagement)
        self.assertIsNotNone(engagement.jira_project)
        self.assertTrue(engagement.has_jira_issue)
