import uuid

from crum import impersonate

from dojo.models import Finding, User
from unittests.dojo_test_case import DojoTestCase, toggle_system_setting_boolean


class ProductGradeTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def run(self, result=None):
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.save()

        # unit tests are running without any user, which will result in actions like dedupe happening in the celery process
        # this doesn't work in unittests as unittests are using an in memory sqlite database and celery can't see the data
        # so we're running the test under the admin user context and set block_execution to True
        with impersonate(testuser):
            super().run(result)

    def create_default_data(self):
        self.product = self.create_product("Product Grader")
        self.engagement = self.create_engagement("engagement name", product=self.product)
        self.test = self.create_test(engagement=self.engagement, scan_type="ZAP Scan")

    def setUp(self):
        self.create_default_data()
        self.default_finding_options = {
            "description": "",
            "active": True,
            "test": self.test,
        }

    def tearDown(self):
        self.product.delete()

    def create_finding_on_test(self, severity, *, verified=True):
        Finding.objects.create(title=str(uuid.uuid4()), severity=severity, verified=verified, **self.default_finding_options)

    def create_single_critical_and_assert_grade(self, expected_grade, *, verified=False):
        self.assertIsNone(self.product.prod_numeric_grade)
        # Add a single critical finding
        self.create_finding_on_test(severity="Critical", verified=verified)
        # See that the grade does not degrade at all
        self.assertEqual(self.product.prod_numeric_grade, expected_grade)

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", True)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_true_and_enforced_verified_product_grading_true_with_verified_is_true(self):
        self.create_single_critical_and_assert_grade(40, verified=True)

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", False)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_true_and_enforced_verified_product_grading_false_with_verified_is_true(self):
        self.create_single_critical_and_assert_grade(40, verified=True)

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", True)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_false_and_enforced_verified_product_grading_true_with_verified_is_true(self):
        self.create_single_critical_and_assert_grade(40, verified=True)

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", False)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_false_and_enforced_verified_product_grading_false_with_verified_is_true(self):
        self.create_single_critical_and_assert_grade(40, verified=True)

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", True)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_true_and_enforced_verified_product_grading_true_with_verified_is_false(self):
        self.create_single_critical_and_assert_grade(100, verified=False)

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", False)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_true_and_enforced_verified_product_grading_false_with_verified_is_false(self):
        self.create_single_critical_and_assert_grade(100, verified=False)

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", True)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_false_and_enforced_verified_product_grading_true_with_verified_is_false(self):
        self.create_single_critical_and_assert_grade(100, verified=False)

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_product_grading", False)  # noqa: FBT003
    def test_grade_change_enforced_verified_globally_false_and_enforced_verified_product_grading_false_with_verified_is_false(self):
        self.create_single_critical_and_assert_grade(40, verified=False)
