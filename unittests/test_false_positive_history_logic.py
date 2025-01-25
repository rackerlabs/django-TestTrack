import logging
from datetime import datetime

from crum import impersonate

from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    System_Settings,
    Test,
    User,
    _copy_model_util,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

# Test data summary. All engagements have deduplication_on_engagement set to true.
#
# product 1: Python How-to
#       engagement 2: April monthly engagement (dedupe_inside: True)
#               test 13: ZAP Scan (algo=hash_code, dynamic=True)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#
# product 2: Security How-to
#       engagement 1: 1st Quarter Engagement (dedupe_inside: True)
#               test 3: ZAP Scan (algo=hash_code, dynamic=True)
#               findings:
#                       2   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: False: dup_id: None: hash_code: 5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7: eps: 0: notes: []: uid: None
#                       3   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7: eps: 0: notes: []: uid: None
#                       4   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7: eps: 0: notes: []: uid: None
#                       5   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7: eps: 0: notes: []: uid: None
#                       6   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7: eps: 0: notes: []: uid: None
#                       7   : "DUMMY FINDING       ": High : act: False: ver: False: mit: False: dup: False: dup_id: None: hash_code: c89d25e445b088ba339908f68e15e3177b78d22f3039d1bfea51c4be251bf4e0: eps: 0: notes: [1]: uid: None
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#               test 14: ZAP Scan (algo=hash_code, dynamic=True)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#       engagement 4: April monthly engagement (dedupe_inside: True)
#               test 4: ZAP Scan (algo=hash_code, dynamic=True)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#       engagement 5: April monthly engagement (dedupe_inside: True)
#               test 55: Checkmarx Scan detailed (algo=unique_id_from_tool, dynamic=False)
#               findings:
#                       124 : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: False: dup_id: None: hash_code: 9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa: eps: 0: notes: []: uid: 12345
#                       125 : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: True : dup_id: None: hash_code: 9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa: eps: 0: notes: []: uid: 12345
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#               test 66: Checkmarx Scan detailed (algo=unique_id_from_tool, dynamic=False)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#               test 77: Veracode Scan (algo=unique_id_from_tool_or_hash_code, dynamic=False)
#               findings:
#                       224 : "UID Impact Test Find": Low  : act: True : ver: True : mit: False: dup: False: dup_id: None: hash_code: 6f8d0bf970c14175e597843f4679769a4775742549d90f902ff803de9244c7e1: eps: 0: notes: []: uid: 6789
#                       225 : "UID Impact Test Find": Low  : act: True : ver: True : mit: False: dup: True : dup_id: 224 : hash_code: 6f8d0bf970c14175e597843f4679769a4775742549d90f902ff803de9244c7e1: eps: 0: notes: []: uid: 6789
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#               test 88: Veracode Scan (algo=unique_id_from_tool_or_hash_code, dynamic=False)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#       engagement 6: April monthly engagement (dedupe_inside: True)
#       engagement 3: weekly engagement (dedupe_inside: True)
#               test 33: Xanitizer Scan Findings Import (algo=legacy, dynamic=False)
#               findings:
#                       22  : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: False: dup_id: None: hash_code: 9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa: eps: 0: notes: []: uid: None
#                       23  : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: True : dup_id: 22  : hash_code: 9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa: eps: 0: notes: []: uid: None
#                       24  : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: True : dup_id: 22  : hash_code: 9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa: eps: 0: notes: []: uid: None
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#
# product 3: Security Podcast


class TestFalsePositiveHistoryLogic(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def run(self, result=None):
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.save()

        # Unit tests are running without any user, which will result in actions like dedupe happening in the celery process
        # this doesn't work in unittests as unittests are using an in memory sqlite database and celery can't see the data
        # so we're running the test under the admin user context and set block_execution to True
        with impersonate(testuser):
            super().run(result)

    def setUp(self):
        logger.debug("disabling dedupe")
        self.disable_dedupe()
        logger.debug("enabling false positive history")
        self.enable_false_positive_history()
        self.enable_retroactive_false_positive_history()
        self.log_summary()

    def tearDown(self):
        self.log_summary()

    # ----------------------------------------------- #
    # Tests with hash_code as deduplication algorithm #
    # ----------------------------------------------- #

    # Same Test #

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_test(self):
        # Copy finding 2 and store it in the same test (to test retroactive replication)
        find_created_before_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it in the same test
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=2, test_id=3, hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=2, test_id=3, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 2 and store it in the same test (to test disabled retroactive replication)
        find_created_before_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it in the same test
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=2, test_id=3, hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=2, test_id=3, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_test_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it in the same test
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.save()
        # Assert that finding belongs to the same test and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=2, test_id=3, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    # Finding 7 in Product 2, Engagement 1, Test 3 (has a different hash code)
    def test_fp_history_different_hash_code_same_test(self):
        # Copy finding 7 and store it in the same test (to test retroactive replication)
        find_created_before_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 7 and store it in the same test
        find_created_after_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=7, test_id=3, not_hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=7, test_id=3, not_hash_code=find_2.hash_code)

    # Same Engagement Different Test #

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_engagement_different_test(self):
        # Copy finding 2 and store it at Product 2, Engagement 1, Test 14 (to test retroactive replication)
        find_created_before_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_before_mark.test = Test.objects.get(id=14)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 2, Engagement 1, Test 14
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=14)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=2, engagement_id=1, not_test_id=3, hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=2, engagement_id=1, not_test_id=3, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_engagement_different_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 2 and store it at Product 2, Engagement 1, Test 14 (to test disabled retroactive replication)
        find_created_before_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_before_mark.test = Test.objects.get(id=14)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 2, Engagement 1, Test 14
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=14)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=2, engagement_id=1, not_test_id=3, hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=2, engagement_id=1, not_test_id=3, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_engagement_different_test_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 2, Engagement 1, Test 14
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=14)
        find_created_after_mark.save()
        # Assert that finding belongs to the same engagement but in a different test and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=7, engagement_id=1, not_test_id=3, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    # Finding 7 in Product 2, Engagement 1, Test 3 (has a different hash code)
    def test_fp_history_different_hash_code_same_engagement_different_test(self):
        # Copy finding 7 and store it at Product 2, Engagement 1, Test 14 (to test retroactive replication)
        find_created_before_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_before_mark.test = Test.objects.get(id=14)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 7 and store it at Product 2, Engagement 1, Test 14
        find_created_after_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_after_mark.test = Test.objects.get(id=14)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=7, engagement_id=1, not_test_id=3, not_hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=7, engagement_id=1, not_test_id=3, not_hash_code=find_2.hash_code)

    # Same Product Different Engagement #

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_product_different_engagement(self):
        # Copy finding 2 and store it at Product 2, Engagement 4, Test 4 (to test retroactive replication)
        find_created_before_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_before_mark.test = Test.objects.get(id=4)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 2, Engagement 4, Test 4
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=4)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=2, product_id=2, not_engagement_id=1, hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=2, product_id=2, not_engagement_id=1, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_product_different_engagement_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 2 and store it at Product 2, Engagement 4, Test 4 (to test disabled retroactive replication)
        find_created_before_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_before_mark.test = Test.objects.get(id=4)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 2, Engagement 4, Test 4
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=4)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=2, product_id=2, not_engagement_id=1, hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=2, product_id=2, not_engagement_id=1, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_same_product_different_engagement_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 2, Engagement 4, Test 4
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=4)
        find_created_after_mark.save()
        # Assert that finding belongs to the same engagement but in a different test and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=2, product_id=2, not_engagement_id=1, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    # Finding 7 in Product 2, Engagement 1, Test 3 (has a different hash code)
    def test_fp_history_different_hash_code_same_product_different_engagement(self):
        # Copy finding 7 and store it at Product 2, Engagement 4, Test 4 (to test retroactive replication)
        find_created_before_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_before_mark.test = Test.objects.get(id=4)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 7 and store it at Product 2, Engagement 4, Test 4
        find_created_after_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_after_mark.test = Test.objects.get(id=4)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=7, product_id=2, not_engagement_id=1, not_hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=7, product_id=2, not_engagement_id=1, not_hash_code=find_2.hash_code)

    # Different Product #

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_different_product(self):
        # Copy finding 2 and store it at Product 1, Engagement 2, Test 13 (to test retroactive replication)
        find_created_before_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_before_mark.test = Test.objects.get(id=13)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 1, Engagement 2, Test 13
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=13)
        find_created_after_mark.save()
        # Assert that both findings belongs to a different product and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=2, not_product_id=2, hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=2, not_product_id=2, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    def test_fp_history_equal_hash_code_different_product_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 2 and store it at Product 1, Engagement 2, Test 13
        find_created_after_mark, find_2 = self.copy_and_reset_finding(find_id=2)
        find_created_after_mark.test = Test.objects.get(id=13)
        find_created_after_mark.save()
        # Assert that finding belongs to a different product and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=2, not_product_id=2, hash_code=find_2.hash_code)

    # Finding 2 in Product 2, Engagement 1, Test 3
    # Finding 7 in Product 2, Engagement 1, Test 3 (has a different hash code)
    def test_fp_history_different_hash_code_different_product(self):
        # Copy finding 7 and store it at Product 1, Engagement 2, Test 13 (to test retroactive replication)
        find_created_before_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_before_mark.test = Test.objects.get(id=13)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 2 as fp
        find_2 = Finding.objects.get(id=2)
        find_2.false_p = True
        find_2.save()
        # Copy finding 7 and store it at Product 1, Engagement 2, Test 13
        find_created_after_mark, _find_7 = self.copy_and_reset_finding(find_id=7)
        find_created_after_mark.test = Test.objects.get(id=13)
        find_created_after_mark.save()
        # Assert that both findings belongs to a different product and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=7, not_product_id=2, not_hash_code=find_2.hash_code)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=7, not_product_id=2, not_hash_code=find_2.hash_code)

    # --------------------------------------------------------- #
    # Tests with unique_id_from_tool as deduplication algorithm #
    # --------------------------------------------------------- #

    # Same Test #

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_test(self):
        # Copy finding 124 and store it in the same test (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it in the same test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=124, test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=124, test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 124 and store it in the same test (to test disabled retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it in the same test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=124, test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_test_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it in the same test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.save()
        # Assert that finding belongs to the same test and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_different_unique_id_same_test(self):
        # Copy finding 124, change unique_id and store it in the same test (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark = self.change_finding_unique_id(find_created_before_mark)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124, change unique_id and store it in the same test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark = self.change_finding_unique_id(find_created_after_mark)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, test_id=55, not_unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, test_id=55, not_unique_id_from_tool=find_124.unique_id_from_tool)

    # Same Engagement Different Test #

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_engagement_different_test(self):
        # Copy finding 124 and store it at Product 2, Engagement 5, Test 66 (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.test = Test.objects.get(id=66)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, Engagement 5, Test 66
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = Test.objects.get(id=66)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=124, engagement_id=5, not_test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=124, engagement_id=5, not_test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_engagement_different_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 124 and store it at Product 2, Engagement 5, Test 66 (to test disabled retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.test = Test.objects.get(id=66)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, Engagement 5, Test 66
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = Test.objects.get(id=66)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, engagement_id=5, not_test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=124, engagement_id=5, not_test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_engagement_different_test_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, Engagement 5, Test 66
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = Test.objects.get(id=66)
        find_created_after_mark.save()
        # Assert that finding belongs to the same engagement but in a different test and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, engagement_id=5, not_test_id=55, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_different_unique_id_same_engagement_different_test(self):
        # Copy finding 124, change unique_id and store it at Product 2, Engagement 5, Test 66 (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark = self.change_finding_unique_id(find_created_before_mark)
        find_created_before_mark.test = Test.objects.get(id=66)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124 = Finding.objects.get(id=124)
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, Engagement 5, Test 66
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.unique_id_from_tool = "somefakeid123"
        find_created_after_mark.test = Test.objects.get(id=66)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, engagement_id=5, not_test_id=55, not_unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, engagement_id=5, not_test_id=55, not_unique_id_from_tool=find_124.unique_id_from_tool)

    # Same Product Different Engagement #

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_product_different_engagement(self):
        # Create new test and new engagament in the same product
        find_124 = Finding.objects.get(id=124)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_124)
        # Copy finding 124 and store it at Product 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same product but in a different engagement and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=124, product_id=2, not_engagement_id=5, unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=124, product_id=2, not_engagement_id=5, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_product_different_engagement_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Create new test and new engagament in the same product
        find_124 = Finding.objects.get(id=124)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_124)
        # Copy finding 124 and store it at Product 2, New Engagement, New Test (to test disabled retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same product but in a different engagement and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, product_id=2, not_engagement_id=5, unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=124, product_id=2, not_engagement_id=5, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_same_product_different_engagement_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Create new test and new engagament in the same product
        find_124 = Finding.objects.get(id=124)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_124)
        # Mark finding 124 as fp
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that finding belongs to the same product but in a different engagement and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, product_id=2, not_engagement_id=5, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_different_unique_id_same_product_different_engagement(self):
        # Create new test and new engagament in the same product
        find_124 = Finding.objects.get(id=124)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_124)
        # Copy finding 124, change unique_id and store it at Product 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark = self.change_finding_unique_id(find_created_before_mark)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124.false_p = True
        find_124.save()
        # Copy finding 124, change unique_id and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark = self.change_finding_unique_id(find_created_after_mark)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same product but in a different engagement and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, product_id=2, not_engagement_id=5, not_unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, product_id=2, not_engagement_id=5, not_unique_id_from_tool=find_124.unique_id_from_tool)

    # Different Product #

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_different_product(self):
        # Create new test, new engagament and new product
        find_124 = Finding.objects.get(id=124)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_124)
        # Copy finding 124 and store it at Product 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same product but in a different engagement and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, not_product_id=2, unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, not_product_id=2, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_equal_unique_id_different_product_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Create new test, new engagament and new product
        find_124 = Finding.objects.get(id=124)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_124)
        # Mark finding 124 as fp
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that finding belongs to the same product but in a different engagement and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, not_product_id=2, unique_id_from_tool=find_124.unique_id_from_tool)

    # Finding 124 in Product 2, Engagement 5, Test 55
    def test_fp_history_different_unique_id_different_product(self):
        # Create new test, new engagament and new product
        find_124 = Finding.objects.get(id=124)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_124)
        # Copy finding 124 and store it at Product 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_before_mark.unique_id_from_tool = "somefakeid123"
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 124 as fp
        find_124.false_p = True
        find_124.save()
        # Copy finding 124 and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_124 = self.copy_and_reset_finding(find_id=124)
        find_created_after_mark.unique_id_from_tool = "somefakeid123"
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same product but in a different engagement and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=124, not_product_id=2, not_unique_id_from_tool=find_124.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=124, not_product_id=2, not_unique_id_from_tool=find_124.unique_id_from_tool)

    # ---------------------------------------------------------------------- #
    # Tests with unique_id_from_tool_or_hash_code as deduplication algorithm #
    # ---------------------------------------------------------------------- #

    # Same Test #

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_test(self):
        # Copy finding 224, change hash_code, and store it in the same test (to test retroactive replication)
        find_created_before_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_hash_code = self.change_finding_hash_code(find_created_before_mark_diff_hash_code)
        find_created_before_mark_diff_hash_code.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False)
        # Copy finding 224, change unique_id, and store it in the same test (to test retroactive replication)
        find_created_before_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_unique_id = self.change_finding_unique_id(find_created_before_mark_diff_unique_id)
        find_created_before_mark_diff_unique_id.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it in the same test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it in the same test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.save()
        # Assert that both findings has a different hash_code, an equal unique_id,
        # belongs to the same test and are marked as fp
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=True, not_pk=224, test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=True, not_pk=224, test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that both findings has an equal hash_code, a different unique_id,
        # belongs to the same test and are marked as fp
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=True, not_pk=224, test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=True, not_pk=224, test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 224, change hash_code, and store it in the same test (to test disabled retroactive replication)
        find_created_before_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_hash_code = self.change_finding_hash_code(find_created_before_mark_diff_hash_code)
        find_created_before_mark_diff_hash_code.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False)
        # Copy finding 224, change unique_id, and store it in the same test (to test disabled retroactive replication)
        find_created_before_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_unique_id = self.change_finding_unique_id(find_created_before_mark_diff_unique_id)
        find_created_before_mark_diff_unique_id.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it in the same test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it in the same test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.save()
        # Assert that both findings has a different hash_code, an equal unique_id,
        # belongs to the same test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False, not_pk=224, test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=True, not_pk=224, test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that both findings has an equal hash_code, a different unique_id,
        # belongs to the same test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False, not_pk=224, test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=True, not_pk=224, test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_test_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it in the same test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it in the same test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.save()
        # Assert that finding has a different hash_code, an equal unique_id,
        # belongs to the same test and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=False, not_pk=224, test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that finding has an equal hash_code, a different unique_id,
        # belongs to the same test and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=False, not_pk=224, test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_different_unique_id_or_hash_code_same_test(self):
        # Copy finding 224, change hash_code, change unique_id and store it in the same test (to test retroactive replication)
        find_created_before_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark = self.change_finding_hash_code(find_created_before_mark)
        find_created_before_mark = self.change_finding_unique_id(find_created_before_mark)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, change unique_id and store it in the same test
        find_created_after_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark = self.change_finding_hash_code(find_created_after_mark)
        find_created_after_mark = self.change_finding_unique_id(find_created_after_mark)
        find_created_after_mark.save()
        # Assert that both findings has a different hash_code, a different unique_id,
        # belongs to the same test and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=224, test_id=77, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=224, test_id=77, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Same Engagement Different Test #

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_engagement_different_test(self):
        # Copy finding 224, change hash_code, and store it at Product 2, Engagement 5, Test 88 (to test retroactive replication)
        find_created_before_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_hash_code = self.change_finding_hash_code(find_created_before_mark_diff_hash_code)
        find_created_before_mark_diff_hash_code.test = Test.objects.get(id=88)
        find_created_before_mark_diff_hash_code.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False)
        # Copy finding 224, change unique_id, and store it at Product 2, Engagement 5, Test 88 (to test retroactive replication)
        find_created_before_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_unique_id = self.change_finding_unique_id(find_created_before_mark_diff_unique_id)
        find_created_before_mark_diff_unique_id.test = Test.objects.get(id=88)
        find_created_before_mark_diff_unique_id.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at Product 2, Engagement 5, Test 88
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = Test.objects.get(id=88)
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at Product 2, Engagement 5, Test 88
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = Test.objects.get(id=88)
        find_created_after_mark_diff_unique_id.save()
        # Assert that both findings has a different hash_code, an equal unique_id,
        # belongs to the same engagement but in a different test and are marked as fp
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=True, not_pk=224, engagement_id=5, not_test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=True, not_pk=224, engagement_id=5, not_test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that both findings has an equal hash_code, a different unique_id,
        # belongs to the same engagement but in a different test and are marked as fp
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=True, not_pk=224, engagement_id=5, not_test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=True, not_pk=224, engagement_id=5, not_test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_engagement_different_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 224, change hash_code, and store it at Product 2, Engagement 5, Test 88 (to test disabled retroactive replication)
        find_created_before_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_hash_code = self.change_finding_hash_code(find_created_before_mark_diff_hash_code)
        find_created_before_mark_diff_hash_code.test = Test.objects.get(id=88)
        find_created_before_mark_diff_hash_code.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False)
        # Copy finding 224, change unique_id, and store it at Product 2, Engagement 5, Test 88 (to test disabled retroactive replication)
        find_created_before_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_unique_id = self.change_finding_unique_id(find_created_before_mark_diff_unique_id)
        find_created_before_mark_diff_unique_id.test = Test.objects.get(id=88)
        find_created_before_mark_diff_unique_id.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at Product 2, Engagement 5, Test 88
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = Test.objects.get(id=88)
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at Product 2, Engagement 5, Test 88
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = Test.objects.get(id=88)
        find_created_after_mark_diff_unique_id.save()
        # Assert that both findings has a different hash_code, an equal unique_id,
        # belongs to the same engagement but in a different test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False, not_pk=224, engagement_id=5, not_test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=True, not_pk=224, engagement_id=5, not_test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that both findings has an equal hash_code, a different unique_id,
        # belongs to the same engagement but in a different test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False, not_pk=224, engagement_id=5, not_test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=True, not_pk=224, engagement_id=5, not_test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_engagement_different_test_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at Product 2, Engagement 5, Test 88
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = Test.objects.get(id=88)
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at Product 2, Engagement 5, Test 88
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = Test.objects.get(id=88)
        find_created_after_mark_diff_unique_id.save()
        # Assert that finding has a different hash_code, an equal unique_id,
        # belongs to the same engagement but in a different test and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=False, not_pk=224, engagement_id=5, not_test_id=77, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that finding has an equal hash_code, a different unique_id,
        # belongs to the same engagement but in a different test and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=False, not_pk=224, engagement_id=5, not_test_id=77, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_different_unique_id_or_hash_code_same_engagement_different_test(self):
        # Copy finding 224, change hash_code, change unique_id and store it at Product 2, Engagement 5, Test 88 (to test retroactive replication)
        find_created_before_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark = self.change_finding_hash_code(find_created_before_mark)
        find_created_before_mark = self.change_finding_unique_id(find_created_before_mark)
        find_created_before_mark.test = Test.objects.get(id=88)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, change unique_id and store it at Product 2, Engagement 5, Test 88
        find_created_after_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark = self.change_finding_hash_code(find_created_after_mark)
        find_created_after_mark = self.change_finding_unique_id(find_created_after_mark)
        find_created_after_mark.test = Test.objects.get(id=88)
        find_created_after_mark.save()
        # Assert that both findings has a different hash_code, a different unique_id,
        # belongs to the same engagement but in a different test and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=224, engagement_id=5, not_test_id=77, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=224, engagement_id=5, not_test_id=77, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Same Product Different Engagement #

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_product_different_engagement(self):
        # Create new test and new engagament in the same product
        find_224 = Finding.objects.get(id=224)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_224)
        # Copy finding 224, change hash_code, and store it at Product 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_hash_code = self.change_finding_hash_code(find_created_before_mark_diff_hash_code)
        find_created_before_mark_diff_hash_code.test = test_new
        find_created_before_mark_diff_hash_code.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False)
        # Copy finding 224, change unique_id, and store it at Product 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_unique_id = self.change_finding_unique_id(find_created_before_mark_diff_unique_id)
        find_created_before_mark_diff_unique_id.test = test_new
        find_created_before_mark_diff_unique_id.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at Product 2, New Engagement, New Test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = test_new
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at Product 2, New Engagement, New Test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = test_new
        find_created_after_mark_diff_unique_id.save()
        # Assert that both findings has a different hash_code, an equal unique_id,
        # belongs to the same product but in a different engagement and are marked as fp
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=True, not_pk=224, product_id=2, not_engagement_id=5, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=True, not_pk=224, product_id=2, not_engagement_id=5, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that both findings has an equal hash_code, a different unique_id,
        # belongs to the same product but in a different engagement and are marked as fp
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=True, not_pk=224, product_id=2, not_engagement_id=5, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=True, not_pk=224, product_id=2, not_engagement_id=5, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_product_different_engagement_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Create new test and new engagament in the same product
        find_224 = Finding.objects.get(id=224)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_224)
        # Copy finding 224, change hash_code, and store it at Product 2, New Engagement, New Test (to test disabled retroactive replication)
        find_created_before_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_hash_code = self.change_finding_hash_code(find_created_before_mark_diff_hash_code)
        find_created_before_mark_diff_hash_code.test = test_new
        find_created_before_mark_diff_hash_code.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False)
        # Copy finding 224, change unique_id, and store it at Product 2, New Engagement, New Test (to test disabled retroactive replication)
        find_created_before_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_unique_id = self.change_finding_unique_id(find_created_before_mark_diff_unique_id)
        find_created_before_mark_diff_unique_id.test = test_new
        find_created_before_mark_diff_unique_id.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at Product 2, New Engagement, New Test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = test_new
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at Product 2, New Engagement, New Test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = test_new
        find_created_after_mark_diff_unique_id.save()
        # Assert that both findings has a different hash_code, an equal unique_id,
        # belongs to the same product but in a different engagement and only one of them is marked as fp
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False, not_pk=224, product_id=2, not_engagement_id=5, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=True, not_pk=224, product_id=2, not_engagement_id=5, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that both findings has an equal hash_code, a different unique_id,
        # belongs to the same product but in a different engagement and only one of them is marked as fp
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False, not_pk=224, product_id=2, not_engagement_id=5, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=True, not_pk=224, product_id=2, not_engagement_id=5, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_same_product_different_engagement_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Create new test and new engagament in the same product
        find_224 = Finding.objects.get(id=224)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_224)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at Product 2, New Engagement, New Test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = test_new
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at Product 2, New Engagement, New Test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = test_new
        find_created_after_mark_diff_unique_id.save()
        # Assert that finding has a different hash_code, an equal unique_id,
        # belongs to the same product but in a different engagement and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=False, not_pk=224, product_id=2, not_engagement_id=5, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that finding has an equal hash_code, a different unique_id,
        # belongs to the same product but in a different engagement and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=False, not_pk=224, product_id=2, not_engagement_id=5, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_different_unique_id_or_hash_code_same_product_different_engagement(self):
        # Create new test and new engagament in the same product
        find_224 = Finding.objects.get(id=224)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_224)
        # Copy finding 224, change hash_code, change unique_id and store it at Product 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark = self.change_finding_hash_code(find_created_before_mark)
        find_created_before_mark = self.change_finding_unique_id(find_created_before_mark)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, change unique_id and store it at Product 2, New Engagement, New Test
        find_created_after_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark = self.change_finding_hash_code(find_created_after_mark)
        find_created_after_mark = self.change_finding_unique_id(find_created_after_mark)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings has a different hash_code, a different unique_id,
        # belongs to the same product but in a different engagement and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=224, product_id=2, not_engagement_id=5, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=224, product_id=2, not_engagement_id=5, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Different Product #

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_different_product(self):
        # Create new test, new engagament and new product
        find_224 = Finding.objects.get(id=224)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_224)
        # Copy finding 224, change hash_code, and store it at New Product, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_hash_code = self.change_finding_hash_code(find_created_before_mark_diff_hash_code)
        find_created_before_mark_diff_hash_code.test = test_new
        find_created_before_mark_diff_hash_code.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False)
        # Copy finding 224, change unique_id, and store it at New Product, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark_diff_unique_id = self.change_finding_unique_id(find_created_before_mark_diff_unique_id)
        find_created_before_mark_diff_unique_id.test = test_new
        find_created_before_mark_diff_unique_id.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at New Product, New Engagement, New Test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = test_new
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at New Product, New Engagement, New Test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = test_new
        find_created_after_mark_diff_unique_id.save()
        # Assert that both findings has a different hash_code, an equal unique_id,
        # belongs to a different product and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_hash_code, false_p=False, not_pk=224, not_product_id=2, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=False, not_pk=224, not_product_id=2, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that both findings has an equal hash_code, a different unique_id,
        # belongs to a different product and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_unique_id, false_p=False, not_pk=224, not_product_id=2, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=False, not_pk=224, not_product_id=2, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_equal_unique_id_or_hash_code_different_product_dedupe_enabled(self):
        # Create new test, new engagament and new product
        find_224 = Finding.objects.get(id=224)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_224)
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, and store it at New Product, New Engagement, New Test
        find_created_after_mark_diff_hash_code, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_hash_code = self.change_finding_hash_code(find_created_after_mark_diff_hash_code)
        find_created_after_mark_diff_hash_code.test = test_new
        find_created_after_mark_diff_hash_code.save()
        # Copy finding 224, change unique_id, and store it at New Product, New Engagement, New Test
        find_created_after_mark_diff_unique_id, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark_diff_unique_id = self.change_finding_unique_id(find_created_after_mark_diff_unique_id)
        find_created_after_mark_diff_unique_id.test = test_new
        find_created_after_mark_diff_unique_id.save()
        # Assert that finding has a different hash_code, an equal unique_id,
        # belongs to a different product and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_hash_code, false_p=False, not_pk=224, not_product_id=2, not_hash_code=find_224.hash_code, unique_id_from_tool=find_224.unique_id_from_tool)
        # Assert that finding has an equal hash_code, a different unique_id,
        # belongs to a different product and is NOT marked as fp
        self.assert_finding(find_created_after_mark_diff_unique_id, false_p=False, not_pk=224, not_product_id=2, hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # Finding 224 in Product 2, Engagement 5, Test 77
    def test_fp_history_different_unique_id_or_hash_code_different_product(self):
        # Create new test, new engagament and new product
        find_224 = Finding.objects.get(id=224)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_224)
        # Copy finding 224, change hash_code, change unique_id and store it at New Product, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_before_mark = self.change_finding_hash_code(find_created_before_mark)
        find_created_before_mark = self.change_finding_unique_id(find_created_before_mark)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 224 as fp
        find_224 = Finding.objects.get(id=224)
        find_224.false_p = True
        find_224.save()
        # Copy finding 224, change hash_code, change unique_id and store it at New Product, New Engagement, New Test
        find_created_after_mark, find_224 = self.copy_and_reset_finding(find_id=224)
        find_created_after_mark = self.change_finding_hash_code(find_created_after_mark)
        find_created_after_mark = self.change_finding_unique_id(find_created_after_mark)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings has a different hash_code, a different unique_id,
        # belongs to the same product but in a different engagement and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=224, not_product_id=2, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=224, not_product_id=2, not_hash_code=find_224.hash_code, not_unique_id_from_tool=find_224.unique_id_from_tool)

    # -------------------------------------------- #
    # Tests with legacy as deduplication algorithm #
    # -------------------------------------------- #

    # Same Test #

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_test(self):
        # Copy finding 22 and store it in the same test (to test retroactive replication)
        find_created_before_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it in the same test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=22, test_id=33, title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=22, test_id=33, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Copy finding 22 and store it in the same test (to test disabled retroactive replication)
        find_created_before_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it in the same test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.save()
        # Assert that both findings belongs to the same test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=22, test_id=33, title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=22, test_id=33, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_test_dedupe_enabled(self):
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it in the same test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.save()
        # Assert that finding belongs to the same test and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=22, test_id=33, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_different_legacy_same_test(self):
        # Copy finding 22, change title and store it in the same test (to test retroactive replication)
        find_created_before_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_title = self.change_finding_title(find_created_before_mark_diff_title)
        find_created_before_mark_diff_title.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_title, false_p=False)
        # Copy finding 22, change severity and store it in the same test (to test retroactive replication)
        find_created_before_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_severity = self.change_finding_severity(find_created_before_mark_diff_severity)
        find_created_before_mark_diff_severity.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22, change title and store it in the same test
        find_created_after_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_title = self.change_finding_title(find_created_after_mark_diff_title)
        find_created_after_mark_diff_title.save()
        # Copy finding 22, change severity and store it in the same test
        find_created_after_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_severity = self.change_finding_severity(find_created_after_mark_diff_severity)
        find_created_after_mark_diff_severity.save()
        # Assert that both findings has a different title , an equal severity,
        # belongs to the same test and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_title, false_p=False, not_pk=22, test_id=33, not_title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_title, false_p=False, not_pk=22, test_id=33, not_title=find_22.title, severity=find_22.severity)
        # Assert that both findings has an equal title , a different severity,
        # belongs to the same test and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False, not_pk=22, test_id=33, title=find_22.title, not_severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_severity, false_p=False, not_pk=22, test_id=33, title=find_22.title, not_severity=find_22.severity)

    # Same Engagement Different Test #

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_engagement_different_test(self):
        # Create new test
        find_22 = Finding.objects.get(id=22)
        test_new = self.create_new_test_from_finding(find_22)
        # Copy finding 22 and store it at Produt 2, Engagement 3, New Test (to test retroactive replication)
        find_created_before_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at Produt 2, Engagement 3, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=22, engagement_id=3, not_test_id=33, title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=22, engagement_id=3, not_test_id=33, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_engagement_different_test_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Create new test
        find_22 = Finding.objects.get(id=22)
        test_new = self.create_new_test_from_finding(find_22)
        # Copy finding 22 and store it at Produt 2, Engagement 3, New Test (to test disabled retroactive replication)
        find_created_before_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at Produt 2, Engagement 3, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same engagement but in a different test and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=22, engagement_id=3, not_test_id=33, title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=22, engagement_id=3, not_test_id=33, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_engagement_different_test_dedupe_enabled(self):
        # Create new test
        find_22 = Finding.objects.get(id=22)
        test_new = self.create_new_test_from_finding(find_22)
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at Produt 2, Engagement 3, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that finding belongs to the same engagement but in a different test and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=22, engagement_id=3, not_test_id=33, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_different_legacy_same_engagement_different_test(self):
        # Create new test
        find_22 = Finding.objects.get(id=22)
        test_new = self.create_new_test_from_finding(find_22)
        # Copy finding 22, change title and store it at Produt 2, Engagement 3, New Test (to test retroactive replication)
        find_created_before_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_title = self.change_finding_title(find_created_before_mark_diff_title)
        find_created_before_mark_diff_title.test = test_new
        find_created_before_mark_diff_title.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_title, false_p=False)
        # Copy finding 22, change severity and store it at Produt 2, Engagement 3, New Test (to test retroactive replication)
        find_created_before_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_severity = self.change_finding_severity(find_created_before_mark_diff_severity)
        find_created_before_mark_diff_severity.test = test_new
        find_created_before_mark_diff_severity.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22, change severity and store it at Produt 2, Engagement 3, New Test
        find_created_after_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_title = self.change_finding_title(find_created_after_mark_diff_title)
        find_created_after_mark_diff_title.test = test_new
        find_created_after_mark_diff_title.save()
        # Copy finding 22, change severity and store it at Produt 2, Engagement 3, New Test
        find_created_after_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_severity = self.change_finding_severity(find_created_after_mark_diff_severity)
        find_created_after_mark_diff_severity.test = test_new
        find_created_after_mark_diff_severity.save()
        # Assert that both findings has a different title , an equal severity,
        # belongs to the same engagement but in a different test and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_title, false_p=False, not_pk=22, engagement_id=3, not_test_id=33, not_title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_title, false_p=False, not_pk=22, engagement_id=3, not_test_id=33, not_title=find_22.title, severity=find_22.severity)
        # Assert that both findings has an equal title , a different severity,
        # belongs to the same engagement but in a different test and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False, not_pk=22, engagement_id=3, not_test_id=33, title=find_22.title, not_severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_severity, false_p=False, not_pk=22, engagement_id=3, not_test_id=33, title=find_22.title, not_severity=find_22.severity)

    # Same Product Different Engagement #

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_product_different_engagement(self):
        # Create new test and new engagement
        find_22 = Finding.objects.get(id=22)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_22)
        # Copy finding 22 and store it at Produt 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at Produt 2, New Engagement, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same product but in a different engagement and are marked as fp
        self.assert_finding(find_created_before_mark, false_p=True, not_pk=22, product_id=2, not_engagement_id=3, title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=22, product_id=2, not_engagement_id=3, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_product_different_engagement_non_retroactive(self):
        # Disable retroactive FP history
        self.disable_retroactive_false_positive_history()
        # Create new test and new engagement
        find_22 = Finding.objects.get(id=22)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_22)
        # Copy finding 22 and store it at Produt 2, New Engagement, New Test (to test disabled retroactive replication)
        find_created_before_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at Produt 2, New Engagement, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to the same product but in a different engagement and only one of them is marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=22, product_id=2, not_engagement_id=3, title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark, false_p=True, not_pk=22, product_id=2, not_engagement_id=3, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_same_product_different_engagement_dedupe_enabled(self):
        # Create new test and new engagement
        find_22 = Finding.objects.get(id=22)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_22)
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at Produt 2, New Engagement, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that finding belongs to the same product but in a different engagement and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=22, product_id=2, not_engagement_id=3, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_different_legacy_same_product_different_engagement(self):
        # Create new test and new engagement
        find_22 = Finding.objects.get(id=22)
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(find_22)
        # Copy finding 22, change title and store it at Produt 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_title = self.change_finding_title(find_created_before_mark_diff_title)
        find_created_before_mark_diff_title.test = test_new
        find_created_before_mark_diff_title.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_title, false_p=False)
        # Copy finding 22, change severity and store it at Produt 2, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_severity = self.change_finding_severity(find_created_before_mark_diff_severity)
        find_created_before_mark_diff_severity.test = test_new
        find_created_before_mark_diff_severity.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22, change severity and store it at Produt 2, New Engagement, New Test
        find_created_after_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_title = self.change_finding_title(find_created_after_mark_diff_title)
        find_created_after_mark_diff_title.test = test_new
        find_created_after_mark_diff_title.save()
        # Copy finding 22, change severity and store it at Produt 2, New Engagement, New Test
        find_created_after_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_severity = self.change_finding_severity(find_created_after_mark_diff_severity)
        find_created_after_mark_diff_severity.test = test_new
        find_created_after_mark_diff_severity.save()
        # Assert that both findings has a different title , an equal severity,
        # belongs to the same product but in a engagement test and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_title, false_p=False, not_pk=22, product_id=2, not_engagement_id=3, not_title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_title, false_p=False, not_pk=22, product_id=2, not_engagement_id=3, not_title=find_22.title, severity=find_22.severity)
        # Assert that both findings has an equal title , a different severity,
        # belongs to the same product but in a different engagement and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False, not_pk=22, product_id=2, not_engagement_id=3, title=find_22.title, not_severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_severity, false_p=False, not_pk=22, product_id=2, not_engagement_id=3, title=find_22.title, not_severity=find_22.severity)

    # Different Product #

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_different_product(self):
        # Create new test, new engagement and new product
        find_22 = Finding.objects.get(id=22)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_22)
        # Copy finding 22 and store it at New Produt, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark.test = test_new
        find_created_before_mark.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at New Produt, New Engagement, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that both findings belongs to a different product and are NOT marked as fp
        self.assert_finding(find_created_before_mark, false_p=False, not_pk=22, not_product_id=2, title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=22, not_product_id=2, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_equal_legacy_different_product_dedupe_enabled(self):
        # Create new test, new engagement and new product
        find_22 = Finding.objects.get(id=22)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_22)
        # Enable deduplication
        self.enable_dedupe()
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22 and store it at New Produt, New Engagement, New Test
        find_created_after_mark, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark.test = test_new
        find_created_after_mark.save()
        # Assert that finding belongs to a different product and is NOT marked as fp
        self.assert_finding(find_created_after_mark, false_p=False, not_pk=22, not_product_id=2, title=find_22.title, severity=find_22.severity)

    # Finding 22 in Product 2, Engagement 3, Test 33
    def test_fp_history_different_legacy_different_product(self):
        # Create new test, new engagement and new product
        find_22 = Finding.objects.get(id=22)
        test_new, _eng_new, _product_new = self.create_new_test_and_engagment_and_product_from_finding(find_22)
        # Copy finding 22, change title and store it at New Produt, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_title = self.change_finding_title(find_created_before_mark_diff_title)
        find_created_before_mark_diff_title.test = test_new
        find_created_before_mark_diff_title.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_title, false_p=False)
        # Copy finding 22, change severity and store it at New Produt, New Engagement, New Test (to test retroactive replication)
        find_created_before_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_before_mark_diff_severity = self.change_finding_severity(find_created_before_mark_diff_severity)
        find_created_before_mark_diff_severity.test = test_new
        find_created_before_mark_diff_severity.save()
        # Makes sure that the copy is not a false positive
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False)
        # Mark finding 22 as fp
        find_22 = Finding.objects.get(id=22)
        find_22.false_p = True
        find_22.save()
        # Copy finding 22, change severity and store it at New Produt, New Engagement, New Test
        find_created_after_mark_diff_title, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_title = self.change_finding_title(find_created_after_mark_diff_title)
        find_created_after_mark_diff_title.test = test_new
        find_created_after_mark_diff_title.save()
        # Copy finding 22, change severity and store it at New Produt, New Engagement, New Test
        find_created_after_mark_diff_severity, find_22 = self.copy_and_reset_finding(find_id=22)
        find_created_after_mark_diff_severity = self.change_finding_severity(find_created_after_mark_diff_severity)
        find_created_after_mark_diff_severity.test = test_new
        find_created_after_mark_diff_severity.save()
        # Assert that both findings has a different title , an equal severity,
        # belongs to a different product and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_title, false_p=False, not_pk=22, not_product_id=2, not_title=find_22.title, severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_title, false_p=False, not_pk=22, not_product_id=2, not_title=find_22.title, severity=find_22.severity)
        # Assert that both findings has an equal title , a different severity,
        # belongs to a different product and are NOT marked as fp
        self.assert_finding(find_created_before_mark_diff_severity, false_p=False, not_pk=22, not_product_id=2, title=find_22.title, not_severity=find_22.severity)
        self.assert_finding(find_created_after_mark_diff_severity, false_p=False, not_pk=22, not_product_id=2, title=find_22.title, not_severity=find_22.severity)

    # --------------- #
    # Utility Methods #
    # --------------- #

    def log_product(self, product):
        if isinstance(product, int):
            product = Product.objects.get(pk=product)

        logger.debug("product %i: %s", product.id, product.name)
        for eng in product.engagement_set.all():
            self.log_engagement(eng)
            for test in eng.test_set.all():
                self.log_test(test)

    def log_engagement(self, eng):
        if isinstance(eng, int):
            eng = Engagement.objects.get(pk=eng)

        logger.debug("\t" + "engagement %i: %s (dedupe_inside: %s)", eng.id, eng.name, eng.deduplication_on_engagement)

    def log_test(self, test):
        if isinstance(test, int):
            test = Test.objects.get(pk=test)

        logger.debug("\t\t" + "test %i: %s (algo=%s, dynamic=%s)", test.id, test, test.deduplication_algorithm, test.test_type.dynamic_tool)
        self.log_findings(test.finding_set.all())

    def log_all_products(self):
        for product in Product.objects.all():
            self.log_summary(product=product)

    def log_findings(self, findings):
        if not findings:
            logger.debug("\t\t" + "no findings")
        else:
            logger.debug("\t\t" + "findings:")
            for finding in findings:
                logger.debug(f"\t\t\t{finding.id!s:4.4}" + ': "' + f"{finding.title:20.20}" + '": ' + f"{finding.severity:5.5}" + ": act: " + f"{finding.active!s:5.5}"
                        + ": ver: " + f"{finding.verified!s:5.5}" + ": mit: " + f"{finding.is_mitigated!s:5.5}"
                        + ": dup: " + f"{finding.duplicate!s:5.5}" + ": dup_id: "
                        + (f"{finding.duplicate_finding.id!s:4.4}" if finding.duplicate_finding else "None") + ": hash_code: " + str(finding.hash_code)
                        + ": eps: " + str(finding.endpoints.count()) + ": notes: " + str([n.id for n in finding.notes.all()])
                        + ": uid: " + f"{finding.unique_id_from_tool!s:5.5}" + (" fp" if finding.false_p else ""),
                        )

        logger.debug("\t\tendpoints")
        for ep in Endpoint.objects.all():
            logger.debug("\t\t\t" + str(ep.id) + ": " + str(ep))

        logger.debug("\t\t" + "endpoint statuses")
        for eps in Endpoint_Status.objects.all():
            logger.debug("\t\t\t" + str(eps.id) + ": " + str(eps))

    def log_summary(self, product=None, engagement=None, test=None):
        if product:
            self.log_product(product)

        if engagement:
            self.log_engagement(engagement)

        if test:
            self.log_test(test)

        if not product and not engagement and not test:
            self.log_all_products()

    def copy_and_reset_finding(find_idself, find_id):
        org = Finding.objects.get(id=find_id)
        new = _copy_model_util(org)
        new.duplicate = False
        new.duplicate_finding = None
        new.false_p = False
        new.active = True
        new.hash_code = None
        # return unsaved new finding and reloaded existing finding
        return new, Finding.objects.get(id=find_id)

    def copy_and_reset_test(self, test_id):
        org = Test.objects.get(id=test_id)
        new = _copy_model_util(org)
        # return unsaved new test and reloaded existing test
        return new, Test.objects.get(id=test_id)

    def copy_and_reset_engagement(self, eng_id):
        org = Engagement.objects.get(id=eng_id)
        new = _copy_model_util(org)
        # return unsaved new engagement and reloaded existing engagement
        return new, Engagement.objects.get(id=eng_id)

    def copy_and_reset_product(self, prod_id):
        org = Product.objects.get(id=prod_id)
        new = _copy_model_util(org)
        new.name = f"{org.name} (Copy {datetime.now()})"
        # return unsaved new product and reloaded existing product
        return new, Product.objects.get(id=prod_id)

    def change_finding_hash_code(self, finding):
        return self.change_finding_title(finding)

    def change_finding_unique_id(self, finding):
        finding.unique_id_from_tool = datetime.now()
        return finding

    def change_finding_title(self, finding):
        finding.title = f"{finding.title} (Copy {datetime.now()})"
        return finding

    def change_finding_severity(self, finding):
        # Get list of severities without the current finding severity
        severities = [sev for sev in ["Info", "Low", "Medium", "High", "Critical"] if sev != finding.severity]
        # Return the finding with the highest severity from list
        finding.severity = severities[-1]
        return finding

    def assert_finding(self, finding, false_p, duplicate=None, not_pk=None,
            hash_code=None, not_hash_code=None, unique_id_from_tool=None,
            not_unique_id_from_tool=None, title=None, not_title=None, severity=None,
            not_severity=None, test_id=None, not_test_id=None, engagement_id=None,
            not_engagement_id=None, product_id=None, not_product_id=None):
        # Ensure we're always asserting against the latest state
        finding = Finding.objects.get(id=finding.id)

        self.assertEqual(finding.false_p, false_p)

        if duplicate:
            self.assertEqual(finding.duplicate, duplicate)

        if not_pk:
            self.assertNotEqual(finding.pk, not_pk)

        if hash_code:
            self.assertEqual(finding.hash_code, hash_code)

        if not_hash_code:
            self.assertNotEqual(finding.hash_code, not_hash_code)

        if unique_id_from_tool:
            self.assertEqual(finding.unique_id_from_tool, unique_id_from_tool)

        if not_unique_id_from_tool:
            self.assertNotEqual(finding.unique_id_from_tool, not_unique_id_from_tool)

        if title:
            self.assertEqual(finding.title, title)

        if not_title:
            self.assertNotEqual(finding.title, not_title)

        if severity:
            self.assertEqual(finding.severity, severity)

        if not_severity:
            self.assertNotEqual(finding.severity, not_severity)

        if test_id:
            self.assertEqual(finding.test.id, test_id)

        if not_test_id:
            self.assertNotEqual(finding.test.id, not_test_id)

        if engagement_id:
            self.assertEqual(finding.test.engagement.id, engagement_id)

        if not_engagement_id:
            self.assertNotEqual(finding.test.engagement.id, not_engagement_id)

        if product_id:
            self.assertEqual(finding.test.engagement.product.id, product_id)

        if not_product_id:
            self.assertNotEqual(finding.test.engagement.product.id, not_product_id)

    def set_dedupe_inside_engagement(self, deduplication_on_engagement):
        for eng in Engagement.objects.all():
            logger.debug("setting deduplication_on_engagment to %s for %i", str(deduplication_on_engagement), eng.id)
            eng.deduplication_on_engagement = deduplication_on_engagement
            eng.save()

    def create_new_test_from_finding(self, finding):
        test_new, _test = self.copy_and_reset_test(test_id=finding.test.id)
        test_new.save()
        return test_new

    def create_new_test_and_engagment_from_finding(self, finding):
        eng_new, _eng = self.copy_and_reset_engagement(eng_id=finding.test.engagement.id)
        eng_new.save()
        test_new, _test = self.copy_and_reset_test(test_id=finding.test.id)
        test_new.engagement = eng_new
        test_new.save()
        return test_new, eng_new

    def create_new_test_and_engagment_and_product_from_finding(self, finding):
        product_new, _product = self.copy_and_reset_product(prod_id=finding.test.engagement.product.id)
        product_new.save()
        eng_new, _eng = self.copy_and_reset_engagement(eng_id=finding.test.engagement.id)
        eng_new.product = product_new
        eng_new.save()
        test_new, _test = self.copy_and_reset_test(test_id=finding.test.id)
        test_new.engagement = eng_new
        test_new.save()
        return test_new, eng_new, product_new

    def enable_false_positive_history(self):
        system_settings = System_Settings.objects.get()
        system_settings.false_positive_history = True
        system_settings.save()

    def enable_retroactive_false_positive_history(self):
        system_settings = System_Settings.objects.get()
        system_settings.retroactive_false_positive_history = True
        system_settings.save()

    def disable_retroactive_false_positive_history(self):
        system_settings = System_Settings.objects.get()
        system_settings.retroactive_false_positive_history = False
        system_settings.save()

    def enable_dedupe(self):
        system_settings = System_Settings.objects.get()
        system_settings.enable_deduplication = True
        system_settings.save()

    def disable_dedupe(self):
        system_settings = System_Settings.objects.get()
        system_settings.enable_deduplication = False
        system_settings.save()
