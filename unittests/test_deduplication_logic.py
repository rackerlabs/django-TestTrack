import logging
import unittest

from crum import impersonate
from django.conf import settings

from dojo.models import Endpoint, Endpoint_Status, Engagement, Finding, Product, System_Settings, Test, User

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

# things to consider:
# - cross scanner deduplication is still flaky as if some scanners don't provide severity, but another doesn, the hashcode will be different so no deduplication happens.
#   so I couldn't create any good tests
# - hash_code is only calculated once and never changed. should we add a feature to run dedupe when somebody modifies a finding? bulk edit action to trigger dedupe?
#   -> this is handled by the dedupe.py script but which suffers stabiblity issues currently
# - deduplication is using the default ordering for findings, so most of the time this means a new finding will be marked as duplicate of the most recent existing finding
#   that matches the criteria. I think it would be better to consider the oldest existing findings first? Otherwise we have the chance that an old finding becomes
#   marked as duplicate of a newer one at some point.
# - legacy: if file_path and line or both empty and there are no endpoints, no dedupe will happen. Is this desirable or a BUG?
#    -> this is just one of the many limitations of the legacy algorithm.
#       For non standard parsers, it's advised to use the deduplication configuration to finely tune which fields should be used
# - DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE should:
#   - try to match on uniquer_id first before falling back to hash_Code. Currently it just takes the first finding it can find
#     that mathces either the hash_code or unique id.
#    -> that is an insteresting improvment to consider
#   - If the unique_id does NOT match, the finding is still considered for dedupe if the hash_code matches. We may need to forbid as the unique_id should be leading for the same test_type

# test data summary
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
# product 3: Security Podcast


class TestDuplicationLogic(DojoTestCase):
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

    def setUp(self):
        logger.debug("enabling deduplication")
        self.enable_dedupe()

        self.log_summary()

    def tearDown(self):
        # some test disable dedupe, always reenable
        self.enable_dedupe()
        self.log_summary()
        # self.log_summary(test=33)
        # self.log_summary(product=2)

    # all engagements in the test data have deduplication_on_engagement set to true

    # legacy algo:  findings 23, 24, 25 in test 33 are scan_Type Generic Findings Import which uses the legacy algo

    def test_identical_legacy(self):
        # 24 is already a duplicate of 22 let's see what happens if we create an identical finding (but reset status)
        # expect: marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=True, duplicate_finding_id=finding_24.duplicate_finding.id, hash_code=finding_24.hash_code)

    def test_identical_ordering_legacy(self):
        finding_22 = Finding.objects.get(id=22)
        # 23 is already a duplicate of 22, but let's reset it's status. then create a new finding and see if it gets marked as duplicate of 22 or 23
        # expect: marked as duplicate of 22 as lowest finding_id should be chosen as original

        finding_23 = Finding.objects.get(id=23)
        finding_23.duplicate = False
        finding_23.duplicate_finding = None
        finding_23.active = True
        finding_23.save(dedupe_option=False)

        self.assert_finding(finding_23, duplicate=False, hash_code=finding_22.hash_code)

        # create a copy of 22
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)
        finding_new.save()

        self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=finding_22.id, hash_code=finding_22.hash_code)
        # self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=finding_23.id, hash_code=finding_22.hash_code)

    def test_identical_except_title_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different title (and reset status)
        # expect: NOT marked as duplicate as title is part of hash_code calculation
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.title = "the best title"
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_4.hash_code)

    def test_identical_except_description_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different description (and reset status)
        # expect: not marked as duplicate as legacy sees description as leading for hash_code
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.description = "useless finding"
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_24.hash_code)

    def test_identical_except_line_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different line (and reset status)
        # expect: not marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.line = 666
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_24.hash_code)

    def test_identical_except_filepath_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different file_path (and reset status)
        # expect: not marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.file_path = "/dev/null"

        Finding.objects.get(id=22)

        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_24.hash_code)

    def test_dedupe_inside_engagement_legacy(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should not result in being marked as duplicate as it crosses engagement boundaries
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)
        # create new engagment + test in same product
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(finding_22)

        finding_new.test = test_new
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=22, duplicate=False, hash_code=finding_22.hash_code)

    def test_dedupe_not_inside_engagement_legacy(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should result in being marked as duplicate as dedupe inside engagement is set to False
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)

        # dedupe_inside_engagment must be false before cloning engagement
        self.set_dedupe_inside_engagement(False)
        # create new engagment + test in same product
        test_new, _eng_new = self.create_new_test_and_engagment_from_finding(finding_22)

        finding_new.test = test_new
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=22, hash_code=finding_22.hash_code)

    # legacy: if file_path and line or both empty and there are no endpoints, no dedupe will happen. Is this desirable or a BUG?
    def test_identical_no_filepath_no_line_no_endpoints_legacy(self):
        finding_new, _finding_22 = self.copy_and_reset_finding(id=22)
        finding_new.file_path = None
        finding_new.line = None
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=22, duplicate=False)

    def test_identical_legacy_with_identical_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding with the same endpoints. it should be marked as duplicate
        finding_new2, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new2.save(dedupe_option=False)

        ep1 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new2.endpoints.add(ep1)
        finding_new2.endpoints.add(ep2)
        finding_new2.save()

        self.assert_finding(finding_new2, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_extra_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create a new finding with 3 endpoints (so 1 extra)
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        ep3 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost3.com", protocol="https")
        ep3.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.endpoints.add(ep3)
        finding_new3.save()

        # expect: marked as duplicate as the requirement for static findings is that the new finding has to contain all the endpoints of the existing finding (extra is no problem)
        #         hash_code not affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_different_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding, but with different endpoints
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost4.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.save()

        # expect: not marked as duplicate as the requirement for static findings is that the new finding has to contain all the endpoints of the existing finding and this is not met
        #         hash_code not affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_no_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding, but with 1 extra endpoint. should not be marked as duplicate
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        finding_new3.save()

        # expect not marked as duplicate as the new finding doesn't have endpoints and we don't have filepath/line
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_with_identical_endpoints_dynamic(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding. it should be marked as duplicate
        finding_new2, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new2.save(dedupe_option=False)

        ep1 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new2.endpoints.add(ep1)
        finding_new2.endpoints.add(ep2)
        finding_new2.save()

        self.assert_finding(finding_new2, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_extra_endpoints_dynamic(self):
        finding_new, _finding_24 = self.copy_and_reset_finding_add_endpoints(id=24)
        finding_new.save()

        # create an identical copy of the new finding, but with 1 extra endpoint.
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        ep3 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost3.com", protocol="https")
        ep3.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.endpoints.add(ep3)
        finding_new3.save()

        # expect: marked as duplicate as hash_code is not affected by endpoints anymore with the legacy algorithm
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=True, hash_code=finding_new.hash_code)

    def test_identical_legacy_different_endpoints_dynamic(self):
        # this test is using the pattern currently in use in the import / serializers.py.
        #  - save finding first with dedupe-false
        #  - add endpoints
        #  - safe finding again with endpoints attached, dedupe=True (default) -> hash_code gets computed
        # create a new finding with 3 endpoints (so 1 extra)
        # expect: not marked as duplicate as endpoints need to be 100% equal for dynamic findings (host+port)
        #         hash_code not affected by endpoints
        finding_new, _finding_24 = self.copy_and_reset_finding_add_endpoints(id=24)
        finding_new.save()

        # create an identical copy of the new finding, but with 1 extra endpoint. should not be marked as duplicate
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost4.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.save()

        # expected: hash_code is not affected by endpoints anymore in legacy algorithm
        # but not duplicate because the legacy dedupe algo examines not only hash_code but endpoints too
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, hash_code=finding_new.hash_code)

    def test_identical_legacy_no_endpoints_dynamic(self):
        finding_new, _finding_24 = self.copy_and_reset_finding_add_endpoints(id=24)
        finding_new.save()

        # create an identical copy of the new finding, but with no endpoints
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        finding_new3.save()

        # expect: marked as duplicate, hash_code not affected by endpoints with the legacy algorithm
        # but not duplicate because the legacy dedupe algo examines not only hash_code but endpoints too
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, hash_code=finding_new.hash_code)

    # hash_code based algorithm tests

    # existing findings in test 3 are from ZAP scanner, which uses hash_code algorithm with ['title', 'cwe', 'endpoints', 'severity']
    def test_identical_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding (but reset status)
        # 2 has an endpoint ftp://localhost, 4 has no endpoint
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.save(dedupe_option=True)

        if (settings.DEDUPE_ALGO_ENDPOINT_FIELDS == []):
            # expect duplicate, as endpoints shouldn't affect dedupe
            self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        else:
            self.assert_finding(finding_new, not_pk=4, duplicate=False, duplicate_finding_id=None, hash_code=finding_4.hash_code)

        finding_new, finding_2 = self.copy_with_endpoints_without_dedupe_and_reset_finding(id=2)
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_2.hash_code)

    def test_identical_ordering_hash_code(self):
        dedupe_algo_endpoint_fields = settings.DEDUPE_ALGO_ENDPOINT_FIELDS
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = []
        finding_2 = Finding.objects.get(id=2)
        # 3 is already a duplicate of 2, but let's reset it's status. then update 24 and see if it gets marked as duplicate of 2 or 3
        # expect: marked as duplicate of 2 as lowest finding_id should be chosen as original

        finding_3 = Finding.objects.get(id=3)
        finding_3.duplicate = False
        finding_3.duplicate_finding = None
        finding_3.active = True
        finding_3.save(dedupe_option=False)

        self.assert_finding(finding_3, duplicate=False, hash_code=finding_2.hash_code)

        # create a copy of 2
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.save()

        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_2.id, hash_code=finding_2.hash_code)
        # self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_3.id, hash_code=finding_2.hash_code)

        # reset for further tests
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = dedupe_algo_endpoint_fields

    def test_identical_except_title_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different title (and reset status)
        # expect: NOT marked as duplicate as title is part of hash_code calculation
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.title = "the best title"
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=False, not_hash_code=finding_4.hash_code)

    def test_identical_except_description_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different description (and reset status)
        # 2 has an endpoint ftp://localhost, 4 has no endpoint
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)

        finding_new.description = "useless finding"
        finding_new.save(dedupe_option=True)

        if (settings.DEDUPE_ALGO_ENDPOINT_FIELDS == []):
            # expect duplicate, as endpoints shouldn't affect dedupe
            self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        else:
            self.assert_finding(finding_new, not_pk=4, duplicate=False, duplicate_finding_id=None, hash_code=finding_4.hash_code)

        finding_new, finding_2 = self.copy_with_endpoints_without_dedupe_and_reset_finding(id=2)
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_2.hash_code)

    # TODO: not usefile with ZAP?
    def test_identical_except_line_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different line (and reset status)
        # 2 has an endpoint ftp://localhost, 4 has no endpoint
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.line = 666
        finding_new.save(dedupe_option=True)

        if (settings.DEDUPE_ALGO_ENDPOINT_FIELDS == []):
            # expect duplicate, as endpoints shouldn't affect dedupe
            self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        else:
            self.assert_finding(finding_new, not_pk=4, duplicate=False, duplicate_finding_id=None, hash_code=finding_4.hash_code)

        finding_new, finding_2 = self.copy_with_endpoints_without_dedupe_and_reset_finding(id=2)
        finding_new.line = 666
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_2.hash_code)

    # TODO: not usefile with ZAP?
    def test_identical_except_filepath_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different file_path (and reset status)
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.file_path = "/dev/null"
        finding_new.save(dedupe_option=True)

        if (settings.DEDUPE_ALGO_ENDPOINT_FIELDS == []):
            # expect duplicate, as endpoints shouldn't affect dedupe
            self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        else:
            self.assert_finding(finding_new, not_pk=4, duplicate=False, duplicate_finding_id=None, hash_code=finding_4.hash_code)

        finding_new, finding_2 = self.copy_with_endpoints_without_dedupe_and_reset_finding(id=2)
        finding_new.file_path = "/dev/null"
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_2.hash_code)

    def test_dedupe_inside_engagement_hash_code(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should not result in being marked as duplicate as it crosses engagement boundaries
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        finding_new, finding_2 = self.copy_with_endpoints_without_dedupe_and_reset_finding(id=2)
        finding_new.test = Test.objects.get(id=4)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=2, duplicate=False, hash_code=finding_2.hash_code)

    def test_dedupe_not_inside_engagement_hash_code(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should result in being marked as duplicate as dedupe inside engagement is set to False
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        self.set_dedupe_inside_engagement(False)

        finding_new, finding_2 = self.copy_with_endpoints_without_dedupe_and_reset_finding(id=2)
        finding_new.test = Test.objects.get(id=4)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=2, hash_code=finding_2.hash_code)

    # hash_code: if file_path and line or both empty and there are no endpoints, dedupe should happen (as opposed to legacy dedupe)
    @unittest.skip("Test is not valid because finding 2 has an endpoint.")
    def test_identical_no_filepath_no_line_no_endpoints_hash_code(self):
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.file_path = None
        finding_new.line = None
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=2, hash_code=finding_2.hash_code)

    def test_identical_hash_code_with_identical_endpoints(self):
        # create an identical copy of the new finding, with the same endpoints
        finding_new, finding_2 = self.copy_with_endpoints_without_dedupe_and_reset_finding(id=2)  # has ftp://localhost
        finding_new.save(dedupe_option=True)

        # expect: marked as duplicate of original finding 2 (because finding 4 is a duplicate of finding 2 in sample data), hash_code not affected by endpoints (endpoints are not anymore in ZAP configuration for hash_code)
        self.assert_finding(finding_new, not_pk=finding_2.pk, duplicate=True, duplicate_finding_id=2, hash_code=finding_2.hash_code, not_hash_code=None)

    def test_dedupe_algo_endpoint_fields_host_port_identical(self):
        dedupe_algo_endpoint_fields = settings.DEDUPE_ALGO_ENDPOINT_FIELDS
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "port"]

        # create an identical copy of the new finding, with the same endpoints but different path
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)  # finding_2 has host ftp://localhost
        finding_new.save()

        ep = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="localhost", protocol="ftp", path="local")
        ep.save()
        finding_new.endpoints.add(ep)
        finding_new.save()

        # expect: marked as duplicate of original finding 2 (because finding 4 is a duplicate of finding 2 in sample data), hash_code not affected by endpoints (endpoints are not anymore in ZAP configuration for hash_code)
        self.assert_finding(finding_new, not_pk=finding_2.pk, duplicate=True, duplicate_finding_id=2, hash_code=finding_2.hash_code, not_hash_code=None)

        # reset for further tests
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = dedupe_algo_endpoint_fields

    def test_dedupe_algo_endpoint_field_path_different(self):
        dedupe_algo_endpoint_fields = settings.DEDUPE_ALGO_ENDPOINT_FIELDS
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = ["path"]

        # create an identical copy of the new finding, with the same endpoints but different path
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)  # finding_2 has host ftp://localhost
        finding_new.save()

        ep = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="localhost", protocol="ftp", path="local")
        ep.save()
        finding_new.endpoints.add(ep)
        finding_new.save()

        # expect: marked as duplicate of original finding 2 (because finding 4 is a duplicate of finding 2 in sample data), hash_code not affected by endpoints (endpoints are not anymore in ZAP configuration for hash_code)
        self.assert_finding(finding_new, not_pk=finding_2.pk, duplicate=False, duplicate_finding_id=None, hash_code=finding_2.hash_code, not_hash_code=None)

        # reset for further tests
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = dedupe_algo_endpoint_fields

    def test_identical_hash_code_with_intersect_endpoints(self):
        dedupe_algo_endpoint_fields = settings.DEDUPE_ALGO_ENDPOINT_FIELDS
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "port"]
        # ep1: https://myhost.com, ep2: https://myhost2.com
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new.endpoints.add(ep1)
        finding_new.endpoints.add(ep2)
        finding_new.save(dedupe_option=True)
        # expect: marked not as duplicate of original finding 2 because the endpoints are different
        self.assert_finding(finding_new, not_pk=finding_2.pk, duplicate=False, hash_code=finding_2.hash_code)

        # create an identical copy of the new finding without original endpoints, but with 3 extra endpoints.
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost4.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        ep3 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost3.com", protocol="https")
        ep3.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.endpoints.add(ep3)
        finding_new3.save()

        # expect: marked not as duplicate of original finding 2 or finding_new3 because the endpoints are different
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code)
        # expect: marked not as duplicate of original finding 2 because the endpoints are different
        self.assert_finding(finding_new, not_pk=finding_2.pk, duplicate=False, hash_code=finding_2.hash_code)
        # reset for further tests
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = dedupe_algo_endpoint_fields

    def test_identical_hash_code_with_different_endpoints(self):
        dedupe_algo_endpoint_fields = settings.DEDUPE_ALGO_ENDPOINT_FIELDS
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "port"]
        # ep1: https://myhost.com, ep2: https://myhost2.com
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new.endpoints.add(ep1)
        finding_new.endpoints.add(ep2)
        finding_new.save(dedupe_option=True)
        # expect: marked not as duplicate of original finding 2 because the endpoints are different
        self.assert_finding(finding_new, not_pk=finding_2.pk, duplicate=False, hash_code=finding_2.hash_code)

        # create an identical copy of the new finding without original endpoints, but with 3 extra endpoints.
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost4.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="http")
        ep2.save()
        ep3 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost3.com", protocol="https")
        ep3.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.endpoints.add(ep3)
        finding_new3.save()

        # expect: marked not as duplicate of original finding 2 or finding_new3 because the endpoints are different
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, hash_code=finding_new.hash_code)
        self.assert_finding(finding_new3, not_pk=finding_2.pk, duplicate=False, hash_code=finding_2.hash_code)
        # expect: marked not as duplicate of original finding 2 because the endpoints are different
        self.assert_finding(finding_new, not_pk=finding_2.pk, duplicate=False, hash_code=finding_2.hash_code)
        # reset for further tests
        settings.DEDUPE_ALGO_ENDPOINT_FIELDS = dedupe_algo_endpoint_fields

    # # unique_id algo uses id from tool. hash_code is still calculated, according to legacy field config Checkmarx detailed scan
    def test_identical_unique_id(self):
        # create identical copy
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)
        finding_new.save()

        # expect duplicate
        self.assert_finding(finding_new, not_pk=124, duplicate=True, duplicate_finding_id=124, hash_code=finding_124.hash_code)

    def test_different_unique_id_unique_id(self):
        # create identical copy
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)
        finding_new.unique_id_from_tool = "9999"
        finding_new.save()

        # expect not duplicate, but same hash_code
        self.assert_finding(finding_new, not_pk=124, duplicate=False, hash_code=finding_124.hash_code)

    def test_identical_ordering_unique_id(self):
        # create identical copy
        finding_new, finding_125 = self.copy_and_reset_finding(id=125)
        finding_new.save()

        # expect duplicate, but of 124 as that is first in the list, but it's newer then 125. feature or BUG?
        self.assert_finding(finding_new, not_pk=124, duplicate=True, duplicate_finding_id=124, hash_code=finding_125.hash_code)

    def test_title_description_line_filepath_different_unique_id(self):
        # create identical copy, change some fields
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)
        finding_new.title = "another title"
        finding_new.unsaved_vulnerability_ids = ["CVE-2020-12345"]
        finding_new.cwe = "456"
        finding_new.description = "useless finding"
        finding_new.save()

        # expect duplicate as we only match on unique id, hash_code also different
        self.assert_finding(finding_new, not_pk=124, duplicate=True, duplicate_finding_id=124, not_hash_code=finding_124.hash_code)

    def test_title_description_line_filepath_different_and_id_different_unique_id(self):
        # create identical copy, change some fields
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)
        finding_new.title = "another title"
        finding_new.unsaved_vulnerability_ids = ["CVE-2020-12345"]
        finding_new.cwe = "456"
        finding_new.description = "useless finding"
        finding_new.unique_id_from_tool = "9999"
        finding_new.save()

        # expect not duplicate as we match on unique id, hash_code also different because fields changed
        self.assert_finding(finding_new, not_pk=124, duplicate=False, not_hash_code=finding_124.hash_code)

    def test_dedupe_not_inside_engagement_unique_id(self):
        # create identical copy
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)

        # first setup some finding with same unique_id in different engagement, but same test_type
        finding_22 = Finding.objects.get(id=22)

        finding_22.test.test_type = finding_124.test.test_type
        finding_22.test.save()

        finding_22.unique_id_from_tool = "888"
        finding_22.save(dedupe_option=False)

        finding_new.unique_id_from_tool = "888"
        finding_new.save()

        # expect not duplicate as dedupe_inside_engagement is True
        self.assert_finding(finding_new, not_pk=124, duplicate=False, hash_code=finding_124.hash_code)

    def test_dedupe_inside_engagement_unique_id(self):
        # create identical copy
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)

        # first setup some finding with same unique_id in same engagement, but different test (same test_type)
        finding_new.test = Test.objects.get(id=66)
        finding_new.save()

        # expect duplicate as dedupe_inside_engagement is True and the other test is in the same engagement
        self.assert_finding(finding_new, not_pk=124, duplicate=True, duplicate_finding_id=124, hash_code=finding_124.hash_code)

    def test_dedupe_inside_engagement_unique_id2(self):
        # create identical copy
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)

        # first setup some finding with same unique_id in different engagement, but same test_type
        self.set_dedupe_inside_engagement(False)
        finding_22 = Finding.objects.get(id=22)

        finding_22.test.test_type = finding_124.test.test_type
        finding_22.test.save()

        finding_22.unique_id_from_tool = "888"
        finding_22.save(dedupe_option=False)

        finding_new.unique_id_from_tool = "888"
        finding_new.save()

        # expect duplicate as dedupe_inside_engagement is false
        self.assert_finding(finding_new, not_pk=124, duplicate=True, duplicate_finding_id=finding_22.id, hash_code=finding_124.hash_code)

    def test_dedupe_same_id_different_test_type_unique_id(self):
        # create identical copy
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)

        # first setup some finding from a different test_Type, but with the same unique_id_from_tool
        finding_22 = Finding.objects.get(id=22)
        finding_22.unique_id_from_tool = "888"
        finding_new.unique_id_from_tool = "888"
        # and we need to look in another engagement this time for finding_22
        self.set_dedupe_inside_engagement(False)
        finding_22.save(dedupe_option=False)
        finding_new.save()

        # expect not duplicate as the mathcing finding is from another test_type, hash_code is the same as original
        self.assert_finding(finding_new, not_pk=124, duplicate=False, hash_code=finding_124.hash_code)

    def test_identical_different_endpoints_unique_id(self):
        # create identical copy
        finding_new, finding_124 = self.copy_and_reset_finding(id=124)

        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        finding_new.endpoints.add(ep1)
        finding_new.save()

        # expect duplicate, as endpoints shouldn't affect dedupe and hash_code due to unique_id
        self.assert_finding(finding_new, not_pk=124, duplicate=True, duplicate_finding_id=124, hash_code=finding_124.hash_code)

    # algo unique_id_or_hash_code Veracode scan

    def test_identical_unique_id_or_hash_code(self):
        # create identical copy
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)
        finding_new.save()

        # expect duplicate as uid matches
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, hash_code=finding_224.hash_code)

    # existing BUG? finding gets matched on hash code, while there is also an existing finding with matching unique_id_from_tool
    def test_identical_unique_id_or_hash_code_bug(self):
        # create identical copy
        finding_124 = Finding.objects.get(id=124)
        finding_new, _finding_224 = self.copy_and_reset_finding(id=224)
        finding_new.title = finding_124.title  # use title from 124 to get matching hashcode
        finding_new.save()

        # marked as duplicate of 124 as that has the same hashcode and is earlier in the list of findings ordered by id
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=124, hash_code=finding_124.hash_code)

    def test_different_unique_id_unique_id_or_hash_code(self):
        # create identical copy
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)
        finding_new.unique_id_from_tool = "9999"
        finding_new.save()

        # expect duplicate, uid mismatch, but same hash_code
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=finding_224.id, hash_code=finding_224.hash_code)

        # but if we change title and thus hash_code, it should no longer matchs
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)
        finding_new.unique_id_from_tool = "9999"
        finding_new.title = "no no no no no no"
        finding_new.save()

        # expect duplicate, uid mismatch, but same hash_code
        self.assert_finding(finding_new, not_pk=224, duplicate=False, not_hash_code=finding_224.hash_code)

    def test_identical_ordering_unique_id_or_hash_code(self):
        # create identical copy
        finding_new, finding_225 = self.copy_and_reset_finding(id=225)
        finding_new.save()

        # expect duplicate, but of 124 as that is first in the list, but it's newer then 225. feature or BUG?
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, hash_code=finding_225.hash_code)

    def test_title_description_line_filepath_different_unique_id_or_hash_code(self):
        # create identical copy, change some fields
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)
        finding_new.title = "another title"
        finding_new.unsaved_vulnerability_ids = ["CVE-2020-12345"]
        finding_new.cwe = "456"
        finding_new.description = "useless finding"
        finding_new.save()

        # expect duplicate as we only match on unique id, hash_code also different
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, not_hash_code=finding_224.hash_code)

    def test_title_description_line_filepath_different_and_id_different_unique_id_or_hash_code(self):
        # create identical copy, change some fields
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)
        finding_new.title = "another title"
        finding_new.unsaved_vulnerability_ids = ["CVE-2020-12345"]
        finding_new.cwe = "456"
        finding_new.description = "useless finding"
        finding_new.unique_id_from_tool = "9999"
        finding_new.save()

        # expect not duplicate as we match on unique id, hash_code also different because fields changed
        self.assert_finding(finding_new, not_pk=224, duplicate=False, not_hash_code=finding_224.hash_code)

    def test_dedupe_not_inside_engagement_same_hash_unique_id_or_hash_code(self):
        # create identical copy
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        # first setup some finding with same unique_id in different engagement, but same test_type, same hash
        finding_22 = Finding.objects.get(id=22)

        finding_22.test.test_type = finding_224.test.test_type
        finding_22.test.save()

        finding_22.unique_id_from_tool = "888"
        finding_22.save(dedupe_option=False)

        finding_new.unique_id_from_tool = "888"
        finding_new.save()

        # should become duplicate of finding 22 because of the uid match, but existing BUG makes it duplicate of 224 due to hashcode match
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, hash_code=finding_224.hash_code)

    def test_dedupe_not_inside_engagement_same_hash_unique_id_or_hash_code2(self):
        # create identical copy
        # create identical copy
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        # first setup some finding with same unique_id in different engagement, different test_type, same hash_code
        finding_22 = Finding.objects.get(id=22)

        finding_22.test.test_type = finding_224.test.test_type
        finding_22.test.save()
        finding_22.unique_id_from_tool = "333"
        finding_22.save(dedupe_option=False)

        finding_new.hash_code = finding_22.hash_code  # sneaky copy of hash_code to be able to test this case icm with the bug in previous test case above
        finding_new.unique_id_from_tool = "333"
        finding_new.save()

        # expect not duplicate as dedupe_inside_engagement is True and 22 is in another engagement
        # but existing BUG? it is marked as duplicate of 124 which has the same hash and same engagement, but different unique_id_from_tool at same test_type
        self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=124, hash_code=finding_22.hash_code)

    def test_dedupe_inside_engagement_unique_id_or_hash_code(self):
        # create identical copy
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        # first setup some finding with same unique_id in same engagement, but different test (same test_type)
        finding_new.test = Test.objects.get(id=66)
        finding_new.save()

        # expect duplicate as dedupe_inside_engagement is True and the other test is in the same engagement
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, hash_code=finding_224.hash_code)

    def test_dedupe_inside_engagement_unique_id_or_hash_code2(self):
        # create identical copy
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        # first setup some finding with same unique_id in different engagement, but same scan_type
        self.set_dedupe_inside_engagement(False)
        finding_22 = Finding.objects.get(id=22)

        finding_22.test.test_type = finding_224.test.test_type
        finding_22.test.scan_type = finding_224.test.scan_type
        finding_22.test.save()

        finding_22.unique_id_from_tool = "888"
        finding_22.save(dedupe_option=False)

        finding_new.unique_id_from_tool = "888"
        finding_new.title = "hack to work around bug that matches on hash_code first"  # arrange different hash_code
        finding_new.save()

        # expect duplicate as dedupe_inside_engagement is false
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=finding_22.id, not_hash_code=finding_22.hash_code)

    def test_dedupe_same_id_different_test_type_unique_id_or_hash_code(self):
        # create identical copy
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        # first setup some finding from a different test_Type, but with the same unique_id_from_tool
        finding_22 = Finding.objects.get(id=22)
        finding_22.unique_id_from_tool = "888"
        finding_new.unique_id_from_tool = "888"
        # and we need to look in another engagement this time for finding_22
        self.set_dedupe_inside_engagement(False)
        finding_22.save(dedupe_option=False)
        finding_new.title = "title to change hash_code"
        finding_new.save()

        # expect not duplicate as the mathcing finding is from another test_type, hash_code is also different
        self.assert_finding(finding_new, not_pk=224, duplicate=False, not_hash_code=finding_224.hash_code)

        # same scenario but with idencital hash_code as 224 leads to being marked as duplicate of 224
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        # first setup some finding from a different test_Type, but with the same unique_id_from_tool
        finding_22 = Finding.objects.get(id=22)
        finding_22.unique_id_from_tool = "888"
        finding_new.unique_id_from_tool = "888"
        # and we need to look in another engagement this time for finding_22
        self.set_dedupe_inside_engagement(False)
        finding_22.save(dedupe_option=False)
        finding_new.save()

        # expect not duplicate as the mathcing finding is from another test_type, hash_code is also different
        self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, hash_code=finding_224.hash_code)

    def test_identical_different_endpoints_unique_id_or_hash_code(self):
        # create identical copy, so unique id is the same
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        finding_new.endpoints.add(ep1)
        finding_new.save()

        if settings.DEDUPE_ALGO_ENDPOINT_FIELDS == []:
            # expect duplicate, as endpoints shouldn't affect dedupe and hash_code due to unique_id
            self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, hash_code=finding_224.hash_code)
        else:
            self.assert_finding(finding_new, not_pk=224, duplicate=False, duplicate_finding_id=None, hash_code=finding_224.hash_code)

        # same scenario, now with different uid. and different endpoints, but hash will be different due the endpoints because we set dynamic_finding to True
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        finding_new.endpoints.add(ep1)
        finding_new.unique_id_from_tool = 1
        finding_new.dynamic_finding = True
        finding_new.save()

        if settings.DEDUPE_ALGO_ENDPOINT_FIELDS == []:
            # different uid. and different endpoints, but endpoints not used for hash anymore -> duplicate
            self.assert_finding(finding_new, not_pk=224, duplicate=True, hash_code=finding_224.hash_code)
        else:
            self.assert_finding(finding_new, not_pk=224, duplicate=False, hash_code=finding_224.hash_code)

        # same scenario, now with different uid. and different endpoints
        finding_new, finding_224 = self.copy_and_reset_finding(id=224)

        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        finding_new.endpoints.add(ep1)
        finding_new.unique_id_from_tool = 1
        finding_new.dynamic_finding = False
        finding_new.save()

        if settings.DEDUPE_ALGO_ENDPOINT_FIELDS == []:
            # different uid. and different endpoints, dynamic_finding is set to False hash_code still not affected by endpoints
            self.assert_finding(finding_new, not_pk=224, duplicate=True, duplicate_finding_id=224, hash_code=finding_224.hash_code)
        else:
            self.assert_finding(finding_new, not_pk=224, duplicate=False, duplicate_finding_id=None, hash_code=finding_224.hash_code)

    # # some extra tests

    # # hash_code currently is only created on finding creation and after that never changed. feature or BUG?
    def test_hash_code_onetime(self):
        finding_new, _finding_2 = self.copy_and_reset_finding(id=2)
        self.assertEqual(finding_new.hash_code, None)

        finding_new.save()
        self.assertIsNotNone(finding_new.hash_code)
        hash_code_at_creation = finding_new.hash_code

        finding_new.title = "new_title"
        finding_new.unsaved_vulnerability_ids = [999]

        # both title and cve affect hash_code for ZAP scans, but not here because hash_code was already calculated
        finding_new.save()
        self.assertEqual(finding_new.hash_code, hash_code_at_creation)
        finding_new.save(dedupe_option=False)
        self.assertEqual(finding_new.hash_code, hash_code_at_creation)
        finding_new.save(dedupe_option=True)
        self.assertEqual(finding_new.hash_code, hash_code_at_creation)

    def test_identical_legacy_dedupe_option_true_false(self):
        # 24 is already a duplicate of 22 let's see what happens if we create an identical finding (but reset status)
        # expect: not marked as duplicate with dedupe_option-False
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.save(dedupe_option=False)
        self.assert_finding(finding_new, not_pk=24, duplicate=False, hash_code=None)

        # expect duplicate when saving with dedupe_option=True
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=24, duplicate=True, duplicate_finding_id=finding_24.duplicate_finding.id, hash_code=finding_24.hash_code)

    def test_duplicate_after_modification(self):
        # we copy a finding but change some important fields so it's no longer a duplicate
        # expect: not marked as duplicate with dedupe_option-False
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.title = "new_title"
        finding_new.unsaved_vulnerability_ids = [999]
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=None)

        # now when we change the title and cve back the same as finding_24, it should be marked as duplicate
        # howwever defect dojo does NOT recalculate the hash_code, so it will not mark this finding as duplicate. feature or BUG?
        finding_new.title = finding_24.title
        finding_new.unsaved_vulnerability_ids = finding_24.unsaved_vulnerability_ids
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=None)

    def test_case_sensitiveness_hash_code_computation(self):
        # hash_code calculation is case sensitive. feature or BUG?
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)
        finding_new.title = finding_22.title.upper()
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=finding_22.id, hash_code=finding_22.hash_code)

    def test_title_case(self):
        # currentlt the finding.save method applies title casing to the title
        #  'absolutely great title' becomes 'Absolutely Great Title'
        # as this affects deduplication (hash_code computation) we provide a test case here
        # it will fail if someone removes title casing and force them to think about the implications
        # ideally we will switch to case-in-sensitive hash_code computation.
        # this could be a relatively small impact change as saving findings (currently) doesn't recompute the hash_code
        finding_new, _finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.title = "the quick brown fox jumps over the lazy dog"
        finding_new.save(dedupe_option=True)
        self.assertEqual(finding_new.title, "The Quick Brown Fox Jumps Over the Lazy Dog")

    def test_hash_code_without_dedupe(self):
        # if dedupe is disabled, hash_code should still be calculated
        self.enable_dedupe(enable=False)
        finding_new, _finding_124 = self.copy_and_reset_finding(id=124)
        finding_new.save(dedupe_option=False)

        # save skips hash_code generation if dedupe_option==False
        self.assertIsNone(finding_new.hash_code)

        finding_new.save(dedupe_option=True)

        self.assertIsNotNone(finding_new.hash_code)

        finding_new, _finding_124 = self.copy_and_reset_finding(id=124)
        finding_new.save()

        # by default hash_code should be generated
        self.assertIsNotNone(finding_new.hash_code)

    # # utility methods

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

    def copy_and_reset_finding(self, id):
        org = Finding.objects.get(id=id)
        new = org
        new.pk = None
        new.duplicate = False
        new.duplicate_finding = None
        new.active = True
        new.hash_code = None
        # return unsaved new finding and reloaded existing finding
        return new, Finding.objects.get(id=id)

    def copy_with_endpoints_without_dedupe_and_reset_finding(self, id):
        finding_new, finding_org = self.copy_and_reset_finding(id=id)
        # first save without dedupe to avoid hash_code calculation to happen without endpoints
        finding_new.save(dedupe_option=False)
        for ep in finding_org.endpoints.all():
            finding_new.endpoints.add(ep)
        finding_new.save(dedupe_option=False)
        # return saved new finding and reloaded existing finding
        return finding_new, finding_org

    def copy_and_reset_finding_add_endpoints(self, id, *, static=False, dynamic=True):
        finding_new, finding_org = self.copy_and_reset_finding(id=id)
        # remove file_path and line as we now have endpoints
        finding_new.file_path = None
        finding_new.line = None
        finding_new.static_finding = static
        finding_new.dynamic_finding = dynamic
        # first save without dedupe to avoid hash_code calculation to happen without endpoints
        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new.endpoints.add(ep1)
        finding_new.endpoints.add(ep2)
        return finding_new, finding_org

    def copy_and_reset_test(self, id):
        org = Test.objects.get(id=id)
        new = org
        new.pk = None
        # return unsaved new finding and reloaded existing finding
        return new, Test.objects.get(id=id)

    def copy_and_reset_engagement(self, id):
        org = Engagement.objects.get(id=id)
        new = org
        new.pk = None
        # return unsaved new finding and reloaded existing finding
        return new, Engagement.objects.get(id=id)

    def assert_finding(self, finding, not_pk=None, *, duplicate=False, duplicate_finding_id=None, hash_code=None, not_hash_code=None):
        if hash_code:
            self.assertEqual(finding.hash_code, hash_code)

        if not_pk:
            self.assertNotEqual(finding.pk, not_pk)

        self.assertEqual(finding.duplicate, duplicate)
        if not duplicate:
            self.assertIsNone(finding.duplicate_finding)

        if duplicate_finding_id:
            logger.debug("asserting that finding %i is a duplicate of %i", finding.id if finding.id is not None else "None", duplicate_finding_id if duplicate_finding_id is not None else "None")
            self.assertIsNotNone(finding.duplicate_finding)
            self.assertEqual(finding.duplicate_finding.id, duplicate_finding_id)

        if not_hash_code:
            self.assertNotEqual(finding.hash_code, not_hash_code)

    def set_dedupe_inside_engagement(self, deduplication_on_engagement):
        for eng in Engagement.objects.all():
            logger.debug("setting deduplication_on_engagment to %s for %i", str(deduplication_on_engagement), eng.id)
            eng.deduplication_on_engagement = deduplication_on_engagement
            eng.save()

    def create_new_test_and_engagment_from_finding(self, finding):
        eng_new, _eng = self.copy_and_reset_engagement(id=finding.test.engagement.id)
        eng_new.save()
        test_new, _test = self.copy_and_reset_test(id=finding.test.id)
        test_new.engagement = eng_new
        test_new.save()
        return test_new, eng_new

    def enable_dedupe(self, *, enable=True):
        system_settings = System_Settings.objects.get()
        system_settings.enable_deduplication = enable
        system_settings.save()
