from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import Finding, Test, Test_Type


class ScanImportOptionsTest(APITestCase):

    """
    Test the options `skip_duplicates` and `close_old_findings` for the scan
    import APIv2 endpoint with ZAP
    """

    fixtures = ["dojo_testdata.json"]
    EMPTY_ZAP_SCAN = """<?xml version="1.0"?>
<OWASPZAPReport version="2.7.0" generated="Tue, 17 Apr 2018 07:18:05">
</OWASPZAPReport>
"""

    def tearDown(self):
        self.payload["file"].close()

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self._first_import_test = self.import_zap_scan()
        test = self.import_zap_scan()
        test.test_type = Test_Type.objects.create(name="some other test tool")
        test.save()

    def import_zap_scan(self, *, upload_empty_scan=False):
        with open("tests/zap_sample.xml", encoding="utf-8") as file:
            if upload_empty_scan:
                tested_file = SimpleUploadedFile("zap_sample.xml", self.EMPTY_ZAP_SCAN.encode("utf-8"))
            else:
                tested_file = file

            self.payload = {
                "engagement": 1,
                "scan_type": "ZAP Scan",
                "file": tested_file,
            }
            test_ids = list(Test.objects.values_list("id", flat=True))
            r = self.client.post(reverse("importscan-list"), self.payload)
            self.assertEqual(201, r.status_code)

            return Test.objects.exclude(id__in=test_ids).get()

    def get_all_finding_ids(self, **kwargs):
        return set(Finding.objects.filter(test__engagement_id=1, **kwargs)
                   .order_by("id").values_list("id", flat=True))

    def test_epmty_scan(self):
        """Import the ZAP scan without a test file."""
        test = self.import_zap_scan(upload_empty_scan=False)
        self.assertNotEqual(len(self.get_all_finding_ids(active=True, test__test_type=test.test_type)), 0)

    def test_full_scan(self):
        """Import the ZAP scan with a test file."""
        test = self.import_zap_scan(upload_empty_scan=True)
        self.assertNotEqual(len(self.get_all_finding_ids(active=True, test__test_type=test.test_type)), 0)
