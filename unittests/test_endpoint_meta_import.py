import logging

from django.test.client import Client
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import User

from .dojo_test_case import DojoAPITestCase, get_unit_tests_path
from .test_utils import assertImportModelsCreated

logger = logging.getLogger(__name__)


# test methods to be used both by API Test and UI Test
class EndpointMetaImportMixin:
    def __init__(self, *args, **kwargs):
        self.meta_import_full = "endpoint_meta_import/full_endpoint_meta_import.csv"
        self.meta_import_no_hostname = "endpoint_meta_import/no_hostname_endpoint_meta_import.csv"
        self.meta_import_updated_added = "endpoint_meta_import/updated_added_endpoint_meta_import.csv"
        self.meta_import_updated_removed = "endpoint_meta_import/updated_removed_endpoint_meta_import.csv"
        self.meta_import_updated_changed = "endpoint_meta_import/updated_changed_endpoint_meta_import.csv"
        self.updated_tag_host = "feedback.internal.google.com"

    def test_endpoint_meta_import_endpoint_create_tag_create_meta_create(self):
        endpoint_count_before = self.db_endpoint_count()
        endpoint_tag_count_before = self.db_endpoint_tag_count()
        meta_count_before = self.db_dojo_meta_count()

        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=3):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_full, create_endpoints=True, create_tags=True, create_dojo_meta=True)

        self.assertEqual(endpoint_count_before + 3, self.db_endpoint_count())
        self.assertEqual(endpoint_tag_count_before + 6, self.db_endpoint_tag_count())
        self.assertEqual(meta_count_before + 6, self.db_dojo_meta_count())

    def test_endpoint_meta_import_endpoint_missing_hostname(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_no_hostname, create_endpoints=True, create_tags=True, create_dojo_meta=True, expected_http_status_code=400)

    def test_endpoint_meta_import_tag_remove_column(self):
        # Import full scan first
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=3):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_full, create_endpoints=True, create_tags=True, create_dojo_meta=False)
        # Record numbers
        endpoint_count_before = self.db_endpoint_count()
        endpoint_tag_count_before = self.db_endpoint_tag_count()
        # Import again with one column missing
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_updated_removed, create_endpoints=True, create_tags=True, create_dojo_meta=False)
        # See that nothing has been removed
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(endpoint_tag_count_before, self.db_endpoint_tag_count())

    def test_endpoint_meta_import_tag_added_column(self):
        # Import full scan first
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=3):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_full, create_endpoints=True, create_tags=True, create_dojo_meta=False)
        # Record numbers
        endpoint_count_before = self.db_endpoint_count()
        endpoint_tag_count_before = self.db_endpoint_tag_count()
        # Import again with one column added
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_updated_added, create_endpoints=True, create_tags=True, create_dojo_meta=False)
        # See that nothing has been removed
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        # 1 tag x 3 endpoints = 3 tags
        self.assertEqual(endpoint_tag_count_before + 3, self.db_endpoint_tag_count())

    def test_endpoint_meta_import_tag_changed_column(self):
        # Import full scan first
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=3):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_full, create_endpoints=True, create_tags=True, create_dojo_meta=False)
        # Record numbers
        endpoint_count_before = self.db_endpoint_count()
        endpoint_tag_count_before = self.db_endpoint_tag_count()
        # Grab the endpoint that is known to change
        endpoint = self.get_product_endpoints_api(1, host=self.updated_tag_host)["results"][0]
        human_resource_tag = endpoint["tags"][endpoint["tags"].index("team:human resources")]
        # Import again with one column missing
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_updated_changed, create_endpoints=True, create_tags=True, create_dojo_meta=False)
        # See that nothing has been added or removed
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(endpoint_tag_count_before, self.db_endpoint_tag_count())
        # Grab the updated endpoint
        endpoint = self.get_product_endpoints_api(1, host=self.updated_tag_host)["results"][0]
        human_resource_tag_updated = endpoint["tags"][endpoint["tags"].index("team:hr")]
        # Make sure the tags are not the same
        self.assertNotEqual(human_resource_tag, human_resource_tag_updated)

    def test_endpoint_meta_import_meta_remove_column(self):
        # Import full scan first
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=3):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_full, create_endpoints=True, create_tags=False, create_dojo_meta=True)
        # Record numbers
        endpoint_count_before = self.db_endpoint_count()
        meta_count_before = self.db_dojo_meta_count()
        # Import again with one column missing
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_updated_removed, create_endpoints=True, create_tags=False, create_dojo_meta=True)
        # See that nothing has been removed
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(meta_count_before, self.db_dojo_meta_count())

    def test_endpoint_meta_import_meta_added_column(self):
        # Import full scan first
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=3):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_full, create_endpoints=True, create_tags=False, create_dojo_meta=True)
        # Record numbers
        endpoint_count_before = self.db_endpoint_count()
        meta_count_before = self.db_dojo_meta_count()
        # Import again with one column added
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_updated_added, create_endpoints=True, create_tags=False, create_dojo_meta=True)
        # 1 meta x 3 endpoints = 3 tags
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(meta_count_before + 3, self.db_dojo_meta_count())

    def test_endpoint_meta_import_meta_changed_column(self):
        # Import full scan first
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=3):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_full, create_endpoints=True, create_tags=False, create_dojo_meta=True)
        # Record numbers
        endpoint_count_before = self.db_endpoint_count()
        meta_count_before = self.db_dojo_meta_count()
        # Grab the endpoint that is known to change
        endpoint_id = self.get_product_endpoints_api(1, host=self.updated_tag_host)["results"][0]["id"]
        meta_value = self.get_endpoints_meta_api(endpoint_id, "team")["results"][0]["value"]
        # Import again with one column missing
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(
                self.meta_import_updated_changed, create_endpoints=True, create_tags=False, create_dojo_meta=True)
        # See that nothing has been added or removed
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        self.assertEqual(meta_count_before, self.db_dojo_meta_count())
        # Grab the updated endpoint
        endpoint_id = self.get_product_endpoints_api(1, host=self.updated_tag_host)["results"][0]["id"]
        meta_value_updated = self.get_endpoints_meta_api(endpoint_id, "team")["results"][0]["value"]
        # Make sure the tags are not the same
        self.assertNotEqual(meta_value, meta_value_updated)


class EndpointMetaImportTestAPI(DojoAPITestCase, EndpointMetaImportMixin):
    fixtures = ["dojo_testdata.json"]

    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        EndpointMetaImportMixin.__init__(self, *args, **kwargs)
        # super(EndpointMetaImportMixin, self).__init__(*args, **kwargs)
        # super(DojoAPITestCase, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)

    def setUp(self):
        testuser = User.objects.get(username="admin")
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        # self.url = reverse(self.viewname + '-list')


class EndpointMetaImportTestUI(DojoAPITestCase, EndpointMetaImportMixin):
    fixtures = ["dojo_testdata.json"]
    client_ui = Client()

    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        EndpointMetaImportMixin.__init__(self, *args, **kwargs)
        # super(EndpointMetaImportMixin, self).__init__(*args, **kwargs)
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

    # override methods to use UI
    def endpoint_meta_import_scan_with_params(self, *args, **kwargs):
        return self.endpoint_meta_import_scan_with_params_ui(*args, **kwargs)

    def endpoint_meta_import_ui(self, product, payload):
        logger.debug("import_scan payload %s", payload)
        response = self.client_ui.post(reverse("import_endpoint_meta", args=(product, )), payload)
        self.assertEqual(302, response.status_code, response.content[:1000])

    def endpoint_meta_import_scan_with_params_ui(self, filename, product=1, *, create_endpoints=True,
                                                 create_tags=True, create_dojo_meta=True, expected_http_status_code=201):
        with open(get_unit_tests_path() + "/" + filename, encoding="utf-8") as testfile:
            payload = {
                "create_endpoints": create_endpoints,
                "create_tags": create_tags,
                "create_dojo_meta": create_dojo_meta,
                "file": testfile,
            }

            return self.endpoint_meta_import_ui(product, payload)
