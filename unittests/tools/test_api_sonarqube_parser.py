import json
from unittest import mock

from dojo.models import (
    Engagement,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Test,
    Tool_Configuration,
    Tool_Type,
)
from dojo.tools.api_sonarqube.parser import ApiSonarQubeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def dummy_product(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "product.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_issues(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "issues.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_rule(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "rule.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_hotspot_rule(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "hotspots" / "rule.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def empty_list(self, *args, **kwargs):
    return []


class TestApiSonarQubeParser(DojoTestCase):
    def setUp(self):
        product_type, _ = Product_Type.objects.get_or_create(name="Fake unit tests")
        product, _ = Product.objects.get_or_create(name="product", prod_type=product_type)
        engagement = Engagement(product=product)
        # build Sonarqube conf (the parser need it)
        tool_type, _ = Tool_Type.objects.get_or_create(name="SonarQube")
        tool_conf, _ = Tool_Configuration.objects.get_or_create(
            name="SQ1_unittests", authentication_type="API", tool_type=tool_type, url="http://dummy.url.foo.bar/api",
        )
        pasc, _ = Product_API_Scan_Configuration.objects.get_or_create(
            product=product, tool_configuration=tool_conf, service_key_1="ABCD",
        )
        self.test = Test(engagement=engagement, api_scan_configuration=pasc)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", empty_list)
    def test_get_findings(self):
        parser = ApiSonarQubeParser()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))
