import json
from unittest import mock

from django.core.exceptions import ValidationError

from dojo.models import Engagement, Product, Product_API_Scan_Configuration, Test
from dojo.tools.api_sonarqube.importer import SonarQubeApiImporter
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


def dummy_rule_wo_html_desc(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "rule_wo_html_desc.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_no_hotspot(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "hotspots" / "no_vuln.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_one_hotspot(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "hotspots" / "one_vuln.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_many_hotspots(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "hotspots" / "many_vulns.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_hotspot_rule(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "hotspots" / "rule.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_hotspot_rule_wo_risk_description(self, *args, **kwargs):
    with open(get_unit_tests_scans_path("api_sonarqube") / "hotspots" / "rule_wo_risk_description.json", encoding="utf-8") as json_file:
        return json.load(json_file)


def empty_list(self, *args, **kwargs):
    return []


class TestSonarqubeImporterNoSQToolConfig(DojoTestCase):
    # Testing case no 1. https://github.com/DefectDojo/django-DefectDojo/pull/4676
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    def test_parser(self):
        with self.assertRaisesRegex(ValidationError, r'There are no API Scan Configurations for this Product\.\\nPlease add at least one API Scan Configuration for SonarQube to this Product\. Product: "product" \(1\)'):
            SonarQubeApiImporter.prepare_client(self.test)


class TestSonarqubeImporterOneSQToolConfig(DojoTestCase):
    # Testing case no 2. https://github.com/DefectDojo/django-DefectDojo/pull/4676
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    def test_parser(self):
        with self.assertRaisesRegex(ValidationError, r'There are no API Scan Configurations for this Product\.\\nPlease add at least one API Scan Configuration for SonarQube to this Product\. Product: "product" \(1\)'):
            SonarQubeApiImporter.prepare_client(self.test)


class TestSonarqubeImporterMultipleSQToolConfig(DojoTestCase):
    # Testing case no 3. https://github.com/DefectDojo/django-DefectDojo/pull/4676
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_toolConfig2.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    def test_parser(self):
        with self.assertRaisesRegex(ValidationError, r'There are no API Scan Configurations for this Product\.\\nPlease add at least one API Scan Configuration for SonarQube to this Product\. Product: "product" \(1\)'):
            SonarQubeApiImporter.prepare_client(self.test)


class TestSonarqubeImporterOneSQConfigNoKey(DojoTestCase):
    # Testing case no 4. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_toolConfig2.json",
        "unit_sonarqube_product.json",
        "unit_sonarqube_sqcNoKey.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterOneSQConfigWithKey(DojoTestCase):
    # Testing case no 5. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_toolConfig2.json",
        "unit_sonarqube_product.json",
        "unit_sonarqube_sqcWithKey.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterMultipleSQConfigs(DojoTestCase):
    # Testing case no 6. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_toolConfig2.json",
        "unit_sonarqube_product.json",
        "unit_sonarqube_sqcNoKey.json",
        "unit_sonarqube_sqcWithKey.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    def test_parser(self):
        with self.assertRaisesRegex(ValidationError, r'More than one Product API Scan Configuration has been configured, but none of them has been chosen\. Please specify which one should be used\. Product: "product" \(1\)'):
            SonarQubeApiImporter.prepare_client(self.test)


class TestSonarqubeImporterSelectedSQConfigsNoKey(DojoTestCase):
    # Testing case no 7. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_toolConfig2.json",
        "unit_sonarqube_product.json",
        "unit_sonarqube_sqcNoKey.json",
        "unit_sonarqube_sqcWithKey.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(
            engagement=engagement,
            api_scan_configuration=Product_API_Scan_Configuration.objects.all().first(),
        )

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterSelectedSQConfigsWithKey(DojoTestCase):
    # Testing case no 8. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_toolConfig2.json",
        "unit_sonarqube_product.json",
        "unit_sonarqube_sqcNoKey.json",
        "unit_sonarqube_sqcWithKey.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(
            engagement=engagement,
            api_scan_configuration=Product_API_Scan_Configuration.objects.all().last(),
        )
        other_product = Product(name="other product")
        other_engagement = Engagement(product=other_product)
        self.other_test = Test(
            engagement=other_engagement,
            api_scan_configuration=Product_API_Scan_Configuration.objects.all().last(),
        )

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))

    def test_product_mismatch(self):
        with self.assertRaisesRegex(ValidationError, r'Product API Scan Configuration and Product do not match\. Product: "other product" \(None\), config.product: "product" \(1\)'):
            SonarQubeApiImporter.prepare_client(self.other_test)


class TestSonarqubeImporterExternalRule(DojoTestCase):
    # Test that finding governed by a rule without htmlDesc can be imported.
    # Custom (user defined) rules may have no htmlDesc field.
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_toolConfig2.json",
        "unit_sonarqube_product.json",
        "unit_sonarqube_sqcNoKey.json",
        "unit_sonarqube_sqcWithKey.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(
            engagement=engagement,
            api_scan_configuration=Product_API_Scan_Configuration.objects.all().last(),
        )

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule_wo_html_desc)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))
        finding = findings[0]
        self.assertEqual('Remove this useless assignment to local variable "currentValue".', finding.title)
        self.assertEqual(None, finding.cwe)
        self.assertEqual("", finding.description)
        self.assertEqual("[Issue permalink](http://localhoproject/issues?issues=AWKWIl8pZpu0CyehMfc4&open=AWKWIl8pZpu0CyehMfc4&resolved=CONFIRMED&id=internal.dummy.project) \n", finding.references)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(242, finding.line)
        self.assertEqual("internal.dummy.project:src/main/javascript/TranslateDirective.ts", finding.file_path)


class TestSonarqubeImporterTwoIssuesNoHotspots(DojoTestCase):
    # Testing case no 9. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_sqcWithKey.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterNoIssuesOneHotspot(DojoTestCase):
    # Testing case no 9. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_sqcWithKey.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", empty_list)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", dummy_one_hotspot)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(1, len(findings))


class TestSonarqubeImporterNoIssuesTwoHotspots(DojoTestCase):
    # Testing case no 11. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_sqcWithKey.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", empty_list)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", dummy_many_hotspots)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterTwoIssuesTwoHotspots(DojoTestCase):
    # Testing case no 12. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_sqcWithKey.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", dummy_many_hotspots)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(4, len(findings))


class TestSonarqubeImporterValidateHotspotData(DojoTestCase):
    # Testing case no 13. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_sqcWithKey.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", empty_list)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", dummy_one_hotspot)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(findings[0].title, '"password" detected here, make sure this is not a hard-coded credential.')
        self.assertEqual(findings[0].cwe, 798)
        self.assertMultiLineEqual(
            "**Ask Yourself Whether**"
            "\n\n  "
            "* Credentials allows access to a sensitive component like a database, a file storage, an API or a service. "
            "\n  "
            "* Credentials are used in production environments. "
            "\n  "
            "* Application re-distribution is required before updating the credentials. "
            "\n\n"
            "There is a risk if you answered yes to any of those questions."
            "\n\n",
            findings[0].description,
        )
        self.assertEqual(str(findings[0].severity), "High")
        self.assertMultiLineEqual(
            "[Hotspot permalink](http://localhosecurity_hotspots?id=internal.dummy.project&hotspots=AXgm6Z-ophPPY0C1qhRq) "
            "\n"
            "[CVE-2019-13466](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13466)"
            "\n"
            "[CVE-2018-15389](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15389)"
            "\n"
            "[OWASP Top 10 2017 Category A2](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication)"
            "\n"
            "[MITRE, CWE-798](http://cwe.mitre.org/data/definitions/798)"
            "\n"
            "[MITRE, CWE-259](http://cwe.mitre.org/data/definitions/259)"
            "\n"
            "[CERT, MSC03-J.](https://wiki.sei.cmu.edu/confluence/x/OjdGBQ)"
            "\n"
            "[SANS Top 25](https://www.sans.org/top25-software-errors/#cat3)"
            "\n"
            "[Hard Coded Password](http://h3xstream.github.io/find-sec-bugs/bugs.htm#HARD_CODE_PASSWORD)"
            "\n",
            findings[0].references,
        )
        self.assertEqual(str(findings[0].file_path), "internal.dummy.project:spec/support/user_fixture.rb")
        self.assertEqual(findings[0].line, 9)
        self.assertEqual(findings[0].active, True)
        self.assertEqual(findings[0].verified, False)
        self.assertEqual(findings[0].false_p, False)
        self.assertEqual(findings[0].duplicate, False)
        self.assertEqual(findings[0].out_of_scope, False)
        self.assertEqual(findings[0].static_finding, True)
        self.assertEqual(findings[0].scanner_confidence, 1)
        self.assertEqual(str(findings[0].sonarqube_issue), "AXgm6Z-ophPPY0C1qhRq")


class TestSonarqubeImporterHotspotRule_WO_Risk_Description(DojoTestCase):
    # Testing case no 14. https://github.com/DefectDojo/django-DefectDojo/issues/6506
    fixtures = [
        "unit_sonarqube_toolType.json",
        "unit_sonarqube_toolConfig1.json",
        "unit_sonarqube_sqcWithKey.json",
        "unit_sonarqube_product.json",
    ]

    def setUp(self):
        product = Product.objects.get(name="product")
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_project", dummy_product)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_issues", empty_list)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.get_hotspot_rule", dummy_hotspot_rule_wo_risk_description)
    @mock.patch("dojo.tools.api_sonarqube.api_client.SonarQubeAPI.find_hotspots", dummy_one_hotspot)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(findings[0].title, '"password" detected here, make sure this is not a hard-coded credential.')
        self.assertIsNone(findings[0].cwe)
        self.assertMultiLineEqual(
            "**Ask Yourself Whether**"
            "\n\n  "
            "* Credentials allows access to a sensitive component like a database, a file storage, an API or a service. "
            "\n  "
            "* Credentials are used in production environments. "
            "\n  "
            "* Application re-distribution is required before updating the credentials. "
            "\n\n"
            "There is a risk if you answered yes to any of those questions."
            "\n\n",
            findings[0].description,
        )
        self.assertEqual(str(findings[0].severity), "High")
        self.assertEqual(findings[0].references, "[Hotspot permalink](http://localhosecurity_hotspots?id=internal.dummy.project&hotspots=AXgm6Z-ophPPY0C1qhRq) \n")
        self.assertEqual(str(findings[0].file_path), "internal.dummy.project:spec/support/user_fixture.rb")
        self.assertEqual(findings[0].line, 9)
        self.assertEqual(findings[0].active, True)
        self.assertEqual(findings[0].verified, False)
        self.assertEqual(findings[0].false_p, False)
        self.assertEqual(findings[0].duplicate, False)
        self.assertEqual(findings[0].out_of_scope, False)
        self.assertEqual(findings[0].static_finding, True)
        self.assertEqual(findings[0].scanner_confidence, 1)
        self.assertEqual(str(findings[0].sonarqube_issue), "AXgm6Z-ophPPY0C1qhRq")
