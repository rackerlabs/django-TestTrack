from datetime import date

from dojo.models import Test
from dojo.tools.azure_security_center_recommendations.parser import AzureSecurityCenterRecommendationsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAzureSecurityCenterRecommendationsParser(DojoTestCase):

    def test_parse_file_with_no_findings(self):
        with open(get_unit_tests_scans_path("azure_security_center_recommendations") / "zero_vulns.csv", encoding="utf-8") as testfile:
            parser = AzureSecurityCenterRecommendationsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_multiple_findings(self):
        with open(get_unit_tests_scans_path("azure_security_center_recommendations") / "many_vulns.csv", encoding="utf-8") as testfile:
            parser = AzureSecurityCenterRecommendationsParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(3, len(findings))

            finding = findings[0]
            self.assertEqual("my_virtual_network - Virtual networks should be protected by Azure Firewall", finding.title)
            self.assertEqual(date.fromisoformat("2021-09-28"), finding.date)
            self.assertEqual(1032, finding.cwe)
            self.assertEqual("Low", finding.severity)
            description = """**Recommendation:** Virtual networks should be protected by Azure Firewall
**Resource Name:** my_virtual_network
**Resource Type:** virtualnetworks
**Resource Group:** my_resource_group
**Description:** Some of your virtual networks aren't protected with a firewall. Use Azure Firewall to restrict access to your virtual networks and prevent potential threats. To learn more about Azure Firewall,  Click here
**Controls:** Restrict unauthorized network access
**Subscription:** My first subscription
**Subscription Id:** 9cfbad7a-7369-42e4-bcce-7677c5b3a44b"""
            self.assertEqual(description, finding.description)
            mitigation = "To protect your virtual networks with Azure Firewall: 1. From the list below, select a network. Or select Take action if you've arrived here from a specific virtual network page. 2. Follow the Azure Firewall deployment instructions. Make sure to configure all default routes properly.Important: Azure Firewall is billed separately from Azure Security Center. Learn more about Azure Firewall pricing."
            self.assertEqual(mitigation, finding.mitigation)
            references = "https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/f67fb4ed-d481-44d7-91e5-efadf504f74a/resourceId/%2fsubscriptions%2f9cfbad7a-7369-42e4-bcce-7677c5b3a44b%2fresourcegroups%2fmy_resource_group%2fproviders%2fmicrosoft.network%2fvirtualnetworks%2fmy_virtual_network"
            self.assertEqual(references, finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            unique_id_from_tool = "/subscriptions/9cfbad7a-7369-42e4-bcce-7677c5b3a44b/resourcegroups/my_resource_group/providers/microsoft.network/virtualnetworks/my_virtual_network/providers/Microsoft.Security/assessments/f67fb4ed-d481-44d7-91e5-efadf504f74a"
            self.assertEqual(unique_id_from_tool, finding.unique_id_from_tool)
            self.assertEqual("f67fb4ed-d481-44d7-91e5-efadf504f74a", finding.vuln_id_from_tool)

            finding = findings[1]
            self.assertEqual("My first subscription - Azure Defender for Resource Manager should be enabled", finding.title)
            self.assertEqual(date.fromisoformat("2021-09-28"), finding.date)
            self.assertEqual(1032, finding.cwe)
            self.assertEqual("High", finding.severity)
            description = """**Recommendation:** Azure Defender for Resource Manager should be enabled
**Resource Name:** My first subscription
**Resource Type:** Subscription
**Description:** Azure Defender for Resource Manager automatically monitors the resource management operations in your organization. Azure Defender detects threats and alerts you about suspicious activity. Learn more about the capabilities of Azure Defender for Resource Manager at https://aka.ms/defender-for-resource-manager . Enabling this Azure Defender plan results in charges. Learn about the pricing details per region on Security Center's pricing page: https://aka.ms/pricing-security-center .
**Controls:** Enable Advanced Threat Protection
**Subscription:** My first subscription
**Subscription Id:** 9cfbad7a-7369-42e4-bcce-7677c5b3a44b
**Native Cloud Account Id:** my_native_cloud_id"""
            self.assertEqual(description, finding.description)
            mitigation = 'To enable Azure Defender for Resource Manager on your subscription: 1. Open Security Center\'s Pricing & settings page. 2. Select the subscription on which you want to enable Azure Defender. 3. Under "Select Azure Defender plan by resource type", set "Resource Manager" to "On".'
            self.assertEqual(mitigation, finding.mitigation)
            references = "https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/f0fb2a7e-16d5-849f-be57-86db712e9bd0/resourceId/%2fsubscriptions%2f9cfbad7a-7369-42e4-bcce-7677c5b3a44b"
            self.assertEqual(references, finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            unique_id_from_tool = "/subscriptions/9cfbad7a-7369-42e4-bcce-7677c5b3a44b/providers/Microsoft.Security/assessments/f0fb2a7e-16d5-849f-be57-86db712e9bd0"
            self.assertEqual(unique_id_from_tool, finding.unique_id_from_tool)
            self.assertEqual("f0fb2a7e-16d5-849f-be57-86db712e9bd0", finding.vuln_id_from_tool)

            finding = findings[2]
            self.assertEqual("swe10032201245e263h - Storage account should use a private link connection", finding.title)
            self.assertEqual(date.fromisoformat("2021-09-28"), finding.date)
            self.assertEqual(1032, finding.cwe)
            self.assertEqual("Medium", finding.severity)
            description = """**Recommendation:** Storage account should use a private link connection
**Resource Name:** swe10032201245e263h
**Resource Type:** storageaccounts
**Resource Group:** storage-westeurope
**Description:** Private links enforce secure communication, by providing private connectivity to the storage account
**Controls:** Restrict unauthorized network access
**Subscription:** My first subscription
**Subscription Id:** 9cfbad7a-7369-42e4-bcce-7677c5b3a44b"""
            self.assertEqual(description, finding.description)
            mitigation = "To enforce secure communications for your storage accounts, add a private endpoint as described here: https://aka.ms/connectprivatelytostorageaccount."
            self.assertEqual(mitigation, finding.mitigation)
            references = "https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/cdc78c07-02b0-4af0-1cb2-cb7c672a8b0a/resourceId/%2fsubscriptions%2f9cfbad7a-7369-42e4-bcce-7677c5b3a44b%2fresourcegroups%2fcloud-shell-storage-westeurope%2fproviders%2fmicrosoft.storage%2fstorageaccounts%2fswe10032201245e263h"
            self.assertEqual(references, finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            unique_id_from_tool = "/subscriptions/9cfbad7a-7369-42e4-bcce-7677c5b3a44b/resourcegroups/cloud-shell-storage-westeurope/providers/microsoft.storage/storageaccounts/swe10032201245e263h/providers/Microsoft.Security/assessments/cdc78c07-02b0-4af0-1cb2-cb7c672a8b0a"
            self.assertEqual(unique_id_from_tool, finding.unique_id_from_tool)
            self.assertEqual("cdc78c07-02b0-4af0-1cb2-cb7c672a8b0a", finding.vuln_id_from_tool)
