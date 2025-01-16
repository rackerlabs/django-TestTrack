from dojo.models import Test
from dojo.tools.kubeaudit.parser import KubeAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKubeAuditParser(DojoTestCase):

    def test_parse_file_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path("kubeaudit") / "kubeaudit.json", encoding="utf-8")
        parser = KubeAuditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(70, len(findings))
        self.assertEqual(findings[1].title, "DeprecatedAPIUsed_scheduler")
        self.assertEqual(findings[5].mitigation, "hostNetwork is set to 'true' in PodSpec. It should be set to 'false'.")
        self.assertEqual(findings[8].description, "AuditResultName: AllowPrivilegeEscalationNil\nResourceApiVersion: v1\nResourceKind: Pod\nResourceName: storage-provisioner\nlevel: error\nmsg: allowPrivilegeEscalation not set which allows privilege escalation. It should be set to 'false'.\nContainer: storage-provisioner\nResourceNamespace: kube-system\n")
        self.assertEqual(findings[11].severity, "High")
