import json

from dojo.models import Finding


class KubeAuditParser:
    def get_scan_types(self):
        return ["Kubeaudit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Kubeaudit Scans."

    def severity_mapping(self, severity_input):
        if severity_input == "warning":
            severity = "Medium"
        elif severity_input == "error":
            severity = "High"
        elif severity_input == "info":
            severity = "Info"
        else:
            severity = "Low"
        return severity

    def get_findings(self, filename, test):
        lines = filename.readlines()
        findings = []
        for line in lines:
            try:
                tree = json.loads(str(line, "utf-8"))
            except BaseException:
                tree = json.loads(line)
            AuditResultName = tree.get("AuditResultName", None)
            DeprecatedMajor = tree.get("DeprecatedMajor", None)
            DeprecatedMinor = tree.get("DeprecatedMinor", None)
            IntroducedMajor = tree.get("IntroducedMajor", None)
            IntroducedMinor = tree.get("IntroducedMinor", None)
            ResourceApiVersion = tree.get("ResourceApiVersion", None)
            ResourceKind = tree.get("ResourceKind", None)
            ResourceName = tree.get("ResourceName", None)
            level = tree.get("level", None)
            msg = tree.get("msg", None)
            Container = tree.get("Container", None)
            MissingAnnotation = tree.get("MissingAnnotation", None)
            ResourceNamespace = tree.get("ResourceNamespace", None)
            description = ""
            if AuditResultName:
                description += "AuditResultName: " + AuditResultName + "\n"
            if DeprecatedMajor:
                description += "DeprecatedMajor: " + DeprecatedMajor + "\n"
            if DeprecatedMinor:
                description += "DeprecatedMinor: " + DeprecatedMinor + "\n"
            if IntroducedMajor:
                description += "IntroducedMajor: " + IntroducedMajor + "\n"
            if IntroducedMinor:
                description += "IntroducedMinor: " + IntroducedMinor + "\n"
            if ResourceApiVersion:
                description += "ResourceApiVersion: " + ResourceApiVersion + "\n"
            if ResourceKind:
                description += "ResourceKind: " + ResourceKind + "\n"
            if ResourceName:
                description += "ResourceName: " + ResourceName + "\n"
            if level:
                description += "level: " + level + "\n"
            if msg:
                description += "msg: " + msg + "\n"
            if Container:
                description += "Container: " + Container + "\n"
            if MissingAnnotation:
                description += "MissingAnnotation: " + MissingAnnotation + "\n"
            if ResourceNamespace:
                description += "ResourceNamespace: " + ResourceNamespace + "\n"
            finding = Finding(
                title=AuditResultName + "_" + ResourceName,
                test=test,
                description=description,
                severity=self.severity_mapping(level),
                mitigation=msg,
                static_finding=True,
                dynamic_finding=False,
            )
            findings.append(finding)
        return findings
