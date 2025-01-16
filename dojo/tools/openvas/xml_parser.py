from xml.dom import NamespaceErr

from defusedxml import ElementTree as ET

from dojo.models import Finding


class OpenVASXMLParser:
    def get_findings(self, filename, test):
        findings = []
        tree = ET.parse(filename)
        root = tree.getroot()
        if "report" not in root.tag:
            msg = "This doesn't seem to be a valid Greenbone OpenVAS XML file."
            raise NamespaceErr(msg)
        report = root.find("report")
        results = report.find("results")
        for result in results:
            script_id = None
            for finding in result:
                if finding.tag == "name":
                    title = finding.text
                    description = [f"**Name**: {finding.text}"]
                if finding.tag == "host":
                    title = title + "_" + finding.text
                    description.append(f"**Host**: {finding.text}")
                if finding.tag == "port":
                    title = title + "_" + finding.text
                    description.append(f"**Port**: {finding.text}")
                if finding.tag == "nvt":
                    description.append(f"**NVT**: {finding.text}")
                    script_id = finding.get("oid") or finding.text
                if finding.tag == "severity":
                    severity = self.convert_cvss_score(finding.text)
                    description.append(f"**Severity**: {finding.text}")
                if finding.tag == "qod":
                    description.append(f"**QOD**: {finding.text}")
                if finding.tag == "description":
                    description.append(f"**Description**: {finding.text}")

            finding = Finding(
                title=str(title),
                test=test,
                description="\n".join(description),
                severity=severity,
                dynamic_finding=True,
                static_finding=False,
                vuln_id_from_tool=script_id,
            )
            findings.append(finding)
        return findings

    def convert_cvss_score(self, raw_value):
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"
