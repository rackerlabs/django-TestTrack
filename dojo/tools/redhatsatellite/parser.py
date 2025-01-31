import json

from dojo.models import Finding


class RedHatSatelliteParser:
    def get_scan_types(self):
        return ["Red Hat Satellite"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JSON Output of Red Hat Satellite."

    def severity_mapping(self, severity_input):
        if severity_input == "Critical":
            severity = "Critical"
        elif severity_input == "Important":
            severity = "High"
        elif severity_input == "Moderate":
            severity = "Medium"
        elif severity_input == "Low":
            severity = "Low"
        else:
            severity = "Low"
        return severity

    def get_findings(self, filename, test):
        findings = []
        tree = filename.read()
        try:
            data = json.loads(str(tree, "utf-8"))
        except Exception:
            data = json.loads(tree)
        for result in data["results"]:
            vulnid = result.get("id", None)
            pulp_id = result.get("pulp_id", None)
            title = result.get("title", None)
            errata_id = result.get("errata_id", None)
            severity = result.get("severity", None)
            description = result.get("description", None) + "\n"
            solution = result.get("solution", None)
            summary = result.get("summary", None)
            uuid = result.get("uuid", None)
            name = result.get("name", None)
            vulntype = result.get("type", None)
            cves = result.get("cves", None)
            bugs = result.get("bugs", [])
            hosts_available_count = result.get("hosts_available_count", None)
            hosts_applicable_count = result.get("hosts_applicable_count", None)
            packages = result.get("packages", None)
            module_streams = result.get("module_streams", [])
            installable = result.get("installable", None)
            description += "**id:** " + str(vulnid) + "\n"
            description += "**pulp_id:** " + pulp_id + "\n"
            description += "**summary:** " + summary + "\n"
            description += "**uuid:** " + uuid + "\n"
            description += "**name:** " + name + "\n"
            description += "**type:** " + vulntype + "\n"
            description += "**hosts_available_count:** " + str(hosts_available_count) + "\n"
            description += "**hosts_applicable_count:** " + str(hosts_applicable_count) + "\n"
            description += "**installable:** " + str(installable) + "\n"
            if bugs != []:
                description += "**bugs:** "
                for bug in bugs[:-1]:
                    description += "[" + bug.get("bug_id") + "](" + bug.get("href") + ")" + ", "
                description += "[" + bugs[-1].get("bug_id") + "](" + bugs[-1].get("href") + ")" + "\n"
            if module_streams != []:
                description += "**module_streams:** " + str(module_streams) + "\n"
            description += "**packages:** " + ", ".join(packages)
            find = Finding(
                title=title,
                test=test,
                description=description,
                severity=self.severity_mapping(severity_input=severity),
                mitigation=solution,
                dynamic_finding=True,
            )
            if errata_id is not None:
                find.unsaved_vulnerability_ids = []
                find.unsaved_vulnerability_ids.append(errata_id)
            if cves is not None:
                for cve in cves:
                    find.unsaved_vulnerability_ids.append(cve["cve_id"])
            findings.append(find)
        return findings
