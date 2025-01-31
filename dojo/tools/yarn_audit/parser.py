import json

from dojo.models import Finding
from dojo.tools.utils import get_npm_cwe


class YarnAuditParser:
    def get_scan_types(self):
        return ["Yarn Audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Yarn Audit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Yarn Audit Scan output file can be imported in JSON format."

    def get_findings(self, json_output, test):
        if json_output is None:
            return []
        tree = None
        lines = json_output.read()
        if isinstance(lines, bytes):
            lines = lines.decode("utf-8")  # passes in unittests, but would fail in production
        if '"type"' in lines:
            lines = lines.split("\n")
            tree = (json.loads(line) for line in lines if "{" in line)
            return self.get_items_yarn(tree, test)
        if '"value"' in lines:
            lines = lines.split("\n")
            tree = (json.loads(line) for line in lines if "{" in line)
            return self.get_items_yarn2(tree, test)
        tree = json.loads(lines)
        return self.get_items_auditci(tree, test)

    def get_items_yarn(self, tree, test):
        items = {}
        for element in tree:
            if element.get("type") == "auditAdvisory":
                node = element.get("data").get("advisory")
                item = self.get_item_yarn(node, test)
                unique_key = str(node.get("id")) + str(node.get("module_name"))
                items[unique_key] = item
            elif element.get("type") == "error":
                error = element.get("data")
                msg = "yarn audit report contains errors: %s"
                raise ValueError(msg, error)
        return list(items.values())

    def get_items_yarn2(self, tree, test):
        items = []
        for element in tree:
            value = element.get("value", None)
            child = element.get("children")
            description = ""
            childid = child.get("ID")
            childissue = child.get("Issue")
            childseverity = child.get("Severity")
            child_vuln_version = child.get("Vulnerable Versions")
            child_tree_versions = ", ".join(set(child.get("Tree Versions")))
            child_dependents = ", ".join(set(child.get("Dependents")))
            description += childissue + "\n"
            description += "**Vulnerable Versions:** " + child_vuln_version + "\n"
            description += "**Dependents:** " + child_dependents + "\n"
            dojo_finding = Finding(
                title=str(childid),
                test=test,
                severity=self.severitytranslator(severity=childseverity),
                description=description,
                component_version=str(child_tree_versions),
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                mitigated=None,
                static_finding=True,
                dynamic_finding=False,
            )
            items.append(dojo_finding)
            if value is not None:
                dojo_finding.component_name = value
        return items

    def get_items_auditci(self, tree, test):  # https://github.com/DefectDojo/django-DefectDojo/issues/6495
        items = []
        for element in tree.get("advisories"):
            findings = "**findings:** " + str(tree.get("advisories").get(element).get("findings"))
            metadata = "**metadata:** " + str(tree.get("advisories").get(element).get("metadata"))
            vulnerable_versions = "**vulnerable_versions:** " + str(tree.get("advisories").get(element).get("vulnerable_versions"))
            github_advisory_id = "**github_advisory_id:** " + str(tree.get("advisories").get(element).get("github_advisory_id"))
            access = "**access:** " + str(tree.get("advisories").get(element).get("access"))
            patched_versions = "**patched_versions:** " + str(tree.get("advisories").get(element).get("patched_versions"))
            cvss = "**cvss:** " + str(tree.get("advisories").get(element).get("cvss"))
            found_by = "**found_by:** " + str(tree.get("advisories").get(element).get("found_by"))
            deleted = "**deleted:** " + str(tree.get("advisories").get(element).get("deleted"))
            elem_id = "**id:** " + str(tree.get("advisories").get(element).get("id"))
            references = "**references:** " + str(tree.get("advisories").get(element).get("references"))
            created = "**created:** " + str(tree.get("advisories").get(element).get("created"))
            reported_by = "**reported_by:** " + str(tree.get("advisories").get(element).get("reported_by"))
            title = "**title:** " + str(tree.get("advisories").get(element).get("title"))
            npm_advisory_id = "**npm_advisory_id:** " + str(tree.get("advisories").get(element).get("npm_advisory_id"))
            overview = "**overview:** " + str(tree.get("advisories").get(element).get("overview"))
            url = "**url:** " + str(tree.get("advisories").get(element).get("url"))
            description = ""
            description += findings + "\n"
            description += metadata + "\n"
            description += vulnerable_versions + "\n"
            description += github_advisory_id + "\n"
            description += access + "\n"
            description += patched_versions + "\n"
            description += cvss + "\n"
            description += found_by + "\n"
            description += deleted + "\n"
            description += elem_id + "\n"
            description += created + "\n"
            description += reported_by + "\n"
            description += title + "\n"
            description += npm_advisory_id + "\n"
            description += overview + "\n"
            dojo_finding = Finding(
                title=tree.get("advisories").get(element).get("cves")[0] + "_" + tree.get("advisories").get(element).get("module_name"),
                test=test,
                severity=self.severitytranslator(severity=tree.get("advisories").get(element).get("severity")),
                description=description,
                mitigation=tree.get("advisories").get(element).get("recommendation"),
                references=url + "\n" + references,
                component_name=tree.get("advisories").get(element).get("module_name"),
                component_version=tree.get("advisories").get(element).get("findings")[0]["version"],
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                mitigated=None,
                impact="No impact provided",
                static_finding=True,
                dynamic_finding=False,
            )
            if tree.get("advisories").get(element).get("cves") != []:
                dojo_finding.unsaved_vulnerability_ids = []
                for cve in tree.get("advisories").get(element).get("cves"):
                    dojo_finding.unsaved_vulnerability_ids.append(cve)
            if tree.get("advisories").get(element).get("cwe") != []:
                dojo_finding.cwe = tree.get("advisories").get(element).get("cwe")[0].strip("CWE-")
            items.append(dojo_finding)
        return items

    def severitytranslator(self, severity):
        if severity == "low":
            severity = "Low"
        elif severity == "moderate":
            severity = "Medium"
        elif severity == "high":
            severity = "High"
        elif severity == "critical":
            severity = "Critical"
        else:
            severity = "Info"
        return severity

    def get_item_yarn(self, item_node, test):
        severity = self.severitytranslator(severity=item_node["severity"])
        paths = ""
        for finding in item_node["findings"]:
            paths += (
                "\n  - "
                + str(finding["version"])
                + ":"
                + str(",".join(finding["paths"][:25]))
            )
            if len(finding["paths"]) > 25:
                paths += "\n  - ..... (list of paths truncated after 25 paths)"
        cwe = get_npm_cwe(item_node)
        dojo_finding = Finding(
            title=item_node["title"]
            + " - "
            + "("
            + item_node["module_name"]
            + ", "
            + item_node["vulnerable_versions"]
            + ")",
            test=test,
            severity=severity,
            file_path=item_node["findings"][0]["paths"][0],
            description=item_node["url"]
            + "\n"
            + item_node["overview"]
            + "\n Vulnerable Module: "
            + item_node["module_name"]
            + "\n Vulnerable Versions: "
            + str(item_node["vulnerable_versions"])
            + "\n Patched Version: "
            + str(item_node["patched_versions"])
            + "\n Vulnerable Paths: "
            + str(paths)
            + "\n CWE: "
            + str(item_node["cwe"])
            + "\n Access: "
            + str(item_node["access"]),
            cwe=cwe,
            mitigation=item_node["recommendation"],
            references=item_node["url"],
            component_name=item_node["module_name"],
            component_version=item_node["findings"][0]["version"],
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=None,
            impact="No impact provided",
            static_finding=True,
            dynamic_finding=False,
        )
        if len(item_node["cves"]) > 0:
            dojo_finding.unsaved_vulnerability_ids = []
            for vulnerability_id in item_node["cves"]:
                dojo_finding.unsaved_vulnerability_ids.append(vulnerability_id)
        return dojo_finding
