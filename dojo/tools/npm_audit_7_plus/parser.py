"""Parser for NPM Audit v7+ Scan."""
import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)

"""
the npm audit json output depends on the params used. this parser
accepts the formats for any of:

npm audit --json
npm audit fix --dry-run --json
npm audit --dry-run --json

In order for this parser to import the same number of findings
as the report's meta block indicates, all top level keys
are consiered a vulnerability and as much information as provided
is added to each
"""


class NpmAudit7PlusParser:

    """Represents the parser class."""

    def get_scan_types(self):
        """Return the scan type."""
        return ["NPM Audit v7+ Scan"]

    def get_label_for_scan_types(self, scan_type):
        """Return the scan label."""
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        """Return the scan description."""
        return "NPM Audit Scan json output from v7 and above."

    def get_findings(self, json_output, test):
        """Return the findings gathered from file upload."""
        tree = self.parse_json(json_output)
        return self.get_items(tree, test)

    def parse_json(self, json_output):
        """Parse the json format to get findings."""
        if json_output is None:
            return None
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, "utf-8"))
            except Exception:
                tree = json.loads(data)
        except Exception:
            msg = "Invalid format, unable to parse json."
            raise ValueError(msg)

        # output from npm audit fix --dry-run --json
        if tree.get("audit"):
            if not tree.get("audit").get("auditReportVersion"):
                msg = (
                    "This parser only supports output from npm audit version"
                    " 7 and above."
                )
                raise ValueError(msg)
            subtree = tree.get("audit").get("vulnerabilities")
        # output from npm audit --dry-run --json
        # or
        # output from npm audit --json
        else:
            if not tree.get("auditReportVersion"):
                msg = (
                    "This parser only supports output from npm audit version"
                    " 7 and above."
                )
                raise ValueError(msg)
            subtree = tree.get("vulnerabilities")

        return subtree

    def get_items(self, tree, test):
        """Return the individual items found in report."""
        items = {}

        for key, node in tree.items():
            item = get_item(node, tree, test)
            unique_key = item.title + item.severity
            items[unique_key] = item

        return list(items.values())


def get_item(item_node, tree, test):
    """Return the individual Findigns from items found in report."""
    references = []
    mitigation = ""
    static_finding = True
    title = ""
    unique_id_from_tool = ""
    cvssv3 = ""
    cwe = ""

    if item_node["severity"] == "low":
        severity = "Low"
    elif item_node["severity"] == "moderate":
        severity = "Medium"
    elif item_node["severity"] == "high":
        severity = "High"
    elif item_node["severity"] == "critical":
        severity = "Critical"
    else:
        severity = "Info"

    if item_node["via"] and isinstance(item_node["via"][0], str):
        # this is a top level key (a vulnerability)
        title = item_node["name"]
        cwe = "CWE-1035"  # default
        component_name = title

    elif item_node["via"] and isinstance(item_node["via"][0], dict):
        title = item_node["via"][0]["title"]
        component_name = item_node["nodes"][0]
        cwe = item_node["via"][0]["cwe"][0] if len(item_node["via"][0]["cwe"]) > 0 else None
        references.append(item_node["via"][0]["url"])
        unique_id_from_tool = str(item_node["via"][0]["source"])
        cvssv3 = item_node["via"][0]["cvss"]["vectorString"]

    if isinstance(item_node["fixAvailable"], dict):
        fix_name = item_node["fixAvailable"]["name"]
        fix_version = item_node["fixAvailable"]["version"]
        mitigation = f"Update {fix_name} to version {fix_version}"
    else:
        mitigation = "No specific mitigation provided by tool."

    description = get_vuln_description(item_node, tree)

    if (item_node["via"]
        and isinstance(item_node["via"][0], dict)
            and len(item_node["via"]) > 1):
        # we have a multiple CWE vuln which we will capture in the
        # vulnerability_ids and references
        for vuln in item_node["via"][1:]:  # have to decide if str or object
            if isinstance(vuln, dict):
                references.append(vuln["url"])

    dojo_finding = Finding(
        title=title,
        test=test,
        severity=severity,
        description=description,
        mitigation=mitigation,
        references=", ".join(references),
        component_name=component_name,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        impact="No impact provided",
        static_finding=static_finding,
        dynamic_finding=False,
        vuln_id_from_tool=unique_id_from_tool,
    )

    if cwe is not None:
        cwe = int(cwe.split("-")[1])
        dojo_finding.cwe = cwe

    if (cvssv3 is not None) and (len(cvssv3) > 0):
        dojo_finding.cvssv3 = cvssv3

    return dojo_finding


def get_vuln_description(item_node, tree):
    """Make output pretty of details."""
    effects_handled = []
    description = ""

    description += (item_node["name"] + " "
                    + item_node["range"] + "\n")
    description += "Severity: " + item_node["severity"] + "\n"

    for via in item_node["via"]:
        if isinstance(via, str):
            description += ("Depends on vulnerable versions of "
                            + via + "\n")
        else:
            description += (via["title"] + " - " + via["url"] + "\n")

    if isinstance(item_node["fixAvailable"], dict):
        fix_name = item_node["fixAvailable"]["name"]
        fix_version = item_node["fixAvailable"]["version"]
        mitigation = f"Fix Available: Update {fix_name} to version {fix_version}"
    else:
        mitigation = "No specific mitigation provided by tool."

    description += mitigation + "\n"

    for node in item_node["nodes"]:
        description += node + "\n"

    for effect in item_node["effects"]:
        # look up info in the main tree
        description += ("  " + tree[effect]["name"] + " "
                        + tree[effect]["range"] + "\n")
        effects_handled.append(tree[effect]["name"])
        for ev in tree[effect]["via"]:
            if isinstance(ev, dict):
                if tree[effect]["name"] != ev["name"]:
                    description += ("  Depends on vulnerable versions of "
                                    + ev["name"] + "\n")
            else:
                if tree[effect]["name"] != ev:
                    description += ("  Depends on vulnerable versions of "
                                    + ev + "\n")
        for en in tree[effect]["nodes"]:
            description += "  " + en + "\n"

        for ee in tree[effect]["effects"]:
            if ee in effects_handled:
                continue  # already added to description
            description += ("    " + tree[ee]["name"] + " "
                            + tree[ee]["range"] + "\n")
            for en in tree[effect]["nodes"]:
                description += "    " + en + "\n"

    return description
