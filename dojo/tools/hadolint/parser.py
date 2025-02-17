import json

from dojo.models import Finding


class HadolintParser:
    def get_scan_types(self):
        return ["Hadolint Dockerfile check"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Hadolint Dockerfile check findings in JSON format."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = {}
        for node in tree:
            item = get_item(node, test)
            unique_key = (
                str(node["line"])
                + "-"
                + str(node["column"])
                + node["code"]
                + node["file"]
            )
            items[unique_key] = item

        return list(items.values())


def get_item(vulnerability, test):
    if "level" in vulnerability:
        # If we're dealing with a license finding, there will be no cvssScore
        if vulnerability["level"] == "error":
            severity = "Critical"
        elif vulnerability["level"] == "warning":
            severity = "High"
        else:
            severity = "Info"
    # TODO: some seem to not have anything. Needs UNKNOWN new status in the
    # model. Some vuln do not yet have cvss assigned.
    else:
        severity = "Info"

    # create the finding object, with 'static' type
    finding = Finding(
        title=vulnerability["code"] + ": " + vulnerability["message"],
        test=test,
        severity=severity,
        file_path=vulnerability["file"],
        line=vulnerability["line"],
        description="Vulnerability ID: {}\nDetails: {}\n".format(
            vulnerability["code"], vulnerability["message"],
        ),
        static_finding=True,
        dynamic_finding=False,
    )

    finding.description = finding.description.strip()

    return finding
