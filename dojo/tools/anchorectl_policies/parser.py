import json
import logging
import re
from datetime import datetime
from json.decoder import JSONDecodeError

from dojo.models import Finding

logger = logging.getLogger(__name__)


class AnchoreCTLPoliciesParser:
    def get_scan_types(self):
        return ["AnchoreCTL Policies Report"]

    def get_label_for_scan_types(self, scan_type):
        return "AnchoreCTL Policies Report"

    def get_description_for_scan_types(self, scan_type):
        return "AnchoreCTLs JSON policies report format."

    def get_findings(self, filename, test):
        content = filename.read()
        try:
            data = json.loads(str(content, "utf-8"))
        except (JSONDecodeError, TypeError):
            data = json.loads(content)

        find_date = datetime.now()
        items = []
        try:
            for image in data:
                if image["detail"] is not None:
                    for result in image["detail"]:
                        try:
                            gate = result["gate"]
                            description = result["description"]
                            policy_id = result["policyId"]
                            status = result["status"]
                            image_name = result["tag"]
                            trigger_id = result["triggerId"]
                            repo, tag = image_name.split(":", 2)
                            severity, active = get_severity(status, description)
                            vulnerability_id = extract_vulnerability_id(trigger_id)
                            title = (
                                policy_id
                                + " - gate|"
                                + gate
                                + " - trigger|"
                                + trigger_id
                            )
                            find = Finding(
                                title=title,
                                test=test,
                                description=description,
                                severity=severity,
                                active=active,
                                references=f"Policy ID: {policy_id}\nTrigger ID: {trigger_id}",
                                file_path=search_filepath(description),
                                component_name=repo,
                                component_version=tag,
                                date=find_date,
                                static_finding=True,
                                dynamic_finding=False,
                            )
                            if vulnerability_id:
                                find.unsaved_vulnerability_ids = [vulnerability_id]
                            items.append(find)
                        except (KeyError, IndexError) as err:
                            msg = f"Invalid format: {err} key not found"
                            raise ValueError(msg)
        except AttributeError as err:
            # import empty policies without error (e.g. policies or images
            # objects are not a dictionary)
            logger.warning(
                "Exception at %s", "parsing anchore policy", exc_info=err,
            )
        return items


def map_gate_action_to_severity(status):
    gate_action_to_severity = {
        "stop": "Critical",
        "warn": "Medium",
    }
    if status in gate_action_to_severity:
        return gate_action_to_severity[status], True

    return "Low", True


def get_severity(status, description):
    parsed_severity = description.split()[0]
    valid_severities = ["LOW", "INFO", "UNKNOWN", "CRITICAL", "MEDIUM"]
    if parsed_severity in valid_severities:
        severity = "Info"
        if parsed_severity == "UNKNOWN":
            severity = "Info"
        elif status != "go":
            severity = parsed_severity.lower().capitalize()

        active = status != "go"

        return severity, active

    return map_gate_action_to_severity(status)


def policy_name(policies, policy_id):
    for policy in policies:
        if policy_id == policy["id"]:
            return policy["name"]
    return "unknown"


def extract_vulnerability_id(trigger_id):
    try:
        vulnerability_id, _ = trigger_id.split("+", 2)
    except ValueError:
        return None
    if vulnerability_id.startswith("CVE"):
        return vulnerability_id
    return None


def search_filepath(text):
    match = re.search(r" (/[^/ ]*)+/?", text)
    path = ""
    if match:
        try:
            path = match.group(0)
        except IndexError:
            path = ""
    return path.strip()
