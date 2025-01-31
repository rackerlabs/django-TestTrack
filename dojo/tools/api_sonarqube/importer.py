import logging
import re
import textwrap

import html2text
from django.conf import settings
from django.core.exceptions import ValidationError
from lxml import etree

from dojo.models import Finding, Sonarqube_Issue
from dojo.notifications.helper import create_notification

from .api_client import SonarQubeAPI

logger = logging.getLogger(__name__)


class SonarQubeApiImporter:

    """
    This class imports from SonarQube (SQ) all open/confirmed SQ issues related to the project related to the test as
     findings.
    """

    def get_findings(self, filename, test):
        items = self.import_issues(test)
        if settings.SONARQUBE_API_PARSER_HOTSPOTS:
            if items:
                items.extend(self.import_hotspots(test))
            else:
                items = self.import_hotspots(test)
        return items

    @staticmethod
    def is_confirmed(state):
        return state.lower() in [
            "confirmed",
            "accepted",
            "detected",
        ]

    @staticmethod
    def is_closed(state):
        return state.lower() in [
            "resolved",
            "falsepositive",
            "wontfix",
            "closed",
            "dismissed",
            "rejected",
        ]

    @staticmethod
    def is_reviewed(state):
        return state.lower() == "reviewed"

    @staticmethod
    def prepare_client(test):
        product = test.engagement.product
        if test.api_scan_configuration:
            config = (
                test.api_scan_configuration
            )  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 7 and 8
            # Double check of config
            if config.product != product:
                msg = (
                    "Product API Scan Configuration and Product do not match. "
                    f'Product: "{product.name}" ({product.id}), config.product: "{config.product.name}" ({config.product.id})'
                )
                raise ValidationError(msg)
        else:
            sqqs = product.product_api_scan_configuration_set.filter(
                product=product,
                tool_configuration__tool_type__name="SonarQube",
            )
            if (
                sqqs.count() == 1
            ):  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 4
                config = sqqs.first()
            elif (
                sqqs.count() > 1
            ):  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 6
                msg = (
                    "More than one Product API Scan Configuration has been configured, but none of them has been "
                    "chosen. Please specify which one should be used. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)
            else:
                # We are not handling cases no. 1-3 anymore -
                # https://github.com/DefectDojo/django-DefectDojo/pull/4676
                msg = (
                    "There are no API Scan Configurations for this Product.\n"
                    "Please add at least one API Scan Configuration for SonarQube to this Product. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)

        return SonarQubeAPI(tool_config=config.tool_configuration), config

    def import_issues(self, test):
        items = []

        try:
            client, config = self.prepare_client(test)
            # Get the value in the service key 2 box
            organization = (
                config.service_key_2
                if (config and config.service_key_2)
                else None
            )
            # Get the value in the service key 1 box
            if config and config.service_key_1:
                component = client.get_project(
                    config.service_key_1,
                    organization=organization,
                    branch=test.branch_tag,
                )
            else:
                component = client.find_project(
                    test.engagement.product.name,
                    organization=organization,
                    branch=test.branch_tag,
                )
            # Get the resource from SonarQube
            issues = client.find_issues(
                component["key"],
                organization=organization,
                branch=test.branch_tag,
            )
            logger.info(
                f'Found {len(issues)} issues for component {component["key"]}',
            )

            sonarUrl = client.sonar_api_url[:-3]  # [:-3] removes the /api part of the sonarqube/cloud URL

            for issue in issues:
                status = issue["status"]
                from_hotspot = issue.get("fromHotspot", False)

                if self.is_closed(status) or from_hotspot:
                    continue

                issue_type = issue["type"]
                title = issue["message"][0:507] + "..." if len(issue["message"]) > 511 else issue["message"]
                component_key = issue["component"]
                line = issue.get("line")
                rule_id = issue["rule"]
                rule = client.get_rule(rule_id, organization=organization)
                severity = self.convert_sonar_severity(issue["severity"])
                try:
                    sonarqube_permalink = f"[Issue permalink]({sonarUrl}project/issues?issues={issue['key']}&open={issue['key']}&resolved={issue['status']}&id={issue['project']}) \n"
                except KeyError:
                    sonarqube_permalink = "No permalink \n"

                # custom (user defined) SQ rules may not have 'htmlDesc'
                if "htmlDesc" in rule:
                    description = self.clean_rule_description_html(
                        rule["htmlDesc"],
                    )
                    cwe = self.clean_cwe(rule["htmlDesc"])
                    references = sonarqube_permalink + self.get_references(rule["htmlDesc"])
                else:
                    description = ""
                    cwe = None
                    references = sonarqube_permalink

                sonarqube_issue, _ = Sonarqube_Issue.objects.update_or_create(
                    key=issue["key"],
                    defaults={
                        "status": status,
                        "type": issue_type,
                    },
                )

                # Only assign the SonarQube_issue to the first finding related
                # to the issue
                if Finding.objects.filter(
                    sonarqube_issue=sonarqube_issue,
                ).exists():
                    sonarqube_issue = None

                find = Finding(
                    title=title,
                    cwe=cwe,
                    description=description,
                    test=test,
                    severity=severity,
                    references=references,
                    file_path=component_key,
                    line=line,
                    verified=self.is_confirmed(status),
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    mitigated=None,
                    mitigation="No mitigation provided",
                    impact="No impact provided",
                    static_finding=True,
                    sonarqube_issue=sonarqube_issue,
                    unique_id_from_tool=issue.get("key"),
                )
                items.append(find)

        except Exception as e:
            logger.exception("SonarQube API import issue")
            create_notification(
                event="sonarqube_failed",
                title="SonarQube API import issue",
                description=e,
                icon="exclamation-triangle",
                source="SonarQube API",
                obj=test.engagement.product,
            )

        return items

    def import_hotspots(self, test):
        try:
            items = []
            client, config = self.prepare_client(test)
            # Get the value in the service key 2 box
            organization = (
                config.service_key_2
                if (config and config.service_key_2)
                else None
            )
            # Get the value in the service key 1 box
            if config and config.service_key_1:
                component = client.get_project(
                    config.service_key_1,
                    organization=organization,
                    branch=test.branch_tag,
                )
            else:
                component = client.find_project(
                    test.engagement.product.name,
                    organization=organization,
                    branch=test.branch_tag,
                )

            hotspots = client.find_hotspots(
                component["key"],
                organization=organization,
                branch=test.branch_tag,
            )
            logger.info(
                f'Found {len(hotspots)} hotspots for project {component["key"]}',
            )
            sonarUrl = client.sonar_api_url[:-3]  # [:-3] removes the /api part of the sonarqube/cloud URL

            for hotspot in hotspots:
                status = hotspot["status"]

                if self.is_reviewed(status):
                    continue

                issue_type = "SECURITY_HOTSPOT"
                if hotspot["vulnerabilityProbability"] == "CRITICAL":
                    severity = "Critical"
                elif hotspot["vulnerabilityProbability"] == "HIGH":
                    severity = "High"
                elif hotspot["vulnerabilityProbability"] == "MEDIUM":
                    severity = "Medium"
                elif hotspot["vulnerabilityProbability"] == "LOW":
                    severity = "Low"
                else:
                    severity = "Info"
                title = textwrap.shorten(
                    text=hotspot.get("message", ""), width=500,
                )
                component_key = hotspot.get("component")
                line = hotspot.get("line")
                rule_id = hotspot.get("key", "")
                rule = client.get_hotspot_rule(rule_id)
                scanner_confidence = self.convert_scanner_confidence(
                    hotspot.get("vulnerabilityProbability", ""),
                )
                description = self.clean_rule_description_html(
                    rule.get(
                        "vulnerabilityDescription", "No description provided.",
                    ),
                )
                cwe = self.clean_cwe(rule.get("fixRecommendations", ""))
                try:
                    sonarqube_permalink = f"[Hotspot permalink]({sonarUrl}security_hotspots?id={hotspot['project']}&hotspots={hotspot['key']}) \n"
                except KeyError:
                    sonarqube_permalink = "No permalink \n"
                references = sonarqube_permalink + self.get_references(
                    rule.get("riskDescription", ""),
                ) + self.get_references(rule.get("fixRecommendations", ""))

                sonarqube_issue, _ = Sonarqube_Issue.objects.update_or_create(
                    key=hotspot["key"],
                    defaults={"status": status, "type": issue_type},
                )

                # Only assign the SonarQube_issue to the first finding related
                # to the issue
                if Finding.objects.filter(
                    sonarqube_issue=sonarqube_issue,
                ).exists():
                    sonarqube_issue = None

                find = Finding(
                    title=title,
                    cwe=cwe,
                    description=description,
                    test=test,
                    severity=severity,
                    references=references,
                    file_path=component_key,
                    line=line,
                    active=True,
                    verified=self.is_confirmed(status),
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    static_finding=True,
                    scanner_confidence=scanner_confidence,
                    sonarqube_issue=sonarqube_issue,
                    unique_id_from_tool=f"hotspot:{hotspot.get('key')}",
                )
                items.append(find)

            return items

        except Exception as e:
            logger.exception("SonarQube API import issue")
            create_notification(
                event="sonarqube_failed",
                title="SonarQube API import issue",
                description=e,
                icon="exclamation-triangle",
                source="SonarQube API",
                obj=test.engagement.product,
            )

    @staticmethod
    def clean_rule_description_html(raw_html):
        search = re.search(
            r"^(.*?)(?:(<h2>See</h2>)|(<b>References</b>))",
            raw_html,
            re.DOTALL,
        )
        if search:
            raw_html = search.group(1)
        h = html2text.HTML2Text()
        raw_html = raw_html.replace("<h2>", "<b>").replace("</h2>", "</b>")
        return h.handle(raw_html)

    @staticmethod
    def clean_cwe(raw_html):
        search = re.search(r"CWE-(\d+)", raw_html)
        if search:
            return int(search.group(1))
        return None

    @staticmethod
    def convert_sonar_severity(sonar_severity):
        sev = sonar_severity.lower()
        if sev == "blocker":
            return "Critical"
        if sev == "critical":
            return "High"
        if sev == "major":
            return "Medium"
        if sev == "minor":
            return "Low"
        return "Info"

    @staticmethod
    def convert_scanner_confidence(sonar_scanner_confidence):
        sev = sonar_scanner_confidence.lower()
        if sev == "high":
            return 1
        if sev == "medium":
            return 4
        if sev == "low":
            return 7
        return 7

    @staticmethod
    def get_references(vuln_details):
        parser = etree.HTMLParser()
        details = etree.fromstring(vuln_details, parser)

        rule_references = ""
        if details is not None:
            for a in details.iter("a"):
                rule_references += f"[{a.text}]({a.get('href')})\n"
        return rule_references
