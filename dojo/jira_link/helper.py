import io
import json
import logging
from pathlib import Path
from typing import Any

import requests
from django.conf import settings
from django.contrib import messages
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from jira import JIRA
from jira.exceptions import JIRAError
from requests.auth import HTTPBasicAuth

from dojo.celery import app
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
from dojo.forms import JIRAEngagementForm, JIRAProjectForm
from dojo.models import (
    Engagement,
    Finding,
    Finding_Group,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Notes,
    Product,
    Risk_Acceptance,
    Stub_Finding,
    System_Settings,
    Test,
    User,
)
from dojo.notifications.helper import create_notification
from dojo.utils import (
    add_error_message_to_response,
    get_file_images,
    get_system_setting,
    prod_name,
    to_str_typed,
    truncate_with_dots,
)

logger = logging.getLogger(__name__)

RESOLVED_STATUS = [
    "Inactive",
    "Mitigated",
    "False Positive",
    "Out of Scope",
    "Duplicate",
]

OPEN_STATUS = [
    "Active",
    "Verified",
]


def is_jira_enabled():
    if not get_system_setting("enable_jira"):
        logger.debug("JIRA is disabled, not doing anything")
        return False

    return True


def is_jira_configured_and_enabled(obj):
    if not is_jira_enabled():
        return False

    jira_project = get_jira_project(obj)
    if jira_project is None:
        logger.debug('JIRA project not found for: "%s" not doing anything', obj)
        return False

    return jira_project.enabled


def is_push_to_jira(instance, push_to_jira_parameter=None):
    if not is_jira_configured_and_enabled(instance):
        return False

    jira_project = get_jira_project(instance)

    # caller explicitly stated true or false (False is different from None!)
    if push_to_jira_parameter is not None:
        return push_to_jira_parameter

    # Check to see if jira project is disabled to prevent pushing findings
    if not jira_project.enabled:
        return False

    # push_to_jira was not specified, so look at push_all_issues in JIRA_Project
    return jira_project.push_all_issues


def is_push_all_issues(instance):
    if not is_jira_configured_and_enabled(instance):
        return False

    if jira_project := get_jira_project(instance):
        # Check to see if jira project is disabled to prevent pushing findings
        if not jira_project.enabled:
            return None
        return jira_project.push_all_issues
    return None


# checks if a finding can be pushed to JIRA
# optionally provides a form with the new data for the finding
# any finding that already has a JIRA issue can be pushed again to JIRA
# returns True/False, error_message, error_code
def can_be_pushed_to_jira(obj, form=None):
    # logger.debug('can be pushed to JIRA: %s', finding_or_form)
    jira_project = get_jira_project(obj)
    if not jira_project:
        return False, f"{to_str_typed(obj)} cannot be pushed to jira as there is no jira project configuration for this product.", "error_no_jira_project"

    if not jira_project.enabled:
        return False, f"{to_str_typed(obj)} cannot be pushed to jira as the jira project is not enabled.", "error_no_jira_project"

    if not hasattr(obj, "has_jira_issue"):
        return False, f"{to_str_typed(obj)} cannot be pushed to jira as there is no jira_issue attribute.", "error_no_jira_issue_attribute"

    if isinstance(obj, Stub_Finding):
        # stub findings don't have active/verified/etc and can always be pushed
        return True, None, None

    if obj.has_jira_issue:
        # findings or groups already having an existing jira issue can always be pushed
        return True, None, None

    if isinstance(obj, Finding):
        if form:
            active = form["active"].value()
            verified = form["verified"].value()
            severity = form["severity"].value()
        else:
            active = obj.active
            verified = obj.verified
            severity = obj.severity

        logger.debug("can_be_pushed_to_jira: %s, %s, %s", active, verified, severity)

        isenforced = get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_jira", True)

        if not active or (not verified and isenforced):
            logger.debug("Findings must be active and verified, if enforced by system settings, to be pushed to JIRA")
            return False, "Findings must be active and verified, if enforced by system settings, to be pushed to JIRA", "not_active_or_verified"

        jira_minimum_threshold = None
        if System_Settings.objects.get().jira_minimum_severity:
            jira_minimum_threshold = Finding.get_number_severity(System_Settings.objects.get().jira_minimum_severity)

            if jira_minimum_threshold and jira_minimum_threshold > Finding.get_number_severity(severity):
                logger.debug(f"Finding below the minimum JIRA severity threshold ({System_Settings.objects.get().jira_minimum_severity}).")
                return False, f"Finding below the minimum JIRA severity threshold ({System_Settings.objects.get().jira_minimum_severity}).", "below_minimum_threshold"
    elif isinstance(obj, Finding_Group):
        if not obj.findings.all():
            return False, f"{to_str_typed(obj)} cannot be pushed to jira as it is empty.", "error_empty"
        # Accommodating a strange behavior where a finding group sometimes prefers `obj.status` rather than `obj.status()`
        try:
            not_active = "Active" not in obj.status()
        except TypeError:  # TypeError: 'str' object is not callable
            not_active = "Active" not in obj.status
        # Determine if the finding group is not active
        if not_active:
            return False, f"{to_str_typed(obj)} cannot be pushed to jira as it is not active.", "error_inactive"

    else:
        return False, f"{to_str_typed(obj)} cannot be pushed to jira as it is of unsupported type.", "error_unsupported"

    return True, None, None


# use_inheritance=True means get jira_project config from product if engagement itself has none
def get_jira_project(obj, *, use_inheritance=True):
    if not is_jira_enabled():
        return None

    if obj is None:
        return None

    # logger.debug('get jira project for: ' + str(obj.id) + ':' + str(obj))

    if isinstance(obj, JIRA_Project):
        return obj

    if isinstance(obj, JIRA_Issue):
        if obj.jira_project:
            return obj.jira_project
        # some old jira_issue records don't have a jira_project, so try to go via the finding instead
        if (hasattr(obj, "finding") and obj.finding) or (hasattr(obj, "engagement") and obj.engagement):
            return get_jira_project(obj.finding, use_inheritance=use_inheritance)
        return None

    if isinstance(obj, Finding | Stub_Finding):
        finding = obj
        return get_jira_project(finding.test)

    if isinstance(obj, Finding_Group):
        return get_jira_project(obj.test)

    if isinstance(obj, Test):
        test = obj
        return get_jira_project(test.engagement)

    if isinstance(obj, Engagement):
        engagement = obj
        jira_project = None
        try:
            jira_project = engagement.jira_project  # first() doesn't work with prefetching
            if jira_project:
                logger.debug("found jira_project %s for %s", jira_project, engagement)
                return jira_project
        except JIRA_Project.DoesNotExist:
            pass  # leave jira_project as None

        if use_inheritance:
            logger.debug("delegating to product %s for %s", engagement.product, engagement)
            return get_jira_project(engagement.product)
        logger.debug("not delegating to product %s for %s", engagement.product, engagement)
        return None

    if isinstance(obj, Product):
        # TODO: refactor relationships, but now this would brake APIv1 (and v2?)
        product = obj
        jira_projects = product.jira_project_set.all()  # first() doesn't work with prefetching
        jira_project = jira_projects[0] if len(jira_projects) > 0 else None
        if jira_project:
            logger.debug("found jira_project %s for %s", jira_project, product)
            return jira_project

    logger.debug("no jira_project found for %s", obj)
    return None


def get_jira_instance(obj):
    if not is_jira_enabled():
        return None

    jira_project = get_jira_project(obj)
    if jira_project:
        logger.debug("found jira_instance %s for %s", jira_project.jira_instance, obj)
        return jira_project.jira_instance

    return None


def get_jira_url(obj):
    logger.debug("getting jira url")

    # finding + engagement
    issue = get_jira_issue(obj)
    if issue is not None:
        return get_jira_issue_url(issue)
    if isinstance(obj, Finding):
        # finding must only have url if there is a jira_issue
        # engagement can continue to show url of jiraproject instead of jira issue
        return None

    if isinstance(obj, JIRA_Project):
        return get_jira_project_url(obj)

    return get_jira_project_url(get_jira_project(obj))


def get_jira_issue_url(issue):
    logger.debug("getting jira issue url")
    jira_project = get_jira_project(issue)
    jira_instance = get_jira_instance(jira_project)
    if jira_instance is None:
        return None

    # example http://jira.com/browser/SEC-123
    return jira_instance.url + "/browse/" + issue.jira_key


def get_jira_project_url(obj):
    logger.debug("getting jira project url")
    jira_project = get_jira_project(obj) if not isinstance(obj, JIRA_Project) else obj

    if jira_project:
        logger.debug("getting jira project url2")
        jira_instance = get_jira_instance(obj)
        if jira_project and jira_instance:
            logger.debug("getting jira project url3")
            return jira_project.jira_instance.url + "/browse/" + jira_project.project_key

    return None


def get_jira_key(obj):
    if hasattr(obj, "has_jira_issue") and obj.has_jira_issue:
        return get_jira_issue_key(obj)

    if isinstance(obj, JIRA_Project):
        return get_jira_project_key(obj)

    return get_jira_project_key(get_jira_project(obj))


def get_jira_issue_key(obj):
    if obj.has_jira_issue:
        return obj.jira_issue.jira_key

    return None


def get_jira_project_key(obj):
    jira_project = get_jira_project(obj)

    if not get_jira_project:
        return None

    return jira_project.project_key


def get_jira_issue_template(obj):
    jira_project = get_jira_project(obj)

    template_dir = jira_project.issue_template_dir
    if not template_dir:
        jira_instance = get_jira_instance(obj)
        template_dir = jira_instance.issue_template_dir

    # fallback to default as before
    if not template_dir:
        template_dir = "issue-trackers/jira_full/"

    if isinstance(obj, Finding_Group):
        return Path(template_dir) / "jira-finding-group-description.tpl"
    return Path(template_dir) / "jira-description.tpl"


def get_jira_creation(obj):
    if isinstance(obj, Finding | Engagement | Finding_Group):
        if obj.has_jira_issue:
            return obj.jira_issue.jira_creation
    return None


def get_jira_change(obj):
    if isinstance(obj, Finding | Engagement | Finding_Group):
        if obj.has_jira_issue:
            return obj.jira_issue.jira_change
    else:
        logger.debug("get_jira_change unsupported object type: %s", obj)
    return None


def get_epic_name_field_name(jira_instance):
    if not jira_instance or not jira_instance.epic_name_id:
        return None

    return "customfield_" + str(jira_instance.epic_name_id)


def has_jira_issue(obj):
    return get_jira_issue(obj) is not None


def get_jira_issue(obj):
    if isinstance(obj, Finding | Engagement | Finding_Group):
        try:
            return obj.jira_issue
        except JIRA_Issue.DoesNotExist:
            return None
    return None


def has_jira_configured(obj):
    return get_jira_project(obj) is not None


def connect_to_jira(jira_server, jira_username, jira_password):
    return JIRA(
        server=jira_server,
        basic_auth=(jira_username, jira_password),
        max_retries=0,
        options={
            "verify": settings.JIRA_SSL_VERIFY,
            "headers": settings.ADDITIONAL_HEADERS,
        })


def get_jira_connect_method():
    if hasattr(settings, "JIRA_CONNECT_METHOD"):
        try:
            import importlib
            mn, _, fn = settings.JIRA_CONNECT_METHOD.rpartition(".")
            m = importlib.import_module(mn)
            return getattr(m, fn)
        except ModuleNotFoundError:
            pass
    return connect_to_jira


def get_jira_connection_raw(jira_server, jira_username, jira_password):
    try:
        connect_method = get_jira_connect_method()
        jira = connect_method(jira_server, jira_username, jira_password)

        logger.debug("logged in to JIRA %s successfully", jira_server)

    except JIRAError as e:
        logger.exception("logged in to JIRA %s unsuccessful", jira_server)

        error_message = e.text if hasattr(e, "text") else e.message if hasattr(e, "message") else e.args[0]

        if e.status_code in {401, 403}:
            log_jira_generic_alert("JIRA Authentication Error", error_message)
        else:
            log_jira_generic_alert("Unknown JIRA Connection Error", error_message)

        add_error_message_to_response("Unable to authenticate to JIRA. Please check the URL, username, password, captcha challenge, Network connection. Details in alert on top right. " + str(error_message))
        raise

    except requests.exceptions.RequestException as re:
        logger.exception("Unknown JIRA Connection Error")
        error_message = re.text if hasattr(re, "text") else re.message if hasattr(re, "message") else re.args[0]
        log_jira_generic_alert("Unknown JIRA Connection Error", re)

        add_error_message_to_response("Unable to authenticate to JIRA. Please check the URL, username, password, captcha challenge, Network connection. Details in alert on top right. " + str(error_message))
        raise

    return jira


# Gets a connection to a Jira server based on the finding
def get_jira_connection(obj):
    jira_instance = obj
    if not isinstance(jira_instance, JIRA_Instance):
        jira_instance = get_jira_instance(obj)

    if jira_instance is not None:
        return get_jira_connection_raw(jira_instance.url, jira_instance.username, jira_instance.password)
    return None


def jira_get_resolution_id(jira, issue, status):
    transitions = jira.transitions(issue)
    resolution_id = None
    for t in transitions:
        if t["name"] == "Resolve Issue":
            resolution_id = t["id"]
            break
        if t["name"] == "Reopen Issue":
            resolution_id = t["id"]
            break

    return resolution_id


def jira_transition(jira, issue, transition_id):
    try:
        if issue and transition_id:
            jira.transition_issue(issue, transition_id)
            return True
    except JIRAError as jira_error:
        logger.debug("error transitioning jira issue " + issue.key + " " + str(jira_error))
        logger.exception("Error with Jira transation issue")
        alert_text = f"JiraError HTTP {jira_error.status_code}"
        if jira_error.url:
            alert_text += f" url: {jira_error.url}"
        if jira_error.text:
            alert_text += f"\ntext: {jira_error.text}"
        log_jira_generic_alert("error transitioning jira issue " + issue.key, alert_text)
        return None


# Used for unit testing so geting all the connections is manadatory
def get_jira_updated(finding):
    if finding.has_jira_issue:
        j_issue = finding.jira_issue.jira_id
    elif finding.finding_group and finding.finding_group.has_jira_issue:
        j_issue = finding.finding_group.jira_issue.jira_id

    if j_issue:
        project = get_jira_project(finding)
        issue = jira_get_issue(project, j_issue)
        return issue.fields.updated
    return None


# Used for unit testing so geting all the connections is manadatory
def get_jira_status(finding):
    if finding.has_jira_issue:
        j_issue = finding.jira_issue.jira_id
    elif finding.finding_group and finding.finding_group.has_jira_issue:
        j_issue = finding.finding_group.jira_issue.jira_id

    if j_issue:
        project = get_jira_project(finding)
        issue = jira_get_issue(project, j_issue)
        return issue.fields.status
    return None


# Used for unit testing so geting all the connections is manadatory
def get_jira_comments(finding):
    if finding.has_jira_issue:
        j_issue = finding.jira_issue.jira_id
    elif finding.finding_group and finding.finding_group.has_jira_issue:
        j_issue = finding.finding_group.jira_issue.jira_id

    if j_issue:
        project = get_jira_project(finding)
        issue = jira_get_issue(project, j_issue)
        return issue.fields.comment.comments
    return None


def log_jira_generic_alert(title, description):
    """Creates a notification for JIRA errors happening outside the scope of a specific (finding/group/epic) object"""
    create_notification(
        event="jira_update",
        title=title,
        description=description,
        icon="bullseye",
        source="JIRA")


def log_jira_alert(error, obj):
    """Creates a notification for JIRA errors when handling a specific (finding/group/epic) object"""
    create_notification(
        event="jira_update",
        title="Error pushing to JIRA " + "(" + truncate_with_dots(prod_name(obj), 25) + ")",
        description=to_str_typed(obj) + ", " + error,
        url=obj.get_absolute_url(),
        icon="bullseye",
        source="Push to JIRA",
        obj=obj)


def log_jira_cannot_be_pushed_reason(error, obj):
    """Creates an Alert for GUI display  when handling a specific (finding/group/epic) object"""
    create_notification(
        event="jira_update",
        title="Error pushing to JIRA " + "(" + truncate_with_dots(prod_name(obj), 25) + ")",
        description=obj.__class__.__name__ + ": " + error,
        url=obj.get_absolute_url(),
        icon="bullseye",
        source="Push to JIRA",
        obj=obj,
        alert_only=True)


# Displays an alert for Jira notifications
def log_jira_message(text, finding):
    create_notification(
        event="jira_update",
        title="Pushing to JIRA: ",
        description=text + " Finding: " + str(finding.id),
        url=reverse("view_finding", args=(finding.id, )),
        icon="bullseye",
        source="JIRA", finding=finding)


def get_labels(obj):
    # Update Label with system settings label
    labels = []
    system_settings = System_Settings.objects.get()
    system_labels = system_settings.jira_labels
    prod_name_label = prod_name(obj).replace(" ", "_")
    jira_project = get_jira_project(obj)

    if system_labels:
        system_labels = system_labels.split()
        for system_label in system_labels:
            labels.append(system_label)
        # Update the label with the product name (underscore)
        labels.append(prod_name_label)

    # labels per-product/engagement
    if jira_project and jira_project.jira_labels:
        project_labels = jira_project.jira_labels.split()
        for project_label in project_labels:
            labels.append(project_label)
        # Update the label with the product name (underscore)
        if prod_name_label not in labels:
            labels.append(prod_name_label)

    if system_settings.add_vulnerability_id_to_jira_label or (jira_project and jira_project.add_vulnerability_id_to_jira_label):
        if isinstance(obj, Finding) and obj.vulnerability_ids:
            for vul_id in obj.vulnerability_ids:
                labels.append(vul_id)
        elif isinstance(obj, Finding_Group):
            for finding in obj.findings.all():
                for vul_id in finding.vulnerability_ids:
                    labels.append(vul_id)

    return labels


def get_tags(obj):
    # Update Label with system setttings label
    tags = []
    if isinstance(obj, Finding | Engagement):
        obj_tags = obj.tags.all()
        if obj_tags:
            for tag in obj_tags:
                tags.append(str(tag.name.replace(" ", "-")))
    if isinstance(obj, Finding_Group):
        for finding in obj.findings.all():
            obj_tags = finding.tags.all()
            if obj_tags:
                for tag in obj_tags:
                    if tag not in tags:
                        tags.append(str(tag.name.replace(" ", "-")))

    return tags


def jira_summary(obj):
    summary = ""
    if isinstance(obj, Finding):
        summary = obj.title
    if isinstance(obj, Finding_Group):
        summary = obj.name

    return summary.replace("\r", "").replace("\n", "")[:255]


def jira_description(obj):
    template = get_jira_issue_template(obj)

    logger.debug("rendering description for jira from: %s", template)

    kwargs = {}
    if isinstance(obj, Finding):
        kwargs["finding"] = obj
    elif isinstance(obj, Finding_Group):
        kwargs["finding_group"] = obj

    description = render_to_string(template, kwargs)
    logger.debug("rendered description: %s", description)
    return description


def jira_priority(obj):
    return get_jira_instance(obj).get_priority(obj.severity)


def jira_environment(obj):
    if isinstance(obj, Finding):
        return "\n".join([str(endpoint) for endpoint in obj.endpoints.all()])
    if isinstance(obj, Finding_Group):
        envs = [
            jira_environment(finding)
            for finding in obj.findings.all()
        ]

        jira_environments = [env for env in envs if env]
        return "\n".join(jira_environments)
    return ""


def push_to_jira(obj, *args, **kwargs):
    if obj is None:
        msg = "Cannot push None to JIRA"
        raise ValueError(msg)

    if isinstance(obj, Finding):
        finding = obj
        if finding.has_jira_issue:
            return update_jira_issue_for_finding(finding, *args, **kwargs)
        return add_jira_issue_for_finding(finding, *args, **kwargs)

    if isinstance(obj, Engagement):
        engagement = obj
        if engagement.has_jira_issue:
            return update_epic(engagement, *args, **kwargs)
        return add_epic(engagement, *args, **kwargs)

    if isinstance(obj, Finding_Group):
        group = obj
        if group.has_jira_issue:
            return update_jira_issue_for_finding_group(group, *args, **kwargs)
        return add_jira_issue_for_finding_group(group, *args, **kwargs)

    logger.error("unsupported object passed to push_to_jira: %s %i %s", obj.__name__, obj.id, obj)
    return None


def add_issues_to_epic(jira, obj, epic_id, issue_keys, *, ignore_epics=True):
    try:
        return jira.add_issues_to_epic(epic_id=epic_id, issue_keys=issue_keys, ignore_epics=ignore_epics)
    except JIRAError as e:
        """
        We must try to accommodate the following:

        The request contains a next-gen issue. This operation can't add next-gen issues to epics.
        To add a next-gen issue to an epic, use the Edit issue operation and set the parent property
        (i.e., '"parent":{"key":"PROJ-123"}' where "PROJ-123" has an issue type at level one of the issue type hierarchy).
        See <a href="https://developer.atlassian.com/cloud/jira/platform/rest/v2/"> developer.atlassian.com </a> for more details.
        """
        try:
            if "The request contains a next-gen issue." in str(e):
                # Attempt to update the issue manually
                for issue_key in issue_keys:
                    issue = jira.issue(issue_key)
                    epic = jira.issue(epic_id)
                    issue.update(parent={"key": epic.key})
        except JIRAError as e:
            logger.exception("error adding issues %s to epic %s for %s", issue_keys, epic_id, obj.id)
            log_jira_alert(e.text, obj)
            return False


# we need two separate celery tasks due to the decorators we're using to map to/from ids

@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def add_jira_issue_for_finding(finding, *args, **kwargs):
    return add_jira_issue(finding, *args, **kwargs)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Finding_Group)
def add_jira_issue_for_finding_group(finding_group, *args, **kwargs):
    return add_jira_issue(finding_group, *args, **kwargs)


def prepare_jira_issue_fields(
        project_key,
        issuetype_name,
        summary,
        description,
        component_name=None,
        custom_fields=None,
        labels=None,
        environment=None,
        priority_name=None,
        epic_name_field=None,
        default_assignee=None,
        duedate=None,
        issuetype_fields=[]):

    fields = {
            "project": {"key": project_key},
            "issuetype": {"name": issuetype_name},
            "summary": summary,
            "description": description,
    }

    if component_name:
        fields["components"] = [{"name": component_name}]

    if custom_fields:
        fields.update(custom_fields)

    if labels and "labels" in issuetype_fields:
        fields["labels"] = labels

    if environment and "environment" in issuetype_fields:
        fields["environment"] = environment

    if priority_name and "priority" in issuetype_fields:
        fields["priority"] = {"name": priority_name}

    if epic_name_field and epic_name_field in issuetype_fields:
        fields[epic_name_field] = summary

    if duedate and "duedate" in issuetype_fields:
        fields["duedate"] = duedate.strftime("%Y-%m-%d")

    if default_assignee:
        fields["assignee"] = {"name": default_assignee}

    return fields


def add_jira_issue(obj, *args, **kwargs):
    def failure_to_add_message(message: str, exception: Exception, _: Any) -> bool:
        if exception:
            logger.error(exception)
        logger.error(message)
        log_jira_alert(message, obj)
        return False

    logger.info("trying to create a new jira issue for %d:%s", obj.id, to_str_typed(obj))

    if not is_jira_enabled():
        return False

    if not is_jira_configured_and_enabled(obj):
        message = f"Object {obj.id} cannot be pushed to JIRA as there is no JIRA configuration for {to_str_typed(obj)}."
        return failure_to_add_message(message, None, obj)

    jira_project = get_jira_project(obj)
    jira_instance = get_jira_instance(obj)

    obj_can_be_pushed_to_jira, error_message, _error_code = can_be_pushed_to_jira(obj)
    if not obj_can_be_pushed_to_jira:
        # not sure why this check is not part of can_be_pushed_to_jira, but afraid to change it
        if isinstance(obj, Finding) and obj.duplicate and not obj.active:
            logger.warning("%s will not be pushed to JIRA as it's a duplicate finding", to_str_typed(obj))
            log_jira_cannot_be_pushed_reason(error_message + " and findis a duplicate", obj)
        else:
            log_jira_cannot_be_pushed_reason(error_message, obj)
            logger.warning("%s cannot be pushed to JIRA: %s.", to_str_typed(obj), error_message)
            logger.warning("The JIRA issue will NOT be created.")
        return False
    logger.debug("Trying to create a new JIRA issue for %s...", to_str_typed(obj))
    # Attempt to get the jira connection
    try:
        JIRAError.log_to_tempfile = False
        jira = get_jira_connection(jira_instance)
    except Exception as e:
        message = f"The following jira instance could not be connected: {jira_instance} - {e}"
        return failure_to_add_message(message, e, obj)
    # Set the list of labels to set on the jira issue
    labels = get_labels(obj) + get_tags(obj)
    if labels:
        labels = list(dict.fromkeys(labels))  # de-dup
    # Determine what due date to set on the jira issue
    duedate = None

    if System_Settings.objects.get().enable_finding_sla:
        duedate = obj.sla_deadline()
    # Set the fields that will compose the jira issue
    try:
        issuetype_fields = get_issuetype_fields(jira, jira_project.project_key, jira_instance.default_issue_type)
        fields = prepare_jira_issue_fields(
            project_key=jira_project.project_key,
            issuetype_name=jira_instance.default_issue_type,
            summary=jira_summary(obj),
            description=jira_description(obj),
            component_name=jira_project.component,
            custom_fields=jira_project.custom_fields,
            labels=labels,
            environment=jira_environment(obj),
            priority_name=jira_priority(obj),
            epic_name_field=get_epic_name_field_name(jira_instance),
            duedate=duedate,
            issuetype_fields=issuetype_fields,
            default_assignee=jira_project.default_assignee)
    except TemplateDoesNotExist as e:
        message = f"Failed to find a jira issue template to be used - {e}"
        return failure_to_add_message(message, e, obj)
    except Exception as e:
        message = f"Failed to fetch fields for {jira_instance.default_issue_type} under project {jira_project.project_key} - {e}"
        return failure_to_add_message(message, e, obj)
    # Create a new issue in Jira with the fields set in the last step
    try:
        logger.debug("sending fields to JIRA: %s", fields)
        new_issue = jira.create_issue(fields)
        logger.debug("saving JIRA_Issue for %s finding %s", new_issue.key, obj.id)
        j_issue = JIRA_Issue(jira_id=new_issue.id, jira_key=new_issue.key, jira_project=jira_project)
        j_issue.set_obj(obj)
        j_issue.jira_creation = timezone.now()
        j_issue.jira_change = timezone.now()
        j_issue.save()
        jira.issue(new_issue.id)
        logger.info("Created the following jira issue for %d:%s", obj.id, to_str_typed(obj))
    except Exception as e:
        message = f"Failed to create jira issue with the following payload: {fields} - {e}"
        return failure_to_add_message(message, e, obj)
    # Attempt to set a default assignee
    try:
        if jira_project.default_assignee:
            created_assignee = str(new_issue.get_field("assignee"))
            logger.debug("new issue created with assignee %s", created_assignee)
            if created_assignee != jira_project.default_assignee:
                jira.assign_issue(new_issue.key, jira_project.default_assignee)
    except Exception as e:
        message = f"Failed to assign the default user: {jira_project.default_assignee} - {e}"
        # Do not return here as this should be a soft failure that should be logged
        failure_to_add_message(message, e, obj)
    # Upload dojo finding screenshots to Jira
    try:
        findings = [obj]
        if isinstance(obj, Finding_Group):
            findings = obj.findings.all()

        for find in findings:
            for pic in get_file_images(find):
                # It doesn't look like the celery cotainer has anything in the media
                # folder. Has this feature ever worked?
                try:
                    jira_attachment(
                        find, jira, new_issue,
                        settings.MEDIA_ROOT + "/" + pic)
                except FileNotFoundError as e:
                    logger.info(e)
    except Exception as e:
        message = f"Failed to attach attachments to the jira issue: {e}"
        # Do not return here as this should be a soft failure that should be logged
        failure_to_add_message(message, e, obj)
    # Add any notes that already exist in the finding to the JIRA
    try:
        for find in findings:
            if find.notes.all():
                for note in find.notes.all().reverse():
                    add_comment(obj, note)
    except Exception as e:
        message = f"Failed to add notes to the jira ticket: {e}"
        # Do not return here as this should be a soft failure that should be logged
        failure_to_add_message(message, e, obj)
    # Determine whether to assign this new jira issue to a mapped epic
    try:
        if jira_project.enable_engagement_epic_mapping:
            eng = obj.test.engagement
            logger.debug("Adding to EPIC Map: %s", eng.name)
            epic = get_jira_issue(eng)
            if epic:
                add_issues_to_epic(jira, obj, epic_id=epic.jira_id, issue_keys=[str(new_issue.id)], ignore_epics=True)
            else:
                logger.info("The following EPIC does not exist: %s", eng.name)
    except Exception as e:
        message = f"Failed to assign jira issue to existing epic: {e}"
        return failure_to_add_message(message, e, obj)

    return True


# we need two separate celery tasks due to the decorators we're using to map to/from ids

@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def update_jira_issue_for_finding(finding, *args, **kwargs):
    return update_jira_issue(finding, *args, **kwargs)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Finding_Group)
def update_jira_issue_for_finding_group(finding_group, *args, **kwargs):
    return update_jira_issue(finding_group, *args, **kwargs)


def update_jira_issue(obj, *args, **kwargs):
    def failure_to_update_message(message: str, exception: Exception, obj: Any) -> bool:
        if exception:
            logger.error(exception)
        logger.error(message)
        log_jira_alert(message, obj)
        return False

    logger.debug("trying to update a linked jira issue for %d:%s", obj.id, to_str_typed(obj))

    if not is_jira_enabled():
        return False

    jira_project = get_jira_project(obj)
    jira_instance = get_jira_instance(obj)

    if not is_jira_configured_and_enabled(obj):
        message = f"Object {obj.id} cannot be pushed to JIRA as there is no JIRA configuration for {to_str_typed(obj)}."
        return failure_to_update_message(message, None, obj)

    j_issue = obj.jira_issue
    try:
        JIRAError.log_to_tempfile = False
        jira = get_jira_connection(jira_instance)
        issue = jira.issue(j_issue.jira_id)
    except Exception as e:
        message = f"The following jira instance could not be connected: {jira_instance} - {e}"
        return failure_to_update_message(message, e, obj)
    # Set the list of labels to set on the jira issue
    labels = get_labels(obj) + get_tags(obj)
    if labels:
        labels = list(dict.fromkeys(labels))  # de-dup
    # Set the fields that will compose the jira issue
    try:
        issuetype_fields = get_issuetype_fields(jira, jira_project.project_key, jira_instance.default_issue_type)
        fields = prepare_jira_issue_fields(
            project_key=jira_project.project_key,
            issuetype_name=jira_instance.default_issue_type,
            summary=jira_summary(obj),
            description=jira_description(obj),
            component_name=jira_project.component if not issue.fields.components else None,
            labels=labels + issue.fields.labels,
            environment=jira_environment(obj),
            # Do not update the priority in jira after creation as this could have changed in jira, but should not change in dojo
            # priority_name=jira_priority(obj),
            issuetype_fields=issuetype_fields)
    except Exception as e:
        message = f"Failed to fetch fields for {jira_instance.default_issue_type} under project {jira_project.project_key} - {e}"
        return failure_to_update_message(message, e, obj)
    # Update the issue in jira
    try:
        logger.debug("sending fields to JIRA: %s", fields)
        issue.update(
            summary=fields["summary"],
            description=fields["description"],
            # Do not update the priority in jira after creation as this could have changed in jira, but should not change in dojo
            # priority=fields['priority'],
            fields=fields)
        j_issue.jira_change = timezone.now()
        j_issue.save()
    except Exception as e:
        message = f"Failed to update the jira issue with the following payload: {fields} - {e}"
        return failure_to_update_message(message, e, obj)
    # Update the status in jira
    try:
        push_status_to_jira(obj, jira_instance, jira, issue)
    except Exception as e:
        message = f"Failed to update the jira issue status - {e}"
        return failure_to_update_message(message, e, obj)
    # Upload dojo finding screenshots to Jira
    try:
        findings = [obj]
        if isinstance(obj, Finding_Group):
            findings = obj.findings.all()

        for find in findings:
            for pic in get_file_images(find):
                # It doesn't look like the celery container has anything in the media
                # folder. Has this feature ever worked?
                try:
                    jira_attachment(
                        find, jira, issue,
                        settings.MEDIA_ROOT + "/" + pic)
                except FileNotFoundError as e:
                    logger.info(e)
    except Exception as e:
        message = f"Failed to attach attachments to the jira issue: {e}"
        # Do not return here as this should be a soft failure that should be logged
        failure_to_update_message(message, e, obj)
    # Determine whether to assign this new jira issue to a mapped epic
    try:
        if jira_project.enable_engagement_epic_mapping:
            eng = find.test.engagement
            logger.debug("Adding to EPIC Map: %s", eng.name)
            epic = get_jira_issue(eng)
            if epic:
                add_issues_to_epic(jira, obj, epic_id=epic.jira_id, issue_keys=[str(j_issue.jira_id)], ignore_epics=True)
            else:
                logger.info("The following EPIC does not exist: %s", eng.name)
    except Exception as e:
        message = f"Failed to assign jira issue to existing epic: {e}"
        return failure_to_update_message(message, e, obj)

    return True


def get_jira_issue_from_jira(find):
    logger.debug("getting jira issue from JIRA for %d:%s", find.id, find)

    if not is_jira_enabled():
        return False

    jira_project = get_jira_project(find)
    jira_instance = get_jira_instance(find)

    j_issue = find.jira_issue
    if not jira_project:
        logger.error("Unable to retrieve latest status change from JIRA %s for finding %s as there is no JIRA_Project configured for this finding.", j_issue.jira_key, format(find.id))
        log_jira_alert(f"Unable to retrieve latest status change from JIRA {j_issue.jira_key} for finding {find} as there is no JIRA_Project configured for this finding.", find)
        return False

    meta = None
    try:
        JIRAError.log_to_tempfile = False
        jira = get_jira_connection(jira_instance)

        logger.debug("getting issue from JIRA")
        return jira.issue(j_issue.jira_id)

    except JIRAError as e:
        logger.exception("jira_meta for project: %s and url: %s meta: %s", jira_project.project_key, jira_project.jira_instance.url, json.dumps(meta, indent=4))  # this is None safe
        log_jira_alert(e.text, find)
        return None


def issue_from_jira_is_active(issue_from_jira):
    #         "resolution":{
    #             "self":"http://www.testjira.com/rest/api/2/resolution/11",
    #             "id":"11",
    #             "description":"Cancelled by the customer.",
    #             "name":"Cancelled"
    #         },

    # or
    #         "resolution": null

    # or
    #         "resolution": "None"

    if not hasattr(issue_from_jira.fields, "resolution"):
        logger.debug(vars(issue_from_jira))
        return True

    if not issue_from_jira.fields.resolution:
        return True

    # some kind of resolution is present that is not null or None
    return issue_from_jira.fields.resolution == "None"


def push_status_to_jira(obj, jira_instance, jira, issue, *, save=False):
    status_list = obj.status()
    issue_closed = False
    # check RESOLVED_STATUS first to avoid corner cases with findings that are Inactive, but verified
    if any(item in status_list for item in RESOLVED_STATUS):
        if issue_from_jira_is_active(issue):
            logger.debug("Transitioning Jira issue to Resolved")
            updated = jira_transition(jira, issue, jira_instance.close_status_key)
        else:
            logger.debug("Jira issue already Resolved")
            updated = False
        issue_closed = True

    if not issue_closed and any(item in status_list for item in OPEN_STATUS):
        if not issue_from_jira_is_active(issue):
            logger.debug("Transitioning Jira issue to Active (Reopen)")
            updated = jira_transition(jira, issue, jira_instance.open_status_key)
        else:
            logger.debug("Jira issue already Active")
            updated = False

    if updated and save:
        obj.jira_issue.jira_change = timezone.now()
        obj.jira_issue.save()


# gets the metadata for the provided issue type in the provided jira project
def get_issuetype_fields(
        jira,
        project_key,
        issuetype_name):

    issuetype_fields = None
    use_cloud_api = jira.deploymentType.lower() == "cloud" or jira._version < (9, 0, 0)

    try:
        if use_cloud_api:
            try:
                meta = jira.createmeta(
                        projectKeys=project_key,
                        issuetypeNames=issuetype_name,
                        expand="projects.issuetypes.fields")
            except JIRAError as e:
                e.text = f"Jira API call 'createmeta' failed with status: {e.status_code} and message: {e.text}"
                raise
            project = None
            try:
                project = meta["projects"][0]
            except Exception:
                msg = "Project misconfigured or no permissions in Jira ?"
                raise JIRAError(msg)

            try:
                issuetype_fields = project["issuetypes"][0]["fields"].keys()
            except Exception:
                msg = "Misconfigured default issue type ?"
                raise JIRAError(msg)

        else:
            try:
                issuetypes = jira.project_issue_types(project_key)
            except JIRAError as e:
                e.text = f"Jira API call 'createmeta/issuetypes' failed with status: {e.status_code} and message: {e.text}. Project misconfigured or no permissions in Jira ?"
                raise

            issuetype_id = None
            for it in issuetypes:
                if it.name == issuetype_name:
                    issuetype_id = it.id
                    break

            if not issuetype_id:
                msg = "Issue type ID can not be matched. Misconfigured default issue type ?"
                raise JIRAError(msg)

            try:
                issuetype_fields = jira.project_issue_fields(project_key, issuetype_id)
            except JIRAError as e:
                e.text = f"Jira API call 'createmeta/fieldtypes' failed with status: {e.status_code} and message: {e.text}. Misconfigured project or default issue type ?"
                raise

            try:
                issuetype_fields = [f.fieldId for f in issuetype_fields]
            except Exception:
                msg = "Misconfigured default issue type ?"
                raise JIRAError(msg)

    except JIRAError as e:
        e.text = f"Failed retrieving field metadata from Jira version: {jira._version}, project: {project_key}, issue type: {issuetype_name}. {e.text}"
        logger.warning(e.text)
        add_error_message_to_response(e.text)

        raise

    return issuetype_fields


def is_jira_project_valid(jira_project):
    try:
        jira = get_jira_connection(jira_project)
        get_issuetype_fields(jira, jira_project.project_key, jira_project.jira_instance.default_issue_type)
    except JIRAError:
        logger.debug("invalid JIRA Project Config, can't retrieve metadata for '%s'", jira_project)
        return False
    return True


def jira_attachment(finding, jira, issue, file, jira_filename=None):
    basename = file
    if jira_filename is None:
        basename = Path(file).name

    # Check to see if the file has been uploaded to Jira
    # TODO: JIRA: check for local existince of attachment as it currently crashes if local attachment doesn't exist
    if jira_check_attachment(issue, basename) is False:
        try:
            if jira_filename is not None:
                attachment = io.StringIO()
                attachment.write(jira_filename)
                jira.add_attachment(
                    issue=issue, attachment=attachment, filename=jira_filename)
            else:
                # read and upload a file
                with open(file, "rb") as f:
                    jira.add_attachment(issue=issue, attachment=f)
        except JIRAError as e:
            logger.exception("Unable to add attachment")
            log_jira_alert("Attachment: " + e.text, finding)
            return False
        return True
    return None


def jira_check_attachment(issue, source_file_name):
    file_exists = False
    for attachment in issue.fields.attachment:
        filename = attachment.filename

        if filename == source_file_name:
            file_exists = True
            break

    return file_exists


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Engagement)
def close_epic(eng, push_to_jira, **kwargs):
    engagement = eng
    if not is_jira_enabled():
        return False

    if not is_jira_configured_and_enabled(engagement):
        return False

    jira_project = get_jira_project(engagement)
    jira_instance = get_jira_instance(engagement)
    if jira_project.enable_engagement_epic_mapping:
        if push_to_jira:
            try:
                jissue = get_jira_issue(eng)
                if jissue is None:
                    logger.warning("JIRA close epic failed: no issue found")
                    return False

                req_url = jira_instance.url + "/rest/api/latest/issue/" + \
                    jissue.jira_id + "/transitions"
                json_data = {"transition": {"id": jira_instance.close_status_key}}
                r = requests.post(
                    url=req_url,
                    auth=HTTPBasicAuth(jira_instance.username, jira_instance.password),
                    json=json_data,
                    timeout=settings.REQUESTS_TIMEOUT,
                )
                if r.status_code != 204:
                    logger.warning(f"JIRA close epic failed with error: {r.text}")
                    return False
            except JIRAError as e:
                logger.exception("Jira Engagement/Epic Close Error")
                log_jira_generic_alert("Jira Engagement/Epic Close Error", str(e))
                return False
            return True
        return None
    add_error_message_to_response("Push to JIRA for Epic skipped because enable_engagement_epic_mapping is not checked for this engagement")
    return False


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Engagement)
def update_epic(engagement, **kwargs):
    logger.debug("trying to update jira EPIC for %d:%s", engagement.id, engagement.name)

    if not is_jira_configured_and_enabled(engagement):
        return False

    logger.debug("config found")

    jira_project = get_jira_project(engagement)
    jira_instance = get_jira_instance(engagement)
    if jira_project.enable_engagement_epic_mapping:
        try:
            jira = get_jira_connection(jira_instance)
            j_issue = get_jira_issue(engagement)
            issue = jira.issue(j_issue.jira_id)

            epic_name = kwargs.get("epic_name")
            if not epic_name:
                epic_name = engagement.name

            jira_issue_update_kwargs = {
                "summary": epic_name,
                "description": epic_name,
            }
            if (epic_priority := kwargs.get("epic_priority")) is not None:
                jira_issue_update_kwargs["priority"] = {"name": epic_priority}
            issue.update(**jira_issue_update_kwargs)
        except JIRAError as e:
            logger.exception("Jira Engagement/Epic Update Error")
            log_jira_generic_alert("Jira Engagement/Epic Update Error", str(e))
            return False

        return True

    add_error_message_to_response("Push to JIRA for Epic skipped because enable_engagement_epic_mapping is not checked for this engagement")
    return False


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Engagement)
def add_epic(engagement, **kwargs):
    logger.debug("trying to create a new jira EPIC for %d:%s", engagement.id, engagement.name)

    if not is_jira_configured_and_enabled(engagement):
        return False

    logger.debug("config found")

    jira_project = get_jira_project(engagement)
    jira_instance = get_jira_instance(engagement)
    if jira_project.enable_engagement_epic_mapping:
        epic_name = kwargs.get("epic_name")
        epic_issue_type_name = getattr(jira_project, "epic_issue_type_name", "Epic")
        if not epic_name:
            epic_name = engagement.name
        issue_dict = {
            "project": {
                "key": jira_project.project_key,
            },
            "summary": epic_name,
            "description": epic_name,
            "issuetype": {
                "name": epic_issue_type_name,
            },
        }
        if kwargs.get("epic_priority"):
            issue_dict["priority"] = {"name": kwargs.get("epic_priority")}
        try:
            jira = get_jira_connection(jira_instance)
            # Determine if we should add the epic name or not
            if (epic_name_field := get_epic_name_field_name(jira_instance)) in get_issuetype_fields(jira, jira_project.project_key, epic_issue_type_name):
                issue_dict[epic_name_field] = epic_name
            logger.debug("add_epic: %s", issue_dict)
            new_issue = jira.create_issue(fields=issue_dict)
            j_issue = JIRA_Issue(
                jira_id=new_issue.id,
                jira_key=new_issue.key,
                engagement=engagement,
                jira_project=jira_project)
            j_issue.save()
        except JIRAError as e:
            # should we try to parse the errors as JIRA is very strange in how it responds.
            # for example a non existent project_key leads to "project key is required" which sounds like something is missing
            # but it's just a non-existent project (or maybe a project for which the account has no create permission?)
            #
            # {"errorMessages":[],"errors":{"project":"project is required"}}
            error = str(e)
            message = ""
            if "customfield" in error:
                message = "The 'Epic name id' in your DefectDojo Jira Configuration does not appear to be correct. Please visit, " + jira_instance.url + \
                    "/rest/api/2/field and search for Epic Name. Copy the number out of cf[number] and place in your DefectDojo settings for Jira and try again. For example, if your results are cf[100001] then copy 100001 and place it in 'Epic name id'. (Your Epic Id will be different.) \n\n"
            logger.exception(message)

            log_jira_generic_alert("Jira Engagement/Epic Creation Error",
                                   message + error)
            return False

        return True

    add_error_message_to_response("Push to JIRA for Epic skipped because enable_engagement_epic_mapping is not checked for this engagement")
    return False


def jira_get_issue(jira_project, issue_key):
    try:
        jira_instance = jira_project.jira_instance
        jira = get_jira_connection(jira_instance)
        return jira.issue(issue_key)

    except JIRAError as jira_error:
        logger.exception("error retrieving jira issue %s", issue_key)
        log_jira_generic_alert("error retrieving jira issue " + issue_key, str(jira_error))
        return None


@dojo_model_to_id(parameter=1)
@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Notes, parameter=1)
@dojo_model_from_id
def add_comment(obj, note, *, force_push=False, **kwargs):
    if not is_jira_configured_and_enabled(obj):
        return False

    logger.debug("trying to add a comment to a linked jira issue for: %d:%s", obj.id, obj)
    if not note.private:
        jira_project = get_jira_project(obj)
        jira_instance = get_jira_instance(obj)

        if jira_project.push_notes or force_push is True:
            try:
                jira = get_jira_connection(jira_instance)
                j_issue = obj.jira_issue
                jira.add_comment(
                    j_issue.jira_id,
                    f"({note.author.get_full_name() or note.author.username}): {note.entry}")
            except JIRAError as e:
                log_jira_generic_alert("Jira Add Comment Error", str(e))
                return False
            return True
        return None
    return None


def add_simple_jira_comment(jira_instance, jira_issue, comment):
    try:
        jira_project = get_jira_project(jira_issue)

        # Check to see if jira project is disabled to prevent pushing findings
        if not jira_project.enabled:
            log_jira_generic_alert("JIRA Project is disabled", "Push to JIRA for Epic skipped because JIRA Project is disabled")
            return False

        jira = get_jira_connection(jira_instance)

        jira.add_comment(
            jira_issue.jira_id, comment,
        )
    except Exception as e:
        log_jira_generic_alert("Jira Add Comment Error", str(e))
        return False
    return True


def jira_already_linked(finding, jira_issue_key, jira_id) -> Finding | None:
    jira_issues = JIRA_Issue.objects.filter(jira_id=jira_id, jira_key=jira_issue_key).exclude(engagement__isnull=False)
    jira_issues = jira_issues.exclude(finding=finding)

    return jira_issues.first()


def finding_link_jira(request, finding, new_jira_issue_key):
    logger.debug("linking existing jira issue %s for finding %i", new_jira_issue_key, finding.id)

    jira_project = get_jira_project(finding)
    existing_jira_issue = jira_get_issue(jira_project, new_jira_issue_key)

    # Check to see if jira project is disabled to prevent pushing findings
    if not jira_project.enabled:
        add_error_message_to_response("Push to JIRA for finding skipped because JIRA Project is disabled")
        return False

    if not existing_jira_issue:
        raise ValueError("JIRA issue not found or cannot be retrieved: " + new_jira_issue_key)

    jira_issue = JIRA_Issue(
        jira_id=existing_jira_issue.id,
        jira_key=existing_jira_issue.key,
        finding=finding,
        jira_project=jira_project)

    jira_issue.jira_key = new_jira_issue_key
    # jira timestampe are in iso format: 'updated': '2020-07-17T09:49:51.447+0200'
    # seems to be a pain to parse these in python < 3.7, so for now just record the curent time as
    # as the timestamp the jira link was created / updated in DD
    jira_issue.jira_creation = timezone.now()
    jira_issue.jira_change = timezone.now()

    jira_issue.save()

    finding.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)

    return True


def finding_group_link_jira(request, finding_group, new_jira_issue_key):
    logger.debug("linking existing jira issue %s for finding group %i", new_jira_issue_key, finding_group.id)

    jira_project = get_jira_project(finding_group)
    existing_jira_issue = jira_get_issue(jira_project, new_jira_issue_key)

    # Check to see if jira project is disabled to prevent pushing findings
    if not jira_project.enabled:
        add_error_message_to_response("Push to JIRA for group skipped because JIRA Project is disabled")
        return False

    if not existing_jira_issue:
        raise ValueError("JIRA issue not found or cannot be retrieved: " + new_jira_issue_key)

    jira_issue = JIRA_Issue(
        jira_id=existing_jira_issue.id,
        jira_key=existing_jira_issue.key,
        finding_group=finding_group,
        jira_project=jira_project)

    jira_issue.jira_key = new_jira_issue_key
    # jira timestampe are in iso format: 'updated': '2020-07-17T09:49:51.447+0200'
    # seems to be a pain to parse these in python < 3.7, so for now just record the curent time as
    # as the timestamp the jira link was created / updated in DD
    jira_issue.jira_creation = timezone.now()
    jira_issue.jira_change = timezone.now()

    jira_issue.save()

    finding_group.save()

    return True


def finding_unlink_jira(request, finding):
    return unlink_jira(request, finding)


def unlink_jira(request, obj):
    logger.debug("removing linked jira issue %s for %i:%s", obj.jira_issue.jira_key, obj.id, to_str_typed(obj))
    obj.jira_issue.delete()
    # finding.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)


# return True if no errors
def process_jira_project_form(request, instance=None, target=None, product=None, engagement=None):
    if not get_system_setting("enable_jira"):
        return True, None

    error = False
    jira_project = None
    # supply empty instance to form so it has default values needed to make has_changed() work
    # jform = JIRAProjectForm(request.POST, instance=instance if instance else JIRA_Project(), product=product)
    jform = JIRAProjectForm(request.POST, instance=instance, target=target, product=product, engagement=engagement)
    # logging has_changed because it sometimes doesn't do what we expect
    logger.debug("jform has changed: %s", str(jform.has_changed()))

    if jform.has_changed():  # if no data was changed, no need to do anything!
        logger.debug("jform changed_data: %s", jform.changed_data)
        logger.debug("jform: %s", vars(jform))
        logger.debug("request.POST: %s", request.POST)

        # calling jform.is_valid() here with inheritance enabled would call clean() on the JIRA_Project model
        # resulting in a validation error if no jira_instance or project_key is provided
        # this validation is done because the form is a model form and cannot be skipped
        # so we check for inheritance checkbox before validating the form.
        # seems like it's impossible to write clean code with the Django forms framework.
        if request.POST.get("jira-project-form-inherit_from_product", False):
            logger.debug("inherit chosen")
            if not instance:
                logger.debug("inheriting but no existing JIRA Project for engagement, so nothing to do")
            else:
                error = True
                msg = "Not allowed to remove existing JIRA Config for an engagement"
                raise ValueError(msg)
        elif jform.is_valid():
            try:
                jira_project = jform.save(commit=False)
                # could be a new jira_project, so set product_id
                if engagement:
                    jira_project.engagement_id = engagement.id
                    obj = engagement
                elif product:
                    jira_project.product_id = product.id
                    obj = product

                if not jira_project.product_id and not jira_project.engagement_id:
                    msg = "encountered JIRA_Project without product_id and without engagement_id"
                    raise ValueError(msg)

                # only check jira project if form is sufficiently populated
                if jira_project.jira_instance and jira_project.project_key:
                    # is_jira_project_valid already adds messages if not a valid jira project
                    if not is_jira_project_valid(jira_project):
                        logger.debug("unable to retrieve jira project from jira instance, invalid?!")
                        error = True
                    else:
                        logger.debug(vars(jira_project))
                        jira_project.save()
                        # update the in memory instance to make jira_project attribute work and it can be retrieved when pushing
                        # an epic in the next step

                        obj.jira_project = jira_project

                        messages.add_message(request,
                                                messages.SUCCESS,
                                                "JIRA Project config stored successfully.",
                                                extra_tags="alert-success")
                        error = False
                        logger.debug("stored JIRA_Project successfully")
            except Exception:
                error = True
                logger.exception("Unable to store Jira project")
        else:
            logger.debug(jform.errors)
            error = True

        if error:
            messages.add_message(request,
                                    messages.ERROR,
                                    "JIRA Project config not stored due to errors.",
                                    extra_tags="alert-danger")
    return not error, jform


# return True if no errors
def process_jira_epic_form(request, engagement=None):
    if not get_system_setting("enable_jira"):
        return True, None

    logger.debug("checking jira epic form for engagement: %i:%s", engagement.id if engagement else 0, engagement)
    # push epic
    error = False
    jira_epic_form = JIRAEngagementForm(request.POST, instance=engagement)

    jira_project = get_jira_project(engagement)  # uses inheritance to get from product if needed

    if jira_project:
        if jira_epic_form.is_valid():
            if jira_epic_form.cleaned_data.get("push_to_jira"):
                logger.debug("pushing engagement to JIRA")
                epic_name = engagement.name
                if jira_epic_form.cleaned_data.get("epic_name"):
                    epic_name = jira_epic_form.cleaned_data.get("epic_name")
                epic_priority = None
                if jira_epic_form.cleaned_data.get("epic_priority"):
                    epic_priority = jira_epic_form.cleaned_data.get("epic_priority")
                if push_to_jira(engagement, epic_name=epic_name, epic_priority=epic_priority):
                    logger.debug("Push to JIRA for Epic queued successfully")
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Push to JIRA for Epic queued succesfully, check alerts on the top right for errors",
                        extra_tags="alert-success")
                else:
                    error = True
                    logger.debug("Push to JIRA for Epic failey")
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Push to JIRA for Epic failed, check alerts on the top right for errors",
                        extra_tags="alert-danger")
        else:
            logger.debug("invalid jira epic form")
    else:
        logger.debug("no jira_project for this engagement, skipping epic push")
    return not error, jira_epic_form


# some character will mess with JIRA formatting, for example when constructing a link:
# [name|url]. if name contains a '|' is will break it
# so [%s|%s] % (escape_for_jira(name), url)
def escape_for_jira(text):
    return text.replace("|", "%7D")


def process_resolution_from_jira(finding, resolution_id, resolution_name, assignee_name, jira_now, jira_issue) -> bool:
    """Processes the resolution field in the JIRA issue and updated the finding in Defect Dojo accordingly"""
    import dojo.risk_acceptance.helper as ra_helper
    status_changed = False
    resolved = resolution_id is not None
    jira_instance = get_jira_instance(finding)

    if resolved:
        if jira_instance and resolution_name in jira_instance.accepted_resolutions:
            if not finding.risk_accepted:
                logger.debug(f"Marking related finding of {jira_issue.jira_key} as accepted. Creating risk acceptance.")
                finding.active = False
                finding.mitigated = None
                finding.is_mitigated = False
                finding.false_p = False
                ra = Risk_Acceptance.objects.create(
                    accepted_by=assignee_name,
                    owner=finding.reporter,
                )
                finding.test.engagement.risk_acceptance.add(ra)
                ra_helper.add_findings_to_risk_acceptance(User.objects.get_or_create(username="JIRA")[0], ra, [finding])
                status_changed = True
        elif jira_instance and resolution_name in jira_instance.false_positive_resolutions:
            if not finding.false_p:
                logger.debug(f"Marking related finding of {jira_issue.jira_key} as false-positive")
                finding.active = False
                finding.verified = False
                finding.mitigated = None
                finding.is_mitigated = False
                finding.false_p = True
                ra_helper.risk_unaccept(User.objects.get_or_create(username="JIRA")[0], finding)
                status_changed = True
        # Mitigated by default as before
        elif not finding.is_mitigated:
            logger.debug(f"Marking related finding of {jira_issue.jira_key} as mitigated (default)")
            finding.active = False
            finding.mitigated = jira_now
            finding.is_mitigated = True
            finding.mitigated_by, _created = User.objects.get_or_create(username="JIRA")
            finding.endpoints.clear()
            finding.false_p = False
            ra_helper.risk_unaccept(User.objects.get_or_create(username="JIRA")[0], finding)
            status_changed = True
    elif not finding.active:
        # Reopen / Open Jira issue
        logger.debug(f"Re-opening related finding of {jira_issue.jira_key}")
        finding.active = True
        finding.mitigated = None
        finding.is_mitigated = False
        finding.false_p = False
        ra_helper.risk_unaccept(User.objects.get_or_create(username="JIRA")[0], finding)
        status_changed = True

    # for findings in a group, there is no jira_issue attached to the finding
    jira_issue.jira_change = jira_now
    jira_issue.save()
    if status_changed:
        finding.save()
    return status_changed


def save_and_push_to_jira(finding):
    # Manage the jira status changes
    push_to_jira = False
    # Determine if the finding is in a group. if so, not push to jira yet
    finding_in_group = finding.has_finding_group
    # Check if there is a jira issue that needs to be updated
    jira_issue_exists = finding.has_jira_issue or (finding.finding_group and finding.finding_group.has_jira_issue)
    # Only push if the finding is not in a group
    if jira_issue_exists:
        # Determine if any automatic sync should occur
        push_to_jira = is_push_all_issues(finding) \
            or get_jira_instance(finding).finding_jira_sync
    # Save the finding
    finding.save(push_to_jira=(push_to_jira and not finding_in_group))

    # we only push the group after saving the finding to make sure
    # the updated data of the finding is pushed as part of the group
    if push_to_jira and finding_in_group:
        push_to_jira(finding.finding_group)
