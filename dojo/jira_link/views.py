# Standard library imports
import datetime
import json
import logging

# Third party imports
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.core.exceptions import PermissionDenied
from django.db import DEFAULT_DB_ALIAS
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization import user_has_configuration_permission

# Local application/library imports
from dojo.forms import AdvancedJIRAForm, DeleteJIRAInstanceForm, JIRAForm
from dojo.models import JIRA_Instance, JIRA_Issue, Notes, System_Settings, User
from dojo.notifications.helper import create_notification
from dojo.utils import add_breadcrumb, add_error_message_to_response, get_setting

logger = logging.getLogger(__name__)


def webhook_responser_handler(
    log_level: str,
    message: str,
) -> HttpResponse:
    # These represent an error and will be sent to the debugger
    # for development purposes
    if log_level == "info":
        logger.info(message)
    # These are more common in misconfigurations and have a better
    # chance of being seen by a user
    elif log_level == "debug":
        logger.debug(message)
    # Return the response with the code
    return HttpResponse(message, status=200)


@csrf_exempt
@require_POST
def webhook(request, secret=None):
    """
    For examples of incoming json, see the unit tests for the webhook:
        https://github.com/DefectDojo/django-DefectDojo/blob/master/unittests/test_jira_webhook.py
    or the officials docs (which are not always clear):
        https://developer.atlassian.com/server/jira/platform/webhooks/

    All responses here will return a 201 so that we may have control over the
    logging level
    """
    # Make sure the request is a POST, otherwise, we reject
    if request.method != "POST":
        return webhook_responser_handler("debug", "Only POST requests are supported")
    # Determine if th webhook is in use or not
    system_settings = System_Settings.objects.get()
    # If the jira integration is not enabled, then return a 404
    if not system_settings.enable_jira:
        return webhook_responser_handler("info", "Ignoring incoming webhook as JIRA is disabled.")
    # If the webhook is not enabled, then return a 404
    if not system_settings.enable_jira_web_hook:
        return webhook_responser_handler("info", "Ignoring incoming webhook as JIRA Webhook is disabled.")
    # Determine if the request should be "authenticated"
    if not system_settings.disable_jira_webhook_secret:
        # Make sure there is a value for the webhook secret before making a comparison
        if not system_settings.jira_webhook_secret:
            return webhook_responser_handler("info", "Ignoring incoming webhook as JIRA Webhook secret is empty in Defect Dojo system settings.")
        # Make sure the secret supplied in the path of the webhook request matches the
        # secret supplied in the system settings
        if secret != system_settings.jira_webhook_secret:
            return webhook_responser_handler("info", "Invalid or no secret provided to JIRA Webhook")
    # if webhook secret is disabled in system_settings, we ignore the incoming secret, even if it doesn't match
    # example json bodies at the end of this file
    if request.content_type != "application/json":
        return webhook_responser_handler("debug", "only application/json supported")
    # Time to process the request
    try:
        parsed = json.loads(request.body.decode("utf-8"))
        # Check if the events supplied are supported
        if parsed.get("webhookEvent") not in ["comment_created", "jira:issue_updated"]:
            return webhook_responser_handler("info", f"Unrecognized JIRA webhook event received: {parsed.get('webhookEvent')}")

        if parsed.get("webhookEvent") == "jira:issue_updated":
            # xml examples at the end of file
            jid = parsed["issue"]["id"]
            # This may raise a 404, but it will be handled in the exception response
            try:
                jissue = JIRA_Issue.objects.get(jira_id=jid)
            except JIRA_Instance.DoesNotExist:
                return webhook_responser_handler("info", f"JIRA issue {jid} is not linked to a DefectDojo Finding")
            findings = None
            # Determine what type of object we will be working with
            if jissue.finding:
                logger.debug(f"Received issue update for {jissue.jira_key} for finding {jissue.finding.id}")
                findings = [jissue.finding]
            elif jissue.finding_group:
                logger.debug(f"Received issue update for {jissue.jira_key} for finding group {jissue.finding_group}")
                findings = jissue.finding_group.findings.all()
            elif jissue.engagement:
                return webhook_responser_handler("debug", "Update for engagement ignored")
            else:
                return webhook_responser_handler("info", f"Received issue update for {jissue.jira_key} for unknown object")
            # Process the assignee if present
            assignee = parsed["issue"]["fields"].get("assignee")
            assignee_name = "Jira User"
            if assignee is not None:
                # First look for the 'name' field. If not present, try 'displayName'. Else put None
                assignee_name = assignee.get("name", assignee.get("displayName"))

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

            resolution = parsed["issue"]["fields"]["resolution"]
            resolution = resolution if resolution and resolution != "None" else None
            resolution_id = resolution["id"] if resolution else None
            resolution_name = resolution["name"] if resolution else None
            jira_now = parse_datetime(parsed["issue"]["fields"]["updated"])

            if findings:
                for finding in findings:
                    jira_helper.process_resolution_from_jira(finding, resolution_id, resolution_name, assignee_name, jira_now, jissue)
            # Check for any comment that could have come along with the resolution
            if (error_response := check_for_and_create_comment(parsed)) is not None:
                return error_response

        if parsed.get("webhookEvent") == "comment_created":
            if (error_response := check_for_and_create_comment(parsed)) is not None:
                return error_response

    except Exception as e:
        # Check if the issue is originally a 404
        if isinstance(e, Http404):
            return webhook_responser_handler("debug", str(e))
        # Try to get a little more information on the exact exception
        try:
            message = (
                f"Original Exception: {e}\n"
                f"jira webhook body parsed:\n{json.dumps(parsed, indent=4)}"
            )
        except Exception:
            message = (
                f"Original Exception: {e}\n"
                f"jira webhook body :\n{request.body.decode('utf-8')}"
            )
        return webhook_responser_handler("debug", message)

    return webhook_responser_handler("No logging here", "Success!")


def check_for_and_create_comment(parsed_json):
    """
    Example incoming requests from JIRA Server 8.14.0
    {
    "timestamp":1610269967824,
    "webhookEvent":"comment_created",
    "comment":{
        "self":"https://jira.host.com/rest/api/2/issue/115254/comment/466578",
        "id":"466578",
        "author":{
            "self":"https://jira.host.com/rest/api/2/user?username=defect.dojo",
            "name":"defect.dojo",
            "key":"defect.dojo", # seems to be only present on JIRA Server, not on Cloud
            "avatarUrls":{
                "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
                "24x24":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
                "16x16":"https://www.gravatar.com/avatar9637bfb970eff6176357df615f548f1c?d=mm&s=16",
                "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
            },
            "displayName":"Defect Dojo",
            "active":true,
            "timeZone":"Europe/Amsterdam"
        },
        "body":"(Valentijn Scholten):test4",
        "updateAuthor":{
            "self":"https://jira.host.com/rest/api/2/user?username=defect.dojo",
            "name":"defect.dojo",
            "key":"defect.dojo",
            "avatarUrls":{
                "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
                "24x24""https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
                "16x16":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=16",
                "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
            },
            "displayName":"Defect Dojo",
            "active":true,
            "timeZone":"Europe/Amsterdam"
        },
        "created":"2021-01-10T10:12:47.824+0100",
        "updated":"2021-01-10T10:12:47.824+0100"
    }
    }
    """
    comment = parsed_json.get("comment", None)
    if comment is None:
        return None

    comment_text = comment.get("body")
    commenter = ""
    if "name" in comment.get("updateAuthor"):
        commenter = comment.get("updateAuthor", {}).get("name")
    elif "emailAddress" in comment.get("updateAuthor"):
        commenter = comment.get("updateAuthor", {}).get("emailAddress")
    else:
        logger.debug("Could not find the author of this jira comment!")
    commenter_display_name = comment.get("updateAuthor", {}).get("displayName")
    # example: body['comment']['self'] = "http://www.testjira.com/jira_under_a_path/rest/api/2/issue/666/comment/456843"
    jid = comment.get("self", "").split("/")[-3]
    try:
        jissue = JIRA_Issue.objects.get(jira_id=jid)
    except JIRA_Instance.DoesNotExist:
        return webhook_responser_handler("info", f"JIRA issue {jid} is not linked to a DefectDojo Finding")
    logger.debug(f"Received issue comment for {jissue.jira_key}")
    logger.debug("jissue: %s", vars(jissue))

    jira_usernames = JIRA_Instance.objects.values_list("username", flat=True)
    for jira_user_id in jira_usernames:
        # logger.debug('incoming username: %s jira config username: %s', commenter.lower(), jira_user_id.lower())
        if jira_user_id.lower() == commenter.lower():
            return webhook_responser_handler("debug", f"skipping incoming JIRA comment as the user id of the comment in JIRA {commenter.lower()} matches the JIRA username in DefectDojo {jira_user_id.lower()}")

    findings = None
    if jissue.finding:
        findings = [jissue.finding]
        create_notification(event="jira_comment", title=f"JIRA incoming comment - {jissue.finding}", finding=jissue.finding, url=reverse("view_finding", args=(jissue.finding.id,)), icon="check")
    elif jissue.finding_group:
        findings = jissue.finding_group.findings.all()
        first_finding_group = findings.first()
        if first_finding_group:
            create_notification(event="jira_comment", title=f"JIRA incoming comment - {jissue.finding_group}", finding=first_finding_group, url=reverse("view_finding_group", args=(jissue.finding_group.id,)), icon="check")
    elif jissue.engagement:
        return webhook_responser_handler("debug", "Comment for engagement ignored")
    else:
        return webhook_responser_handler("info", f"Received issue update for {jissue.jira_key} for unknown object")
    # Set the fields for the notes
    author, _ = User.objects.get_or_create(username="JIRA")
    entry = f"({commenter_display_name} ({commenter})): {comment_text}"
    # Iterate (potentially) over each of the findings the note should be added to
    for finding in findings:
        # Determine if this exact note was created within the last 30 seconds to avoid duplicate notes
        existing_notes = finding.notes.filter(
            entry=entry,
            author=author,
            date__gte=(timezone.now() - datetime.timedelta(seconds=30)),
        )
        # Check the query for any hits
        if existing_notes.count() == 0:
            new_note = Notes()
            new_note.entry = entry
            new_note.author = author
            new_note.save()
            finding.notes.add(new_note)
            finding.jira_issue.jira_change = timezone.now()
            finding.jira_issue.save()
            finding.save()
    return None


def get_custom_field(jira, label):
    url = jira._options["server"].strip("/") + "/rest/api/2/field"
    response = jira._session.get(url).json()
    for node in response:
        if label in node["clauseNames"]:
            field = int(node["schema"]["customId"])
            break

    return field


class NewJiraView(View):
    def get_template(self):
        return "dojo/new_jira.html"

    def get_fallback_template(self):
        return "dojo/new_jira_advanced.html"

    def get_form_class(self):
        return JIRAForm

    def get_fallback_form_class(self):
        return AdvancedJIRAForm

    def get(self, request):
        if not user_has_configuration_permission(request.user, "dojo.add_jira_instance"):
            raise PermissionDenied
        jform = self.get_form_class()()
        add_breadcrumb(title="New Jira Configuration", top_level=False, request=request)
        return render(request, self.get_template(), {"jform": jform})

    def post(self, request):
        if not user_has_configuration_permission(request.user, "dojo.add_jira_instance"):
            raise PermissionDenied
        jform = self.get_form_class()(request.POST, instance=JIRA_Instance())
        if jform.is_valid():
            jira_server = jform.cleaned_data.get("url").rstrip("/")
            jira_username = jform.cleaned_data.get("username")
            jira_password = jform.cleaned_data.get("password")

            try:
                jira = jira_helper.get_jira_connection_raw(jira_server, jira_username, jira_password)
            except Exception:
                logger.exception("Unable to authenticate. Please check credentials.")  # already logged in jira_helper
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to authenticate. Please check credentials.",
                    extra_tags="alert-danger")
                return render(request, self.get_template(), {"jform": jform})
            # authentication successful
            # Get the open and close keys
            try:
                issue_id = jform.cleaned_data.get("issue_key")
                key_url = jira_server.strip("/") + "/rest/api/latest/issue/" + issue_id + "/transitions?expand=transitions.fields"
                response = jira._session.get(key_url).json()
                logger.debug("Retrieved JIRA issue successfully")
                open_key = close_key = None
                for node in response["transitions"]:
                    if node["to"]["statusCategory"]["name"] == "To Do":
                        open_key = open_key or int(node["id"])
                    if node["to"]["statusCategory"]["name"] == "Done":
                        close_key = close_key or int(node["id"])
            except Exception:
                msg = "Unable to find Open/Close ID's (invalid issue key specified?). They will need to be found manually"
                logger.exception(msg)  # already logged in jira_helper
                messages.add_message(
                    request,
                    messages.ERROR,
                    msg,
                    extra_tags="alert-danger")
                fallback_form = self.get_fallback_form_class()(request.POST, instance=JIRA_Instance())
                return render(request, self.get_fallback_template(), {"jform": fallback_form})
            # Get the epic id name
            try:
                epic_name = get_custom_field(jira, "Epic Name")
            except Exception:
                msg = "Unable to find Epic Name. It will need to be found manually"
                logger.exception(msg)  # already logged in jira_helper
                messages.add_message(
                    request,
                    messages.ERROR,
                    msg,
                    extra_tags="alert-danger")
                fallback_form = self.get_fallback_form_class()(request.POST, instance=JIRA_Instance())
                return render(request, self.get_fallback_template(), {"jform": fallback_form})

            jira_instance = JIRA_Instance(
                username=jira_username,
                password=jira_password,
                url=jira_server,
                configuration_name=jform.cleaned_data.get("configuration_name"),
                info_mapping_severity="Lowest",
                low_mapping_severity="Low",
                medium_mapping_severity="Medium",
                high_mapping_severity="High",
                critical_mapping_severity="Highest",
                epic_name_id=epic_name,
                open_status_key=open_key,
                close_status_key=close_key,
                finding_text="",
                default_issue_type=jform.cleaned_data.get("default_issue_type"),
                finding_jira_sync=jform.cleaned_data.get("finding_jira_sync"))
            jira_instance.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "JIRA Configuration Successfully Created.",
                extra_tags="alert-success")
            create_notification(
                event="jira_config_added",
                title=f"New addition of JIRA: {jform.cleaned_data.get('configuration_name')}",
                description=f"JIRA \"{jform.cleaned_data.get('configuration_name')}\" was added by {request.user}",
                url=request.build_absolute_uri(reverse("jira")))

            return HttpResponseRedirect(reverse("jira"))
        return render(request, self.get_template(), {"jform": jform})


class AdvancedJiraView(View):
    def get_template(self):
        return "dojo/new_jira_advanced.html"

    def get_form_class(self):
        return AdvancedJIRAForm

    def get(self, request):
        if not user_has_configuration_permission(request.user, "dojo.add_jira_instance"):
            raise PermissionDenied
        jform = self.get_form_class()()
        add_breadcrumb(title="New Jira Configuration (Advanced)", top_level=False, request=request)
        return render(request, self.get_template(), {"jform": jform})

    def post(self, request):
        if not user_has_configuration_permission(request.user, "dojo.add_jira_instance"):
            raise PermissionDenied
        jform = self.get_form_class()(request.POST, instance=JIRA_Instance())
        if jform.is_valid():
            jira_server = jform.cleaned_data.get("url").rstrip("/")
            jira_username = jform.cleaned_data.get("username")
            jira_password = jform.cleaned_data.get("password")

            logger.debug("calling get_jira_connection_raw")
            # Make sure the connection can be completed
            jira_helper.get_jira_connection_raw(jira_server, jira_username, jira_password)

            new_j = jform.save(commit=False)
            new_j.url = jira_server
            new_j.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "JIRA Configuration Successfully Created.",
                extra_tags="alert-success")
            create_notification(
                event="jira_config_added",
                title=f"New addition of JIRA: {jform.cleaned_data.get('configuration_name')}",
                description=f"JIRA \"{jform.cleaned_data.get('configuration_name')}\" was added by {request.user}",
                url=request.build_absolute_uri(reverse("jira")))

            return HttpResponseRedirect(reverse("jira"))
        logger.error("jform.errors: %s", jform.errors)
        return render(request, self.get_template(), {"jform": jform})


class EditJiraView(View):
    def get_template(self):
        return "dojo/edit_jira.html"

    def get_form_class(self):
        return AdvancedJIRAForm

    def get(self, request, jid=None):
        if not user_has_configuration_permission(request.user, "dojo.change_jira_instance"):
            raise PermissionDenied
        jira = JIRA_Instance.objects.get(pk=jid)
        jform = self.get_form_class()(instance=jira)
        add_breadcrumb(title="Edit JIRA Configuration", top_level=False, request=request)
        return render(request, self.get_template(), {"jform": jform})

    def post(self, request, jid=None):
        if not user_has_configuration_permission(request.user, "dojo.change_jira_instance"):
            raise PermissionDenied
        jira = JIRA_Instance.objects.get(pk=jid)
        jira_password_from_db = jira.password
        jform = self.get_form_class()(request.POST, instance=jira)
        if jform.is_valid():
            jira_server = jform.cleaned_data.get("url").rstrip("/")
            jira_username = jform.cleaned_data.get("username")

            if jform.cleaned_data.get("password"):
                jira_password = jform.cleaned_data.get("password")
            else:
                # on edit the password is optional
                jira_password = jira_password_from_db

            jira_helper.get_jira_connection_raw(jira_server, jira_username, jira_password)

            new_j = jform.save(commit=False)
            new_j.url = jira_server
            # on edit the password is optional
            new_j.password = jira_password
            new_j.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "JIRA Configuration Successfully Saved.",
                extra_tags="alert-success")
            create_notification(
                event="jira_config_edited",
                title=f"Edit of JIRA: {jform.cleaned_data.get('configuration_name')}",
                description=f"JIRA \"{jform.cleaned_data.get('configuration_name')}\" was edited by {request.user}",
                url=request.build_absolute_uri(reverse("jira")))

            return HttpResponseRedirect(reverse("jira"))

        return render(request, self.get_template(), {"jform": jform})


class ListJiraView(View):
    def get_template(self):
        return "dojo/jira.html"

    def get(self, request):
        if not user_has_configuration_permission(request.user, "dojo.view_jira_instance"):
            raise PermissionDenied
        jira_instances = JIRA_Instance.objects.all()
        context = {"jira_instances": jira_instances}
        add_breadcrumb(title="JIRA List", top_level=not len(request.GET), request=request)
        return render(request, self.get_template(), context)


class DeleteJiraView(View):
    def get_template(self):
        return "dojo/delete_jira.html"

    def get_form_class(self):
        return DeleteJIRAInstanceForm

    def get(self, request, tid=None):
        if not user_has_configuration_permission(request.user, "dojo.delete_jira_instance"):
            raise PermissionDenied
        jira_instance = get_object_or_404(JIRA_Instance, pk=tid)
        form = self.get_form_class()(instance=jira_instance)
        rels = ["Previewing the relationships has been disabled.", ""]
        display_preview = get_setting("DELETE_PREVIEW")
        if display_preview:
            collector = NestedObjects(using=DEFAULT_DB_ALIAS)
            collector.collect([jira_instance])
            rels = collector.nested()

        add_breadcrumb(title="Delete", top_level=False, request=request)
        return render(request, self.get_template(), {
            "inst": jira_instance,
            "form": form,
            "rels": rels,
            "deletable_objects": rels,
        })

    def post(self, request, tid=None):
        if not user_has_configuration_permission(request.user, "dojo.delete_jira_instance"):
            raise PermissionDenied
        jira_instance = get_object_or_404(JIRA_Instance, pk=tid)
        if "id" in request.POST and str(jira_instance.id) == request.POST["id"]:
            form = self.get_form_class()(request.POST, instance=jira_instance)
            if form.is_valid():
                try:
                    jira_instance.delete()
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "JIRA Conf and relationships removed.",
                        extra_tags="alert-success")
                    create_notification(
                        event="jira_config_deleted",
                        title=_("Deletion of JIRA: %s") % jira_instance.configuration_name,
                        description=f'JIRA "{jira_instance.configuration_name}" was deleted by {request.user}',
                        url=request.build_absolute_uri(reverse("jira")))
                    return HttpResponseRedirect(reverse("jira"))
                except Exception as e:
                    add_error_message_to_response(f"Unable to delete JIRA Instance, probably because it is used by JIRA Issues: {e}")

        rels = ["Previewing the relationships has been disabled.", ""]
        display_preview = get_setting("DELETE_PREVIEW")
        if display_preview:
            collector = NestedObjects(using=DEFAULT_DB_ALIAS)
            collector.collect([jira_instance])
            rels = collector.nested()

        add_breadcrumb(title="Delete", top_level=False, request=request)
        return render(request, self.get_template(), {
            "inst": jira_instance,
            "form": form,
            "rels": rels,
            "deletable_objects": rels,
        })
