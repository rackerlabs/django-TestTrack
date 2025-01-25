# #  tests
import base64
import logging
import operator
from datetime import datetime
from functools import reduce

from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.core.exceptions import ValidationError
from django.db import DEFAULT_DB_ALIAS
from django.db.models import Count, Q, QuerySet
from django.db.models.query import Prefetch
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import Resolver404, reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_cookie

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.engagement.queries import get_authorized_engagements
from dojo.filters import FindingFilter, FindingFilterWithoutObjectLookups, TemplateFindingFilter, TestImportFilter
from dojo.finding.views import find_available_notetypes
from dojo.forms import (
    AddFindingForm,
    CopyTestForm,
    DeleteTestForm,
    FindingBulkUpdateForm,
    JIRAFindingForm,
    JIRAImportScanForm,
    NoteForm,
    ReImportScanForm,
    TestForm,
    TypedNoteForm,
)
from dojo.importers.base_importer import BaseImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    IMPORT_UNTOUCHED_FINDING,
    BurpRawRequestResponse,
    Cred_Mapping,
    Endpoint,
    Finding,
    Finding_Group,
    Finding_Template,
    Note_Type,
    Product_API_Scan_Configuration,
    Stub_Finding,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
)
from dojo.notifications.helper import create_notification
from dojo.test.queries import get_authorized_tests
from dojo.tools.factory import get_choices_sorted, get_scan_types_sorted
from dojo.user.queries import get_authorized_users
from dojo.utils import (
    Product_Tab,
    add_breadcrumb,
    add_error_message_to_response,
    add_field_errors_to_response,
    add_success_message_to_response,
    async_delete,
    calculate_grade,
    get_cal_event,
    get_page_items,
    get_page_items_and_count,
    get_setting,
    get_system_setting,
    get_words_for_field,
    process_tag_notifications,
    redirect_to_return_url_or_else,
)

logger = logging.getLogger(__name__)
parse_logger = logging.getLogger("dojo")
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def prefetch_for_findings(findings):
    prefetched_findings = findings
    if isinstance(findings, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
        prefetched_findings = prefetched_findings.select_related("reporter")
        prefetched_findings = prefetched_findings.prefetch_related("jira_issue__jira_project__jira_instance")
        prefetched_findings = prefetched_findings.prefetch_related("test__test_type")
        prefetched_findings = prefetched_findings.prefetch_related("test__engagement__jira_project__jira_instance")
        prefetched_findings = prefetched_findings.prefetch_related("test__engagement__product__jira_project_set__jira_instance")
        prefetched_findings = prefetched_findings.prefetch_related("found_by")
        prefetched_findings = prefetched_findings.prefetch_related("risk_acceptance_set")
        # we could try to prefetch only the latest note with SubQuery and OuterRef, but I'm getting that MySql doesn't support limits in subqueries.
        prefetched_findings = prefetched_findings.prefetch_related("notes")
        prefetched_findings = prefetched_findings.prefetch_related("tags")
        # filter out noop reimport actions from finding status history
        prefetched_findings = prefetched_findings.prefetch_related(Prefetch("test_import_finding_action_set",
                                                                            queryset=Test_Import_Finding_Action.objects.exclude(action=IMPORT_UNTOUCHED_FINDING)))

        prefetched_findings = prefetched_findings.prefetch_related("endpoints")
        prefetched_findings = prefetched_findings.prefetch_related("status_finding")
        prefetched_findings = prefetched_findings.annotate(active_endpoint_count=Count("status_finding__id", filter=Q(status_finding__mitigated=False)))
        prefetched_findings = prefetched_findings.annotate(mitigated_endpoint_count=Count("status_finding__id", filter=Q(status_finding__mitigated=True)))
        prefetched_findings = prefetched_findings.prefetch_related("finding_group_set__jira_issue")
        prefetched_findings = prefetched_findings.prefetch_related("duplicate_finding")
        prefetched_findings = prefetched_findings.prefetch_related("vulnerability_id_set")
    else:
        logger.debug("unable to prefetch because query was already executed")

    return prefetched_findings


class ViewTest(View):
    def get_test(self, test_id: int):
        test_prefetched = get_authorized_tests(Permissions.Test_View)
        test_prefetched = test_prefetched.annotate(total_reimport_count=Count("test_import__id", distinct=True))
        return get_object_or_404(test_prefetched, pk=test_id)

    def get_test_import_data(self, request: HttpRequest, test: Test):
        test_imports = Test_Import.objects.filter(test=test)
        test_import_filter = TestImportFilter(request.GET, test_imports)

        paged_test_imports = get_page_items_and_count(request, test_import_filter.qs, 5, prefix="test_imports")
        paged_test_imports.object_list = paged_test_imports.object_list.prefetch_related("test_import_finding_action_set")

        return {
            "paged_test_imports": paged_test_imports,
            "test_import_filter": test_import_filter,
        }

    def get_stub_findings(self, request: HttpRequest, test: Test):
        stub_findings = Stub_Finding.objects.filter(test=test)
        paged_stub_findings = get_page_items(request, stub_findings, 25)

        return {
            "stub_findings": paged_stub_findings,
        }

    def get_findings(self, request: HttpRequest, test: Test):
        findings = Finding.objects.filter(test=test).order_by("numerical_severity")
        filter_string_matching = get_system_setting("filter_string_matching", False)
        finding_filter_class = FindingFilterWithoutObjectLookups if filter_string_matching else FindingFilter
        findings = finding_filter_class(request.GET, queryset=findings)
        paged_findings = get_page_items_and_count(request, prefetch_for_findings(findings.qs), 25, prefix="findings")

        return {
            "findings": paged_findings,
            "filtered": findings,
        }

    def get_note_form(self, request: HttpRequest):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {}

        return NoteForm(*args, **kwargs)

    def get_typed_note_form(self, request: HttpRequest, context: dict):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "available_note_types": context.get("available_note_types"),
        }

        return TypedNoteForm(*args, **kwargs)

    def get_form(self, request: HttpRequest, context: dict):
        return (
            self.get_typed_note_form(request, context)
            if context.get("note_type_activation")
            else self.get_note_form(request)
        )

    def get_initial_context(self, request: HttpRequest, test: Test):
        # Set up the product tab
        product_tab = Product_Tab(test.engagement.product, title=_("Test"), tab="engagements")
        product_tab.setEngagement(test.engagement)
        # Set up the notes and associated info to generate the form with
        notes = test.notes.all()
        note_type_activation = Note_Type.objects.filter(is_active=True).count()
        available_note_types = None
        if note_type_activation:
            available_note_types = find_available_notetypes(notes)
        # Set the current context
        context = {
            "test": test,
            "prod": test.engagement.product,
            "product_tab": product_tab,
            "title_words": get_words_for_field(Finding, "title"),
            "component_words": get_words_for_field(Finding, "component_name"),
            "notes": notes,
            "note_type_activation": note_type_activation,
            "available_note_types": available_note_types,
            "files": test.files.all(),
            "person": request.user.username,
            "request": request,
            "show_re_upload": any(test.test_type.name in code for code in get_choices_sorted()),
            "creds": Cred_Mapping.objects.filter(engagement=test.engagement).select_related("cred_id").order_by("cred_id"),
            "cred_test": Cred_Mapping.objects.filter(test=test).select_related("cred_id").order_by("cred_id"),
            "jira_project": jira_helper.get_jira_project(test),
            "bulk_edit_form": FindingBulkUpdateForm(request.GET),
            "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
            "finding_groups": test.finding_group_set.all().prefetch_related("findings", "jira_issue", "creator", "findings__vulnerability_id_set"),
            "finding_group_by_options": Finding_Group.GROUP_BY_OPTIONS,
        }
        # Set the form using the context, and then update the context
        form = self.get_form(request, context)
        context["form"] = form
        # Add some of the related objects
        context |= self.get_findings(request, test)
        context |= self.get_stub_findings(request, test)
        context |= self.get_test_import_data(request, test)

        return context

    def process_form(self, request: HttpRequest, test: Test, context: dict):
        if context["form"].is_valid():
            # Save the note
            new_note = context["form"].save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            test.notes.add(new_note)
            # Make a notification for this actions
            url = request.build_absolute_uri(reverse("view_test", args=(test.id,)))
            title = f"Test: {test.test_type.name} on {test.engagement.product.name}"
            process_tag_notifications(request, new_note, url, title)
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Note added successfully."),
                extra_tags="alert-success")

            return request, True
        return request, False

    def get_template(self):
        return "dojo/view_test.html"

    def get(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Test_View)
        # Quick perms check to determine if the user has access to add a note to the test
        user_has_permission_or_403(request.user, test, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Test_View)
        # Quick perms check to determine if the user has access to add a note to the test
        user_has_permission_or_403(request.user, test, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Determine the validity of the form
        request, success = self.process_form(request, test, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_test", args=(test_id,)))
        # Render the form
        return render(request, self.get_template(), context)


# def prefetch_for_test_imports(test_imports):
#     prefetched_test_imports = test_imports
#     if isinstance(test_imports, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
#         #could we make this dynamic, i.e for action_type in IMPORT_ACTIONS: prefetch
#         prefetched_test_imports = prefetched_test_imports.annotate(created_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_CREATED_FINDING)))
#         prefetched_test_imports = prefetched_test_imports.annotate(closed_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_CLOSED_FINDING)))
#         prefetched_test_imports = prefetched_test_imports.annotate(reactivated_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_REACTIVATED_FINDING)))
#         prefetched_test_imports = prefetched_test_imports.annotate(updated_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_UNTOUCHED_FINDING)))

#     return prefetch_for_test_imports


@user_is_authorized(Test, Permissions.Test_Edit, "tid")
def edit_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    form = TestForm(instance=test)
    if request.method == "POST":
        form = TestForm(request.POST, instance=test)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Test saved."),
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("view_engagement", args=(test.engagement.id,)))

    form.initial["target_start"] = test.target_start.date()
    form.initial["target_end"] = test.target_end.date()
    form.initial["description"] = test.description

    product_tab = Product_Tab(test.engagement.product, title=_("Edit Test"), tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, "dojo/edit_test.html",
                  {"test": test,
                   "product_tab": product_tab,
                   "form": form,
                   })


@user_is_authorized(Test, Permissions.Test_Delete, "tid")
def delete_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    eng = test.engagement
    form = DeleteTestForm(instance=test)

    if request.method == "POST":
        if "id" in request.POST and str(test.id) == request.POST["id"]:
            form = DeleteTestForm(request.POST, instance=test)
            if form.is_valid():
                if get_setting("ASYNC_OBJECT_DELETE"):
                    async_del = async_delete()
                    async_del.delete(test)
                    message = _("Test and relationships will be removed in the background.")
                else:
                    message = _("Test and relationships removed.")
                    test.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("view_engagement", args=(eng.id,)))

    rels = ["Previewing the relationships has been disabled.", ""]
    display_preview = get_setting("DELETE_PREVIEW")
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([test])
        rels = collector.nested()

    product_tab = Product_Tab(test.engagement.product, title=_("Delete Test"), tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, "dojo/delete_test.html",
                  {"test": test,
                   "product_tab": product_tab,
                   "form": form,
                   "rels": rels,
                   "deletable_objects": rels,
                   })


@user_is_authorized(Test, Permissions.Test_Edit, "tid")
def copy_test(request, tid):
    test = get_object_or_404(Test, id=tid)
    product = test.engagement.product
    engagement_list = get_authorized_engagements(Permissions.Engagement_Edit).filter(product=product)
    form = CopyTestForm(engagements=engagement_list)

    if request.method == "POST":
        form = CopyTestForm(request.POST, engagements=engagement_list)
        if form.is_valid():
            engagement = form.cleaned_data.get("engagement")
            product = test.engagement.product
            test_copy = test.copy(engagement=engagement)
            calculate_grade(product)
            messages.add_message(
                request,
                messages.SUCCESS,
                "Test Copied successfully.",
                extra_tags="alert-success")
            create_notification(event="test_copied",  # TODO: - if 'copy' functionality will be supported by API as well, 'create_notification' needs to be migrated to place where it will be able to cover actions from both interfaces
                                title=f"Copying of {test.title}",
                                description=f'The test "{test.title}" was copied by {request.user} to {engagement.name}',
                                product=product,
                                url=request.build_absolute_uri(reverse("view_test", args=(test_copy.id,))),
                                recipients=[test.engagement.lead],
                                icon="exclamation-triangle")
            return redirect_to_return_url_or_else(request, reverse("view_engagement", args=(engagement.id, )))
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to copy test, please try again.",
            extra_tags="alert-danger")

    product_tab = Product_Tab(product, title="Copy Test", tab="engagements")
    return render(request, "dojo/copy_object.html", {
        "source": test,
        "source_label": "Test",
        "destination_label": "Engagement",
        "product_tab": product_tab,
        "form": form,
    })


@cache_page(60 * 5)  # cache for 5 minutes
@vary_on_cookie
def test_calendar(request):

    if not get_system_setting("enable_calendar"):
        raise Resolver404

    if "lead" not in request.GET or "0" in request.GET.getlist("lead"):
        tests = get_authorized_tests(Permissions.Test_View)
    else:
        filters = []
        leads = request.GET.getlist("lead", "")
        if "-1" in request.GET.getlist("lead"):
            leads.remove("-1")
            filters.append(Q(lead__isnull=True))
        filters.append(Q(lead__in=leads))
        tests = get_authorized_tests(Permissions.Test_View).filter(reduce(operator.or_, filters))

    tests = tests.prefetch_related("test_type", "lead", "engagement__product")

    add_breadcrumb(title=_("Test Calendar"), top_level=True, request=request)
    return render(request, "dojo/calendar.html", {
        "caltype": "tests",
        "leads": request.GET.getlist("lead", ""),
        "tests": tests,
        "users": get_authorized_users(Permissions.Test_View)})


@user_is_authorized(Test, Permissions.Test_View, "tid")
def test_ics(request, tid):
    test = get_object_or_404(Test, id=tid)
    start_date = datetime.combine(test.target_start, datetime.min.time())
    end_date = datetime.combine(test.target_end, datetime.max.time())
    uid = f"dojo_test_{test.id}_{test.engagement.id}_{test.engagement.product.id}"
    cal = get_cal_event(
        start_date,
        end_date,
        _("Test: %s (%s)") % (
            test.test_type.name,
            test.engagement.product.name,
        ),
        _(
            "Set aside for test %s, on product %s. "
            "Additional detail can be found at %s",
        ) % (
            test.test_type.name,
            test.engagement.product.name,
            request.build_absolute_uri(reverse("view_test", args=(test.id,))),
        ),
        uid,
    )
    output = cal.serialize()
    response = HttpResponse(content=output)
    response["Content-Type"] = "text/calendar"
    response["Content-Disposition"] = f"attachment; filename={test.test_type.name}.ics"
    return response


class AddFindingView(View):
    def get_test(self, test_id: int):
        return get_object_or_404(Test, id=test_id)

    def get_initial_context(self, request: HttpRequest, test: Test):
        # Get the finding form first since it is used in another place
        finding_form = self.get_finding_form(request, test)
        product_tab = Product_Tab(test.engagement.product, title=_("Add Finding"), tab="engagements")
        product_tab.setEngagement(test.engagement)
        return {
            "form": finding_form,
            "product_tab": product_tab,
            "temp": False,
            "test": test,
            "tid": test.id,
            "pid": test.engagement.product.id,
            "form_error": False,
            "jform": self.get_jira_form(request, test, finding_form=finding_form),
        }

    def get_finding_form(self, request: HttpRequest, test: Test):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "initial": {"date": timezone.now().date(), "verified": True, "dynamic_finding": False},
            "req_resp": None,
            "product": test.engagement.product,
        }
        # Remove the initial state on post
        if request.method == "POST":
            kwargs.pop("initial")

        return AddFindingForm(*args, **kwargs)

    def get_jira_form(self, request: HttpRequest, test: Test, finding_form: AddFindingForm = None):
        # Determine if jira should be used
        if (jira_project := jira_helper.get_jira_project(test)) is not None:
            # Set up the args for the form
            args = [request.POST] if request.method == "POST" else []
            # Set the initial form args
            kwargs = {
                "push_all": jira_helper.is_push_all_issues(test),
                "prefix": "jiraform",
                "jira_project": jira_project,
                "finding_form": finding_form,
            }

            return JIRAFindingForm(*args, **kwargs)
        return None

    def validate_status_change(self, request: HttpRequest, context: dict):
        if ((context["form"]["active"].value() is False
             or context["form"]["false_p"].value())
             and context["form"]["duplicate"].value() is False):

            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _("Can not set a finding as inactive without adding all mandatory notes"),
                    code="inactive_without_mandatory_notes")
                error_false_p = ValidationError(
                    _("Can not set a finding as false positive without adding all mandatory notes"),
                    code="false_p_without_mandatory_notes")
                if context["form"]["active"].value() is False:
                    context["form"].add_error("active", error_inactive)
                if context["form"]["false_p"].value():
                    context["form"].add_error("false_p", error_false_p)
                messages.add_message(
                    request,
                    messages.ERROR,
                    _("Can not set a finding as inactive or false positive without adding all mandatory notes"),
                    extra_tags="alert-danger")

        return request

    def process_finding_form(self, request: HttpRequest, test: Test, context: dict):
        finding = None
        if context["form"].is_valid():
            finding = context["form"].save(commit=False)
            finding.test = test
            finding.reporter = request.user
            finding.numerical_severity = Finding.get_numerical_severity(finding.severity)
            finding.tags = context["form"].cleaned_data["tags"]
            finding.save()
            # Save and add new endpoints
            finding_helper.add_endpoints(finding, context["form"])
            # Save the finding at the end and return
            finding.save()

            return finding, request, True
        add_error_message_to_response("The form has errors, please correct them below.")
        add_field_errors_to_response(context["form"])

        return finding, request, False

    def process_jira_form(self, request: HttpRequest, finding: Finding, context: dict):
        # Capture case if the jira not being enabled
        if context["jform"] is None:
            return request, True, False

        if context["jform"] and context["jform"].is_valid():
            # can't use helper as when push_all_jira_issues is True, the checkbox gets disabled and is always false
            # push_to_jira = jira_helper.is_push_to_jira(finding, jform.cleaned_data.get('push_to_jira'))
            push_to_jira = jira_helper.is_push_all_issues(finding) or context["jform"].cleaned_data.get("push_to_jira")
            jira_message = None
            # if the jira issue key was changed, update database
            new_jira_issue_key = context["jform"].cleaned_data.get("jira_issue")
            if finding.has_jira_issue:
                # everything in DD around JIRA integration is based on the internal id of the issue in JIRA
                # instead of on the public jira issue key.
                # I have no idea why, but it means we have to retrieve the issue from JIRA to get the internal JIRA id.
                # we can assume the issue exist, which is already checked in the validation of the jform
                if not new_jira_issue_key:
                    jira_helper.finding_unlink_jira(request, finding)
                    jira_message = "Link to JIRA issue removed successfully."

                elif new_jira_issue_key != finding.jira_issue.jira_key:
                    jira_helper.finding_unlink_jira(request, finding)
                    jira_helper.finding_link_jira(request, finding, new_jira_issue_key)
                    jira_message = "Changed JIRA link successfully."
            else:
                logger.debug("finding has no jira issue yet")
                if new_jira_issue_key:
                    logger.debug("finding has no jira issue yet, but jira issue specified in request. trying to link.")
                    jira_helper.finding_link_jira(request, finding, new_jira_issue_key)
                    jira_message = "Linked a JIRA issue successfully."
            # Determine if a message should be added
            if jira_message:
                messages.add_message(
                    request, messages.SUCCESS, jira_message, extra_tags="alert-success",
                )

            return request, True, push_to_jira
        add_field_errors_to_response(context["jform"])

        return request, False, False

    def process_forms(self, request: HttpRequest, test: Test, context: dict):
        form_success_list = []
        finding = None
        # Set vars for the completed forms
        # Validate finding mitigation
        request = self.validate_status_change(request, context)
        # Check the validity of the form overall
        finding, request, success = self.process_finding_form(request, test, context)
        form_success_list.append(success)
        request, success, push_to_jira = self.process_jira_form(request, finding, context)
        form_success_list.append(success)
        # Determine if all forms were successful
        all_forms_valid = all(form_success_list)
        # Check the validity of all the forms
        if all_forms_valid:
            # if we're removing the "duplicate" in the edit finding screen
            finding_helper.save_vulnerability_ids(finding, context["form"].cleaned_data["vulnerability_ids"].split())
            # Push things to jira if needed
            finding.save(push_to_jira=push_to_jira)
            # Save the burp req resp
            if "request" in context["form"].cleaned_data or "response" in context["form"].cleaned_data:
                burp_rr = BurpRawRequestResponse(
                    finding=finding,
                    burpRequestBase64=base64.b64encode(context["form"].cleaned_data["request"].encode()),
                    burpResponseBase64=base64.b64encode(context["form"].cleaned_data["response"].encode()),
                )
                burp_rr.clean()
                burp_rr.save()

            # Note: this notification has not be moved to "@receiver(post_save, sender=Finding)" method as many other notifications
            # Because it could generate too much noise, we keep it here only for findings created by hand in WebUI
            # TODO: but same should be implemented for API endpoint

            # Create a notification
            create_notification(
                event="finding_added",
                title=_("Addition of %s") % finding.title,
                finding=finding,
                description=_('Finding "%s" was added by %s') % (finding.title, request.user),
                url=reverse("view_finding", args=(finding.id,)),
                icon="exclamation-triangle")
            # Add a success message
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Finding added successfully."),
                extra_tags="alert-success")

        return finding, request, all_forms_valid

    def get_template(self):
        return "dojo/add_findings.html"

    def get(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Finding_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Finding_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Process the form
        _, request, success = self.process_forms(request, test, context)
        # Handle the case of a successful form
        if success:
            if "_Finished" in request.POST:
                return HttpResponseRedirect(reverse("view_test", args=(test.id,)))
            return HttpResponseRedirect(reverse("add_findings", args=(test.id,)))
        context["form_error"] = True
        # Render the form
        return render(request, self.get_template(), context)


@user_is_authorized(Test, Permissions.Finding_Add, "tid")
def add_temp_finding(request, tid, fid):
    jform = None
    test = get_object_or_404(Test, id=tid)
    finding = get_object_or_404(Finding_Template, id=fid)
    findings = Finding_Template.objects.all()
    push_all_jira_issues = jira_helper.is_push_all_issues(finding)

    if request.method == "POST":

        form = AddFindingForm(request.POST, req_resp=None, product=test.engagement.product)
        if jira_helper.get_jira_project(test):
            jform = JIRAFindingForm(push_all=jira_helper.is_push_all_issues(test), prefix="jiraform", jira_project=jira_helper.get_jira_project(test), finding_form=form)
            logger.debug(f"jform valid: {jform.is_valid()}")

        if (form["active"].value() is False or form["false_p"].value()) and form["duplicate"].value() is False:
            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _("Can not set a finding as inactive without adding all mandatory notes"),
                    code="not_active_or_false_p_true")
                error_false_p = ValidationError(
                    _("Can not set a finding as false positive without adding all mandatory notes"),
                    code="not_active_or_false_p_true")
                if form["active"].value() is False:
                    form.add_error("active", error_inactive)
                if form["false_p"].value():
                    form.add_error("false_p", error_false_p)
                messages.add_message(request,
                                     messages.ERROR,
                                     _("Can not set a finding as inactive or false positive without adding all mandatory notes"),
                                     extra_tags="alert-danger")
        if form.is_valid():
            finding.last_used = timezone.now()
            finding.save()
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)

            new_finding.tags = form.cleaned_data["tags"]
            new_finding.cvssv3 = finding.cvssv3
            new_finding.date = form.cleaned_data["date"] or datetime.today()

            finding_helper.update_finding_status(new_finding, request.user)

            new_finding.save(dedupe_option=False)

            # Save and add new endpoints
            finding_helper.add_endpoints(new_finding, form)

            new_finding.save()
            if "jiraform-push_to_jira" in request.POST:
                jform = JIRAFindingForm(request.POST, prefix="jiraform", instance=new_finding, push_all=push_all_jira_issues, jira_project=jira_helper.get_jira_project(test), finding_form=form)
                if jform.is_valid():
                    if jform.cleaned_data.get("push_to_jira"):
                        jira_helper.push_to_jira(new_finding)
                else:
                    add_error_message_to_response(f"jira form validation failed: {jform.errors}")
            if "request" in form.cleaned_data or "response" in form.cleaned_data:
                burp_rr = BurpRawRequestResponse(
                    finding=new_finding,
                    burpRequestBase64=base64.b64encode(form.cleaned_data.get("request", "").encode("utf-8")),
                    burpResponseBase64=base64.b64encode(form.cleaned_data.get("response", "").encode("utf-8")),
                )
                burp_rr.clean()
                burp_rr.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Finding from template added successfully."),
                                 extra_tags="alert-success")

            return HttpResponseRedirect(reverse("view_test", args=(test.id,)))
        messages.add_message(request,
                             messages.ERROR,
                             _("The form has errors, please correct them below."),
                             extra_tags="alert-danger")

    else:
        form = AddFindingForm(req_resp=None, product=test.engagement.product, initial={"active": False,
                                    "date": timezone.now().date(),
                                    "verified": False,
                                    "false_p": False,
                                    "duplicate": False,
                                    "out_of_scope": False,
                                    "title": finding.title,
                                    "description": finding.description,
                                    "cwe": finding.cwe,
                                    "severity": finding.severity,
                                    "mitigation": finding.mitigation,
                                    "impact": finding.impact,
                                    "references": finding.references,
                                    "numerical_severity": finding.numerical_severity})

        if jira_helper.get_jira_project(test):
            jform = JIRAFindingForm(push_all=jira_helper.is_push_all_issues(test), prefix="jiraform", jira_project=jira_helper.get_jira_project(test), finding_form=form)

    product_tab = Product_Tab(test.engagement.product, title=_("Add Finding"), tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, "dojo/add_findings.html",
                  {"form": form,
                   "product_tab": product_tab,
                   "jform": jform,
                   "findings": findings,
                   "temp": True,
                   "fid": finding.id,
                   "tid": test.id,
                   "test": test,
                   })


@user_is_authorized(Test, Permissions.Test_View, "tid")
def search(request, tid):
    test = get_object_or_404(Test, id=tid)
    templates = Finding_Template.objects.all()
    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    title_words = get_words_for_field(Finding_Template, "title")

    add_breadcrumb(parent=test, title=_("Add From Template"), top_level=False, request=request)
    return render(request, "dojo/templates.html",
                  {"templates": paged_templates,
                   "filtered": templates,
                   "title_words": title_words,
                   "tid": tid,
                   "add_from_template": True,
                   })


class ReImportScanResultsView(View):
    def get_template(self) -> str:
        """Returns the template that will be presented to the user"""
        return "dojo/import_scan_results.html"

    def get_form(
        self,
        request: HttpRequest,
        test: Test,
        **kwargs: dict,
    ) -> ReImportScanForm:
        """Returns the default import form for importing findings"""
        if request.method == "POST":
            return ReImportScanForm(request.POST, request.FILES, test=test, **kwargs)
        return ReImportScanForm(test=test, **kwargs)

    def get_jira_form(
        self,
        request: HttpRequest,
        test: Test,
    ) -> tuple[JIRAImportScanForm | None, bool]:
        """Returns a JiraImportScanForm if jira is enabled"""
        jira_form = None
        push_all_jira_issues = False
        # Decide if we need to present the Push to JIRA form
        if get_system_setting("enable_jira"):
            # Determine if jira issues should be pushed automatically
            push_all_jira_issues = jira_helper.is_push_all_issues(test)
            # Only return the form if the jira is enabled on this engagement or product
            if jira_helper.get_jira_project(test):
                if request.method == "POST":
                    jira_form = JIRAImportScanForm(
                        request.POST,
                        push_all=push_all_jira_issues,
                        prefix="jiraform",
                    )
                else:
                    jira_form = JIRAImportScanForm(
                        push_all=push_all_jira_issues,
                        prefix="jiraform",
                    )
        return jira_form, push_all_jira_issues

    def handle_request(
        self,
        request: HttpRequest,
        test_id: int,
    ) -> tuple[HttpRequest, dict]:
        """
        Process the common behaviors between request types, and then return
        the request and context dict back to be rendered
        """
        # Get the test object
        test = get_object_or_404(Test, id=test_id)
        # Ensure the supplied user has access to import to the engagement or product
        user_has_permission_or_403(request.user, test, Permissions.Import_Scan_Result)
        # by default we keep a trace of the scan_type used to create the test
        # if it's not here, we use the "name" of the test type
        # this feature exists to provide custom label for tests for some parsers
        scan_type = test.scan_type or test.test_type.name
        # Set the product tab
        product_tab = Product_Tab(test.engagement.product, title=_("Re-upload a %s") % scan_type, tab="engagements")
        product_tab.setEngagement(test.engagement)
        # Get the import form with some initial data in place
        form = self.get_form(
            request,
            test,
            endpoints=Endpoint.objects.filter(product__id=product_tab.product.id),
            api_scan_configuration=test.api_scan_configuration,
            api_scan_configuration_queryset=Product_API_Scan_Configuration.objects.filter(product__id=product_tab.product.id),
        )
        # Get the jira form
        jira_form, push_all_jira_issues = self.get_jira_form(request, test)
        # Return the request and the context
        return request, {
            "test": test,
            "form": form,
            "product_tab": product_tab,
            "eid": test.engagement.id,
            "jform": jira_form,
            "scan_type": scan_type,
            "scan_types": get_scan_types_sorted(),
            "push_all_jira_issues": push_all_jira_issues,
            "additional_message": (
                "When re-uploading a scan, any findings not found in original scan will be updated as "
                "mitigated.  The process attempts to identify the differences, however manual verification "
                "is highly recommended."
            ),
        }

    def validate_forms(
        self,
        context: dict,
    ) -> bool:
        """
        Validates each of the forms to ensure all errors from the form
        level are bubbled up to the user first before we process too much
        """
        form_validation_list = []
        if context.get("form") is not None:
            form_validation_list.append(context.get("form").is_valid())
        if context.get("jform") is not None:
            form_validation_list.append(context.get("jform").is_valid())
        return all(form_validation_list)

    def process_form(
        self,
        request: HttpRequest,
        form: ReImportScanForm,
        context: dict,
    ) -> str | None:
        """Process the form and manipulate the input in any way that is appropriate"""
        # Update the running context dict with cleaned form input
        context.update({
            "scan": request.FILES.get("file", None),
            "scan_date": form.cleaned_data.get("scan_date"),
            "minimum_severity": form.cleaned_data.get("minimum_severity"),
            "do_not_reactivate": form.cleaned_data.get("do_not_reactivate"),
            "tags": form.cleaned_data.get("tags"),
            "version": form.cleaned_data.get("version"),
            "branch_tag": form.cleaned_data.get("branch_tag", None),
            "build_id": form.cleaned_data.get("build_id", None),
            "commit_hash": form.cleaned_data.get("commit_hash", None),
            "api_scan_configuration": form.cleaned_data.get("api_scan_configuration", None),
            "service": form.cleaned_data.get("service", None),
            "apply_tags_to_findings": form.cleaned_data.get("apply_tags_to_findings", False),
            "apply_tags_to_endpoints": form.cleaned_data.get("apply_tags_to_endpoints", False),
            "group_by": form.cleaned_data.get("group_by", None),
            "close_old_findings": form.cleaned_data.get("close_old_findings", None),
            "create_finding_groups_for_all_findings": form.cleaned_data.get("create_finding_groups_for_all_findings"),
        })
        # Override the form values of active and verified
        if activeChoice := form.cleaned_data.get("active", None):
            if activeChoice == "force_to_true":
                context["active"] = True
            elif activeChoice == "force_to_false":
                context["active"] = False
        if verifiedChoice := form.cleaned_data.get("verified", None):
            if verifiedChoice == "force_to_true":
                context["verified"] = True
            elif verifiedChoice == "force_to_false":
                context["verified"] = False
        # Override the tags and version
        context.get("test").tags = context.get("tags")
        context.get("test").version = context.get("version")
        return None

    def process_jira_form(
        self,
        request: HttpRequest,
        form: JIRAImportScanForm,
        context: dict,
    ) -> str | None:
        """
        Process the jira form by first making sure one was supplied
        and then setting any values supplied by the user. An error
        may be returned and will be bubbled up in the form of a message
        """
        # Determine if push all issues is enabled
        push_all_jira_issues = context.get("push_all_jira_issues", False)
        context["push_to_jira"] = push_all_jira_issues or (form and form.cleaned_data.get("push_to_jira"))
        return None

    def get_reimporter(
        self,
        context: dict,
    ) -> BaseImporter:
        """Gets the reimporter to use"""
        return DefaultReImporter(**context)

    def reimport_findings(
        self,
        context: dict,
    ) -> str | None:
        """Attempt to import with all the supplied information"""
        try:
            importer_client = self.get_reimporter(context)
            (
                context["test"],
                finding_count,
                new_finding_count,
                closed_finding_count,
                reactivated_finding_count,
                untouched_finding_count,
                _,
            ) = importer_client.process_scan(
                context.pop("scan", None),
            )
            # Add a message to the view for the user to see the results
            add_success_message_to_response(importer_client.construct_imported_message(
                finding_count=finding_count,
                new_finding_count=new_finding_count,
                closed_finding_count=closed_finding_count,
                reactivated_finding_count=reactivated_finding_count,
                untouched_finding_count=untouched_finding_count,
            ))
        except Exception as e:
            logger.exception("An exception error occurred during the report import")
            return f"An exception error occurred during the report import: {e}"
        return None

    def success_redirect(
        self,
        context: dict,
    ) -> HttpResponseRedirect:
        """Redirect the user to a place that indicates a successful import"""
        return HttpResponseRedirect(reverse("view_test", args=(context.get("test").id, )))

    def failure_redirect(
        self,
        context: dict,
    ) -> HttpResponseRedirect:
        """Redirect the user to a place that indicates a failed import"""
        return HttpResponseRedirect(reverse(
            "re_import_scan_results",
            args=(context.get("test").id, ),
        ))

    def get(
        self,
        request: HttpRequest,
        test_id: int,
    ) -> HttpResponse:
        """Process GET requests for the ReImport View"""
        # process the request and path parameters
        request, context = self.handle_request(
            request,
            test_id=test_id,
        )
        # Render the form
        return render(request, self.get_template(), context)

    def post(
        self,
        request: HttpRequest,
        test_id: int,
    ) -> HttpResponse:
        """Process POST requests for the ReImport View"""
        # process the request and path parameters
        request, context = self.handle_request(
            request,
            test_id=test_id,
        )
        # ensure all three forms are valid first before moving forward
        if not self.validate_forms(context):
            return self.failure_redirect(context)
        # Process the jira form if it is present
        if form_error := self.process_jira_form(request, context.get("jform"), context):
            add_error_message_to_response(form_error)
            return self.failure_redirect(context)
        # Process the import form
        if form_error := self.process_form(request, context.get("form"), context):
            add_error_message_to_response(form_error)
            return self.failure_redirect(context)
        # Kick off the import process
        if import_error := self.reimport_findings(context):
            add_error_message_to_response(import_error)
            return self.failure_redirect(context)
        # Otherwise return the user back to the engagement (if present) or the product
        return self.success_redirect(context)
