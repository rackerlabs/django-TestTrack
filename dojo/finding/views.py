# #  findings
import base64
import contextlib
import copy
import json
import logging
import mimetypes
from collections import OrderedDict, defaultdict
from itertools import chain

from django.conf import settings
from django.contrib import messages
from django.core import serializers
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models
from django.db.models import Count, Q, QuerySet
from django.db.models.functions import Length
from django.db.models.query import Prefetch
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, render
from django.template.defaultfilters import pluralize
from django.urls import reverse
from django.utils import formats, timezone
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.http import require_POST
from imagekit import ImageSpec
from imagekit.processors import ResizeToFill

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
import dojo.risk_acceptance.helper as ra_helper
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import (
    user_has_global_permission,
    user_is_authorized,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import (
    AcceptedFindingFilter,
    AcceptedFindingFilterWithoutObjectLookups,
    FindingFilter,
    FindingFilterWithoutObjectLookups,
    SimilarFindingFilter,
    SimilarFindingFilterWithoutObjectLookups,
    TemplateFindingFilter,
    TestImportFilter,
    TestImportFindingActionFilter,
)
from dojo.finding.queries import get_authorized_findings
from dojo.forms import (
    ApplyFindingTemplateForm,
    ClearFindingReviewForm,
    CloseFindingForm,
    CopyFindingForm,
    DefectFindingForm,
    DeleteFindingForm,
    DeleteFindingTemplateForm,
    DeleteStubFindingForm,
    EditPlannedRemediationDateFindingForm,
    FindingBulkUpdateForm,
    FindingForm,
    FindingFormID,
    FindingTemplateForm,
    GITHUBFindingForm,
    JIRAFindingForm,
    MergeFindings,
    NoteForm,
    PromoteFindingForm,
    ReviewFindingForm,
    StubFindingForm,
    TypedNoteForm,
)
from dojo.models import (
    IMPORT_UNTOUCHED_FINDING,
    BurpRawRequestResponse,
    Cred_Mapping,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    FileAccessToken,
    Finding,
    Finding_Group,
    Finding_Template,
    GITHUB_Issue,
    GITHUB_PKey,
    Note_Type,
    NoteHistory,
    Notes,
    Product,
    Stub_Finding,
    System_Settings,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    User,
    Vulnerability_Id_Template,
)
from dojo.notifications.helper import create_notification
from dojo.test.queries import get_authorized_tests
from dojo.utils import (
    FileIterWrapper,
    Product_Tab,
    add_breadcrumb,
    add_error_message_to_response,
    add_external_issue,
    add_field_errors_to_response,
    add_success_message_to_response,
    apply_cwe_to_template,
    calculate_grade,
    close_external_issue,
    do_false_positive_history,
    get_page_items,
    get_page_items_and_count,
    get_return_url,
    get_system_setting,
    get_words_for_field,
    match_finding_to_existing_findings,
    process_tag_notifications,
    redirect,
    redirect_to_return_url_or_else,
    reopen_external_issue,
    update_external_issue,
)

JFORM_PUSH_TO_JIRA_MESSAGE = "jform.push_to_jira: %s"

logger = logging.getLogger(__name__)


def prefetch_for_findings(findings, prefetch_type="all", *, exclude_untouched=True):
    prefetched_findings = findings
    if isinstance(
        findings, QuerySet,
    ):  # old code can arrive here with prods being a list because the query was already executed
        prefetched_findings = prefetched_findings.prefetch_related(
            "reviewers",
        )
        prefetched_findings = prefetched_findings.prefetch_related("reporter")
        prefetched_findings = prefetched_findings.prefetch_related(
            "jira_issue__jira_project__jira_instance",
        )
        prefetched_findings = prefetched_findings.prefetch_related("test__test_type")
        prefetched_findings = prefetched_findings.prefetch_related(
            "test__engagement__jira_project__jira_instance",
        )
        prefetched_findings = prefetched_findings.prefetch_related(
            "test__engagement__product__jira_project_set__jira_instance",
        )
        prefetched_findings = prefetched_findings.prefetch_related("found_by")

        # for open/active findings the following 4 prefetches are not needed
        if prefetch_type != "open":
            prefetched_findings = prefetched_findings.prefetch_related(
                "risk_acceptance_set",
            )
            prefetched_findings = prefetched_findings.prefetch_related(
                "risk_acceptance_set__accepted_findings",
            )
            prefetched_findings = prefetched_findings.prefetch_related(
                "original_finding",
            )
            prefetched_findings = prefetched_findings.prefetch_related(
                "duplicate_finding",
            )

        if exclude_untouched:
            # filter out noop reimport actions from finding status history
            prefetched_findings = prefetched_findings.prefetch_related(
                Prefetch(
                    "test_import_finding_action_set",
                    queryset=Test_Import_Finding_Action.objects.exclude(
                        action=IMPORT_UNTOUCHED_FINDING,
                    ),
                ),
            )
        else:
            prefetched_findings = prefetched_findings.prefetch_related(
                "test_import_finding_action_set",
            )
        """
        we could try to prefetch only the latest note with SubQuery and OuterRef,
        but I'm getting that MySql doesn't support limits in subqueries.
        """
        prefetched_findings = prefetched_findings.prefetch_related("notes")
        prefetched_findings = prefetched_findings.prefetch_related("tags")
        prefetched_findings = prefetched_findings.prefetch_related("endpoints")
        prefetched_findings = prefetched_findings.prefetch_related("status_finding")
        prefetched_findings = prefetched_findings.annotate(
            active_endpoint_count=Count(
                "status_finding__id", filter=Q(status_finding__mitigated=False),
            ),
        )
        prefetched_findings = prefetched_findings.annotate(
            mitigated_endpoint_count=Count(
                "status_finding__id", filter=Q(status_finding__mitigated=True),
            ),
        )
        prefetched_findings = prefetched_findings.prefetch_related("finding_group_set")
        prefetched_findings = prefetched_findings.prefetch_related(
            "test__engagement__product__members",
        )
        prefetched_findings = prefetched_findings.prefetch_related(
            "test__engagement__product__prod_type__members",
        )
        prefetched_findings = prefetched_findings.prefetch_related(
            "vulnerability_id_set",
        )
    else:
        logger.debug("unable to prefetch because query was already executed")

    return prefetched_findings


def prefetch_for_similar_findings(findings):
    prefetched_findings = findings
    if isinstance(
        findings, QuerySet,
    ):  # old code can arrive here with prods being a list because the query was already executed
        prefetched_findings = prefetched_findings.prefetch_related("reporter")
        prefetched_findings = prefetched_findings.prefetch_related(
            "jira_issue__jira_project__jira_instance",
        )
        prefetched_findings = prefetched_findings.prefetch_related("test__test_type")
        prefetched_findings = prefetched_findings.prefetch_related(
            "test__engagement__jira_project__jira_instance",
        )
        prefetched_findings = prefetched_findings.prefetch_related(
            "test__engagement__product__jira_project_set__jira_instance",
        )
        prefetched_findings = prefetched_findings.prefetch_related("found_by")
        prefetched_findings = prefetched_findings.prefetch_related(
            "risk_acceptance_set",
        )
        prefetched_findings = prefetched_findings.prefetch_related(
            "risk_acceptance_set__accepted_findings",
        )
        prefetched_findings = prefetched_findings.prefetch_related("original_finding")
        prefetched_findings = prefetched_findings.prefetch_related("duplicate_finding")
        # filter out noop reimport actions from finding status history
        prefetched_findings = prefetched_findings.prefetch_related(
            Prefetch(
                "test_import_finding_action_set",
                queryset=Test_Import_Finding_Action.objects.exclude(
                    action=IMPORT_UNTOUCHED_FINDING,
                ),
            ),
        )
        """
        we could try to prefetch only the latest note with SubQuery and OuterRef,
        but I'm getting that MySql doesn't support limits in subqueries.
        """
        prefetched_findings = prefetched_findings.prefetch_related("notes")
        prefetched_findings = prefetched_findings.prefetch_related("tags")
        prefetched_findings = prefetched_findings.prefetch_related(
            "vulnerability_id_set",
        )
    else:
        logger.debug("unable to prefetch because query was already executed")

    return prefetched_findings


class BaseListFindings:
    def __init__(
        self,
        filter_name: str = "All",
        product_id: int | None = None,
        engagement_id: int | None = None,
        test_id: int | None = None,
        order_by: str = "numerical_severity",
        prefetch_type: str = "all",
    ):
        self.filter_name = filter_name
        self.product_id = product_id
        self.engagement_id = engagement_id
        self.test_id = test_id
        self.order_by = order_by
        self.prefetch_type = prefetch_type

    def get_filter_name(self):
        if not hasattr(self, "filter_name"):
            self.filter_name = "All"
        return self.filter_name

    def get_order_by(self):
        if not hasattr(self, "order_by"):
            self.order_by = "numerical_severity"
        return self.order_by

    def get_prefetch_type(self):
        if not hasattr(self, "prefetch_type"):
            self.prefetch_type = "all"
        return self.prefetch_type

    def get_product_id(self):
        if not hasattr(self, "product_id"):
            self.product_id = None
        return self.product_id

    def get_engagement_id(self):
        if not hasattr(self, "engagement_id"):
            self.engagement_id = None
        return self.engagement_id

    def get_test_id(self):
        if not hasattr(self, "test_id"):
            self.test_id = None
        return self.test_id

    def filter_findings_by_object(self, findings: QuerySet[Finding]):
        if product_id := self.get_product_id():
            return findings.filter(test__engagement__product__id=product_id)
        if engagement_id := self.get_engagement_id():
            return findings.filter(test__engagement=engagement_id)
        if test_id := self.get_test_id():
            return findings.filter(test=test_id)
        return findings

    def filter_findings_by_filter_name(self, findings: QuerySet[Finding]):
        filter_name = self.get_filter_name()
        if filter_name == "Open":
            return findings.filter(finding_helper.OPEN_FINDINGS_QUERY)
        if filter_name == "Verified":
            return findings.filter(finding_helper.VERIFIED_FINDINGS_QUERY)
        if filter_name == "Out of Scope":
            return findings.filter(finding_helper.OUT_OF_SCOPE_FINDINGS_QUERY)
        if filter_name == "False Positive":
            return findings.filter(finding_helper.FALSE_POSITIVE_FINDINGS_QUERY)
        if filter_name == "Inactive":
            return findings.filter(finding_helper.INACTIVE_FINDINGS_QUERY)
        if filter_name == "Accepted":
            return findings.filter(finding_helper.ACCEPTED_FINDINGS_QUERY)
        if filter_name == "Closed":
            return findings.filter(finding_helper.CLOSED_FINDINGS_QUERY)
        return findings

    def filter_findings_by_form(self, request: HttpRequest, findings: QuerySet[Finding]):
        # Set up the args for the form
        args = [request.GET, findings]
        # Set the initial form args
        kwargs = {
            "user": request.user,
            "pid": self.get_product_id(),
        }

        filter_string_matching = get_system_setting("filter_string_matching", False)
        finding_filter_class = FindingFilterWithoutObjectLookups if filter_string_matching else FindingFilter
        accepted_finding_filter_class = AcceptedFindingFilterWithoutObjectLookups if filter_string_matching else AcceptedFindingFilter
        return (
            accepted_finding_filter_class(*args, **kwargs)
            if self.get_filter_name() == "Accepted"
            else finding_filter_class(*args, **kwargs)
        )

    def get_filtered_findings(self):
        findings = get_authorized_findings(Permissions.Finding_View).order_by(self.get_order_by())
        findings = self.filter_findings_by_object(findings)
        return self.filter_findings_by_filter_name(findings)

    def get_fully_filtered_findings(self, request: HttpRequest):
        findings = self.get_filtered_findings()
        return self.filter_findings_by_form(request, findings)


class ListFindings(View, BaseListFindings):
    def get_initial_context(self, request: HttpRequest):
        context = {
            "filter_name": self.get_filter_name(),
            "show_product_column": True,
            "custom_breadcrumb": None,
            "product_tab": None,
            "jira_project": None,
            "github_config": None,
            "bulk_edit_form": FindingBulkUpdateForm(request.GET),
            "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
            "title_words": get_words_for_field(Finding, "title"),
            "component_words": get_words_for_field(Finding, "component_name"),
        }
        # Look to see if the product was used
        if product_id := self.get_product_id():
            product = get_object_or_404(Product, id=product_id)
            user_has_permission_or_403(request.user, product, Permissions.Product_View)
            context["show_product_column"] = False
            context["product_tab"] = Product_Tab(product, title="Findings", tab="findings")
            context["jira_project"] = jira_helper.get_jira_project(product)
            if github_config := GITHUB_PKey.objects.filter(product=product).first():
                context["github_config"] = github_config.git_conf_id
        elif engagement_id := self.get_engagement_id():
            engagement = get_object_or_404(Engagement, id=engagement_id)
            user_has_permission_or_403(request.user, engagement, Permissions.Engagement_View)
            context["show_product_column"] = False
            context["product_tab"] = Product_Tab(engagement.product, title=engagement.name, tab="engagements")
            context["jira_project"] = jira_helper.get_jira_project(engagement)
            if github_config := GITHUB_PKey.objects.filter(product__engagement=engagement).first():
                context["github_config"] = github_config.git_conf_id

        return request, context

    def get_template(self):
        return "dojo/findings_list.html"

    def add_breadcrumbs(self, request: HttpRequest, context: dict):
        # show custom breadcrumb if user has filtered by exactly 1 endpoint
        if "endpoints" in request.GET:
            endpoint_ids = request.GET.getlist("endpoints", [])
            if len(endpoint_ids) == 1 and endpoint_ids[0] != "":
                endpoint_id = endpoint_ids[0]
                endpoint = get_object_or_404(Endpoint, id=endpoint_id)
                context["filter_name"] = "Vulnerable Endpoints"
                context["custom_breadcrumb"] = OrderedDict(
                    [
                        ("Endpoints", reverse("vulnerable_endpoints")),
                        (endpoint, reverse("view_endpoint", args=(endpoint.id,))),
                    ],
                )
        # Show the "All findings" breadcrumb if nothing is coming from the product or engagement
        elif not self.get_engagement_id() and not self.get_product_id():
            add_breadcrumb(title="Findings", top_level=not len(request.GET), request=request)

        return request, context

    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        # Store the product and engagement ids
        self.product_id = product_id
        self.engagement_id = engagement_id
        # Get the initial context
        request, context = self.get_initial_context(request)
        # Get the filtered findings
        filtered_findings = self.get_fully_filtered_findings(request)
        # trick to prefetch after paging to avoid huge join generated by select count(*) from Paginator
        paged_findings = get_page_items(request, filtered_findings.qs, 25)
        # prefetch the related objects in the findings
        paged_findings.object_list = prefetch_for_findings(
            paged_findings.object_list,
            self.get_prefetch_type())
        # Add some breadcrumbs
        request, context = self.add_breadcrumbs(request, context)
        # Add the filtered and paged findings into the context
        context |= {
            "findings": paged_findings,
            "filtered": filtered_findings,
        }
        # Render the view
        return render(request, self.get_template(), context)


class ListOpenFindings(ListFindings):
    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        self.filter_name = "Open"
        return super().get(request, product_id=product_id, engagement_id=engagement_id)


class ListVerifiedFindings(ListFindings):
    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        self.filter_name = "Verified"
        return super().get(request, product_id=product_id, engagement_id=engagement_id)


class ListOutOfScopeFindings(ListFindings):
    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        self.filter_name = "Out of Scope"
        return super().get(request, product_id=product_id, engagement_id=engagement_id)


class ListFalsePositiveFindings(ListFindings):
    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        self.filter_name = "False Positive"
        return super().get(request, product_id=product_id, engagement_id=engagement_id)


class ListInactiveFindings(ListFindings):
    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        self.filter_name = "Inactive"
        return super().get(request, product_id=product_id, engagement_id=engagement_id)


class ListAcceptedFindings(ListFindings):
    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        self.filter_name = "Accepted"
        return super().get(request, product_id=product_id, engagement_id=engagement_id)


class ListClosedFindings(ListFindings):
    def get(self, request: HttpRequest, product_id: int | None = None, engagement_id: int | None = None):
        self.filter_name = "Closed"
        self.order_by = "-mitigated"
        return super().get(request, product_id=product_id, engagement_id=engagement_id)


class ViewFinding(View):
    def get_finding(self, finding_id: int):
        finding_qs = prefetch_for_findings(Finding.objects.all(), exclude_untouched=False)
        return get_object_or_404(finding_qs, id=finding_id)

    def get_dojo_user(self, request: HttpRequest):
        user = request.user
        return get_object_or_404(Dojo_User, id=user.id)

    def get_previous_and_next_findings(self, finding: Finding):
        # Get the whole list of findings in the current test
        findings = (
            Finding.objects.filter(test=finding.test)
            .order_by("numerical_severity")
            .values_list("id", flat=True)
        )
        logger.debug(findings)
        # Set some reasonable defaults
        next_finding_id = finding.id
        prev_finding_id = finding.id
        last_pos = (len(findings)) - 1
        # get the index of the current finding
        current_finding_index = list(findings).index(finding.id)
        # Try to get the previous ID
        with contextlib.suppress(IndexError, ValueError):
            prev_finding_id = findings[current_finding_index - 1]
        # Try to get the next ID
        with contextlib.suppress(IndexError, ValueError):
            next_finding_id = findings[current_finding_index + 1]

        return {
            "prev_finding_id": prev_finding_id,
            "next_finding_id": next_finding_id,
            "findings_list": findings,
            "findings_list_lastElement": findings[last_pos],
        }

    def get_credential_objects(self, finding: Finding):
        cred = (
            Cred_Mapping.objects.filter(test=finding.test.id)
            .select_related("cred_id")
            .order_by("cred_id")
        )
        cred_engagement = (
            Cred_Mapping.objects.filter(engagement=finding.test.engagement.id)
            .select_related("cred_id")
            .order_by("cred_id")
        )
        cred_finding = (
            Cred_Mapping.objects.filter(finding=finding.id)
            .select_related("cred_id")
            .order_by("cred_id")
        )

        return {
            "cred_finding": cred_finding,
            "cred": cred,
            "cred_engagement": cred_engagement,
        }

    def get_cwe_template(self, finding: Finding):
        cwe_template = None
        with contextlib.suppress(Finding_Template.DoesNotExist):
            cwe_template = Finding_Template.objects.filter(cwe=finding.cwe).first()

        return {
            "cwe_template": cwe_template,
        }

    def get_request_response(self, finding: Finding):
        request_response = None
        burp_request = None
        burp_response = None
        try:
            request_response = BurpRawRequestResponse.objects.filter(finding=finding).first()
            if request_response is not None:
                burp_request = base64.b64decode(request_response.burpRequestBase64)
                burp_response = base64.b64decode(request_response.burpResponseBase64)
        except Exception as e:
            logger.debug(f"unsuspected error: {e}")

        return {
            "burp_request": burp_request,
            "burp_response": burp_response,
        }

    def get_test_import_data(self, request: HttpRequest, finding: Finding):
        test_imports = Test_Import.objects.filter(findings_affected=finding)
        test_import_filter = TestImportFilter(request.GET, test_imports)

        test_import_finding_actions = finding.test_import_finding_action_set
        test_import_finding_actions_count = test_import_finding_actions.all().count()
        test_import_finding_actions = test_import_finding_actions.filter(test_import__in=test_import_filter.qs)
        test_import_finding_action_filter = TestImportFindingActionFilter(request.GET, test_import_finding_actions)

        paged_test_import_finding_actions = get_page_items_and_count(request, test_import_finding_action_filter.qs, 5, prefix="test_import_finding_actions")
        paged_test_import_finding_actions.object_list = paged_test_import_finding_actions.object_list.prefetch_related("test_import")

        latest_test_import_finding_action = finding.test_import_finding_action_set.order_by("-created").first

        return {
            "test_import_filter": test_import_filter,
            "test_import_finding_action_filter": test_import_finding_action_filter,
            "paged_test_import_finding_actions": paged_test_import_finding_actions,
            "latest_test_import_finding_action": latest_test_import_finding_action,
            "test_import_finding_actions_count": test_import_finding_actions_count,
        }

    def get_similar_findings(self, request: HttpRequest, finding: Finding):
        similar_findings_enabled = get_system_setting("enable_similar_findings", True)
        if similar_findings_enabled is False:
            return {
                "similar_findings_enabled": similar_findings_enabled,
                "duplicate_cluster": duplicate_cluster(request, finding),
                "similar_findings": None,
                "similar_findings_filter": None,
            }
        # add related actions for non-similar and non-duplicate cluster members
        finding.related_actions = calculate_possible_related_actions_for_similar_finding(
            request, finding, finding,
        )
        if finding.duplicate_finding:
            finding.duplicate_finding.related_actions = (
                calculate_possible_related_actions_for_similar_finding(
                    request, finding, finding.duplicate_finding,
                )
            )
        filter_string_matching = get_system_setting("filter_string_matching", False)
        finding_filter_class = SimilarFindingFilterWithoutObjectLookups if filter_string_matching else SimilarFindingFilter
        similar_findings_filter = finding_filter_class(
            request.GET,
            queryset=get_authorized_findings(Permissions.Finding_View),
            user=request.user,
            finding=finding,
        )
        logger.debug("similar query: %s", similar_findings_filter.qs.query)
        similar_findings = get_page_items(
            request,
            similar_findings_filter.qs,
            settings.SIMILAR_FINDINGS_MAX_RESULTS,
            prefix="similar",
        )
        similar_findings.object_list = prefetch_for_similar_findings(
            similar_findings.object_list,
        )
        for similar_finding in similar_findings:
            similar_finding.related_actions = (
                calculate_possible_related_actions_for_similar_finding(
                    request, finding, similar_finding,
                )
            )

        return {
            "similar_findings_enabled": similar_findings_enabled,
            "duplicate_cluster": duplicate_cluster(request, finding),
            "similar_findings": similar_findings,
            "similar_findings_filter": similar_findings_filter,
        }

    def get_jira_data(self, finding: Finding):
        (
            can_be_pushed_to_jira,
            can_be_pushed_to_jira_error,
            error_code,
        ) = jira_helper.can_be_pushed_to_jira(finding)
        # Check the error code
        if error_code:
            logger.error(error_code)

        return {
            "can_be_pushed_to_jira": can_be_pushed_to_jira,
            "can_be_pushed_to_jira_error": can_be_pushed_to_jira_error,
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

    def process_form(self, request: HttpRequest, finding: Finding, context: dict):
        if context["form"].is_valid():
            # Create the note object
            new_note = context["form"].save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            # Add an entry to the note history
            history = NoteHistory(
                data=new_note.entry, time=new_note.date, current_editor=new_note.author,
            )
            history.save()
            new_note.history.add(history)
            # Associate the note with the finding
            finding.notes.add(new_note)
            finding.last_reviewed = new_note.date
            finding.last_reviewed_by = context["user"]
            finding.save()
            # Determine if the note should be sent to jira
            if finding.has_jira_issue:
                jira_helper.add_comment(finding, new_note)
            elif finding.has_jira_group_issue:
                jira_helper.add_comment(finding.finding_group, new_note)
            # Send the notification of the note being added
            url = request.build_absolute_uri(
                reverse("view_finding", args=(finding.id,)),
            )
            title = f"Finding: {finding.title}"
            process_tag_notifications(request, new_note, url, title)
            # Add a message to the request
            messages.add_message(
                request, messages.SUCCESS, "Note saved.", extra_tags="alert-success",
            )

            return request, True

        return request, False

    def get_initial_context(self, request: HttpRequest, finding: Finding, user: Dojo_User):
        notes = finding.notes.all()
        note_type_activation = Note_Type.objects.filter(is_active=True).count()
        available_note_types = None
        if note_type_activation:
            available_note_types = find_available_notetypes(notes)
        # Set the current context
        context = {
            "finding": finding,
            "dojo_user": user,
            "user": request.user,
            "notes": notes,
            "files": finding.files.all(),
            "note_type_activation": note_type_activation,
            "available_note_types": available_note_types,
            "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
            "product_tab": Product_Tab(
                finding.test.engagement.product, title="View Finding", tab="findings",
            ),
        }
        # Set the form using the context, and then update the context
        form = self.get_form(request, context)
        context["form"] = form

        return context

    def get_template(self):
        return "dojo/view_finding.html"

    def get(self, request: HttpRequest, finding_id: int):
        # Get the initial objects
        finding = self.get_finding(finding_id)
        user = self.get_dojo_user(request)
        # Make sure the user is authorized
        user_has_permission_or_403(user, finding, Permissions.Finding_View)
        # Set up the initial context
        context = self.get_initial_context(request, finding, user)
        # Add in the other extras
        context |= self.get_previous_and_next_findings(finding)
        context |= self.get_credential_objects(finding)
        context |= self.get_cwe_template(finding)
        # Add in more of the other extras
        context |= self.get_request_response(finding)
        context |= self.get_similar_findings(request, finding)
        context |= self.get_test_import_data(request, finding)
        context |= self.get_jira_data(finding)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, finding_id):
        # Get the initial objects
        finding = self.get_finding(finding_id)
        user = self.get_dojo_user(request)
        # Make sure the user is authorized
        user_has_permission_or_403(user, finding, Permissions.Finding_View)
        # Quick perms check to determine if the user has access to add a note to the finding
        user_has_permission_or_403(user, finding, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, finding, user)
        # Determine the validity of the form
        request, success = self.process_form(request, finding, context)
        # Handle the case of a successful form
        if success:
            return HttpResponseRedirect(reverse("view_finding", args=(finding_id,)))
        # Add in more of the other extras
        context |= self.get_request_response(finding)
        context |= self.get_similar_findings(request, finding)
        context |= self.get_test_import_data(request, finding)
        context |= self.get_jira_data(finding)
        # Render the form
        return render(request, self.get_template(), context)


class EditFinding(View):
    def get_finding(self, finding_id: int):
        return get_object_or_404(Finding, id=finding_id)

    def get_request_response(self, finding: Finding):
        req_resp = None
        if burp_rr := BurpRawRequestResponse.objects.filter(finding=finding).first():
            req_resp = (burp_rr.get_request(), burp_rr.get_response())

        return req_resp

    def get_finding_form(self, request: HttpRequest, finding: Finding):
        # Get the burp request if available
        req_resp = self.get_request_response(finding)
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "instance": finding,
            "req_resp": req_resp,
            "can_edit_mitigated_data": finding_helper.can_edit_mitigated_data(request.user),
            "initial": {"vulnerability_ids": "\n".join(finding.vulnerability_ids)},
        }

        return FindingForm(*args, **kwargs)

    def get_jira_form(self, request: HttpRequest, finding: Finding, finding_form: FindingForm = None):
        # Determine if jira should be used
        if (jira_project := jira_helper.get_jira_project(finding)) is not None:
            # Determine if push all findings is enabled
            push_all_findings = jira_helper.is_push_all_issues(finding)
            # Set up the args for the form
            args = [request.POST] if request.method == "POST" else []
            # Set the initial form args
            kwargs = {
                "push_all": push_all_findings,
                "prefix": "jiraform",
                "instance": finding,
                "jira_project": jira_project,
                "finding_form": finding_form,
            }

            return JIRAFindingForm(*args, **kwargs)
        return None

    def get_github_form(self, request: HttpRequest, finding: Finding):
        # Determine if github should be used
        if get_system_setting("enable_github"):
            # Ensure there is a github conf correctly configured for the product
            config_present = GITHUB_PKey.objects.filter(product=finding.test.engagement.product)
            if config_present := config_present.exclude(git_conf_id=None):
                # Set up the args for the form
                args = [request.POST] if request.method == "POST" else []
                # Set the initial form args
                kwargs = {
                    "enabled": finding.has_github_issue(),
                    "prefix": "githubform",
                }

                return GITHUBFindingForm(*args, **kwargs)
        return None

    def get_initial_context(self, request: HttpRequest, finding: Finding):
        # Get the finding form first since it is used in another place
        finding_form = self.get_finding_form(request, finding)
        return {
            "form": finding_form,
            "finding": finding,
            "jform": self.get_jira_form(request, finding, finding_form=finding_form),
            "gform": self.get_github_form(request, finding),
            "return_url": get_return_url(request),
            "product_tab": Product_Tab(
                finding.test.engagement.product, title="Edit Finding", tab="findings",
            ),
        }

    def validate_status_change(self, request: HttpRequest, finding: Finding, context: dict):
        # If the finding is already not active, skip this extra validation
        if not finding.active:
            return request
        # Validate the proper notes are added for mitigation
        if (not context["form"]["active"].value() or context["form"]["false_p"].value() or context["form"]["out_of_scope"].value()) and not context["form"]["duplicate"].value():
            note_type_activation = Note_Type.objects.filter(is_active=True).count()
            closing_disabled = 0
            if note_type_activation:
                closing_disabled = len(get_missing_mandatory_notetypes(finding))
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    "Can not set a finding as inactive without adding all mandatory notes",
                    code="inactive_without_mandatory_notes",
                )
                error_false_p = ValidationError(
                    "Can not set a finding as false positive without adding all mandatory notes",
                    code="false_p_without_mandatory_notes",
                )
                error_out_of_scope = ValidationError(
                    "Can not set a finding as out of scope without adding all mandatory notes",
                    code="out_of_scope_without_mandatory_notes",
                )
                if context["form"]["active"].value() is False:
                    context["form"].add_error("active", error_inactive)
                if context["form"]["false_p"].value():
                    context["form"].add_error("false_p", error_false_p)
                if context["form"]["out_of_scope"].value():
                    context["form"].add_error("out_of_scope", error_out_of_scope)
                messages.add_message(
                    request,
                    messages.ERROR,
                    ("Can not set a finding as inactive, "
                        "false positive or out of scope without adding all mandatory notes"),
                    extra_tags="alert-danger",
                )

        return request

    def process_mitigated_data(self, request: HttpRequest, finding: Finding, context: dict):
        # If active is not checked and CAN_EDIT_MITIGATED_DATA,
        # mitigate the finding and the associated endpoints status
        if finding_helper.can_edit_mitigated_data(request.user) and ((
            context["form"]["active"].value() is False
            or context["form"]["false_p"].value()
            or context["form"]["out_of_scope"].value()
        ) and context["form"]["duplicate"].value() is False):
            now = timezone.now()
            finding.is_mitigated = True
            endpoint_status = finding.status_finding.all()
            for status in endpoint_status:
                status.mitigated_by = (
                    context["form"].cleaned_data.get("mitigated_by") or request.user
                )
                status.mitigated_time = (
                    context["form"].cleaned_data.get("mitigated") or now
                )
                status.mitigated = True
                status.last_modified = timezone.now()
                status.save()

    def process_false_positive_history(self, finding: Finding):
        if get_system_setting("false_positive_history", False):
            # If the finding is being marked as a false positive we dont need to call the
            # fp history function because it will be called by the save function
            # If finding was a false positive and is being reactivated: retroactively reactivates all equal findings
            if finding.false_p and not finding.false_p and get_system_setting("retroactive_false_positive_history"):
                logger.debug("FALSE_POSITIVE_HISTORY: Reactivating existing findings based on: %s", finding)

                existing_fp_findings = match_finding_to_existing_findings(
                    finding, product=finding.test.engagement.product,
                ).filter(false_p=True)

                for fp in existing_fp_findings:
                    logger.debug("FALSE_POSITIVE_HISTORY: Reactivating false positive %i: %s", fp.id, fp)
                    fp.active = finding.active
                    fp.verified = finding.verified
                    fp.false_p = False
                    fp.out_of_scope = finding.out_of_scope
                    fp.is_mitigated = finding.is_mitigated
                    fp.save_no_options()

    def process_burp_request_response(self, finding: Finding, context: dict):
        if "request" in context["form"].cleaned_data or "response" in context["form"].cleaned_data:
            try:
                burp_rr, _ = BurpRawRequestResponse.objects.get_or_create(finding=finding)
            except BurpRawRequestResponse.MultipleObjectsReturned:
                burp_rr = BurpRawRequestResponse.objects.filter(finding=finding).first()
            burp_rr.burpRequestBase64 = base64.b64encode(
                context["form"].cleaned_data["request"].encode(),
            )
            burp_rr.burpResponseBase64 = base64.b64encode(
                context["form"].cleaned_data["response"].encode(),
            )
            burp_rr.clean()
            burp_rr.save()

    def process_finding_form(self, request: HttpRequest, finding: Finding, context: dict):
        if context["form"].is_valid():
            # process some of the easy stuff first
            new_finding = context["form"].save(commit=False)
            new_finding.test = finding.test
            new_finding.numerical_severity = Finding.get_numerical_severity(new_finding.severity)
            new_finding.last_reviewed = timezone.now()
            new_finding.last_reviewed_by = request.user
            new_finding.tags = context["form"].cleaned_data["tags"]
            # Handle group related things
            if "group" in context["form"].cleaned_data:
                finding_group = context["form"].cleaned_data["group"]
                finding_helper.update_finding_group(new_finding, finding_group)
            # Handle risk exception related things
            if "risk_accepted" in context["form"].cleaned_data and context["form"]["risk_accepted"].value():
                if new_finding.test.engagement.product.enable_simple_risk_acceptance:
                    ra_helper.simple_risk_accept(request.user, new_finding, perform_save=False)
            else:
                if new_finding.risk_accepted:
                    ra_helper.risk_unaccept(request.user, new_finding, perform_save=False)
            # Save and add new endpoints
            finding_helper.add_endpoints(new_finding, context["form"])
            # Remove unrelated endpoints
            endpoint_status_list = Endpoint_Status.objects.filter(finding=new_finding)
            for endpoint_status in endpoint_status_list:
                if endpoint_status.endpoint not in new_finding.endpoints.all():
                    endpoint_status.delete()
            # Handle some of the other steps
            self.process_mitigated_data(request, new_finding, context)
            self.process_false_positive_history(new_finding)
            self.process_burp_request_response(new_finding, context)
            # Save the vulnerability IDs
            finding_helper.save_vulnerability_ids(new_finding, context["form"].cleaned_data["vulnerability_ids"].split())
            # Add a success message
            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding saved successfully.",
                extra_tags="alert-success",
            )

            return finding, request, True
        add_error_message_to_response("The form has errors, please correct them below.")
        add_field_errors_to_response(context["form"])

        return finding, request, False

    def process_jira_form(self, request: HttpRequest, finding: Finding, context: dict):
        # Capture case if the jira not being enabled
        if context["jform"] is None:
            return request, True, False

        if context["jform"] and context["jform"].is_valid():
            jira_message = None
            logger.debug("jform.jira_issue: %s", context["jform"].cleaned_data.get("jira_issue"))
            logger.debug(JFORM_PUSH_TO_JIRA_MESSAGE, context["jform"].cleaned_data.get("push_to_jira"))
            # can't use helper as when push_all_jira_issues is True, the checkbox gets disabled and is always false
            push_all_jira_issues = jira_helper.is_push_all_issues(finding)
            push_to_jira = push_all_jira_issues or context["jform"].cleaned_data.get("push_to_jira")
            logger.debug("push_to_jira: %s", push_to_jira)
            logger.debug("push_all_jira_issues: %s", push_all_jira_issues)
            logger.debug("has_jira_group_issue: %s", finding.has_jira_group_issue)
            # if the jira issue key was changed, update database
            new_jira_issue_key = context["jform"].cleaned_data.get("jira_issue")
            # we only support linking / changing if there is no group issue
            if not finding.has_jira_group_issue:
                if finding.has_jira_issue:
                    """
                    everything in DD around JIRA integration is based on the internal id
                    of the issue in JIRA instead of on the public jira issue key.
                    I have no idea why, but it means we have to retrieve the issue from JIRA
                    to get the internal JIRA id. we can assume the issue exist,
                    which is already checked in the validation of the form
                    """
                    if not new_jira_issue_key:
                        jira_helper.finding_unlink_jira(request, finding)
                        jira_message = "Link to JIRA issue removed successfully."
                    elif new_jira_issue_key != finding.jira_issue.jira_key:
                        jira_helper.finding_unlink_jira(request, finding)
                        jira_helper.finding_link_jira(request, finding, new_jira_issue_key)
                        jira_message = "Changed JIRA link successfully."
                else:
                    if new_jira_issue_key:
                        jira_helper.finding_link_jira(request, finding, new_jira_issue_key)
                        jira_message = "Linked a JIRA issue successfully."
            # any existing finding should be updated
            push_to_jira = (
                push_to_jira
                and not (push_to_jira and finding.finding_group)
                and (finding.has_jira_issue or jira_helper.get_jira_instance(finding).finding_jira_sync)
            )
            # Determine if a message should be added
            if jira_message:
                messages.add_message(
                    request, messages.SUCCESS, jira_message, extra_tags="alert-success",
                )

            return request, True, push_to_jira
        add_field_errors_to_response(context["jform"])

        return request, False, False

    def process_github_form(self, request: HttpRequest, finding: Finding, context: dict, old_status: str):
        if "githubform-push_to_github" not in request.POST:
            return request, True

        if context["gform"].is_valid():
            if GITHUB_Issue.objects.filter(finding=finding).exists():
                update_external_issue(finding, old_status, "github")
            else:
                add_external_issue(finding, "github")

            return request, True
        add_field_errors_to_response(context["gform"])

        return request, False

    def process_forms(self, request: HttpRequest, finding: Finding, context: dict):
        form_success_list = []
        # Set vars for the completed forms
        old_status = finding.status()
        old_finding = copy.copy(finding)
        # Validate finding mitigation
        request = self.validate_status_change(request, finding, context)
        # Check the validity of the form overall
        new_finding, request, success = self.process_finding_form(request, finding, context)
        form_success_list.append(success)
        request, success, push_to_jira = self.process_jira_form(request, new_finding, context)
        form_success_list.append(success)
        request, success = self.process_github_form(request, new_finding, context, old_status)
        form_success_list.append(success)
        # Determine if all forms were successful
        all_forms_valid = all(form_success_list)
        # Check the validity of all the forms
        if all_forms_valid:
            # if we're removing the "duplicate" in the edit finding screen
            # do not relaunch deduplication, otherwise, it's never taken into account
            if old_finding.duplicate and not new_finding.duplicate:
                new_finding.duplicate_finding = None
                new_finding.save(push_to_jira=push_to_jira, dedupe_option=False)
            else:
                new_finding.save(push_to_jira=push_to_jira)
            # we only push the group after storing the finding to make sure
            # the updated data of the finding is pushed as part of the group
            if push_to_jira and finding.finding_group:
                jira_helper.push_to_jira(finding.finding_group)

        return request, all_forms_valid

    def get_template(self):
        return "dojo/edit_finding.html"

    def get(self, request: HttpRequest, finding_id: int):
        # Get the initial objects
        finding = self.get_finding(finding_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, finding, Permissions.Finding_Edit)
        # Set up the initial context
        context = self.get_initial_context(request, finding)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, finding_id: int):
        # Get the initial objects
        finding = self.get_finding(finding_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, finding, Permissions.Finding_Edit)
        # Set up the initial context
        context = self.get_initial_context(request, finding)
        # Process the form
        request, success = self.process_forms(request, finding, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_finding", args=(finding_id,)))
        # Render the form
        return render(request, self.get_template(), context)


class DeleteFinding(View):
    def get_finding(self, finding_id: int):
        return get_object_or_404(Finding, id=finding_id)

    def process_form(self, request: HttpRequest, finding: Finding, context: dict):
        if context["form"].is_valid():
            product = finding.test.engagement.product
            finding.delete()
            # Update the grade of the product async
            calculate_grade(product)
            # Add a message to the request that the finding was successfully deleted
            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding deleted successfully.",
                extra_tags="alert-success",
            )

            # Note: this notification has not be moved to "@receiver(post_delete, sender=Finding)" method as many other notifications
            # Because it could generate too much noise, we keep it here only for findings created by hand in WebUI
            # TODO: but same should be implemented for API endpoint

            # Send a notification that the finding had been deleted
            create_notification(
                event="finding_deleted",
                title=f"Deletion of {finding.title}",
                description=f'The finding "{finding.title}" was deleted by {request.user}',
                product=product,
                url=request.build_absolute_uri(reverse("all_findings")),
                recipients=[finding.test.engagement.lead],
                icon="exclamation-triangle",
            )
            # return the request
            return request, True

        # Add a failure message
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to delete finding, please try again.",
            extra_tags="alert-danger",
        )

        return request, False

    def post(self, request: HttpRequest, finding_id):
        # Get the initial objects
        finding = self.get_finding(finding_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, finding, Permissions.Finding_Delete)
        # Get the finding form
        context = {
            "form": DeleteFindingForm(request.POST, instance=finding),
        }
        # Process the form
        request, success = self.process_form(request, finding, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_test", args=(finding.test.id,)))
        raise PermissionDenied


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def close_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    # in order to close a finding, we need to capture why it was closed
    # we can do this with a Note
    note_type_activation = Note_Type.objects.filter(is_active=True)
    missing_note_types = get_missing_mandatory_notetypes(finding) if len(note_type_activation) else note_type_activation
    form = CloseFindingForm(missing_note_types=missing_note_types)
    if request.method == "POST":
        form = CloseFindingForm(request.POST, missing_note_types=missing_note_types)

        close_external_issue(finding, "Closed by defectdojo", "github")

        if form.is_valid():
            now = timezone.now()
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = form.cleaned_data.get("mitigated") or now
            new_note.save()
            finding.notes.add(new_note)

            messages.add_message(
                request, messages.SUCCESS, "Note Saved.", extra_tags="alert-success",
            )

            if len(missing_note_types) <= 1:
                finding.active = False
                now = timezone.now()
                finding.mitigated = form.cleaned_data.get("mitigated") or now
                finding.mitigated_by = (
                    form.cleaned_data.get("mitigated_by") or request.user
                )
                finding.is_mitigated = True
                finding.under_review = False
                finding.last_reviewed = finding.mitigated
                finding.last_reviewed_by = request.user
                finding.false_p = form.cleaned_data.get("false_p", False)
                finding.out_of_scope = form.cleaned_data.get("out_of_scope", False)
                finding.duplicate = form.cleaned_data.get("duplicate", False)
                endpoint_status = finding.status_finding.all()
                for status in endpoint_status:
                    status.mitigated_by = (
                        form.cleaned_data.get("mitigated_by") or request.user
                    )
                    status.mitigated_time = form.cleaned_data.get("mitigated") or now
                    status.mitigated = True
                    status.last_modified = timezone.now()
                    status.save()
                # Clear the risk acceptance, if present
                ra_helper.risk_unaccept(request.user, finding)

                # Manage the jira status changes
                push_to_jira = False
                # Determine if the finding is in a group. if so, not push to jira
                finding_in_group = finding.has_finding_group
                # Check if there is a jira issue that needs to be updated
                jira_issue_exists = finding.has_jira_issue or (finding.finding_group and finding.finding_group.has_jira_issue)
                # fetch the project
                jira_instance = jira_helper.get_jira_instance(finding)
                jira_project = jira_helper.get_jira_project(finding)
                # Only push if the finding is not in a group
                if jira_issue_exists:
                    # Determine if any automatic sync should occur
                    push_to_jira = jira_helper.is_push_all_issues(finding) or jira_instance.finding_jira_sync
                    # Add the closing note
                    if (jira_project.push_notes or push_to_jira) and not finding_in_group:
                        jira_helper.add_comment(finding, new_note, force_push=True)
                # Save the finding
                finding.save(push_to_jira=(push_to_jira and not finding_in_group))
                # we only push the group after saving the finding to make sure
                # the updated data of the finding is pushed as part of the group
                if push_to_jira and finding_in_group:
                    jira_helper.push_to_jira(finding.finding_group)

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "Finding closed.",
                    extra_tags="alert-success",
                )

                # Note: this notification has not be moved to "@receiver(pre_save, sender=Finding)" method as many other notifications
                # Because it could generate too much noise, we keep it here only for findings created by hand in WebUI
                # TODO: but same should be implemented for API endpoint

                create_notification(
                    event="finding_closed",
                    title=_("Closing of %s") % finding.title,
                    finding=finding,
                    description=f'The finding "{finding.title}" was closed by {request.user}',
                    url=reverse("view_finding", args=(finding.id,)),
                )
                return HttpResponseRedirect(
                    reverse("view_test", args=(finding.test.id,)),
                )
            return HttpResponseRedirect(
                reverse("close_finding", args=(finding.id,)),
            )

    product_tab = Product_Tab(
        finding.test.engagement.product, title="Close", tab="findings",
    )

    return render(
        request,
        "dojo/close_finding.html",
        {
            "finding": finding,
            "product_tab": product_tab,
            "active_tab": "findings",
            "user": request.user,
            "form": form,
            "note_types": missing_note_types,
        },
    )


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def defect_finding_review(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    # in order to close a finding, we need to capture why it was closed
    # we can do this with a Note
    if request.method == "POST":
        form = DefectFindingForm(request.POST)
        if form.is_valid():
            now = timezone.now()
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            finding.notes.add(new_note)
            finding.under_review = False
            defect_choice = form.cleaned_data["defect_choice"]

            if defect_choice == "Close Finding":
                finding.active = False
                finding.verified = True
                finding.mitigated = now
                finding.mitigated_by = request.user
                finding.is_mitigated = True
                finding.last_reviewed = finding.mitigated
                finding.last_reviewed_by = request.user
                finding.endpoints.clear()
            else:
                finding.active = True
                finding.verified = True
                finding.mitigated = None
                finding.mitigated_by = None
                finding.is_mitigated = False
                finding.last_reviewed = now
                finding.last_reviewed_by = request.user

            # Manage the jira status changes
            push_to_jira = False
            # Determine if the finding is in a group. if so, not push to jira
            finding_in_group = finding.has_finding_group
            # Check if there is a jira issue that needs to be updated
            jira_issue_exists = finding.has_jira_issue or (finding.finding_group and finding.finding_group.has_jira_issue)
            # Only push if the finding is not in a group
            if jira_issue_exists:
                # Determine if any automatic sync should occur
                push_to_jira = jira_helper.is_push_all_issues(finding) \
                    or jira_helper.get_jira_instance(finding).finding_jira_sync
            # Add the closing note
            if push_to_jira and not finding_in_group:
                if defect_choice == "Close Finding":
                    new_note.entry = new_note.entry + "\nJira issue set to resolved."
                else:
                    new_note.entry = new_note.entry + "\nJira issue re-opened."
                jira_helper.add_comment(finding, new_note, force_push=True)
            # Save the finding
            finding.save(push_to_jira=(push_to_jira and not finding_in_group))

            # we only push the group after saving the finding to make sure
            # the updated data of the finding is pushed as part of the group
            if push_to_jira and finding_in_group:
                jira_helper.push_to_jira(finding.finding_group)

            messages.add_message(
                request, messages.SUCCESS, "Defect Reviewed", extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_test", args=(finding.test.id,)))

    else:
        form = DefectFindingForm()

    product_tab = Product_Tab(
        finding.test.engagement.product, title="Jira Status Review", tab="findings",
    )

    return render(
        request,
        "dojo/defect_finding_review.html",
        {
            "finding": finding,
            "product_tab": product_tab,
            "user": request.user,
            "form": form,
        },
    )


@user_is_authorized(
    Finding,
    Permissions.Finding_Edit,
    "fid",
)
def reopen_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    finding.active = True
    finding.mitigated = None
    finding.mitigated_by = request.user
    finding.is_mitigated = False
    finding.last_reviewed = finding.mitigated
    finding.last_reviewed_by = request.user
    finding.under_review = False
    endpoint_status = finding.status_finding.all()
    for status in endpoint_status:
        status.mitigated_by = None
        status.mitigated_time = None
        status.mitigated = False
        status.last_modified = timezone.now()
        status.save()
    # Clear the risk acceptance, if present
    ra_helper.risk_unaccept(request.user, finding)
    jira_helper.save_and_push_to_jira(finding)

    reopen_external_issue(finding, "re-opened by defectdojo", "github")

    messages.add_message(
        request, messages.SUCCESS, "Finding Reopened.", extra_tags="alert-success",
    )

    # Note: this notification has not be moved to "@receiver(pre_save, sender=Finding)" method as many other notifications
    # Because it could generate too much noise, we keep it here only for findings created by hand in WebUI
    # TODO: but same should be implemented for API endpoint

    create_notification(
        event="finding_reopened",
        title=_("Reopening of %s") % finding.title,
        finding=finding,
        description=f'The finding "{finding.title}" was reopened by {request.user}',
        url=reverse("view_finding", args=(finding.id,)),
    )
    return HttpResponseRedirect(reverse("view_finding", args=(finding.id,)))


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def apply_template_cwe(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    if request.method == "POST":
        form = FindingFormID(request.POST, instance=finding)
        if form.is_valid():
            finding = apply_cwe_to_template(finding)
            finding.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding CWE template applied successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_finding", args=(fid,)))
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to apply CWE template finding, please try again.",
            extra_tags="alert-danger",
        )
        return None
    raise PermissionDenied


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def copy_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    product = finding.test.engagement.product
    tests = get_authorized_tests(Permissions.Test_Edit).filter(
        engagement=finding.test.engagement,
    )
    form = CopyFindingForm(tests=tests)

    if request.method == "POST":
        form = CopyFindingForm(request.POST, tests=tests)
        if form.is_valid():
            test = form.cleaned_data.get("test")
            product = finding.test.engagement.product
            finding_copy = finding.copy(test=test)
            calculate_grade(product)
            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding Copied successfully.",
                extra_tags="alert-success",
            )
            create_notification(
                event="finding_copied",  # TODO: - if 'copy' functionality will be supported by API as well, 'create_notification' needs to be migrated to place where it will be able to cover actions from both interfaces
                title=_("Copying of %s") % finding.title,
                description=f'The finding "{finding.title}" was copied by {request.user} to {test.title}',
                product=product,
                url=request.build_absolute_uri(
                    reverse("copy_finding", args=(finding_copy.id,)),
                ),
                recipients=[finding.test.engagement.lead],
                icon="exclamation-triangle",
            )
            return redirect_to_return_url_or_else(
                request, reverse("view_test", args=(test.id,)),
            )
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to copy finding, please try again.",
            extra_tags="alert-danger",
        )

    product_tab = Product_Tab(product, title="Copy Finding", tab="findings")
    return render(
        request,
        "dojo/copy_object.html",
        {
            "source": finding,
            "source_label": "Finding",
            "destination_label": "Test",
            "product_tab": product_tab,
            "form": form,
        },
    )


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def remediation_date(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)

    if request.method == "POST":
        form = EditPlannedRemediationDateFindingForm(request.POST)

        if form.is_valid():
            finding.planned_remediation_date = request.POST.get(
                "planned_remediation_date", "",
            )
            finding.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding Planned Remediation Date saved.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_finding", args=(finding.id,)))

    else:
        form = EditPlannedRemediationDateFindingForm(finding=finding)

    product_tab = Product_Tab(
        finding.test.engagement.product,
        title="Planned Remediation Date",
        tab="findings",
    )

    return render(
        request,
        "dojo/remediation_date.html",
        {"finding": finding, "product_tab": product_tab, "user": user, "form": form},
    )


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def touch_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    finding.last_reviewed = timezone.now()
    finding.last_reviewed_by = request.user
    finding.save()
    return redirect_to_return_url_or_else(
        request, reverse("view_finding", args=(finding.id,)),
    )


@user_is_authorized(Finding, Permissions.Risk_Acceptance, "fid")
def simple_risk_accept(request, fid):
    finding = get_object_or_404(Finding, id=fid)

    if not finding.test.engagement.product.enable_simple_risk_acceptance:
        raise PermissionDenied

    ra_helper.simple_risk_accept(request.user, finding)

    messages.add_message(
        request, messages.WARNING, "Finding risk accepted.", extra_tags="alert-success",
    )

    return redirect_to_return_url_or_else(
        request, reverse("view_finding", args=(finding.id,)),
    )


@user_is_authorized(Finding, Permissions.Risk_Acceptance, "fid")
def risk_unaccept(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    ra_helper.risk_unaccept(request.user, finding)

    messages.add_message(
        request,
        messages.WARNING,
        "Finding risk unaccepted.",
        extra_tags="alert-success",
    )

    return redirect_to_return_url_or_else(
        request, reverse("view_finding", args=(finding.id,)),
    )


@user_is_authorized(Finding, Permissions.Finding_View, "fid")
def request_finding_review(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)
    form = ReviewFindingForm(finding=finding, user=user)
    # in order to review a finding, we need to capture why a review is needed
    # we can do this with a Note
    if request.method == "POST":
        form = ReviewFindingForm(request.POST, finding=finding, user=user)

        if form.is_valid():
            now = timezone.now()
            new_note = Notes()
            new_note.entry = "Review Request: " + form.cleaned_data["entry"]
            new_note.private = True
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            finding.notes.add(new_note)
            finding.active = True
            finding.verified = False
            finding.is_mitigated = False
            finding.under_review = True
            finding.review_requested_by = user
            finding.last_reviewed = now
            finding.last_reviewed_by = request.user

            reviewers = form.cleaned_data["reviewers"]
            finding.reviewers.set(reviewers)

            # Manage the jira status changes
            push_to_jira = False
            # Determine if the finding is in a group. if so, not push to jira
            finding_in_group = finding.has_finding_group
            # Check if there is a jira issue that needs to be updated
            jira_issue_exists = finding.has_jira_issue or (finding.finding_group and finding.finding_group.has_jira_issue)
            # Only push if the finding is not in a group
            if jira_issue_exists:
                # Determine if any automatic sync should occur
                push_to_jira = jira_helper.is_push_all_issues(finding) \
                    or jira_helper.get_jira_instance(finding).finding_jira_sync
            # Add the closing note
            if push_to_jira and not finding_in_group:
                jira_helper.add_comment(finding, new_note, force_push=True)
            # Save the finding
            finding.save(push_to_jira=(push_to_jira and not finding_in_group))

            # we only push the group after saving the finding to make sure
            # the updated data of the finding is pushed as part of the group
            if push_to_jira and finding_in_group:
                jira_helper.push_to_jira(finding.finding_group)

            reviewers = Dojo_User.objects.filter(id__in=form.cleaned_data["reviewers"])
            reviewers_string = ", ".join([f"{user} ({user.id})" for user in reviewers])
            reviewers_usernames = [user.username for user in reviewers]
            logger.debug(f"Asking {reviewers_string} for review")

            create_notification(
                event="review_requested",  # TODO: - if 'review_requested' functionality will be supported by API as well, 'create_notification' needs to be migrated to place where it will be able to cover actions from both interfaces
                title="Finding review requested",
                requested_by=user,
                note=new_note,
                finding=finding,
                reviewers=reviewers,
                recipients=reviewers_usernames,
                description=f'User {user.get_full_name()}({user.id}) has requested that user(s) {reviewers_string} review the finding "{finding.title}" for accuracy:\n\n{new_note}',
                icon="check",
                url=reverse("view_finding", args=(finding.id,)),
            )

            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding marked for review and reviewers notified.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_finding", args=(finding.id,)))

    product_tab = Product_Tab(
        finding.test.engagement.product, title="Review Finding", tab="findings",
    )

    return render(
        request,
        "dojo/review_finding.html",
        {"finding": finding, "product_tab": product_tab, "user": user, "form": form, "enable_table_filtering": get_system_setting("enable_ui_table_based_searching")},
    )


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def clear_finding_review(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)
    # If the user wanting to clear the review is not the user who requested
    # the review or one of the users requested to provide the review, then
    # do not allow the user to clear the review.
    if user != finding.review_requested_by and user not in finding.reviewers.all():
        raise PermissionDenied

    # in order to clear a review for a finding, we need to capture why and how it was reviewed
    # we can do this with a Note
    if request.method == "POST":
        form = ClearFindingReviewForm(request.POST, instance=finding)

        if form.is_valid():
            now = timezone.now()
            new_note = Notes()
            new_note.entry = "Review Cleared: " + form.cleaned_data["entry"]
            new_note.author = request.user
            new_note.date = now
            new_note.save()

            finding = form.save(commit=False)

            if finding.is_mitigated:
                finding.mitigated = now
                finding.mitigated_by = request.user
            finding.under_review = False
            finding.last_reviewed = now
            finding.last_reviewed_by = request.user

            finding.reviewers.set([])
            finding.notes.add(new_note)

            # Manage the jira status changes
            push_to_jira = False
            # Determine if the finding is in a group. if so, not push to jira
            finding_in_group = finding.has_finding_group
            # Check if there is a jira issue that needs to be updated
            jira_issue_exists = finding.has_jira_issue or (finding.finding_group and finding.finding_group.has_jira_issue)
            # Only push if the finding is not in a group
            if jira_issue_exists:
                # Determine if any automatic sync should occur
                push_to_jira = jira_helper.is_push_all_issues(finding) \
                    or jira_helper.get_jira_instance(finding).finding_jira_sync
            # Add the closing note
            if push_to_jira and not finding_in_group:
                jira_helper.add_comment(finding, new_note, force_push=True)
            # Save the finding
            finding.save(push_to_jira=(push_to_jira and not finding_in_group))

            # we only push the group after saving the finding to make sure
            # the updated data of the finding is pushed as part of the group
            if push_to_jira and finding_in_group:
                jira_helper.push_to_jira(finding.finding_group)

            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding review has been updated successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_finding", args=(finding.id,)))

    else:
        form = ClearFindingReviewForm(instance=finding)

    product_tab = Product_Tab(
        finding.test.engagement.product, title="Clear Finding Review", tab="findings",
    )

    return render(
        request,
        "dojo/clear_finding_review.html",
        {"finding": finding, "product_tab": product_tab, "user": user, "form": form},
    )


@user_has_global_permission(Permissions.Finding_Add)
def mktemplate(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    templates = Finding_Template.objects.filter(title=finding.title)
    if len(templates) > 0:
        messages.add_message(
            request,
            messages.ERROR,
            "A finding template with that title already exists.",
            extra_tags="alert-danger",
        )
    else:
        template = Finding_Template(
            title=finding.title,
            cwe=finding.cwe,
            cvssv3=finding.cvssv3,
            severity=finding.severity,
            description=finding.description,
            mitigation=finding.mitigation,
            impact=finding.impact,
            references=finding.references,
            numerical_severity=finding.numerical_severity,
            tags=finding.tags.all(),
        )
        template.save()
        template.tags = finding.tags.all()

        for vulnerability_id in finding.vulnerability_ids:
            Vulnerability_Id_Template(
                finding_template=template, vulnerability_id=vulnerability_id,
            ).save()

        messages.add_message(
            request,
            messages.SUCCESS,
            mark_safe(
                'Finding template added successfully. You may edit it <a href="{}">here</a>.'.format(reverse("edit_template", args=(template.id,))),
            ),
            extra_tags="alert-success",
        )
    return HttpResponseRedirect(reverse("view_finding", args=(finding.id,)))


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def find_template_to_apply(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    test = get_object_or_404(Test, id=finding.test.id)
    templates_by_cve = (
        Finding_Template.objects.annotate(
            cve_len=Length("cve"), order=models.Value(1, models.IntegerField()),
        )
        .filter(cve=finding.cve, cve_len__gt=0)
        .order_by("-last_used")
    )
    if templates_by_cve.count() == 0:
        templates_by_last_used = (
            Finding_Template.objects.all()
            .order_by("-last_used")
            .annotate(
                cve_len=Length("cve"), order=models.Value(2, models.IntegerField()),
            )
        )
        templates = templates_by_last_used
    else:
        templates_by_last_used = (
            Finding_Template.objects.all()
            .exclude(cve=finding.cve)
            .order_by("-last_used")
            .annotate(
                cve_len=Length("cve"), order=models.Value(2, models.IntegerField()),
            )
        )
        templates = templates_by_last_used.union(templates_by_cve).order_by(
            "order", "-last_used",
        )

    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    # just query all templates as this weird ordering above otherwise breaks Django ORM
    title_words = get_words_for_field(Finding_Template, "title")
    product_tab = Product_Tab(
        test.engagement.product, title="Apply Template to Finding", tab="findings",
    )
    return render(
        request,
        "dojo/templates.html",
        {
            "templates": paged_templates,
            "product_tab": product_tab,
            "filtered": templates,
            "title_words": title_words,
            "tid": test.id,
            "fid": fid,
            "add_from_template": False,
            "apply_template": True,
        },
    )


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def choose_finding_template_options(request, tid, fid):
    finding = get_object_or_404(Finding, id=fid)
    template = get_object_or_404(Finding_Template, id=tid)
    data = finding.__dict__
    # Not sure what's going on here, just leave same as with django-tagging
    data["tags"] = [tag.name for tag in template.tags.all()]
    data["vulnerability_ids"] = "\n".join(finding.vulnerability_ids)

    form = ApplyFindingTemplateForm(data=data, template=template)
    product_tab = Product_Tab(
        finding.test.engagement.product,
        title="Finding Template Options",
        tab="findings",
    )
    return render(
        request,
        "dojo/apply_finding_template.html",
        {
            "finding": finding,
            "product_tab": product_tab,
            "template": template,
            "form": form,
            "finding_tags": [tag.name for tag in finding.tags.all()],
        },
    )


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
def apply_template_to_finding(request, fid, tid):
    finding = get_object_or_404(Finding, id=fid)
    template = get_object_or_404(Finding_Template, id=tid)

    if request.method == "POST":
        form = ApplyFindingTemplateForm(data=request.POST)

        if form.is_valid():
            template.last_used = timezone.now()
            template.save()
            finding.title = form.cleaned_data["title"]
            finding.cwe = form.cleaned_data["cwe"]
            finding.severity = form.cleaned_data["severity"]
            finding.description = form.cleaned_data["description"]
            finding.mitigation = form.cleaned_data["mitigation"]
            finding.impact = form.cleaned_data["impact"]
            finding.references = form.cleaned_data["references"]
            finding.last_reviewed = timezone.now()
            finding.last_reviewed_by = request.user
            finding.tags = form.cleaned_data["tags"]

            finding.cve = None
            finding_helper.save_vulnerability_ids(
                finding, form.cleaned_data["vulnerability_ids"].split(),
            )

            finding.save()
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "There appears to be errors on the form, please correct below.",
                extra_tags="alert-danger",
            )
            product_tab = Product_Tab(
                finding.test.engagement.product,
                title="Apply Finding Template",
                tab="findings",
            )
            return render(
                request,
                "dojo/apply_finding_template.html",
                {
                    "finding": finding,
                    "product_tab": product_tab,
                    "template": template,
                    "form": form,
                },
            )

        return HttpResponseRedirect(reverse("view_finding", args=(finding.id,)))
    return HttpResponseRedirect(reverse("view_finding", args=(finding.id,)))


@user_is_authorized(Test, Permissions.Finding_Add, "tid")
def add_stub_finding(request, tid):
    test = get_object_or_404(Test, id=tid)
    if request.method == "POST":
        form = StubFindingForm(request.POST)
        if form.is_valid():
            stub_finding = form.save(commit=False)
            stub_finding.test = test
            stub_finding.reporter = request.user
            stub_finding.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Stub Finding created successfully.",
                extra_tags="alert-success",
            )
            if request.headers.get("x-requested-with") == "XMLHttpRequest":
                data = {
                    "message": "Stub Finding created successfully.",
                    "id": stub_finding.id,
                    "severity": "None",
                    "date": formats.date_format(stub_finding.date, "DATE_FORMAT"),
                }
                return HttpResponse(json.dumps(data))
        else:
            if request.headers.get("x-requested-with") == "XMLHttpRequest":
                data = {
                    "message": "Stub Finding form has error, please revise and try again.",
                }
                return HttpResponse(json.dumps(data))

            messages.add_message(
                request,
                messages.ERROR,
                "Stub Finding form has error, please revise and try again.",
                extra_tags="alert-danger",
            )
    add_breadcrumb(title="Add Stub Finding", top_level=False, request=request)
    return HttpResponseRedirect(reverse("view_test", args=(tid,)))


@user_is_authorized(Stub_Finding, Permissions.Finding_Delete, "fid")
def delete_stub_finding(request, fid):
    finding = get_object_or_404(Stub_Finding, id=fid)

    if request.method == "POST":
        form = DeleteStubFindingForm(request.POST, instance=finding)
        if form.is_valid():
            tid = finding.test.id
            finding.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Potential Finding deleted successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_test", args=(tid,)))
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to delete potential finding, please try again.",
            extra_tags="alert-danger",
        )
        return None
    raise PermissionDenied


@user_is_authorized(Stub_Finding, Permissions.Finding_Edit, "fid")
def promote_to_finding(request, fid):
    finding = get_object_or_404(Stub_Finding, id=fid)
    test = finding.test
    form_error = False
    push_all_jira_issues = jira_helper.is_push_all_issues(finding)
    jform = None
    use_jira = jira_helper.get_jira_project(finding) is not None
    product_tab = Product_Tab(
        finding.test.engagement.product, title="Promote Finding", tab="findings",
    )

    if request.method == "POST":
        form = PromoteFindingForm(request.POST, product=test.engagement.product)
        if use_jira:
            jform = JIRAFindingForm(
                request.POST,
                instance=finding,
                prefix="jiraform",
                push_all=push_all_jira_issues,
                jira_project=jira_helper.get_jira_project(finding),
            )

        if form.is_valid() and (jform is None or jform.is_valid()):
            if jform:
                logger.debug(
                    "jform.jira_issue: %s", jform.cleaned_data.get("jira_issue"),
                )
                logger.debug(
                    JFORM_PUSH_TO_JIRA_MESSAGE, jform.cleaned_data.get("push_to_jira"),
                )

            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity,
            )

            new_finding.active = True
            new_finding.false_p = False
            new_finding.duplicate = False
            new_finding.mitigated = None
            new_finding.verified = True
            new_finding.out_of_scope = False

            new_finding.save()

            finding_helper.add_endpoints(new_finding, form)

            push_to_jira = False
            if jform and jform.is_valid():
                # Push to Jira?
                logger.debug("jira form valid")
                push_to_jira = push_all_jira_issues or jform.cleaned_data.get(
                    "push_to_jira",
                )

                # if the jira issue key was changed, update database
                new_jira_issue_key = jform.cleaned_data.get("jira_issue")
                if new_finding.has_jira_issue:
                    # vaiable "jira_issue" no used
                    # jira_issue = new_finding.jira_issue
                    """
                    everything in DD around JIRA integration is based on the internal id of
                    the issue in JIRA instead of on the public jira issue key.
                    I have no idea why, but it means we have to retrieve
                    the issue from JIRA to get the internal JIRA id. we can assume the issue exist,
                    which is already checked in the validation of the jform
                    """

                    if not new_jira_issue_key:
                        jira_helper.finding_unlink_jira(request, new_finding)

                    elif new_jira_issue_key != new_finding.jira_issue.jira_key:
                        jira_helper.finding_unlink_jira(request, new_finding)
                        jira_helper.finding_link_jira(
                            request, new_finding, new_jira_issue_key,
                        )
                else:
                    logger.debug("finding has no jira issue yet")
                    if new_jira_issue_key:
                        logger.debug(
                            "finding has no jira issue yet, but jira issue specified in request. trying to link.")
                        jira_helper.finding_link_jira(
                            request, new_finding, new_jira_issue_key,
                        )

            finding_helper.save_vulnerability_ids(
                new_finding, form.cleaned_data["vulnerability_ids"].split(),
            )

            new_finding.save(push_to_jira=push_to_jira)

            finding.delete()
            if "githubform" in request.POST:
                gform = GITHUBFindingForm(
                    request.POST,
                    prefix="githubform",
                    enabled=GITHUB_PKey.objects.get(
                        product=test.engagement.product,
                    ).push_all_issues,
                )
                if gform.is_valid():
                    add_external_issue(new_finding, "github")

            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding promoted successfully.",
                extra_tags="alert-success",
            )

            return HttpResponseRedirect(reverse("view_test", args=(test.id,)))
        form_error = True
        add_error_message_to_response(
            "The form has errors, please correct them below.",
        )
        add_field_errors_to_response(jform)
        add_field_errors_to_response(form)
    else:
        form = PromoteFindingForm(
            initial={
                "title": finding.title,
                "product_tab": product_tab,
                "date": finding.date,
                "severity": finding.severity,
                "description": finding.description,
                "test": finding.test,
                "reporter": finding.reporter,
            },
            product=test.engagement.product,
        )

        if use_jira:
            jform = JIRAFindingForm(
                prefix="jiraform",
                push_all=jira_helper.is_push_all_issues(test),
                jira_project=jira_helper.get_jira_project(test),
            )

    return render(
        request,
        "dojo/promote_to_finding.html",
        {
            "form": form,
            "product_tab": product_tab,
            "test": test,
            "stub_finding": finding,
            "form_error": form_error,
            "jform": jform,
        },
    )


@user_has_global_permission(Permissions.Finding_Edit)
def templates(request):
    templates = Finding_Template.objects.all().order_by("cwe")
    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    title_words = get_words_for_field(templates.qs, "title")

    add_breadcrumb(title="Template Listing", top_level=True, request=request)
    return render(
        request,
        "dojo/templates.html",
        {
            "templates": paged_templates,
            "filtered": templates,
            "title_words": title_words,
        },
    )


@user_has_global_permission(Permissions.Finding_Edit)
def export_templates_to_json(request):
    leads_as_json = serializers.serialize("json", Finding_Template.objects.all())
    return HttpResponse(leads_as_json, content_type="json")


def apply_cwe_mitigation(apply_to_findings, template, *, update=True):
    count = 0
    if apply_to_findings and template.template_match and template.cwe is not None:
        # Update active, verified findings with the CWE template
        # If CWE only match only update issues where there isn't a CWE + Title match
        if template.template_match_title:
            count = Finding.objects.filter(
                active=True,
                verified=True,
                cwe=template.cwe,
                title__icontains=template.title,
            ).update(
                mitigation=template.mitigation,
                impact=template.impact,
                references=template.references,
            )
        else:
            finding_templates = Finding_Template.objects.filter(
                cwe=template.cwe, template_match=True, template_match_title=True,
            )

            finding_ids = None
            result_list = None
            # Exclusion list
            for title_template in finding_templates:
                finding_ids = Finding.objects.filter(
                    active=True,
                    verified=True,
                    cwe=title_template.cwe,
                    title__icontains=title_template.title,
                ).values_list("id", flat=True)
                result_list = finding_ids if result_list is None else list(chain(result_list, finding_ids))

            # If result_list is None the filter exclude won't work
            if result_list:
                count = Finding.objects.filter(
                    active=True, verified=True, cwe=template.cwe,
                ).exclude(id__in=result_list)
            else:
                count = Finding.objects.filter(
                    active=True, verified=True, cwe=template.cwe,
                )

            if update:
                # MySQL won't allow an 'update in statement' so loop will have to do
                for finding in count:
                    finding.mitigation = template.mitigation
                    finding.impact = template.impact
                    finding.references = template.references
                    template.last_used = timezone.now()
                    template.save()
                    new_note = Notes()
                    new_note.entry = (
                        f"CWE remediation text applied to finding for CWE: {template.cwe} using template: {template.title}."
                    )
                    new_note.author, _created = User.objects.get_or_create(
                        username="System",
                    )
                    new_note.save()
                    finding.notes.add(new_note)
                    finding.save()

            count = count.count()
    return count


@user_has_global_permission(Permissions.Finding_Add)
def add_template(request):
    form = FindingTemplateForm()
    if request.method == "POST":
        form = FindingTemplateForm(request.POST)
        if form.is_valid():
            apply_message = ""
            template = form.save(commit=False)
            template.numerical_severity = Finding.get_numerical_severity(
                template.severity,
            )
            template.save()
            finding_helper.save_vulnerability_ids_template(
                template, form.cleaned_data["vulnerability_ids"].split(),
            )
            form.save_m2m()
            count = apply_cwe_mitigation(
                form.cleaned_data["apply_to_findings"], template,
            )
            if count > 0:
                apply_message = (
                    " and " + str(count) + pluralize(count, "finding,findings") + " "
                )

            messages.add_message(
                request,
                messages.SUCCESS,
                "Template created successfully. " + apply_message,
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("templates"))
        messages.add_message(
            request,
            messages.ERROR,
            "Template form has error, please revise and try again.",
            extra_tags="alert-danger",
        )
    add_breadcrumb(title="Add Template", top_level=False, request=request)
    return render(
        request, "dojo/add_template.html", {"form": form, "name": "Add Template"},
    )


@user_has_global_permission(Permissions.Finding_Edit)
def edit_template(request, tid):
    template = get_object_or_404(Finding_Template, id=tid)
    form = FindingTemplateForm(
        instance=template,
        initial={"vulnerability_ids": "\n".join(template.vulnerability_ids)},
    )

    if request.method == "POST":
        form = FindingTemplateForm(request.POST, instance=template)
        if form.is_valid():
            template = form.save(commit=False)
            template.numerical_severity = Finding.get_numerical_severity(
                template.severity,
            )
            finding_helper.save_vulnerability_ids_template(
                template, form.cleaned_data["vulnerability_ids"].split(),
            )
            template.save()
            form.save_m2m()

            count = apply_cwe_mitigation(
                form.cleaned_data["apply_to_findings"], template,
            )
            apply_message = " and " + str(count) + " " + pluralize(count, "finding,findings") + " " if count > 0 else ""

            messages.add_message(
                request,
                messages.SUCCESS,
                "Template " + apply_message + "updated successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("templates"))
        messages.add_message(
            request,
            messages.ERROR,
            "Template form has error, please revise and try again.",
            extra_tags="alert-danger",
        )

    count = apply_cwe_mitigation(apply_to_findings=True, template=template, update=False)
    add_breadcrumb(title="Edit Template", top_level=False, request=request)
    return render(
        request,
        "dojo/add_template.html",
        {
            "form": form,
            "count": count,
            "name": "Edit Template",
            "template": template,
        },
    )


@user_has_global_permission(Permissions.Finding_Delete)
def delete_template(request, tid):
    template = get_object_or_404(Finding_Template, id=tid)
    if request.method == "POST":
        form = DeleteFindingTemplateForm(request.POST, instance=template)
        if form.is_valid():
            template.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding Template deleted successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("templates"))
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to delete Template, please revise and try again.",
            extra_tags="alert-danger",
        )
        return None
    raise PermissionDenied


def download_finding_pic(request, token):
    class Thumbnail(ImageSpec):
        processors = [ResizeToFill(100, 100)]
        format = "JPEG"
        options = {"quality": 70}

    class Small(ImageSpec):
        processors = [ResizeToFill(640, 480)]
        format = "JPEG"
        options = {"quality": 100}

    class Medium(ImageSpec):
        processors = [ResizeToFill(800, 600)]
        format = "JPEG"
        options = {"quality": 100}

    class Large(ImageSpec):
        processors = [ResizeToFill(1024, 768)]
        format = "JPEG"
        options = {"quality": 100}

    class Original(ImageSpec):
        format = "JPEG"
        options = {"quality": 100}

    mimetypes.init()

    size_map = {
        "thumbnail": Thumbnail,
        "small": Small,
        "medium": Medium,
        "large": Large,
        "original": Original,
    }

    try:
        access_token = FileAccessToken.objects.get(token=token)
        size = access_token.size

        if access_token.size not in list(size_map.keys()):
            raise Http404
        size = access_token.size
        # we know there is a token - is it for this image
        if access_token.size == size:
            """all is good, one time token used, delete it"""
            access_token.delete()
        else:
            raise PermissionDenied
    except Exception:
        raise PermissionDenied

    with open(access_token.file.file.file.name, "rb") as file:
        file_name = file.name
        image = size_map[size](source=file).generate()
        response = StreamingHttpResponse(FileIterWrapper(image))
        response["Content-Disposition"] = "inline"
        mimetype, _encoding = mimetypes.guess_type(file_name)
        response["Content-Type"] = mimetype
        return response


@user_is_authorized(Product, Permissions.Finding_Edit, "pid")
def merge_finding_product(request, pid):
    product = get_object_or_404(Product, pk=pid)
    finding_to_update = request.GET.getlist("finding_to_update")
    findings = None

    if (
        request.GET.get("merge_findings") or request.method == "POST"
    ) and finding_to_update:
        finding = Finding.objects.get(
            id=finding_to_update[0], test__engagement__product=product,
        )
        findings = Finding.objects.filter(
            id__in=finding_to_update, test__engagement__product=product,
        )
        form = MergeFindings(
            finding=finding,
            findings=findings,
            initial={"finding_to_merge_into": finding_to_update[0]},
        )

        if request.method == "POST":
            form = MergeFindings(request.POST, finding=finding, findings=findings)
            if form.is_valid():
                finding_to_merge_into = form.cleaned_data["finding_to_merge_into"]
                findings_to_merge = form.cleaned_data["findings_to_merge"]
                finding_descriptions = ""
                finding_references = ""
                notes_entry = ""
                static = False
                dynamic = False

                if finding_to_merge_into not in findings_to_merge:
                    for finding in findings_to_merge.exclude(
                        pk=finding_to_merge_into.pk,
                    ):
                        notes_entry = f"{notes_entry}\n- {finding.title} ({finding.id}),"
                        if finding.static_finding:
                            static = finding.static_finding

                        if finding.dynamic_finding:
                            dynamic = finding.dynamic_finding

                        if form.cleaned_data["append_description"]:
                            finding_descriptions = f"{finding_descriptions}\n{finding.description}"
                            # Workaround until file path is one to many
                            if finding.file_path:
                                finding_descriptions = f"{finding_descriptions}\n**File Path:** {finding.file_path}\n"

                        # If checked merge the Reference
                        if (
                            form.cleaned_data["append_reference"]
                            and finding.references is not None
                        ):
                            finding_references = f"{finding_references}\n{finding.references}"

                        # if checked merge the endpoints
                        if form.cleaned_data["add_endpoints"]:
                            finding_to_merge_into.endpoints.add(
                                *finding.endpoints.all(),
                            )

                        # if checked merge the tags
                        if form.cleaned_data["tag_finding"]:
                            for tag in finding.tags.all():
                                finding_to_merge_into.tags.add(tag)

                        # if checked re-assign the burp requests to the merged finding
                        if form.cleaned_data["dynamic_raw"]:
                            BurpRawRequestResponse.objects.filter(
                                finding=finding,
                            ).update(finding=finding_to_merge_into)

                        # Add merge finding information to the note if set to inactive
                        if form.cleaned_data["finding_action"] == "inactive":
                            single_finding_notes_entry = ("Finding has been set to inactive "
                                                          f"and merged with the finding: {finding_to_merge_into.title}.")
                            note = Notes(
                                entry=single_finding_notes_entry, author=request.user,
                            )
                            note.save()
                            finding.notes.add(note)

                            # If the merged finding should be tagged as merged-into
                            if form.cleaned_data["mark_tag_finding"]:
                                finding.tags.add("merged-inactive")

                    # Update the finding to merge into
                    if finding_descriptions != "":
                        finding_to_merge_into.description = f"{finding_to_merge_into.description}\n\n{finding_descriptions}"

                    if finding_to_merge_into.static_finding:
                        static = finding.static_finding

                    if finding_to_merge_into.dynamic_finding:
                        dynamic = finding.dynamic_finding

                    if finding_references != "":
                        finding_to_merge_into.references = f"{finding_to_merge_into.references}\n{finding_references}"

                    finding_to_merge_into.static_finding = static
                    finding_to_merge_into.dynamic_finding = dynamic

                    # Update the timestamp
                    finding_to_merge_into.last_reviewed = timezone.now()
                    finding_to_merge_into.last_reviewed_by = request.user

                    # Save the data to the merged finding
                    finding_to_merge_into.save()

                    # If the finding merged into should be tagged as merged
                    if form.cleaned_data["mark_tag_finding"]:
                        finding_to_merge_into.tags.add("merged")

                    finding_action = ""
                    # Take action on the findings
                    if form.cleaned_data["finding_action"] == "inactive":
                        finding_action = "inactivated"
                        findings_to_merge.exclude(pk=finding_to_merge_into.pk).update(
                            active=False,
                            last_reviewed=timezone.now(),
                            last_reviewed_by=request.user,
                        )
                    elif form.cleaned_data["finding_action"] == "delete":
                        finding_action = "deleted"
                        findings_to_merge.delete()

                    notes_entry = ("Finding consists of merged findings from the following "
                                   f"findings which have been {finding_action}: {notes_entry[:-1]}")
                    note = Notes(entry=notes_entry, author=request.user)
                    note.save()
                    finding_to_merge_into.notes.add(note)

                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Findings merged",
                        extra_tags="alert-success",
                    )
                    return HttpResponseRedirect(
                        reverse("edit_finding", args=(finding_to_merge_into.id,)),
                    )
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to merge findings. Findings to merge contained in finding to merge into.",
                    extra_tags="alert-danger",
                )
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to merge findings. Required fields were not selected.",
                    extra_tags="alert-danger",
                )

    product_tab = Product_Tab(
        finding.test.engagement.product, title="Merge Findings", tab="findings",
    )
    custom_breadcrumb = {
        "Open Findings": reverse(
            "product_open_findings", args=(finding.test.engagement.product.id,),
        )
        + "?test__engagement__product="
        + str(finding.test.engagement.product.id),
    }

    return render(
        request,
        "dojo/merge_findings.html",
        {
            "form": form,
            "name": "Merge Findings",
            "finding": finding,
            "product_tab": product_tab,
            "title": product_tab.title,
            "custom_breadcrumb": custom_breadcrumb,
        },
    )


# bulk update and delete are combined, so we can't have the nice user_is_authorized decorator
def finding_bulk_update_all(request, pid=None):
    system_settings = System_Settings.objects.get()

    logger.debug("bulk 10")
    form = FindingBulkUpdateForm(request.POST)
    now = timezone.now()
    return_url = None

    if request.method == "POST":
        logger.debug("bulk 20")

        finding_to_update = request.POST.getlist("finding_to_update")
        finds = Finding.objects.filter(id__in=finding_to_update).order_by("id")
        total_find_count = finds.count()
        prods = set(find.test.engagement.product for find in finds)  # noqa: C401
        if request.POST.get("delete_bulk_findings"):
            if form.is_valid() and finding_to_update:
                if pid is not None:
                    product = get_object_or_404(Product, id=pid)
                    user_has_permission_or_403(
                        request.user, product, Permissions.Finding_Delete,
                    )

                finds = get_authorized_findings(
                    Permissions.Finding_Delete, finds,
                ).distinct()

                skipped_find_count = total_find_count - finds.count()
                deleted_find_count = finds.count()

                for find in finds:
                    find.delete()

                if skipped_find_count > 0:
                    add_error_message_to_response(
                        f"Skipped deletion of {skipped_find_count} findings because you are not authorized.",
                    )

                if deleted_find_count > 0:
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        f"Bulk delete of {deleted_find_count} findings was successful.",
                        extra_tags="alert-success",
                    )
        else:
            if form.is_valid() and finding_to_update:
                if pid is not None:
                    product = get_object_or_404(Product, id=pid)
                    user_has_permission_or_403(
                        request.user, product, Permissions.Finding_Edit,
                    )

                # make sure users are not editing stuff they are not authorized for
                finds = get_authorized_findings(
                    Permissions.Finding_Edit, finds,
                ).distinct()

                skipped_find_count = total_find_count - finds.count()
                updated_find_count = finds.count()

                if skipped_find_count > 0:
                    add_error_message_to_response(
                        f"Skipped update of {skipped_find_count} findings because you are not authorized.",
                    )

                finds = prefetch_for_findings(finds)
                note = None
                if form.cleaned_data["severity"] or form.cleaned_data["status"]:
                    for find in finds:
                        old_find = copy.deepcopy(find)

                        if form.cleaned_data["severity"]:
                            find.severity = form.cleaned_data["severity"]
                            find.numerical_severity = Finding.get_numerical_severity(
                                form.cleaned_data["severity"],
                            )
                            find.last_reviewed = now
                            find.last_reviewed_by = request.user

                        if form.cleaned_data["status"]:
                            # logger.debug('setting status from bulk edit form: %s', form)
                            find.active = form.cleaned_data["active"]
                            find.verified = form.cleaned_data["verified"]
                            find.false_p = form.cleaned_data["false_p"]
                            find.out_of_scope = form.cleaned_data["out_of_scope"]
                            find.is_mitigated = form.cleaned_data["is_mitigated"]
                            find.last_reviewed = timezone.now()
                            find.last_reviewed_by = request.user

                        # use super to avoid all custom logic in our overriden save method
                        # it will trigger the pre_save signal
                        find.save_no_options()

                        if system_settings.false_positive_history:
                            # If finding is being marked as false positive
                            if find.false_p:
                                do_false_positive_history(find)

                            # If finding was a false positive and is being reactivated: retroactively reactivates all equal findings
                            elif old_find.false_p and not find.false_p:
                                if system_settings.retroactive_false_positive_history:
                                    logger.debug("FALSE_POSITIVE_HISTORY: Reactivating existing findings based on: %s", find)

                                    existing_fp_findings = match_finding_to_existing_findings(
                                        find, product=find.test.engagement.product,
                                    ).filter(false_p=True)

                                    for fp in existing_fp_findings:
                                        logger.debug("FALSE_POSITIVE_HISTORY: Reactivating false positive %i: %s", fp.id, fp)
                                        fp.active = find.active
                                        fp.verified = find.verified
                                        fp.false_p = False
                                        fp.out_of_scope = find.out_of_scope
                                        fp.is_mitigated = find.is_mitigated
                                        fp.save_no_options()

                    for prod in prods:
                        calculate_grade(prod)

                if form.cleaned_data["date"]:
                    for finding in finds:
                        finding.date = form.cleaned_data["date"]
                        finding.save_no_options()

                if form.cleaned_data["planned_remediation_date"]:
                    for finding in finds:
                        finding.planned_remediation_date = form.cleaned_data[
                            "planned_remediation_date"
                        ]
                        finding.save_no_options()

                if form.cleaned_data["planned_remediation_version"]:
                    for finding in finds:
                        finding.planned_remediation_version = form.cleaned_data[
                            "planned_remediation_version"
                        ]
                        finding.save_no_options()

                skipped_risk_accept_count = 0
                if form.cleaned_data["risk_acceptance"]:
                    for finding in finds:
                        if not finding.duplicate:
                            if form.cleaned_data["risk_accept"]:
                                if (
                                    not finding.test.engagement.product.enable_simple_risk_acceptance
                                ):
                                    skipped_risk_accept_count += 1
                                else:
                                    ra_helper.simple_risk_accept(request.user, finding)
                            elif form.cleaned_data["risk_unaccept"]:
                                ra_helper.risk_unaccept(request.user, finding)

                    for prod in prods:
                        calculate_grade(prod)

                if skipped_risk_accept_count > 0:
                    messages.add_message(
                        request,
                        messages.WARNING,
                        (f"Skipped simple risk acceptance of {skipped_risk_accept_count} findings, "
                         "simple risk acceptance is disabled on the related products"),
                        extra_tags="alert-warning",
                    )

                if form.cleaned_data["finding_group_create"]:
                    logger.debug("finding_group_create checked!")
                    finding_group_name = form.cleaned_data["finding_group_create_name"]
                    logger.debug("finding_group_create_name: %s", finding_group_name)
                    finding_group, added, skipped = finding_helper.create_finding_group(
                        finds, finding_group_name,
                    )

                    if added:
                        add_success_message_to_response(
                            f"Created finding group with {added} findings",
                        )
                        return_url = reverse(
                            "view_finding_group", args=(finding_group.id,),
                        )

                    if skipped:
                        add_success_message_to_response(
                            f"Skipped {skipped} findings in group creation, findings already part of another group",
                        )

                    # refresh findings from db
                    finds = finds.all()

                if form.cleaned_data["finding_group_add"]:
                    logger.debug("finding_group_add checked!")
                    fgid = form.cleaned_data["add_to_finding_group_id"]
                    finding_group = Finding_Group.objects.get(id=fgid)
                    finding_group, added, skipped = finding_helper.add_to_finding_group(
                        finding_group, finds,
                    )

                    if added:
                        add_success_message_to_response(
                            f"Added {added} findings to finding group {finding_group.name}",
                        )
                        return_url = reverse(
                            "view_finding_group", args=(finding_group.id,),
                        )

                    if skipped:
                        add_success_message_to_response(
                            f"Skipped {skipped} findings when adding to finding group {finding_group.name}, "
                            "findings already part of another group",
                        )

                    # refresh findings from db
                    finds = finds.all()

                if form.cleaned_data["finding_group_remove"]:
                    logger.debug("finding_group_remove checked!")
                    (
                        finding_groups,
                        removed,
                        skipped,
                    ) = finding_helper.remove_from_finding_group(finds)

                    if removed:
                        add_success_message_to_response(
                            "Removed {} findings from finding groups {}".format(
                                removed,
                                ",".join(
                                    [
                                        finding_group.name
                                        for finding_group in finding_groups
                                    ],
                                ),
                            ),
                        )

                    if skipped:
                        add_success_message_to_response(
                            f"Skipped {skipped} findings when removing from any finding group, findings not part of any group",
                        )

                    # refresh findings from db
                    finds = finds.all()

                if form.cleaned_data["finding_group_by"]:
                    logger.debug("finding_group_by checked!")
                    logger.debug(form.cleaned_data)
                    finding_group_by_option = form.cleaned_data[
                        "finding_group_by_option"
                    ]
                    logger.debug("finding_group_by_option: %s", finding_group_by_option)

                    (
                        finding_groups,
                        grouped,
                        skipped,
                        groups_created,
                    ) = finding_helper.group_findings_by(finds, finding_group_by_option)

                    if grouped:
                        add_success_message_to_response(
                            f"Grouped {grouped} findings into {len(finding_groups)} ({groups_created} newly created) finding groups",
                        )

                    if skipped:
                        add_success_message_to_response(
                            f"Skipped {skipped} findings when grouping by {finding_group_by_option} as these findings "
                            "were already in an existing group",
                        )

                    # refresh findings from db
                    finds = finds.all()

                if form.cleaned_data["push_to_github"]:
                    logger.debug("push selected findings to github")
                    for finding in finds:
                        logger.debug("will push to GitHub finding: " + str(finding))
                        old_status = finding.status()
                        if form.cleaned_data["push_to_github"]:
                            if GITHUB_Issue.objects.filter(finding=finding).exists():
                                update_external_issue(finding, old_status, "github")
                            else:
                                add_external_issue(finding, "github")

                if form.cleaned_data["notes"]:
                    logger.debug("Setting bulk notes")
                    note = Notes(
                        entry=form.cleaned_data["notes"],
                        author=request.user,
                        date=timezone.now(),
                    )
                    note.save()
                    history = NoteHistory(
                        data=note.entry, time=note.date, current_editor=note.author,
                    )
                    history.save()
                    note.history.add(history)
                    for finding in finds:
                        finding.notes.add(note)
                        finding.save()

                if form.cleaned_data["tags"]:
                    for finding in finds:
                        tags = form.cleaned_data["tags"]
                        logger.debug(
                            "bulk_edit: setting tags for: %i %s %s",
                            finding.id,
                            finding,
                            tags,
                        )
                        # currently bulk edit overwrites existing tags
                        finding.tags = tags
                        finding.save()

                error_counts = defaultdict(lambda: 0)
                success_count = 0
                finding_groups = set(  # noqa: C401
                    find.finding_group for find in finds if find.has_finding_group
                )
                logger.debug("finding_groups: %s", finding_groups)
                groups_pushed_to_jira = False
                for group in finding_groups:
                    if form.cleaned_data.get("push_to_jira"):
                        (
                            can_be_pushed_to_jira,
                            error_message,
                            _error_code,
                        ) = jira_helper.can_be_pushed_to_jira(group)
                        if not can_be_pushed_to_jira:
                            error_counts[error_message] += 1
                            jira_helper.log_jira_alert(error_message, group)
                        else:
                            logger.debug(
                                "pushing to jira from finding.finding_bulk_update_all()",
                            )
                            jira_helper.push_to_jira(group)
                            success_count += 1

                for error_message, error_count in error_counts.items():
                    add_error_message_to_response(f"{error_count} finding groups could not be pushed to JIRA: {error_message}")

                if success_count > 0:
                    add_success_message_to_response(f"{success_count} finding groups pushed to JIRA successfully")
                    groups_pushed_to_jira = True

                # refresh from db
                finds = finds.all()

                error_counts = defaultdict(lambda: 0)
                success_count = 0
                for finding in finds:
                    from dojo.tools import tool_issue_updater

                    tool_issue_updater.async_tool_issue_update(finding)

                    # not sure yet if we want to support bulk unlink, so leave as commented out for now
                    # if form.cleaned_data['unlink_from_jira']:
                    #     if finding.has_jira_issue:
                    #         jira_helper.finding_unlink_jira(request, finding)

                    # Because we never call finding.save() in a bulk update, we need to actually
                    # push the JIRA stuff here, rather than in finding.save()
                    # can't use helper as when push_all_jira_issues is True,
                    # the checkbox gets disabled and is always false
                    # push_to_jira = jira_helper.is_push_to_jira(new_finding,
                    # form.cleaned_data.get('push_to_jira'))
                    if not groups_pushed_to_jira and (
                        jira_helper.is_push_all_issues(finding)
                        or form.cleaned_data.get("push_to_jira")
                    ):
                        (
                            can_be_pushed_to_jira,
                            error_message,
                            _error_code,
                        ) = jira_helper.can_be_pushed_to_jira(finding)
                        if finding.has_jira_group_issue and not finding.has_jira_issue:
                            error_message = (
                                "finding already pushed as part of Finding Group"
                            )
                            error_counts[error_message] += 1
                            jira_helper.log_jira_alert(error_message, finding)
                        elif not can_be_pushed_to_jira:
                            error_counts[error_message] += 1
                            jira_helper.log_jira_alert(error_message, finding)
                        else:
                            logger.debug(
                                "pushing to jira from finding.finding_bulk_update_all()",
                            )
                            jira_helper.push_to_jira(finding)
                            if note is not None and isinstance(note, Notes):
                                jira_helper.add_comment(finding, note)
                            success_count += 1

                for error_message, error_count in error_counts.items():
                    add_error_message_to_response(f"{error_count} findings could not be pushed to JIRA: {error_message}")

                if success_count > 0:
                    add_success_message_to_response(f"{success_count} findings pushed to JIRA successfully")

                if updated_find_count > 0:
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        f"Bulk update of {updated_find_count} findings was successful.",
                        extra_tags="alert-success",
                    )
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to process bulk update. Required fields were not selected.",
                    extra_tags="alert-danger",
                )

    if return_url:
        redirect(request, return_url)

    return redirect_to_return_url_or_else(request, None)


def find_available_notetypes(notes):
    single_note_types = Note_Type.objects.filter(
        is_single=True, is_active=True,
    ).values_list("id", flat=True)
    multiple_note_types = Note_Type.objects.filter(
        is_single=False, is_active=True,
    ).values_list("id", flat=True)
    available_note_types = []
    for note_type_id in multiple_note_types:
        available_note_types.append(note_type_id)
    for note_type_id in single_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            available_note_types.append(note_type_id)
    return Note_Type.objects.filter(id__in=available_note_types).order_by("-id")


def get_missing_mandatory_notetypes(finding):
    notes = finding.notes.all()
    mandatory_note_types = Note_Type.objects.filter(
        is_mandatory=True, is_active=True,
    ).values_list("id", flat=True)
    notes_to_be_added = []
    for note_type_id in mandatory_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            notes_to_be_added.append(note_type_id)
    return Note_Type.objects.filter(id__in=notes_to_be_added)


@user_is_authorized(Finding, Permissions.Finding_Edit, "original_id")
@require_POST
def mark_finding_duplicate(request, original_id, duplicate_id):

    original = get_object_or_404(Finding, id=original_id)
    duplicate = get_object_or_404(Finding, id=duplicate_id)

    if original.test.engagement != duplicate.test.engagement:
        if (original.test.engagement.deduplication_on_engagement
                or duplicate.test.engagement.deduplication_on_engagement):
            messages.add_message(
                request,
                messages.ERROR,
                ("Marking finding as duplicate/original failed as they are not in the same engagement "
                 "and deduplication_on_engagement is enabled for at least one of them"),
                extra_tags="alert-danger",
            )
            return redirect_to_return_url_or_else(
                request, reverse("view_finding", args=(duplicate.id,)),
            )

    duplicate.duplicate = True
    duplicate.active = False
    duplicate.verified = False
    # make sure we don't create circular or transitive duplicates
    if original.duplicate:
        duplicate.duplicate_finding = original.duplicate_finding
    else:
        duplicate.duplicate_finding = original

    logger.debug(
        "marking finding %i as duplicate of %i",
        duplicate.id,
        duplicate.duplicate_finding.id,
    )

    duplicate.last_reviewed = timezone.now()
    duplicate.last_reviewed_by = request.user
    duplicate.save(dedupe_option=False)
    original.found_by.add(duplicate.test.test_type)
    original.save(dedupe_option=False)

    return redirect_to_return_url_or_else(
        request, reverse("view_finding", args=(duplicate.id,)),
    )


def reset_finding_duplicate_status_internal(user, duplicate_id):
    duplicate = get_object_or_404(Finding, id=duplicate_id)

    if not duplicate.duplicate:
        return None

    logger.debug("resetting duplicate status of %i", duplicate.id)
    duplicate.duplicate = False
    duplicate.active = True
    if duplicate.duplicate_finding:
        # duplicate.duplicate_finding.original_finding.remove(duplicate)  # shouldn't be needed
        duplicate.duplicate_finding = None
    duplicate.last_reviewed = timezone.now()
    duplicate.last_reviewed_by = user
    duplicate.save(dedupe_option=False)

    return duplicate.id


@user_is_authorized(Finding, Permissions.Finding_Edit, "duplicate_id")
@require_POST
def reset_finding_duplicate_status(request, duplicate_id):
    checked_duplicate_id = reset_finding_duplicate_status_internal(
        request.user, duplicate_id,
    )
    if checked_duplicate_id is None:
        messages.add_message(
            request,
            messages.ERROR,
            "Can't reset duplicate status of a finding that is not a duplicate",
            extra_tags="alert-danger",
        )
        return redirect_to_return_url_or_else(
            request, reverse("view_finding", args=(duplicate_id,)),
        )

    return redirect_to_return_url_or_else(
        request, reverse("view_finding", args=(checked_duplicate_id,)),
    )


def set_finding_as_original_internal(user, finding_id, new_original_id):
    finding = get_object_or_404(Finding, id=finding_id)
    new_original = get_object_or_404(Finding, id=new_original_id)

    if finding.test.engagement != new_original.test.engagement:
        if (finding.test.engagement.deduplication_on_engagement
                or new_original.test.engagement.deduplication_on_engagement):
            return False

    if finding.duplicate or finding.original_finding.all():
        # existing cluster, so update all cluster members

        if finding.duplicate and finding.duplicate_finding:
            logger.debug(
                "setting old original %i as duplicate of %i",
                finding.duplicate_finding.id,
                new_original.id,
            )
            finding.duplicate_finding.duplicate_finding = new_original
            finding.duplicate_finding.duplicate = True
            finding.duplicate_finding.save(dedupe_option=False)

        for cluster_member in finding.duplicate_finding_set():
            if cluster_member != new_original:
                logger.debug(
                    "setting new original for %i to %i",
                    cluster_member.id,
                    new_original.id,
                )
                cluster_member.duplicate_finding = new_original
                cluster_member.save(dedupe_option=False)

        logger.debug(
            "setting new original for old root %i to %i", finding.id, new_original.id,
        )
        finding.duplicate = True
        finding.duplicate_finding = new_original
        finding.save(dedupe_option=False)

    else:
        # creating a new cluster, so mark finding as duplicate
        logger.debug("marking %i as duplicate of %i", finding.id, new_original.id)
        finding.duplicate = True
        finding.active = False
        finding.duplicate_finding = new_original
        finding.last_reviewed = timezone.now()
        finding.last_reviewed_by = user
        finding.save(dedupe_option=False)

    logger.debug("marking new original %i as not duplicate", new_original.id)
    new_original.duplicate = False
    new_original.duplicate_finding = None
    new_original.save(dedupe_option=False)

    return True


@user_is_authorized(Finding, Permissions.Finding_Edit, "finding_id")
@require_POST
def set_finding_as_original(request, finding_id, new_original_id):
    success = set_finding_as_original_internal(
        request.user, finding_id, new_original_id,
    )
    if not success:
        messages.add_message(
            request,
            messages.ERROR,
            ("Marking finding as duplicate/original failed as they are not in the same engagement "
             "and deduplication_on_engagement is enabled for at least one of them"),
            extra_tags="alert-danger",
        )

    return redirect_to_return_url_or_else(
        request, reverse("view_finding", args=(finding_id,)),
    )


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
@require_POST
def unlink_jira(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    logger.info(
        "trying to unlink a linked jira issue from %d:%s", finding.id, finding.title,
    )
    if finding.has_jira_issue:
        try:
            jira_helper.finding_unlink_jira(request, finding)

            messages.add_message(
                request,
                messages.SUCCESS,
                "Link to JIRA issue succesfully deleted",
                extra_tags="alert-success",
            )

            return JsonResponse({"result": "OK"})
        except Exception as e:
            logger.exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Link to JIRA could not be deleted, see alerts for details",
                extra_tags="alert-danger",
            )

            return HttpResponse(status=500)
    else:
        messages.add_message(
            request, messages.ERROR, "Link to JIRA not found", extra_tags="alert-danger",
        )
        return HttpResponse(status=400)


@user_is_authorized(Finding, Permissions.Finding_Edit, "fid")
@require_POST
def push_to_jira(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    try:
        logger.info(
            "trying to push %d:%s to JIRA to create or update JIRA issue",
            finding.id,
            finding.title,
        )
        logger.debug("pushing to jira from finding.push_to-jira()")

        # it may look like succes here, but the push_to_jira are swallowing exceptions
        # but cant't change too much now without having a test suite,
        # so leave as is for now with the addition warning message
        # to check alerts for background errors.
        if jira_helper.push_to_jira(finding):
            messages.add_message(
                request,
                messages.SUCCESS,
                message="Action queued to create or update linked JIRA issue, check alerts for background errors.",
                extra_tags="alert-success",
            )
        else:
            messages.add_message(
                request,
                messages.SUCCESS,
                "Push to JIRA failed, check alerts on the top right for errors",
                extra_tags="alert-danger",
            )

        return JsonResponse({"result": "OK"})
    except Exception:
        logger.exception("Error pushing to JIRA")
        messages.add_message(
            request, messages.ERROR, "Error pushing to JIRA", extra_tags="alert-danger",
        )
        return HttpResponse(status=500)


# precalculate because we need related_actions to be set
def duplicate_cluster(request, finding):
    duplicate_cluster = finding.duplicate_finding_set()

    duplicate_cluster = prefetch_for_findings(duplicate_cluster)

    # populate actions for findings in duplicate cluster
    for duplicate_member in duplicate_cluster:
        duplicate_member.related_actions = (
            calculate_possible_related_actions_for_similar_finding(
                request, finding, duplicate_member,
            )
        )

    return duplicate_cluster


# django doesn't allow much logic or even method calls with parameters in templates.
# so we have to use a function in this view to calculate the possible actions on a similar (or duplicate) finding.
# and we assign this dictionary to the finding so it can be accessed in the template.
# these actions are always calculated in the context of the finding the user is viewing
# because this determines which actions are possible
def calculate_possible_related_actions_for_similar_finding(
    request, finding, similar_finding,
):
    actions = []
    if similar_finding.test.engagement != finding.test.engagement and (
        similar_finding.test.engagement.deduplication_on_engagement
        or finding.test.engagement.deduplication_on_engagement
    ):
        actions.append(
            {
                "action": "None",
                "reason": ("This finding is in a different engagement and deduplication_inside_engagment "
                           "is enabled here or in that finding"),
            },
        )
    elif finding.duplicate_finding == similar_finding:
        actions.append(
            {
                "action": "None",
                "reason": ("This finding is the root of the cluster, use an action on another row, "
                           "or the finding on top of the page to change the root of the cluser"),
            },
        )
    elif similar_finding.original_finding.all():
        actions.append(
            {
                "action": "None",
                "reason": ("This finding is similar, but is already an original in a different cluster. "
                           "Remove it from that cluster before you connect it to this cluster."),
            },
        )
    else:
        if similar_finding.duplicate_finding:
            # reset duplicate status is always possible
            actions.append(
                {
                    "action": "reset_finding_duplicate_status",
                    "reason": ("This will remove the finding from the cluster, "
                               "effectively marking it no longer as duplicate. "
                               "Will not trigger deduplication logic after saving."),
                },
            )

            if (
                similar_finding.duplicate_finding == finding
                or similar_finding.duplicate_finding == finding.duplicate_finding
            ):
                # duplicate inside the same cluster
                actions.append(
                    {
                        "action": "set_finding_as_original",
                        "reason": ("Sets this finding as the Original for the whole cluster. "
                                   "The existing Original will be downgraded to become a member of the cluster and, "
                                   "together with the other members, will be marked as duplicate of the new Original."),
                    },
                )
            else:
                # duplicate inside different cluster
                actions.append(
                    {
                        "action": "mark_finding_duplicate",
                        "reason": ("Will mark this finding as duplicate of the root finding in this cluster, "
                                   "effectively adding it to the cluster and removing it from the other cluster."),
                    },
                )
        else:
            # similar is not a duplicate yet
            if finding.duplicate or finding.original_finding.all():
                actions.extend((
                    {
                        "action": "mark_finding_duplicate",
                        "reason": "Will mark this finding as duplicate of the root finding in this cluster",
                    }, {
                        "action": "set_finding_as_original",
                        "reason": (
                            "Sets this finding as the Original for the whole cluster. "
                            "The existing Original will be downgraded to become a member of the cluster and, "
                            "together with the other members, will be marked as duplicate of the new Original."
                        ),
                    },
                ))
            else:
                # similar_finding is not an original/root of a cluster as per earlier if clause
                actions.extend((
                    {
                        "action": "mark_finding_duplicate",
                        "reason": "Will mark this finding as duplicate of the finding on this page.",
                    }, {
                        "action": "set_finding_as_original",
                        "reason": (
                            "Sets this finding as the Original marking the finding "
                            "on this page as duplicate of this original."
                        ),
                    },
                ))

    return actions
