import logging

from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.db.utils import DEFAULT_DB_ALIAS
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls.base import reverse
from django.views.decorators.http import require_POST

import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import FindingFilter, FindingFilterWithoutObjectLookups
from dojo.finding.views import prefetch_for_findings
from dojo.forms import DeleteFindingGroupForm, EditFindingGroupForm, FindingBulkUpdateForm
from dojo.models import Engagement, Finding, Finding_Group, GITHUB_PKey, Product
from dojo.utils import Product_Tab, add_breadcrumb, get_page_items, get_setting, get_system_setting, get_words_for_field

logger = logging.getLogger(__name__)


@user_is_authorized(Finding_Group, Permissions.Finding_Group_View, "fgid")
def view_finding_group(request, fgid):
    finding_group = get_object_or_404(Finding_Group, pk=fgid)
    findings = finding_group.findings.all()
    edit_finding_group_form = EditFindingGroupForm(instance=finding_group)
    filter_string_matching = get_system_setting("filter_string_matching", False)
    finding_filter_class = FindingFilterWithoutObjectLookups if filter_string_matching else FindingFilter

    show_product_column = True
    custom_breadcrumb = None
    product_tab = None
    jira_project = None
    github_config = None
    if finding_group.test.engagement.product.id:
        pid = finding_group.test.engagement.product.id
        product = get_object_or_404(Product, id=pid)
        user_has_permission_or_403(request.user, product, Permissions.Product_View)
        product_tab = Product_Tab(product, title="Findings", tab="findings")
        jira_project = jira_helper.get_jira_project(product)
        github_config = GITHUB_PKey.objects.filter(product=pid).first()
        findings_filter = finding_filter_class(request.GET, findings, user=request.user, pid=pid)
    elif finding_group.test.engagement.id:
        eid = finding_group.test.engagement.id
        engagement = get_object_or_404(Engagement, id=eid)
        user_has_permission_or_403(request.user, engagement, Permissions.Engagement_View)
        product_tab = Product_Tab(engagement.product, title=engagement.name, tab="engagements")
        jira_project = jira_helper.get_jira_project(engagement)
        github_config = GITHUB_PKey.objects.filter(product__engagement=eid).first()
        findings_filter = finding_filter_class(request.GET, findings, user=request.user, eid=eid)

    title_words = get_words_for_field(Finding, "title")
    component_words = get_words_for_field(Finding, "component_name")

    paged_findings = get_page_items(request, findings_filter.qs, 25)
    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list, "all")

    bulk_edit_form = FindingBulkUpdateForm(request.GET)

    if github_config:
        github_config = github_config.git_conf_id

    filter_name = finding_group.name

    if request.method == "POST":
        edit_finding_group_form = EditFindingGroupForm(request.POST, instance=finding_group)
        if edit_finding_group_form.is_valid():
            finding_group.name = edit_finding_group_form.cleaned_data.get("name", "")
            push_to_jira = edit_finding_group_form.cleaned_data.get("push_to_jira")
            jira_issue = edit_finding_group_form.cleaned_data.get("jira_issue")

            if jira_issue:
                # See if the submitted issue was a issue key or the full URL
                jira_instance = jira_helper.get_jira_project(finding_group).jira_instance
                jira_issue = jira_issue.removeprefix(jira_instance.url + "/browse/")

                if finding_group.has_jira_issue and jira_issue != jira_helper.get_jira_key(finding_group):
                    jira_helper.unlink_jira(request, finding_group)
                    jira_helper.finding_group_link_jira(request, finding_group, jira_issue)
                elif not finding_group.has_jira_issue:
                    jira_helper.finding_group_link_jira(request, finding_group, jira_issue)
            elif push_to_jira:
                jira_helper.push_to_jira(finding_group, sync=True)

            finding_group.save()
            return HttpResponseRedirect(reverse("view_test", args=(finding_group.test.id,)))

    add_breadcrumb(title=finding_group.name, top_level=not len(request.GET), request=request)
    return render(request, "dojo/view_finding_group.html", {
        "show_product_column": show_product_column,
        "product_tab": product_tab,
        "findings": paged_findings,
        "filtered": findings_filter,
        "title_words": title_words,
        "component_words": component_words,
        "custom_breadcrumb": custom_breadcrumb,
        "filter_name": filter_name,
        "jira_project": jira_project,
        "bulk_edit_form": bulk_edit_form,
        "edit_finding_group_form": edit_finding_group_form,
    })


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Delete, "fgid")
@require_POST
def delete_finding_group(request, fgid):
    finding_group = get_object_or_404(Finding_Group, pk=fgid)
    form = DeleteFindingGroupForm(instance=finding_group)

    if request.method == "POST":
        if "id" in request.POST and str(finding_group.id) == request.POST["id"]:
            form = DeleteFindingGroupForm(request.POST, instance=finding_group)
            if form.is_valid():
                finding_group.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     "Finding Group and relationships removed.",
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("view_test", args=(finding_group.test.id,)))

    rels = ["Previewing the relationships has been disabled.", ""]
    display_preview = get_setting("DELETE_PREVIEW")
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([finding_group])
        rels = collector.nested()
    product_tab = Product_Tab(finding_group.test.engagement.product, title="Product", tab="settings")

    return render(request, "dojo/delete_finding_group.html", {
        "finding_group": finding_group,
        "form": form,
        "product_tab": product_tab,
        "rels": rels,
    })


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Edit, "fgid")
@require_POST
def unlink_jira(request, fgid):
    logger.debug("/finding_group/%s/jira/unlink", fgid)
    group = get_object_or_404(Finding_Group, id=fgid)
    logger.info("trying to unlink a linked jira issue from %d:%s", group.id, group.name)
    if group.has_jira_issue:
        try:
            jira_helper.unlink_jira(request, group)

            messages.add_message(
                request,
                messages.SUCCESS,
                "Link to JIRA issue succesfully deleted",
                extra_tags="alert-success")

            return JsonResponse({"result": "OK"})
        except Exception:
            logger.exception("Link to JIRA could not be deleted")
            messages.add_message(
                request,
                messages.ERROR,
                "Link to JIRA could not be deleted, see alerts for details",
                extra_tags="alert-danger")

            return HttpResponse(status=500)
    else:
        messages.add_message(
            request,
            messages.ERROR,
            "Link to JIRA not found",
            extra_tags="alert-danger")
        return HttpResponse(status=400)


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Edit, "fgid")
@require_POST
def push_to_jira(request, fgid):
    logger.debug("/finding_group/%s/jira/push", fgid)
    group = get_object_or_404(Finding_Group, id=fgid)
    try:
        logger.info("trying to push %d:%s to JIRA to create or update JIRA issue", group.id, group.name)
        logger.debug("pushing to jira from group.push_to-jira()")

        # it may look like success here, but the push_to_jira are swallowing exceptions
        # but cant't change too much now without having a test suite, so leave as is for now with the addition warning message to check alerts for background errors.
        if jira_helper.push_to_jira(group, sync=True):
            messages.add_message(
                request,
                messages.SUCCESS,
                message="Action queued to create or update linked JIRA issue, check alerts for background errors.",
                extra_tags="alert-success")
        else:
            messages.add_message(
                request,
                messages.SUCCESS,
                "Push to JIRA failed, check alerts on the top right for errors",
                extra_tags="alert-danger")

        return JsonResponse({"result": "OK"})
    except Exception:
        logger.exception("Error pushing to JIRA")
        messages.add_message(
            request,
            messages.ERROR,
            "Error pushing to JIRA",
            extra_tags="alert-danger")
        return HttpResponse(status=500)
