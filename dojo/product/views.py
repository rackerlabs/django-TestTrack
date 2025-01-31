# #  product
import base64
import calendar as tcalendar
import logging
from collections import OrderedDict
from datetime import date, datetime, timedelta
from math import ceil

from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.contrib.postgres.aggregates import StringAgg
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DEFAULT_DB_ALIAS, connection
from django.db.models import Count, F, Max, OuterRef, Prefetch, Q, Subquery, Sum
from django.db.models.expressions import Value
from django.db.models.query import QuerySet
from django.http import Http404, HttpRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from github import Github

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization import user_has_permission, user_has_permission_or_403
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.components.sql_group_concat import Sql_GroupConcat
from dojo.filters import (
    EngagementFilter,
    EngagementFilterWithoutObjectLookups,
    MetricsEndpointFilter,
    MetricsEndpointFilterWithoutObjectLookups,
    MetricsFindingFilter,
    MetricsFindingFilterWithoutObjectLookups,
    ProductComponentFilter,
    ProductEngagementFilter,
    ProductEngagementFilterWithoutObjectLookups,
    ProductFilter,
    ProductFilterWithoutObjectLookups,
)
from dojo.forms import (
    Add_Product_GroupForm,
    Add_Product_MemberForm,
    AdHocFindingForm,
    AppAnalysisForm,
    Delete_Product_GroupForm,
    Delete_Product_MemberForm,
    DeleteAppAnalysisForm,
    DeleteEngagementPresetsForm,
    DeleteProduct_API_Scan_ConfigurationForm,
    DeleteProductForm,
    DojoMetaDataForm,
    Edit_Product_Group_Form,
    Edit_Product_MemberForm,
    EngagementPresetsForm,
    EngForm,
    GITHUB_Product_Form,
    GITHUBFindingForm,
    JIRAEngagementForm,
    JIRAFindingForm,
    JIRAProjectForm,
    Product_API_Scan_ConfigurationForm,
    ProductForm,
    ProductNotificationsForm,
    SLA_Configuration,
)
from dojo.models import (
    App_Analysis,
    Benchmark_Product_Summary,
    BurpRawRequestResponse,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Presets,
    Finding,
    GITHUB_PKey,
    Languages,
    Note_Type,
    Notifications,
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
    Product_Type,
    System_Settings,
    Test,
    Test_Type,
)
from dojo.product.queries import (
    get_authorized_global_groups_for_product,
    get_authorized_global_members_for_product,
    get_authorized_groups_for_product,
    get_authorized_members_for_product,
    get_authorized_products,
)
from dojo.product_type.queries import (
    get_authorized_groups_for_product_type,
    get_authorized_members_for_product_type,
    get_authorized_product_types,
)
from dojo.templatetags.display_tags import asvs_calc_level
from dojo.tool_config.factory import create_API
from dojo.tools.factory import get_api_scan_configuration_hints
from dojo.utils import (
    Product_Tab,
    add_breadcrumb,
    add_error_message_to_response,
    add_external_issue,
    add_field_errors_to_response,
    async_delete,
    calculate_finding_age,
    get_enabled_notifications_list,
    get_open_findings_burndown,
    get_page_items,
    get_punchcard_data,
    get_setting,
    get_system_setting,
    get_zero_severity_level,
    is_title_in_breadcrumbs,
    queryset_check,
    sum_by_severity_level,
)

logger = logging.getLogger(__name__)


def product(request):
    prods = get_authorized_products(Permissions.Product_View)
    # perform all stuff for filtering and pagination first, before annotation/prefetching
    # otherwise the paginator will perform all the annotations/prefetching already only to count the total number of records
    # see https://code.djangoproject.com/ticket/23771 and https://code.djangoproject.com/ticket/25375
    name_words = prods.values_list("name", flat=True)
    prods = prods.annotate(
        findings_count=Count("engagement__test__finding", filter=Q(engagement__test__finding__active=True)),
    )
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = ProductFilterWithoutObjectLookups if filter_string_matching else ProductFilter
    prod_filter = filter_class(request.GET, queryset=prods, user=request.user)
    prod_list = get_page_items(request, prod_filter.qs, 25)

    # perform annotation/prefetching by replacing the queryset in the page with an annotated/prefetched queryset.
    prod_list.object_list = prefetch_for_product(prod_list.object_list)

    add_breadcrumb(title=_("Product List"), top_level=not len(request.GET), request=request)

    return render(request, "dojo/product.html", {
        "prod_list": prod_list,
        "prod_filter": prod_filter,
        "name_words": sorted(set(name_words)),
        "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
        "user": request.user})


def prefetch_for_product(prods):
    prefetched_prods = prods
    if isinstance(prods,
                  QuerySet):  # old code can arrive here with prods being a list because the query was already executed

        prefetched_prods = prefetched_prods.prefetch_related("team_manager")
        prefetched_prods = prefetched_prods.prefetch_related("product_manager")
        prefetched_prods = prefetched_prods.prefetch_related("technical_contact")

        prefetched_prods = prefetched_prods.annotate(
            active_engagement_count=Count("engagement__id", filter=Q(engagement__active=True)))
        prefetched_prods = prefetched_prods.annotate(
            closed_engagement_count=Count("engagement__id", filter=Q(engagement__active=False)))
        prefetched_prods = prefetched_prods.annotate(last_engagement_date=Max("engagement__target_start"))
        prefetched_prods = prefetched_prods.annotate(active_finding_count=Count("engagement__test__finding__id",
                                                                                filter=Q(
                                                                                    engagement__test__finding__active=True)))
        prefetched_prods = prefetched_prods.annotate(
            active_verified_finding_count=Count("engagement__test__finding__id",
                                                filter=Q(
                                                    engagement__test__finding__active=True,
                                                    engagement__test__finding__verified=True)))
        prefetched_prods = prefetched_prods.prefetch_related("jira_project_set__jira_instance")
        prefetched_prods = prefetched_prods.prefetch_related("members")
        prefetched_prods = prefetched_prods.prefetch_related("prod_type__members")
        active_endpoint_query = Endpoint.objects.filter(
            status_endpoint__mitigated=False,
            status_endpoint__false_positive=False,
            status_endpoint__out_of_scope=False,
            status_endpoint__risk_accepted=False,
        ).distinct()
        prefetched_prods = prefetched_prods.prefetch_related(
            Prefetch("endpoint_set", queryset=active_endpoint_query, to_attr="active_endpoints"))
        prefetched_prods = prefetched_prods.prefetch_related("tags")

        if get_system_setting("enable_github"):
            prefetched_prods = prefetched_prods.prefetch_related(
                Prefetch("github_pkey_set", queryset=GITHUB_PKey.objects.all().select_related("git_conf"),
                         to_attr="github_confs"))

    else:
        logger.debug("unable to prefetch because query was already executed")

    return prefetched_prods


def iso_to_gregorian(iso_year, iso_week, iso_day):
    jan4 = date(iso_year, 1, 4)
    start = jan4 - timedelta(days=jan4.isoweekday() - 1)
    return start + timedelta(weeks=iso_week - 1, days=iso_day - 1)


@user_is_authorized(Product, Permissions.Product_View, "pid")
def view_product(request, pid):
    prod_query = Product.objects.all().select_related("product_manager", "technical_contact", "team_manager", "sla_configuration") \
                                      .prefetch_related("members") \
                                      .prefetch_related("prod_type__members")
    prod = get_object_or_404(prod_query, id=pid)
    product_members = get_authorized_members_for_product(prod, Permissions.Product_View)
    global_product_members = get_authorized_global_members_for_product(prod, Permissions.Product_View)
    product_type_members = get_authorized_members_for_product_type(prod.prod_type, Permissions.Product_Type_View)
    product_groups = get_authorized_groups_for_product(prod, Permissions.Product_View)
    global_product_groups = get_authorized_global_groups_for_product(prod, Permissions.Product_View)
    product_type_groups = get_authorized_groups_for_product_type(prod.prod_type, Permissions.Product_Type_View)
    personal_notifications_form = ProductNotificationsForm(
        instance=Notifications.objects.filter(user=request.user).filter(product=prod).first())
    langSummary = Languages.objects.filter(product=prod).aggregate(Sum("files"), Sum("code"), Count("files"))
    languages = Languages.objects.filter(product=prod).order_by("-code").select_related("language")
    app_analysis = App_Analysis.objects.filter(product=prod).order_by("name")
    benchmarks = Benchmark_Product_Summary.objects.filter(product=prod, publish=True,
                                                          benchmark_type__enabled=True).order_by("benchmark_type__name")
    sla = SLA_Configuration.objects.filter(id=prod.sla_configuration_id).first()
    benchAndPercent = []
    for i in range(len(benchmarks)):
        desired_level, total, total_pass, total_wait, total_fail, _total_viewed = asvs_calc_level(benchmarks[i])

        success_percent = round((float(total_pass) / float(total)) * 100, 2)
        waiting_percent = round((float(total_wait) / float(total)) * 100, 2)
        fail_percent = round(100 - success_percent - waiting_percent, 2)
        benchAndPercent.append({
            "id": benchmarks[i].benchmark_type.id,
            "name": benchmarks[i].benchmark_type,
            "level": desired_level,
            "success": {"count": total_pass, "percent": success_percent},
            "waiting": {"count": total_wait, "percent": waiting_percent},
            "fail": {"count": total_fail, "percent": fail_percent},
            "pass": total_pass + total_fail,
            "total": total,
        })
    system_settings = System_Settings.objects.get()

    product_metadata = dict(prod.product_meta.order_by("name").values_list("name", "value"))

    open_findings = Finding.objects.filter(test__engagement__product=prod,
                                           false_p=False,
                                           active=True,
                                           duplicate=False,
                                           out_of_scope=False).order_by("numerical_severity").values(
        "severity").annotate(count=Count("severity"))

    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0

    for v in open_findings:
        if v["severity"] == "Critical":
            critical = v["count"]
        elif v["severity"] == "High":
            high = v["count"]
        elif v["severity"] == "Medium":
            medium = v["count"]
        elif v["severity"] == "Low":
            low = v["count"]
        elif v["severity"] == "Info":
            info = v["count"]

    total = critical + high + medium + low + info

    product_tab = Product_Tab(prod, title=_("Product"), tab="overview")
    return render(request, "dojo/view_product_details.html", {
        "prod": prod,
        "product_tab": product_tab,
        "product_metadata": product_metadata,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "total": total,
        "user": request.user,
        "languages": languages,
        "langSummary": langSummary,
        "app_analysis": app_analysis,
        "system_settings": system_settings,
        "benchmarks_percents": benchAndPercent,
        "benchmarks": benchmarks,
        "product_members": product_members,
        "global_product_members": global_product_members,
        "product_type_members": product_type_members,
        "product_groups": product_groups,
        "global_product_groups": global_product_groups,
        "product_type_groups": product_type_groups,
        "personal_notifications_form": personal_notifications_form,
        "enabled_notifications": get_enabled_notifications_list(),
        "sla": sla})


@user_is_authorized(Product, Permissions.Component_View, "pid")
def view_product_components(request, pid):
    prod = get_object_or_404(Product, id=pid)
    product_tab = Product_Tab(prod, title=_("Product"), tab="components")
    separator = ", "

    # Get components ordered by component_name and concat component versions to the same row
    if connection.vendor == "postgresql":
        component_query = Finding.objects.filter(test__engagement__product__id=pid).values("component_name").order_by(
            "component_name").annotate(
            component_version=StringAgg("component_version", delimiter=separator, distinct=True, default=Value("")))
    else:
        component_query = Finding.objects.filter(test__engagement__product__id=pid).values("component_name")
        component_query = component_query.annotate(
            component_version=Sql_GroupConcat("component_version", separator=separator, distinct=True))

    # Append finding counts
    component_query = component_query.annotate(total=Count("id")).order_by("component_name", "component_version")
    component_query = component_query.annotate(active=Count("id", filter=Q(active=True)))
    component_query = component_query.annotate(duplicate=(Count("id", filter=Q(duplicate=True))))

    # Default sort by total descending
    component_query = component_query.order_by("-total")

    comp_filter = ProductComponentFilter(request.GET, queryset=component_query)
    result = get_page_items(request, comp_filter.qs, 25)

    # Filter out None values for auto-complete
    component_words = component_query.exclude(component_name__isnull=True).values_list("component_name", flat=True)

    return render(request, "dojo/product_components.html", {
        "prod": prod,
        "filter": comp_filter,
        "product_tab": product_tab,
        "result": result,
        "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
        "component_words": sorted(set(component_words)),
    })


def identify_view(request):
    get_data = request.GET
    view = get_data.get("type", None)
    if view:
        # value of view is reflected in the template, make sure it's valid
        # although any XSS should be catch by django autoescape, we see people sometimes using '|safe'...
        if view in ["Endpoint", "Finding"]:
            return view
        msg = 'invalid view, view must be "Endpoint" or "Finding"'
        raise ValueError(msg)
    if get_data.get("finding__severity", None) or get_data.get("false_positive", None):
        return "Endpoint"
    referer = request.META.get("HTTP_REFERER", None)
    if referer:
        if referer.find("type=Endpoint") > -1:
            return "Endpoint"
    return "Finding"


def finding_querys(request, prod):
    filters = {}
    findings_query = Finding.objects.filter(test__engagement__product=prod)
    # prefetch only what's needed to avoid lots of repeated queries
    findings_query = findings_query.prefetch_related(
        # 'test__engagement',
        # 'test__engagement__risk_acceptance',
        # 'found_by',
        # 'test',
        # 'test__test_type',
        # 'risk_acceptance_set',
        "reporter")
    filter_string_matching = get_system_setting("filter_string_matching", False)
    finding_filter_class = MetricsFindingFilterWithoutObjectLookups if filter_string_matching else MetricsFindingFilter
    findings = finding_filter_class(request.GET, queryset=findings_query, pid=prod)
    findings_qs = queryset_check(findings)
    filters["form"] = findings.form

    try:
        # logger.debug(findings_qs.query)
        start_date = findings_qs.earliest("date").date
        start_date = datetime(
            start_date.year,
            start_date.month, start_date.day,
            tzinfo=timezone.get_current_timezone())
        end_date = findings_qs.latest("date").date
        end_date = datetime(
            end_date.year,
            end_date.month, end_date.day,
            tzinfo=timezone.get_current_timezone())
    except Exception as e:
        logger.debug(e)
        start_date = timezone.now()
        end_date = timezone.now()
    week = end_date - timedelta(days=7)  # seven days and /newer are considered "new"

    filters["accepted"] = findings_qs.filter(finding_helper.ACCEPTED_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["verified"] = findings_qs.filter(finding_helper.VERIFIED_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["new_verified"] = findings_qs.filter(finding_helper.VERIFIED_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["open"] = findings_qs.filter(finding_helper.OPEN_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["inactive"] = findings_qs.filter(finding_helper.INACTIVE_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["closed"] = findings_qs.filter(finding_helper.CLOSED_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["false_positive"] = findings_qs.filter(finding_helper.FALSE_POSITIVE_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["out_of_scope"] = findings_qs.filter(finding_helper.OUT_OF_SCOPE_FINDINGS_QUERY).filter(date__range=[start_date, end_date]).order_by("date")
    filters["all"] = findings_qs.order_by("date")
    filters["open_vulns"] = findings_qs.filter(finding_helper.OPEN_FINDINGS_QUERY).filter(
        cwe__isnull=False,
    ).order_by("cwe").values(
        "cwe",
    ).annotate(
        count=Count("cwe"),
    )

    filters["all_vulns"] = findings_qs.filter(
        duplicate=False,
        cwe__isnull=False,
    ).order_by("cwe").values(
        "cwe",
    ).annotate(
        count=Count("cwe"),
    )

    filters["start_date"] = start_date
    filters["end_date"] = end_date
    filters["week"] = week

    return filters


def endpoint_querys(request, prod):
    filters = {}
    endpoints_query = Endpoint_Status.objects.filter(finding__test__engagement__product=prod,
                                                     finding__severity__in=(
                                                         "Critical", "High", "Medium", "Low", "Info")).prefetch_related(
        "finding__test__engagement",
        "finding__test__engagement__risk_acceptance",
        "finding__risk_acceptance_set",
        "finding__reporter").annotate(severity=F("finding__severity"))
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = MetricsEndpointFilterWithoutObjectLookups if filter_string_matching else MetricsEndpointFilter
    endpoints = filter_class(request.GET, queryset=endpoints_query)
    endpoints_qs = queryset_check(endpoints)
    filters["form"] = endpoints.form

    if not endpoints_qs and not endpoints_query:
        endpoints = endpoints_query
        endpoints_qs = queryset_check(endpoints)
        messages.add_message(request,
                             messages.ERROR,
                             _("All objects have been filtered away. Displaying all objects"),
                             extra_tags="alert-danger")

    try:
        start_date = endpoints_qs.earliest("date").date
        start_date = datetime(start_date.year,
                              start_date.month, start_date.day,
                              tzinfo=timezone.get_current_timezone())
        end_date = endpoints_qs.latest("date").date
        end_date = datetime(end_date.year,
                            end_date.month, end_date.day,
                            tzinfo=timezone.get_current_timezone())
    except:
        start_date = timezone.now()
        end_date = timezone.now()
    week = end_date - timedelta(days=7)  # seven days and /newnewer are considered "new"

    filters["accepted"] = endpoints_qs.filter(date__range=[start_date, end_date],
                                              risk_accepted=True).order_by("date")
    filters["verified"] = endpoints_qs.filter(date__range=[start_date, end_date],
                                              false_positive=False,
                                              mitigated=True,
                                              out_of_scope=False).order_by("date")
    filters["new_verified"] = endpoints_qs.filter(date__range=[week, end_date],
                                                  false_positive=False,
                                                  mitigated=True,
                                                  out_of_scope=False).order_by("date")
    filters["open"] = endpoints_qs.filter(date__range=[start_date, end_date],
                                          mitigated=False,
                                          finding__active=True)
    filters["inactive"] = endpoints_qs.filter(date__range=[start_date, end_date],
                                              mitigated=True)
    filters["closed"] = endpoints_qs.filter(date__range=[start_date, end_date],
                                            mitigated=True)
    filters["false_positive"] = endpoints_qs.filter(date__range=[start_date, end_date],
                                                    false_positive=True)
    filters["out_of_scope"] = endpoints_qs.filter(date__range=[start_date, end_date],
                                                  out_of_scope=True)
    filters["all"] = endpoints_qs
    filters["open_vulns"] = endpoints_qs.filter(
        false_positive=False,
        out_of_scope=False,
        mitigated=True,
        finding__cwe__isnull=False,
    ).order_by("finding__cwe").values(
        "finding__cwe",
    ).annotate(
        count=Count("finding__cwe"),
    ).annotate(
        cwe=F("finding__cwe"),
    )

    filters["all_vulns"] = endpoints_qs.filter(
        finding__cwe__isnull=False,
    ).order_by("finding__cwe").values(
        "finding__cwe",
    ).annotate(
        count=Count("finding__cwe"),
    ).annotate(
        cwe=F("finding__cwe"),
    )

    filters["start_date"] = start_date
    filters["end_date"] = end_date
    filters["week"] = week

    return filters


@user_is_authorized(Product, Permissions.Product_View, "pid")
def view_product_metrics(request, pid):
    prod = get_object_or_404(Product, id=pid)
    engs = Engagement.objects.filter(product=prod, active=True)
    view = identify_view(request)

    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = EngagementFilterWithoutObjectLookups if filter_string_matching else EngagementFilter
    result = filter_class(
        request.GET,
        queryset=Engagement.objects.filter(product=prod, active=False).order_by("-target_end"))

    inactive_engs_page = get_page_items(request, result.qs, 10)

    filters = {}
    if view == "Finding":
        filters = finding_querys(request, prod)
    elif view == "Endpoint":
        filters = endpoint_querys(request, prod)

    start_date = timezone.make_aware(datetime.combine(filters["start_date"], datetime.min.time()))
    end_date = filters["end_date"]

    r = relativedelta(end_date, start_date)
    weeks_between = ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7))
    if weeks_between <= 0:
        weeks_between += 2

    punchcard, ticks = get_punchcard_data(filters.get("open", None), start_date, weeks_between, view)

    add_breadcrumb(parent=prod, top_level=False, request=request)

    # An ordered dict does not make sense here.
    open_close_weekly = OrderedDict()
    severity_weekly = OrderedDict()
    critical_weekly = OrderedDict()
    high_weekly = OrderedDict()
    medium_weekly = OrderedDict()
    open_objs_by_age = {}

    open_objs_by_severity = get_zero_severity_level()
    closed_objs_by_severity = get_zero_severity_level()
    accepted_objs_by_severity = get_zero_severity_level()

    # Optimization: Make all queries lists, and only pull values of fields for metrics based calculations
    open_vulnerabilities = list(filters["open_vulns"].values("cwe", "count"))
    all_vulnerabilities = list(filters["all_vulns"].values("cwe", "count"))

    verified_objs_by_severity = list(filters.get("verified").values("severity"))
    inactive_objs_by_severity = list(filters.get("inactive").values("severity"))
    false_positive_objs_by_severity = list(filters.get("false_positive").values("severity"))
    out_of_scope_objs_by_severity = list(filters.get("out_of_scope").values("severity"))
    new_objs_by_severity = list(filters.get("new_verified").values("severity"))
    all_objs_by_severity = list(filters.get("all").values("severity"))

    all_findings = list(filters.get("all", []).values("id", "date", "severity"))
    open_findings = list(filters.get("open", []).values("id", "date", "mitigated", "severity"))
    closed_findings = list(filters.get("closed", []).values("id", "date", "severity"))
    accepted_findings = list(filters.get("accepted", []).values("id", "date", "severity"))

    """
        Optimization: Create dictionaries in the structure of { finding_id: True } for index based search
        Previously the for-loop below used "if finding in open_findings" -- an average O(n^2) time complexity
        This allows for "if open_findings.get(finding_id, None)" -- an average O(n) time complexity
    """
    open_findings_dict = {f.get("id"): True for f in open_findings}
    closed_findings_dict = {f.get("id"): True for f in closed_findings}
    accepted_findings_dict = {f.get("id"): True for f in accepted_findings}

    for finding in all_findings:
        iso_cal = finding.get("date").isocalendar()
        date = iso_to_gregorian(iso_cal[0], iso_cal[1], 1)
        html_date = date.strftime("<span class='small'>%m/%d<br/>%Y</span>")
        unix_timestamp = (tcalendar.timegm(date.timetuple()) * 1000)

        # Open findings
        if open_findings_dict.get(finding.get("id", None)):
            if unix_timestamp not in critical_weekly:
                critical_weekly[unix_timestamp] = {"count": 0, "week": html_date}
            if unix_timestamp not in high_weekly:
                high_weekly[unix_timestamp] = {"count": 0, "week": html_date}
            if unix_timestamp not in medium_weekly:
                medium_weekly[unix_timestamp] = {"count": 0, "week": html_date}

            if unix_timestamp in open_close_weekly:
                open_close_weekly[unix_timestamp]["open"] += 1
            else:
                open_close_weekly[unix_timestamp] = {"closed": 0, "open": 1, "accepted": 0}
                open_close_weekly[unix_timestamp]["week"] = html_date

            if view == "Finding" or view == "Endpoint":
                severity = finding.get("severity")

            finding_age = calculate_finding_age(finding)
            if open_objs_by_age.get(finding_age):
                open_objs_by_age[finding_age] += 1
            else:
                open_objs_by_age[finding_age] = 1

            if unix_timestamp in severity_weekly:
                if severity in severity_weekly[unix_timestamp]:
                    severity_weekly[unix_timestamp][severity] += 1
                else:
                    severity_weekly[unix_timestamp][severity] = 1
            else:
                severity_weekly[unix_timestamp] = get_zero_severity_level()
                severity_weekly[unix_timestamp][severity] = 1
                severity_weekly[unix_timestamp]["week"] = html_date

            if severity == "Critical":
                if unix_timestamp in critical_weekly:
                    critical_weekly[unix_timestamp]["count"] += 1
                else:
                    critical_weekly[unix_timestamp] = {"count": 1, "week": html_date}
            elif severity == "High":
                if unix_timestamp in high_weekly:
                    high_weekly[unix_timestamp]["count"] += 1
                else:
                    high_weekly[unix_timestamp] = {"count": 1, "week": html_date}
            elif severity == "Medium":
                if unix_timestamp in medium_weekly:
                    medium_weekly[unix_timestamp]["count"] += 1
                else:
                    medium_weekly[unix_timestamp] = {"count": 1, "week": html_date}
            # Optimization: count severity level on server side
            if open_objs_by_severity.get(finding.get("severity")) is not None:
                open_objs_by_severity[finding.get("severity")] += 1

        # Close findings
        elif closed_findings_dict.get(finding.get("id", None)):
            if unix_timestamp in open_close_weekly:
                open_close_weekly[unix_timestamp]["closed"] += 1
            else:
                open_close_weekly[unix_timestamp] = {"closed": 1, "open": 0, "accepted": 0}
                open_close_weekly[unix_timestamp]["week"] = html_date
            # Optimization: count severity level on server side
            if closed_objs_by_severity.get(finding.get("severity")) is not None:
                closed_objs_by_severity[finding.get("severity")] += 1

        # Risk Accepted findings
        if accepted_findings_dict.get(finding.get("id", None)):
            if unix_timestamp in open_close_weekly:
                open_close_weekly[unix_timestamp]["accepted"] += 1
            else:
                open_close_weekly[unix_timestamp] = {"closed": 0, "open": 0, "accepted": 1}
                open_close_weekly[unix_timestamp]["week"] = html_date
            # Optimization: count severity level on server side
            if accepted_objs_by_severity.get(finding.get("severity")) is not None:
                accepted_objs_by_severity[finding.get("severity")] += 1

    tests = Test.objects.filter(engagement__product=prod).prefetch_related("finding_set", "test_type")
    tests = tests.annotate(verified_finding_count=Count("finding__id", filter=Q(finding__verified=True)))

    test_data = {}
    for t in tests:
        if t.test_type.name in test_data:
            test_data[t.test_type.name] += t.verified_finding_count
        else:
            test_data[t.test_type.name] = t.verified_finding_count

    # Optimization: Format Open/Total CWE vulnerabilities graph data here, instead of template
    open_vulnerabilities = [["CWE-" + str(f.get("cwe")), f.get("count")] for f in open_vulnerabilities]
    all_vulnerabilities = [["CWE-" + str(f.get("cwe")), f.get("count")] for f in all_vulnerabilities]

    product_tab = Product_Tab(prod, title=_("Product"), tab="metrics")

    return render(request, "dojo/product_metrics.html", {
        "prod": prod,
        "product_tab": product_tab,
        "engs": engs,
        "inactive_engs": inactive_engs_page,
        "view": view,
        "verified_objs": len(verified_objs_by_severity),
        "verified_objs_by_severity": sum_by_severity_level(verified_objs_by_severity),
        "open_objs": len(open_findings),
        "open_objs_by_severity": open_objs_by_severity,
        "open_objs_by_age": open_objs_by_age,
        "inactive_objs": len(inactive_objs_by_severity),
        "inactive_objs_by_severity": sum_by_severity_level(inactive_objs_by_severity),
        "closed_objs": len(closed_findings),
        "closed_objs_by_severity": closed_objs_by_severity,
        "false_positive_objs": len(false_positive_objs_by_severity),
        "false_positive_objs_by_severity": sum_by_severity_level(false_positive_objs_by_severity),
        "out_of_scope_objs": len(out_of_scope_objs_by_severity),
        "out_of_scope_objs_by_severity": sum_by_severity_level(out_of_scope_objs_by_severity),
        "accepted_objs": len(accepted_findings),
        "accepted_objs_by_severity": accepted_objs_by_severity,
        "new_objs": len(new_objs_by_severity),
        "new_objs_by_severity": sum_by_severity_level(new_objs_by_severity),
        "all_objs": len(all_objs_by_severity),
        "all_objs_by_severity": sum_by_severity_level(all_objs_by_severity),
        "form": filters.get("form", None),
        "reset_link": reverse("view_product_metrics", args=(prod.id,)) + "?type=" + view,
        "open_vulnerabilities_count": len(open_vulnerabilities),
        "open_vulnerabilities": open_vulnerabilities,
        "all_vulnerabilities_count": len(all_vulnerabilities),
        "all_vulnerabilities": all_vulnerabilities,
        "start_date": start_date,
        "punchcard": punchcard,
        "ticks": ticks,
        "open_close_weekly": open_close_weekly,
        "severity_weekly": severity_weekly,
        "critical_weekly": critical_weekly,
        "high_weekly": high_weekly,
        "medium_weekly": medium_weekly,
        "test_data": test_data,
        "user": request.user})


@user_is_authorized(Product, Permissions.Product_View, "pid")
def async_burndown_metrics(request, pid):
    prod = get_object_or_404(Product, id=pid)
    open_findings_burndown = get_open_findings_burndown(prod)

    return JsonResponse({
        "critical": open_findings_burndown.get("Critical", []),
        "high": open_findings_burndown.get("High", []),
        "medium": open_findings_burndown.get("Medium", []),
        "low": open_findings_burndown.get("Low", []),
        "info": open_findings_burndown.get("Info", []),
        "max": open_findings_burndown.get("y_max", 0),
        "min": open_findings_burndown.get("y_min", 0),
    })


@user_is_authorized(Product, Permissions.Engagement_View, "pid")
def view_engagements(request, pid):
    prod = get_object_or_404(Product, id=pid)
    default_page_num = 10
    recent_test_day_count = 7
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = ProductEngagementFilterWithoutObjectLookups if filter_string_matching else ProductEngagementFilter
    # In Progress Engagements
    engs = Engagement.objects.filter(product=prod, active=True, status="In Progress").order_by("-updated")
    active_engs_filter = filter_class(request.GET, queryset=engs, prefix="active")
    result_active_engs = get_page_items(request, active_engs_filter.qs, default_page_num, prefix="engs")
    # prefetch only after creating the filters to avoid https://code.djangoproject.com/ticket/23771
    # and https://code.djangoproject.com/ticket/25375
    result_active_engs.object_list = prefetch_for_view_engagements(
        result_active_engs.object_list,
        recent_test_day_count,
    )
    # Engagements that are queued because they haven't started or paused
    engs = Engagement.objects.filter(~Q(status="In Progress"), product=prod, active=True).order_by("-updated")
    queued_engs_filter = filter_class(request.GET, queryset=engs, prefix="queued")
    result_queued_engs = get_page_items(request, queued_engs_filter.qs, default_page_num, prefix="queued_engs")
    result_queued_engs.object_list = prefetch_for_view_engagements(
        result_queued_engs.object_list,
        recent_test_day_count,
    )
    # Cancelled or Completed Engagements
    engs = Engagement.objects.filter(product=prod, active=False).order_by("-target_end")
    inactive_engs_filter = filter_class(request.GET, queryset=engs, prefix="closed")
    result_inactive_engs = get_page_items(request, inactive_engs_filter.qs, default_page_num, prefix="inactive_engs")
    result_inactive_engs.object_list = prefetch_for_view_engagements(
        result_inactive_engs.object_list,
        recent_test_day_count,
    )

    product_tab = Product_Tab(prod, title=_("All Engagements"), tab="engagements")
    return render(request, "dojo/view_engagements.html", {
        "prod": prod,
        "product_tab": product_tab,
        "engs": result_active_engs,
        "engs_count": result_active_engs.paginator.count,
        "engs_filter": active_engs_filter,
        "queued_engs": result_queued_engs,
        "queued_engs_count": result_queued_engs.paginator.count,
        "queued_engs_filter": queued_engs_filter,
        "inactive_engs": result_inactive_engs,
        "inactive_engs_count": result_inactive_engs.paginator.count,
        "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
        "inactive_engs_filter": inactive_engs_filter,
        "recent_test_day_count": recent_test_day_count,
        "user": request.user})


def prefetch_for_view_engagements(engagements, recent_test_day_count):
    engagements = engagements.select_related(
        "lead",
    ).prefetch_related(
        Prefetch("test_set", queryset=Test.objects.filter(
            id__in=Subquery(
                Test.objects.filter(
                    engagement_id=OuterRef("engagement_id"),
                    updated__gte=timezone.now() - timedelta(days=recent_test_day_count),
                ).values_list("id", flat=True),
            )),
                 ),
        "test_set__test_type",
    ).annotate(
        count_tests=Count("test", distinct=True),
        count_findings_all=Count("test__finding__id"),
        count_findings_open=Count("test__finding__id", filter=Q(test__finding__active=True)),
        count_findings_open_verified=Count("test__finding__id",
                                           filter=Q(test__finding__active=True) & Q(test__finding__verified=True)),
        count_findings_close=Count("test__finding__id", filter=Q(test__finding__is_mitigated=True)),
        count_findings_duplicate=Count("test__finding__id", filter=Q(test__finding__duplicate=True)),
        count_findings_accepted=Count("test__finding__id", filter=Q(test__finding__risk_accepted=True)),
    )

    if System_Settings.objects.get().enable_jira:
        engagements = engagements.prefetch_related(
            "jira_project__jira_instance",
            "product__jira_project_set__jira_instance",
        )

    return engagements


# Authorization is within the import_scan_results method
def import_scan_results_prod(request, pid=None):
    from dojo.engagement.views import import_scan_results
    return import_scan_results(request, pid=pid)


def new_product(request, ptid=None):
    if get_authorized_product_types(Permissions.Product_Type_Add_Product).count() == 0:
        raise PermissionDenied

    jira_project_form = None
    error = False
    initial = None
    if ptid is not None:
        prod_type = get_object_or_404(Product_Type, pk=ptid)
        initial = {"prod_type": prod_type}

    form = ProductForm(initial=initial)

    if request.method == "POST":
        form = ProductForm(request.POST, instance=Product())

        if get_system_setting("enable_github"):
            gform = GITHUB_Product_Form(request.POST, instance=GITHUB_PKey())
        else:
            gform = None

        if form.is_valid():
            product_type = form.instance.prod_type
            user_has_permission_or_403(request.user, product_type, Permissions.Product_Type_Add_Product)

            product = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Product added successfully."),
                                 extra_tags="alert-success")
            success, jira_project_form = jira_helper.process_jira_project_form(request, product=product)
            error = not success

            if get_system_setting("enable_github"):
                if gform.is_valid():
                    github_pkey = gform.save(commit=False)
                    if github_pkey.git_conf is not None and github_pkey.git_project:
                        github_pkey.product = product
                        github_pkey.save()
                        messages.add_message(request,
                                             messages.SUCCESS,
                                             _("GitHub information added successfully."),
                                             extra_tags="alert-success")
                        # Create appropriate labels in the repo
                        logger.info("Create label in repo: " + github_pkey.git_project)

                        description = _("This label is automatically applied to all issues created by DefectDojo")
                        try:
                            g = Github(github_pkey.git_conf.api_key)
                            repo = g.get_repo(github_pkey.git_project)
                            repo.create_label(name="security", color="FF0000",
                                              description=description)
                            repo.create_label(name="security / info", color="00FEFC",
                                              description=description)
                            repo.create_label(name="security / low", color="B7FE00",
                                              description=description)
                            repo.create_label(name="security / medium", color="FEFE00",
                                              description=description)
                            repo.create_label(name="security / high", color="FE9A00",
                                              description=description)
                            repo.create_label(name="security / critical", color="FE2200",
                                              description=description)
                        except:
                            logger.info("Labels cannot be created - they may already exists")

            if not error:
                return HttpResponseRedirect(reverse("view_product", args=(product.id,)))
            # engagement was saved, but JIRA errors, so goto edit_product
            return HttpResponseRedirect(reverse("edit_product", args=(product.id,)))
    else:
        if get_system_setting("enable_jira"):
            jira_project_form = JIRAProjectForm()

        gform = GITHUB_Product_Form() if get_system_setting("enable_github") else None

    add_breadcrumb(title=_("New Product"), top_level=False, request=request)
    return render(request, "dojo/new_product.html",
                  {"form": form,
                   "jform": jira_project_form,
                   "gform": gform})


@user_is_authorized(Product, Permissions.Product_Edit, "pid")
def edit_product(request, pid):
    product = Product.objects.get(pk=pid)
    system_settings = System_Settings.objects.get()
    jira_enabled = system_settings.enable_jira
    jira_project = None
    jform = None
    github_enabled = system_settings.enable_github
    github_inst = None
    gform = None
    error = False

    try:
        github_inst = GITHUB_PKey.objects.get(product=product)
    except:
        github_inst = None

    if request.method == "POST":
        form = ProductForm(request.POST, instance=product)
        jira_project = jira_helper.get_jira_project(product)
        if form.is_valid():
            initial_sla_config = Product.objects.get(pk=form.instance.id).sla_configuration
            form.save()
            msg = "Product updated successfully."
            # check if the SLA config was changed, append additional context to message
            if initial_sla_config != form.instance.sla_configuration:
                msg += " All SLA expiration dates for findings within this product will be recalculated asynchronously for the newly assigned SLA configuration."
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _(msg),
                                 extra_tags="alert-success")

            success, jform = jira_helper.process_jira_project_form(request, instance=jira_project, product=product)
            error = not success

            if get_system_setting("enable_github") and github_inst:
                gform = GITHUB_Product_Form(request.POST, instance=github_inst)
                if gform.is_valid():
                    gform.save()
            elif get_system_setting("enable_github"):
                gform = GITHUB_Product_Form(request.POST)
                if gform.is_valid():
                    new_conf = gform.save(commit=False)
                    new_conf.product_id = pid
                    new_conf.save()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         _("GITHUB information updated successfully."),
                                         extra_tags="alert-success")

            if not error:
                return HttpResponseRedirect(reverse("view_product", args=(pid,)))
    else:
        form = ProductForm(instance=product)

        if jira_enabled:
            jira_project = jira_helper.get_jira_project(product)
            jform = JIRAProjectForm(instance=jira_project)
        else:
            jform = None

        if github_enabled:
            gform = GITHUB_Product_Form(instance=github_inst) if github_inst is not None else GITHUB_Product_Form()
        else:
            gform = None

    product_tab = Product_Tab(product, title=_("Edit Product"), tab="settings")
    return render(request,
                  "dojo/edit_product.html",
                  {"form": form,
                   "product_tab": product_tab,
                   "jform": jform,
                   "gform": gform,
                   "product": product,
                   })


@user_is_authorized(Product, Permissions.Product_Delete, "pid")
def delete_product(request, pid):
    product = get_object_or_404(Product, pk=pid)
    form = DeleteProductForm(instance=product)

    if request.method == "POST":
        logger.debug("delete_product: POST")
        if "id" in request.POST and str(product.id) == request.POST["id"]:
            form = DeleteProductForm(request.POST, instance=product)
            if form.is_valid():
                if get_setting("ASYNC_OBJECT_DELETE"):
                    async_del = async_delete()
                    async_del.delete(product)
                    message = _("Product and relationships will be removed in the background.")
                else:
                    message = _("Product and relationships removed.")
                    product.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags="alert-success")
                logger.debug("delete_product: POST RETURN")
                return HttpResponseRedirect(reverse("product"))
            logger.debug("delete_product: POST INVALID FORM")
            logger.error(form.errors)

    logger.debug("delete_product: GET")

    rels = ["Previewing the relationships has been disabled.", ""]
    display_preview = get_setting("DELETE_PREVIEW")
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([product])
        rels = collector.nested()

    product_tab = Product_Tab(product, title=_("Product"), tab="settings")

    logger.debug("delete_product: GET RENDER")

    return render(request, "dojo/delete_product.html", {
        "product": product,
        "form": form,
        "product_tab": product_tab,
        "rels": rels})


@user_is_authorized(Product, Permissions.Engagement_Add, "pid")
def new_eng_for_app(request, pid, cicd=False):
    jira_project_form = None
    jira_epic_form = None

    product = Product.objects.get(id=pid)

    if request.method == "POST":
        form = EngForm(request.POST, cicd=cicd, product=product, user=request.user)
        logger.debug("new_eng_for_app")

        if form.is_valid():
            # first create the new engagement
            engagement = form.save(commit=False)
            engagement.threat_model = False
            engagement.api_test = False
            engagement.pen_test = False
            engagement.check_list = False
            engagement.product = form.cleaned_data.get("product")
            if engagement.threat_model:
                engagement.progress = "threat_model"
            else:
                engagement.progress = "other"
            if cicd:
                engagement.engagement_type = "CI/CD"
                engagement.status = "In Progress"
            engagement.active = True

            engagement.save()
            form.save_m2m()

            logger.debug("new_eng_for_app: process jira coming")

            # new engagement, so do not provide jira_project
            success, jira_project_form = jira_helper.process_jira_project_form(request, instance=None,
                                                                               engagement=engagement)
            error = not success

            logger.debug("new_eng_for_app: process jira epic coming")

            success, jira_epic_form = jira_helper.process_jira_epic_form(request, engagement=engagement)
            error = error or not success

            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Engagement added successfully."),
                                 extra_tags="alert-success")

            if not error:
                if "_Add Tests" in request.POST:
                    return HttpResponseRedirect(reverse("add_tests", args=(engagement.id,)))
                if "_Import Scan Results" in request.POST:
                    return HttpResponseRedirect(reverse("import_scan_results", args=(engagement.id,)))
                return HttpResponseRedirect(reverse("view_engagement", args=(engagement.id,)))
            # engagement was saved, but JIRA errors, so goto edit_engagement
            logger.debug("new_eng_for_app: jira errors")
            return HttpResponseRedirect(reverse("edit_engagement", args=(engagement.id,)))
        logger.debug(form.errors)
    else:
        form = EngForm(initial={"lead": request.user, "target_start": timezone.now().date(),
                                "target_end": timezone.now().date() + timedelta(days=7), "product": product}, cicd=cicd,
                       product=product, user=request.user)

        if get_system_setting("enable_jira"):
            logger.debug("showing jira-project-form")
            jira_project_form = JIRAProjectForm(target="engagement", product=product)
            logger.debug("showing jira-epic-form")
            jira_epic_form = JIRAEngagementForm()

    title = _("New CI/CD Engagement") if cicd else _("New Interactive Engagement")

    product_tab = Product_Tab(product, title=title, tab="engagements")
    return render(request, "dojo/new_eng.html", {
        "form": form,
        "title": title,
        "product_tab": product_tab,
        "jira_epic_form": jira_epic_form,
        "jira_project_form": jira_project_form})


@user_is_authorized(Product, Permissions.Technology_Add, "pid")
def new_tech_for_prod(request, pid):
    if request.method == "POST":
        form = AppAnalysisForm(request.POST)
        if form.is_valid():
            tech = form.save(commit=False)
            tech.product_id = pid
            tech.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Technology added successfully."),
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("view_product", args=(pid,)))

    form = AppAnalysisForm(initial={"user": request.user})
    product_tab = Product_Tab(get_object_or_404(Product, id=pid), title=_("Add Technology"), tab="settings")
    return render(request, "dojo/new_tech.html",
                  {"form": form,
                   "product_tab": product_tab,
                   "pid": pid})


@user_is_authorized(App_Analysis, Permissions.Technology_Edit, "tid")
def edit_technology(request, tid):
    technology = get_object_or_404(App_Analysis, id=tid)
    form = AppAnalysisForm(instance=technology)
    if request.method == "POST":
        form = AppAnalysisForm(request.POST, instance=technology)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Technology changed successfully."),
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("view_product", args=(technology.product.id,)))

    product_tab = Product_Tab(technology.product, title=_("Edit Technology"), tab="settings")
    return render(request, "dojo/edit_technology.html",
                  {"form": form,
                   "product_tab": product_tab,
                   "technology": technology})


@user_is_authorized(App_Analysis, Permissions.Technology_Delete, "tid")
def delete_technology(request, tid):
    technology = get_object_or_404(App_Analysis, id=tid)
    form = DeleteAppAnalysisForm(instance=technology)
    if request.method == "POST":
        form = Delete_Product_MemberForm(request.POST, instance=technology)
        technology = form.instance
        technology.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _("Technology deleted successfully."),
                             extra_tags="alert-success")
        return HttpResponseRedirect(reverse("view_product", args=(technology.product.id,)))

    product_tab = Product_Tab(technology.product, title=_("Delete Technology"), tab="settings")
    return render(request, "dojo/delete_technology.html", {
        "technology": technology,
        "form": form,
        "product_tab": product_tab,
    })


@user_is_authorized(Product, Permissions.Engagement_Add, "pid")
def new_eng_for_app_cicd(request, pid):
    # we have to use pid=pid here as new_eng_for_app expects kwargs, because that is how django calls the function based on urls.py named groups
    return new_eng_for_app(request, pid=pid, cicd=True)


@user_is_authorized(Product, Permissions.Product_Edit, "pid")
def add_meta_data(request, pid):
    prod = Product.objects.get(id=pid)
    if request.method == "POST":
        form = DojoMetaDataForm(request.POST, instance=DojoMeta(product=prod))
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Metadata added successfully."),
                                 extra_tags="alert-success")
            if "add_another" in request.POST:
                return HttpResponseRedirect(reverse("add_meta_data", args=(pid,)))
            return HttpResponseRedirect(reverse("view_product", args=(pid,)))
    else:
        form = DojoMetaDataForm()

    product_tab = Product_Tab(prod, title=_("Add Metadata"), tab="settings")

    return render(request, "dojo/add_product_meta_data.html",
                  {"form": form,
                   "product_tab": product_tab,
                   "product": prod,
                   })


@user_is_authorized(Product, Permissions.Product_Edit, "pid")
def edit_meta_data(request, pid):
    prod = Product.objects.get(id=pid)
    if request.method == "POST":
        for key, orig_value in request.POST.items():
            if key.startswith("cfv_"):
                cfv_id = int(key.split("_")[1])
                cfv = get_object_or_404(DojoMeta, id=cfv_id)
                value = orig_value.strip()
                if value:
                    cfv.value = value
                    cfv.save()
            if key.startswith("delete_"):
                cfv_id = int(key.split("_")[2])
                cfv = get_object_or_404(DojoMeta, id=cfv_id)
                cfv.delete()

        messages.add_message(request,
                             messages.SUCCESS,
                             _("Metadata edited successfully."),
                             extra_tags="alert-success")
        return HttpResponseRedirect(reverse("view_product", args=(pid,)))

    product_tab = Product_Tab(prod, title=_("Edit Metadata"), tab="settings")
    return render(request, "dojo/edit_product_meta_data.html",
                  {"product": prod,
                   "product_tab": product_tab,
                   })


class AdHocFindingView(View):
    def get_product(self, product_id: int):
        return get_object_or_404(Product, id=product_id)

    def get_test_type(self):
        test_type, _nil = Test_Type.objects.get_or_create(name=_("Pen Test"))
        return test_type

    def get_engagement(self, product: Product):
        try:
            return Engagement.objects.get(product=product, name=_("Ad Hoc Engagement"))
        except Engagement.DoesNotExist:
            return Engagement.objects.create(
                name=_("Ad Hoc Engagement"),
                target_start=timezone.now(),
                target_end=timezone.now(),
                active=False, product=product)

    def get_test(self, engagement: Engagement, test_type: Test_Type):
        if test := Test.objects.filter(engagement=engagement).first():
            return test
        return Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now())

    def create_nested_objects(self, product: Product):
        engagement = self.get_engagement(product)
        test_type = self.get_test_type()
        return self.get_test(engagement, test_type)

    def get_initial_context(self, request: HttpRequest, test: Test):
        # Get the finding form first since it is used in another place
        finding_form = self.get_finding_form(request, test.engagement.product)
        product_tab = Product_Tab(test.engagement.product, title=_("Add Finding"), tab="engagements")
        product_tab.setEngagement(test.engagement)
        return {
            "form": finding_form,
            "product_tab": product_tab,
            "temp": False,
            "tid": test.id,
            "pid": test.engagement.product.id,
            "form_error": False,
            "jform": self.get_jira_form(request, test, finding_form=finding_form),
            "gform": self.get_github_form(request, test),
        }

    def get_finding_form(self, request: HttpRequest, product: Product):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "initial": {"date": timezone.now().date()},
            "req_resp": None,
            "product": product,
        }
        # Remove the initial state on post
        if request.method == "POST":
            kwargs.pop("initial")

        return AdHocFindingForm(*args, **kwargs)

    def get_jira_form(self, request: HttpRequest, test: Test, finding_form: AdHocFindingForm = None):
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

    def get_github_form(self, request: HttpRequest, test: Test):
        # Determine if github should be used
        if get_system_setting("enable_github"):
            # Ensure there is a github conf correctly configured for the product
            config_present = GITHUB_PKey.objects.filter(product=test.engagement.product)
            if config_present := config_present.exclude(git_conf_id=None):
                # Set up the args for the form
                args = [request.POST] if request.method == "POST" else []
                # Set the initial form args
                kwargs = {
                    "enabled": jira_helper.is_push_all_issues(test),
                    "prefix": "githubform",
                }

                return GITHUBFindingForm(*args, **kwargs)
        return None

    def validate_status_change(self, request: HttpRequest, context: dict):
        if ((context["form"]["active"].value() is False
             or context["form"]["false_p"].value())
             and context["form"]["duplicate"].value() is False):

            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _("Can not set a finding as inactive without adding all mandatory notes"),
                    code="inactive_without_mandatory_notes",
                )
                error_false_p = ValidationError(
                    _("Can not set a finding as false positive without adding all mandatory notes"),
                    code="false_p_without_mandatory_notes",
                )
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
            # Push to Jira?
            logger.debug("jira form valid")
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
                    logger.debug(
                        "finding has no jira issue yet, but jira issue specified in request. trying to link.")
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

    def process_github_form(self, request: HttpRequest, finding: Finding, context: dict):
        if "githubform-push_to_github" not in request.POST:
            return request, True

        if context["gform"].is_valid():
            add_external_issue(finding, "github")

            return request, True
        add_field_errors_to_response(context["gform"])

        return request, False

    def process_forms(self, request: HttpRequest, test: Test, context: dict):
        form_success_list = []
        # Set vars for the completed forms
        # Validate finding mitigation
        request = self.validate_status_change(request, context)
        # Check the validity of the form overall
        finding, request, success = self.process_finding_form(request, test, context)
        form_success_list.append(success)
        request, success, push_to_jira = self.process_jira_form(request, finding, context)
        form_success_list.append(success)
        request, success = self.process_github_form(request, finding, context)
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
            # Add a success message
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Finding added successfully."),
                extra_tags="alert-success")

        return finding, request, all_forms_valid

    def get_template(self):
        return "dojo/ad_hoc_findings.html"

    def get(self, request: HttpRequest, product_id: int):
        # Get the initial objects
        product = self.get_product(product_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, product, Permissions.Finding_Add)
        # Create the necessary nested objects
        test = self.create_nested_objects(product)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, product_id: int):
        # Get the initial objects
        product = self.get_product(product_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, product, Permissions.Finding_Add)
        # Create the necessary nested objects
        test = self.create_nested_objects(product)
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


@user_is_authorized(Product, Permissions.Product_View, "pid")
def engagement_presets(request, pid):
    prod = get_object_or_404(Product, id=pid)
    presets = Engagement_Presets.objects.filter(product=prod).all()

    product_tab = Product_Tab(prod, title=_("Engagement Presets"), tab="settings")

    return render(request, "dojo/view_presets.html",
                  {"product_tab": product_tab,
                   "presets": presets,
                   "prod": prod})


@user_is_authorized(Product, Permissions.Product_Edit, "pid")
def edit_engagement_presets(request, pid, eid):
    prod = get_object_or_404(Product, id=pid)
    preset = get_object_or_404(Engagement_Presets, id=eid)

    product_tab = Product_Tab(prod, title=_("Edit Engagement Preset"), tab="settings")

    if request.method == "POST":
        tform = EngagementPresetsForm(request.POST, instance=preset)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Engagement Preset Successfully Updated."),
                extra_tags="alert-success")
            return HttpResponseRedirect(reverse("engagement_presets", args=(pid,)))
    else:
        tform = EngagementPresetsForm(instance=preset)

    return render(request, "dojo/edit_presets.html",
                  {"product_tab": product_tab,
                   "tform": tform,
                   "prod": prod})


@user_is_authorized(Product, Permissions.Product_Edit, "pid")
def add_engagement_presets(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == "POST":
        tform = EngagementPresetsForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.product = prod
            form_copy.save()
            tform.save_m2m()
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Engagement Preset Successfully Created."),
                extra_tags="alert-success")
            return HttpResponseRedirect(reverse("engagement_presets", args=(pid,)))
    else:
        tform = EngagementPresetsForm()

    product_tab = Product_Tab(prod, title=_("New Engagement Preset"), tab="settings")
    return render(request, "dojo/new_params.html", {"tform": tform, "pid": pid, "product_tab": product_tab})


@user_is_authorized(Product, Permissions.Product_Edit, "pid")
def delete_engagement_presets(request, pid, eid):
    prod = get_object_or_404(Product, id=pid)
    preset = get_object_or_404(Engagement_Presets, id=eid)
    form = DeleteEngagementPresetsForm(instance=preset)

    if request.method == "POST":
        if "id" in request.POST:
            form = DeleteEngagementPresetsForm(request.POST, instance=preset)
            if form.is_valid():
                preset.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _("Engagement presets and engagement relationships removed."),
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("engagement_presets", args=(pid,)))

    rels = ["Previewing the relationships has been disabled.", ""]
    display_preview = get_setting("DELETE_PREVIEW")
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([preset])
        rels = collector.nested()

    product_tab = Product_Tab(prod, title=_("Delete Engagement Preset"), tab="settings")
    return render(request, "dojo/delete_presets.html",
                  {"product": product,
                   "form": form,
                   "product_tab": product_tab,
                   "rels": rels,
                   })


@user_is_authorized(Product, Permissions.Product_View, "pid")
def edit_notifications(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == "POST":
        product_notifications = Notifications.objects.filter(user=request.user).filter(product=prod).first()
        if not product_notifications:
            product_notifications = Notifications(user=request.user, product=prod)
            logger.debug("no existing product notifications found")
        else:
            logger.debug("existing product notifications found")

        form = ProductNotificationsForm(request.POST, instance=product_notifications)

        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Notification settings updated."),
                                 extra_tags="alert-success")

    return HttpResponseRedirect(reverse("view_product", args=(pid,)))


@user_is_authorized(Product, Permissions.Product_Manage_Members, "pid")
def add_product_member(request, pid):
    product = get_object_or_404(Product, pk=pid)
    memberform = Add_Product_MemberForm(initial={"product": product.id})
    if request.method == "POST":
        memberform = Add_Product_MemberForm(request.POST, initial={"product": product.id})
        if memberform.is_valid():
            if memberform.cleaned_data["role"].is_owner and not user_has_permission(request.user, product,
                                                                                    Permissions.Product_Member_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _("You are not permitted to add users as owners."),
                                     extra_tags="alert-warning")
            else:
                if "users" in memberform.cleaned_data and len(memberform.cleaned_data["users"]) > 0:
                    for user in memberform.cleaned_data["users"]:
                        existing_members = Product_Member.objects.filter(product=product, user=user)
                        if existing_members.count() == 0:
                            product_member = Product_Member()
                            product_member.product = product
                            product_member.user = user
                            product_member.role = memberform.cleaned_data["role"]
                            product_member.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _("Product members added successfully."),
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("view_product", args=(pid,)))
    product_tab = Product_Tab(product, title=_("Add Product Member"), tab="settings")
    return render(request, "dojo/new_product_member.html", {
        "product": product,
        "form": memberform,
        "product_tab": product_tab,
    })


@user_is_authorized(Product_Member, Permissions.Product_Manage_Members, "memberid")
def edit_product_member(request, memberid):
    member = get_object_or_404(Product_Member, pk=memberid)
    memberform = Edit_Product_MemberForm(instance=member)
    if request.method == "POST":
        memberform = Edit_Product_MemberForm(request.POST, instance=member)
        if memberform.is_valid():
            if member.role.is_owner and not user_has_permission(request.user, member.product,
                                                                Permissions.Product_Member_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _("You are not permitted to make users to owners."),
                                     extra_tags="alert-warning")
            else:
                memberform.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _("Product member updated successfully."),
                                     extra_tags="alert-success")
                if is_title_in_breadcrumbs("View User"):
                    return HttpResponseRedirect(reverse("view_user", args=(member.user.id,)))
                return HttpResponseRedirect(reverse("view_product", args=(member.product.id,)))
    product_tab = Product_Tab(member.product, title=_("Edit Product Member"), tab="settings")
    return render(request, "dojo/edit_product_member.html", {
        "memberid": memberid,
        "form": memberform,
        "product_tab": product_tab,
    })


@user_is_authorized(Product_Member, Permissions.Product_Member_Delete, "memberid")
def delete_product_member(request, memberid):
    member = get_object_or_404(Product_Member, pk=memberid)
    memberform = Delete_Product_MemberForm(instance=member)
    if request.method == "POST":
        memberform = Delete_Product_MemberForm(request.POST, instance=member)
        member = memberform.instance
        user = member.user
        member.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _("Product member deleted successfully."),
                             extra_tags="alert-success")
        if is_title_in_breadcrumbs("View User"):
            return HttpResponseRedirect(reverse("view_user", args=(member.user.id,)))
        if user == request.user:
            return HttpResponseRedirect(reverse("product"))
        return HttpResponseRedirect(reverse("view_product", args=(member.product.id,)))
    product_tab = Product_Tab(member.product, title=_("Delete Product Member"), tab="settings")
    return render(request, "dojo/delete_product_member.html", {
        "memberid": memberid,
        "form": memberform,
        "product_tab": product_tab,
    })


@user_is_authorized(Product, Permissions.Product_API_Scan_Configuration_Add, "pid")
def add_api_scan_configuration(request, pid):
    product = get_object_or_404(Product, id=pid)
    if request.method == "POST":
        form = Product_API_Scan_ConfigurationForm(request.POST)
        if form.is_valid():
            product_api_scan_configuration = form.save(commit=False)
            product_api_scan_configuration.product = product
            try:
                api = create_API(product_api_scan_configuration.tool_configuration)
                if api and hasattr(api, "test_product_connection"):
                    result = api.test_product_connection(product_api_scan_configuration)
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         _("API connection successful with message: %(result)s.") % {"result": result},
                                         extra_tags="alert-success")
                product_api_scan_configuration.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _("API Scan Configuration added successfully."),
                                     extra_tags="alert-success")
                if "add_another" in request.POST:
                    return HttpResponseRedirect(reverse("add_api_scan_configuration", args=(pid,)))
                return HttpResponseRedirect(reverse("view_api_scan_configurations", args=(pid,)))
            except Exception as e:
                logger.exception("Unable to add API Scan Configuration")
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags="alert-danger")
    else:
        form = Product_API_Scan_ConfigurationForm()

    product_tab = Product_Tab(product, title=_("Add API Scan Configuration"), tab="settings")

    return render(request,
                  "dojo/add_product_api_scan_configuration.html",
                  {"form": form,
                   "product_tab": product_tab,
                   "product": product,
                   "api_scan_configuration_hints": get_api_scan_configuration_hints(),
                   })


@user_is_authorized(Product, Permissions.Product_View, "pid")
def view_api_scan_configurations(request, pid):
    product_api_scan_configurations = Product_API_Scan_Configuration.objects.filter(product=pid)

    product_tab = Product_Tab(get_object_or_404(Product, id=pid), title=_("API Scan Configurations"), tab="settings")
    return render(request,
                  "dojo/view_product_api_scan_configurations.html",
                  {
                      "product_api_scan_configurations": product_api_scan_configurations,
                      "product_tab": product_tab,
                      "pid": pid,
                  })


@user_is_authorized(Product_API_Scan_Configuration, Permissions.Product_API_Scan_Configuration_Edit, "pascid")
def edit_api_scan_configuration(request, pid, pascid):
    product_api_scan_configuration = get_object_or_404(Product_API_Scan_Configuration, id=pascid)

    if product_api_scan_configuration.product.pk != int(
            pid):  # user is trying to edit Tool Configuration from another product (trying to by-pass auth)
        raise Http404

    if request.method == "POST":
        form = Product_API_Scan_ConfigurationForm(request.POST, instance=product_api_scan_configuration)
        if form.is_valid():
            try:
                form_copy = form.save(commit=False)
                api = create_API(form_copy.tool_configuration)
                if api and hasattr(api, "test_product_connection"):
                    result = api.test_product_connection(form_copy)
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         _("API connection successful with message: %(result)s.") % {"result": result},
                                         extra_tags="alert-success")
                form.save()

                messages.add_message(request,
                                     messages.SUCCESS,
                                     _("API Scan Configuration successfully updated."),
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("view_api_scan_configurations", args=(pid,)))
            except Exception as e:
                logger.info(e)
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags="alert-danger")
    else:
        form = Product_API_Scan_ConfigurationForm(instance=product_api_scan_configuration)

    product_tab = Product_Tab(get_object_or_404(Product, id=pid), title=_("Edit API Scan Configuration"), tab="settings")
    return render(request,
                  "dojo/edit_product_api_scan_configuration.html",
                  {
                      "form": form,
                      "product_tab": product_tab,
                      "api_scan_configuration_hints": get_api_scan_configuration_hints(),
                  })


@user_is_authorized(Product_API_Scan_Configuration, Permissions.Product_API_Scan_Configuration_Delete, "pascid")
def delete_api_scan_configuration(request, pid, pascid):
    product_api_scan_configuration = get_object_or_404(Product_API_Scan_Configuration, id=pascid)

    if product_api_scan_configuration.product.pk != int(
            pid):  # user is trying to delete Tool Configuration from another product (trying to by-pass auth)
        raise Http404

    if request.method == "POST":
        form = Product_API_Scan_ConfigurationForm(request.POST)
        product_api_scan_configuration.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _("API Scan Configuration deleted."),
                             extra_tags="alert-success")
        return HttpResponseRedirect(reverse("view_api_scan_configurations", args=(pid,)))
    form = DeleteProduct_API_Scan_ConfigurationForm(instance=product_api_scan_configuration)

    product_tab = Product_Tab(get_object_or_404(Product, id=pid), title=_("Delete Tool Configuration"), tab="settings")
    return render(request,
                  "dojo/delete_product_api_scan_configuration.html",
                  {
                      "form": form,
                      "product_tab": product_tab,
                  })


@user_is_authorized(Product_Group, Permissions.Product_Group_Edit, "groupid")
def edit_product_group(request, groupid):
    logger.exception(groupid)
    group = get_object_or_404(Product_Group, pk=groupid)
    groupform = Edit_Product_Group_Form(instance=group)

    if request.method == "POST":
        groupform = Edit_Product_Group_Form(request.POST, instance=group)
        if groupform.is_valid():
            if group.role.is_owner and not user_has_permission(request.user, group.product,
                                                               Permissions.Product_Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _("You are not permitted to make groups owners."),
                                     extra_tags="alert-warning")
            else:
                groupform.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _("Product group updated successfully."),
                                     extra_tags="alert-success")
                if is_title_in_breadcrumbs("View Group"):
                    return HttpResponseRedirect(reverse("view_group", args=(group.group.id,)))
                return HttpResponseRedirect(reverse("view_product", args=(group.product.id,)))

    product_tab = Product_Tab(group.product, title=_("Edit Product Group"), tab="settings")
    return render(request, "dojo/edit_product_group.html", {
        "groupid": groupid,
        "form": groupform,
        "product_tab": product_tab,
    })


@user_is_authorized(Product_Group, Permissions.Product_Group_Delete, "groupid")
def delete_product_group(request, groupid):
    group = get_object_or_404(Product_Group, pk=groupid)
    groupform = Delete_Product_GroupForm(instance=group)

    if request.method == "POST":
        groupform = Delete_Product_GroupForm(request.POST, instance=group)
        group = groupform.instance
        group.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _("Product group deleted successfully."),
                             extra_tags="alert-success")
        if is_title_in_breadcrumbs("View Group"):
            return HttpResponseRedirect(reverse("view_group", args=(group.group.id,)))
        # TODO: If user was in the group that was deleted and no longer has access, redirect back to product listing
        #  page
        return HttpResponseRedirect(reverse("view_product", args=(group.product.id,)))

    product_tab = Product_Tab(group.product, title=_("Delete Product Group"), tab="settings")
    return render(request, "dojo/delete_product_group.html", {
        "groupid": groupid,
        "form": groupform,
        "product_tab": product_tab,
    })


@user_is_authorized(Product, Permissions.Product_Group_Add, "pid")
def add_product_group(request, pid):
    product = get_object_or_404(Product, pk=pid)
    group_form = Add_Product_GroupForm(initial={"product": product.id})

    if request.method == "POST":
        group_form = Add_Product_GroupForm(request.POST, initial={"product": product.id})
        if group_form.is_valid():
            if group_form.cleaned_data["role"].is_owner and not user_has_permission(request.user, product,
                                                                                    Permissions.Product_Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _("You are not permitted to add groups as owners."),
                                     extra_tags="alert-warning")
            else:
                if "groups" in group_form.cleaned_data and len(group_form.cleaned_data["groups"]) > 0:
                    for group in group_form.cleaned_data["groups"]:
                        groups = Product_Group.objects.filter(product=product, group=group)
                        if groups.count() == 0:
                            product_group = Product_Group()
                            product_group.product = product
                            product_group.group = group
                            product_group.role = group_form.cleaned_data["role"]
                            product_group.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _("Product groups added successfully."),
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("view_product", args=(pid,)))
    product_tab = Product_Tab(product, title=_("Edit Product Group"), tab="settings")
    return render(request, "dojo/new_product_group.html", {
        "product": product,
        "form": group_form,
        "product_tab": product_tab,
    })
