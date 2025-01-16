
import operator
from collections.abc import Callable
from datetime import date, datetime, timedelta
from enum import Enum
from functools import partial
from typing import Any, NamedTuple, TypeVar

from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.db.models import Case, Count, F, IntegerField, Q, Sum, Value, When
from django.db.models.functions import Coalesce, ExtractDay, Now, TruncMonth, TruncWeek
from django.db.models.query import QuerySet
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext as _

from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.queries import get_authorized_endpoint_status
from dojo.filters import (
    MetricsEndpointFilter,
    MetricsEndpointFilterWithoutObjectLookups,
    MetricsFindingFilter,
    MetricsFindingFilterWithoutObjectLookups,
)
from dojo.finding.helper import ACCEPTED_FINDINGS_QUERY, CLOSED_FINDINGS_QUERY, OPEN_FINDINGS_QUERY
from dojo.finding.queries import get_authorized_findings
from dojo.models import Endpoint_Status, Finding, Product_Type
from dojo.product.queries import get_authorized_products
from dojo.utils import (
    get_system_setting,
    queryset_check,
)


def get_metrics_finding_filter_class() -> type[MetricsFindingFilter | MetricsFindingFilterWithoutObjectLookups]:
    if get_system_setting("filter_string_matching", False):
        return MetricsFindingFilterWithoutObjectLookups
    return MetricsFindingFilter


def finding_queries(
    prod_type: QuerySet[Product_Type],
    request: HttpRequest,
) -> dict[str, Any]:
    # Get the initial list of findings the user is authorized to see
    all_authorized_findings: QuerySet[Finding] = get_authorized_findings(
        Permissions.Finding_View,
        user=request.user,
    ).select_related(
        "reporter",
        "test",
        "test__engagement__product",
        "test__engagement__product__prod_type",
    ).prefetch_related(
        "risk_acceptance_set",
        "test__engagement__risk_acceptance",
        "test__test_type",
    )

    finding_filter_class = get_metrics_finding_filter_class()
    findings_filter = finding_filter_class(request.GET, queryset=all_authorized_findings)
    form = findings_filter.form
    filtered_findings: QuerySet[Finding] = queryset_check(findings_filter)
    # Quick check to determine if the filters were too tight and filtered everything away. If so, fall back to using all
    # authorized Findings instead.
    if not filtered_findings.exists() and all_authorized_findings.exists():
        filtered_findings = all_authorized_findings
        messages.add_message(
            request,
            messages.ERROR,
            _("All objects have been filtered away. Displaying all objects"),
            extra_tags="alert-danger")

    start_date, end_date = get_date_range(filtered_findings)

    # Filter by the date ranges supplied
    all_findings_within_date_range = all_authorized_findings.filter(date__range=[start_date, end_date])
    # Get the list of closed and risk accepted findings
    closed_filtered_findings = all_findings_within_date_range.filter(CLOSED_FINDINGS_QUERY)
    accepted_filtered_findings = all_findings_within_date_range.filter(ACCEPTED_FINDINGS_QUERY)
    active_filtered_findings = all_findings_within_date_range.filter(OPEN_FINDINGS_QUERY)

    # filter by product type if applicable
    if len(prod_type) > 0:
        all_findings_within_date_range = all_findings_within_date_range.filter(
            test__engagement__product__prod_type__in=prod_type)
        closed_filtered_findings = closed_filtered_findings.filter(test__engagement__product__prod_type__in=prod_type)
        accepted_filtered_findings = accepted_filtered_findings.filter(
            test__engagement__product__prod_type__in=prod_type)
        active_filtered_findings = active_filtered_findings.filter(test__engagement__product__prod_type__in=prod_type)

    # Get the severity counts of risk accepted findings
    accepted_findings_counts = severity_count(accepted_filtered_findings, "aggregate", "severity")

    weeks_between, months_between = period_deltas(start_date, end_date)

    query_counts_for_period = query_counts(
        all_findings_within_date_range,
        active_filtered_findings,
        accepted_filtered_findings,
        start_date,
        MetricsType.FINDING,
    )

    monthly_counts = query_counts_for_period(MetricsPeriod.MONTH, months_between)
    weekly_counts = query_counts_for_period(MetricsPeriod.WEEK, weeks_between)

    top_ten = get_authorized_products(Permissions.Product_View)
    if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
        top_ten = top_ten.filter(engagement__test__finding__verified=True)

    top_ten = top_ten.filter(engagement__test__finding__false_p=False,
                             engagement__test__finding__duplicate=False,
                             engagement__test__finding__out_of_scope=False,
                             engagement__test__finding__mitigated__isnull=True,
                             engagement__test__finding__severity__in=("Critical", "High", "Medium", "Low"),
                             prod_type__in=prod_type)

    top_ten = severity_count(
        top_ten, "annotate", "engagement__test__finding__severity",
    ).order_by(
        "-critical", "-high", "-medium", "-low",
    )[:10]

    return {
        "all": filtered_findings,
        "closed": closed_filtered_findings,
        "accepted": accepted_filtered_findings,
        "accepted_count": accepted_findings_counts,
        "top_ten": top_ten,
        "monthly_counts": monthly_counts,
        "weekly_counts": weekly_counts,
        "weeks_between": weeks_between,
        "start_date": start_date,
        "end_date": end_date,
        "form": form,
    }


def endpoint_queries(
    prod_type: QuerySet[Product_Type],
    request: HttpRequest,
) -> dict[str, Any]:
    endpoints_query = Endpoint_Status.objects.filter(
        mitigated=False,
        finding__severity__in=("Critical", "High", "Medium", "Low", "Info"),
    ).prefetch_related(
        "finding__test__engagement__product",
        "finding__test__engagement__product__prod_type",
        "finding__test__engagement__risk_acceptance",
        "finding__risk_acceptance_set",
        "finding__reporter",
    )

    endpoints_query = get_authorized_endpoint_status(Permissions.Endpoint_View, endpoints_query, request.user)
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = MetricsEndpointFilterWithoutObjectLookups if filter_string_matching else MetricsEndpointFilter
    endpoints = filter_class(request.GET, queryset=endpoints_query)
    form = endpoints.form
    endpoints_qs = queryset_check(endpoints)

    if not endpoints_qs.exists():
        endpoints = endpoints_query
        endpoints_qs = endpoints if isinstance(endpoints, QuerySet) else endpoints.qs
        messages.add_message(
            request,
            messages.ERROR,
            _("All objects have been filtered away. Displaying all objects"),
            extra_tags="alert-danger")

    start_date, end_date = get_date_range(endpoints_qs)

    if len(prod_type) > 0:
        endpoints_closed = Endpoint_Status.objects.filter(
            mitigated_time__range=[start_date, end_date],
            finding__test__engagement__product__prod_type__in=prod_type,
        ).prefetch_related(
            "finding__test__engagement__product",
        )
        # capture the accepted findings in period
        accepted_endpoints = Endpoint_Status.objects.filter(
            date__range=[start_date, end_date],
            risk_accepted=True,
            finding__test__engagement__product__prod_type__in=prod_type,
        ).prefetch_related(
            "finding__test__engagement__product",
        )
    else:
        endpoints_closed = Endpoint_Status.objects.filter(
            mitigated_time__range=[start_date, end_date],
        ).prefetch_related(
            "finding__test__engagement__product",
        )
        # capture the accepted findings in period
        accepted_endpoints = Endpoint_Status.objects.filter(
            date__range=[start_date, end_date],
            risk_accepted=True,
        ).prefetch_related(
            "finding__test__engagement__product",
        )

    endpoints_closed = get_authorized_endpoint_status(Permissions.Endpoint_View, endpoints_closed, request.user)
    accepted_endpoints = get_authorized_endpoint_status(Permissions.Endpoint_View, accepted_endpoints, request.user)
    accepted_endpoints_counts = severity_count(accepted_endpoints, "aggregate", "finding__severity")

    weeks_between, months_between = period_deltas(start_date, end_date)

    query_counts_for_period = query_counts(
        endpoints_qs,
        endpoints_qs.filter(finding__active=True),
        accepted_endpoints,
        start_date,
        MetricsType.ENDPOINT,
    )

    monthly_counts = query_counts_for_period(MetricsPeriod.MONTH, months_between)
    weekly_counts = query_counts_for_period(MetricsPeriod.WEEK, weeks_between)

    top_ten = get_authorized_products(Permissions.Product_View)
    top_ten = top_ten.filter(engagement__test__finding__status_finding__mitigated=False,
                             engagement__test__finding__status_finding__false_positive=False,
                             engagement__test__finding__status_finding__out_of_scope=False,
                             engagement__test__finding__status_finding__risk_accepted=False,
                             engagement__test__finding__severity__in=("Critical", "High", "Medium", "Low"),
                             prod_type__in=prod_type)

    top_ten = severity_count(
        top_ten, "annotate", "engagement__test__finding__severity",
    ).order_by(
        "-critical", "-high", "-medium", "-low",
    )[:10]

    return {
        "all": endpoints,
        "closed": endpoints_closed,
        "accepted": accepted_endpoints,
        "accepted_count": accepted_endpoints_counts,
        "top_ten": top_ten,
        "monthly_counts": monthly_counts,
        "weekly_counts": weekly_counts,
        "weeks_between": weeks_between,
        "start_date": start_date,
        "end_date": end_date,
        "form": form,
    }


# For type-hinting methods that take querysets we can perform metrics over
MetricsQuerySet = TypeVar("MetricsQuerySet", QuerySet[Finding], QuerySet[Endpoint_Status])


class _MetricsPeriodEntry(NamedTuple):

    """
    Class for holding information for a metrics period. Allows us to store a kwarg for date manipulation alongside a DB
    method used to aggregate around the same timeframe.
    """

    datetime_name: str
    db_method: TruncWeek | TruncMonth


class MetricsPeriod(_MetricsPeriodEntry, Enum):

    """Enum for the two metrics periods supported: by week and month"""

    WEEK = ("weeks", TruncWeek)
    MONTH = ("months", TruncMonth)


class _MetricsTypeEntry(NamedTuple):

    """
    Class for holding information for a metrics type. Allows us to store relative queryset lookups for severities
    alongside relative lookups for closed statuses.
    """

    severity_lookup: str
    closed_lookup: str


class MetricsType(_MetricsTypeEntry, Enum):

    """Enum for the two metrics types supported: by Findings and by Endpoints (Endpoint_Status)"""

    FINDING = ("severity", "is_mitigated")
    ENDPOINT = ("finding__severity", "mitigated")


def query_counts(
    open_qs: MetricsQuerySet,
    active_qs: MetricsQuerySet,
    accepted_qs: MetricsQuerySet,
    start_date: date,
    metrics_type: MetricsType,
) -> Callable[[MetricsPeriod, int], dict[str, list[dict]]]:
    """
    Given three QuerySets, a start date, and a MetricsType, returns a method that can be used to generate statistics for
    the three QuerySets across a given period. In use, simplifies gathering monthly and weekly aggregates for QuerySets.

    :param open_qs: QuerySet for open findings/endpoints
    :param active_qs: QuerySet for active findings/endpoints
    :param accepted_qs: QuerySet for accepted findings/endpoints
    :param start_date: The start date for statistics generation
    :param metrics_type: The type of metrics to generate statistics for
    :return: A method that takes period information to generate statistics for the given QuerySets
    """
    def _aggregates_for_period(period: MetricsPeriod, period_count: int) -> dict[str, list[dict]]:
        def _aggregate_data(qs: MetricsQuerySet, *, include_closed: bool = False) -> list[dict]:
            chart_data = partial(get_charting_data, start_date=start_date, period=period, period_count=period_count)
            agg_qs = partial(aggregate_counts_by_period, period=period, metrics_type=metrics_type)
            return chart_data(agg_qs(qs, include_closed=include_closed), include_closed=include_closed)
        return {
            "opened_per_period": _aggregate_data(open_qs, include_closed=True),
            "active_per_period": _aggregate_data(active_qs),
            "accepted_per_period": _aggregate_data(accepted_qs),
        }
    return _aggregates_for_period


def get_date_range(
    qs: QuerySet,
) -> tuple[datetime, datetime]:
    """
    Given a queryset of objects, returns a tuple of (earliest date, latest date) from among those objects, based on the
    objects' 'date' attribute. On exception, return a tuple representing (now, now).

    :param qs: The queryset of objects
    :return: A tuple of (earliest date, latest date)
    """
    try:
        tz = timezone.get_current_timezone()

        start_date = qs.earliest("date").date
        start_date = datetime(start_date.year, start_date.month, start_date.day, tzinfo=tz)

        end_date = qs.latest("date").date
        end_date = datetime(end_date.year, end_date.month, end_date.day, tzinfo=tz)
    except:
        start_date = end_date = timezone.now()

    return start_date, end_date


def severity_count(
    queryset: MetricsQuerySet,
    method: str,
    expression: str,
) -> MetricsQuerySet | dict[str, int]:
    """
    Aggregates counts by severity for the given queryset.

    :param queryset: The queryset to aggregate
    :param method: The method to use for aggregation, either 'annotate' or 'aggregate' depending on use case.
    :param expression: The lookup expression for severity, relative to the queryset model type
    :return: A queryset containing aggregated counts of severities
    """
    total_expression = expression + "__in"
    return getattr(queryset, method)(
        total=Count("id", filter=Q(**{total_expression: ("Critical", "High", "Medium", "Low", "Info")})),
        critical=Count("id", filter=Q(**{expression: "Critical"})),
        high=Count("id", filter=Q(**{expression: "High"})),
        medium=Count("id", filter=Q(**{expression: "Medium"})),
        low=Count("id", filter=Q(**{expression: "Low"})),
        info=Count("id", filter=Q(**{expression: "Info"})),
    )


def identify_view(
    request: HttpRequest,
) -> str:
    """
    Identifies the requested metrics view.

    :param request: The request object
    :return: A string, either 'Endpoint' or 'Finding,' that represents the requested metrics view
    """
    get_data = request.GET
    view = get_data.get("type", None)
    if view:
        return view

    finding_severity = get_data.get("finding__severity", None)
    false_positive = get_data.get("false_positive", None)

    referer = request.META.get("HTTP_REFERER", None)
    endpoint_in_referer = referer and referer.find("type=Endpoint") > -1

    if finding_severity or false_positive or endpoint_in_referer:
        return "Endpoint"

    return "Finding"


def js_epoch(
    d: date | datetime,
) -> int:
    """
    Converts a date/datetime object to a JavaScript epoch time (for use in FE charts)

    :param d: The date or datetime object
    :return: The js epoch time (milliseconds since the epoch)
    """
    if isinstance(d, date):
        d = datetime.combine(d, datetime.min.time())
    return int(d.timestamp()) * 1000


def get_charting_data(
    qs: MetricsQuerySet,
    start_date: date,
    period: MetricsPeriod,
    period_count: int,
    *,
    include_closed: bool,
) -> list[dict]:
    """
    Given a queryset of severities data for charting, adds epoch timestamp information and fills in missing data points
    queryset aggregation didn't include (because the data didn't exist) with zero-element data, all useful for frontend
    chart rendering. Returns a list of these dictionaries, sorted by date ascending.

    :param qs: The query set
    :param start_date: The start date
    :param period: A MetricsPeriod to generate charting data across
    :param period_count: The number of periods we should have data for
    :param include_closed: A boolean dictating whether 'closed' finding/status aggregates should be included
    :return: A list of dictionaries representing data points for charting, sorted by date
    """
    tz = timezone.get_current_timezone()

    # Calculate the start date for our data. This will depend on whether we're generating for months or weeks.
    if period == MetricsPeriod.WEEK:
        # For weeks, start at the first day of the specified week
        start_date = datetime(start_date.year, start_date.month, start_date.day, tzinfo=tz)
        start_date = start_date + timedelta(days=-start_date.weekday())
    else:
        # For months, start on the first day of the month
        start_date = datetime(start_date.year, start_date.month, 1, tzinfo=tz)

    # Arrange all our data by epoch date for easy lookup in the loop below.
    # At the same time, add the epoch date to each entry as the charts will rely on that.
    by_date = {e: {"epoch": e, **q} for q in qs if (e := js_epoch(q["grouped_date"])) is not None}

    # Iterate over our period of time, adding zero-element data entries for dates not represented
    for x in range(-1, period_count):
        cur_date = start_date + relativedelta(**{period.datetime_name: x})
        if (e := js_epoch(cur_date)) not in by_date:
            by_date[e] = {
                "epoch": e, "grouped_date": cur_date.date(),
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            if include_closed:
                by_date[e]["closed"] = 0

    # Return, sorting by date
    return sorted(by_date.values(), key=operator.itemgetter("grouped_date"))


def period_deltas(start_date, end_date):
    """
    Given a start date and end date, returns a tuple of (weeks between the dates, months between the dates).

    :param start_date: The start date to consider
    :param end_date: The end date to consider
    :return: A tuple of integers representing (number of weeks between the dates, number of months between the dates)
    """
    r = relativedelta(end_date, start_date)
    months_between = max((r.years * 12) + r.months, 2)
    weeks_between = max((end_date - start_date).days // 7, 2)
    return weeks_between, months_between


def aggregate_counts_by_period(
    qs: MetricsQuerySet,
    period: MetricsPeriod,
    metrics_type: MetricsType,
    *,
    include_closed: bool,
) -> QuerySet:
    """
    Annotates the given queryset with severity counts, grouping by desired period as defined by the specified
    trunc_method. Optionally includes a sum of closed findings/statuses as well.

    :param qs: The queryset to annotate with aggregate severity counts, either of Findings or Endpoint_Statuses
    :param period: A MetricsPeriod to aggregate across
    :param metrics_type: The type of metrics to generate statistics for
    :param include_closed: A boolean dictating whether 'closed' finding/status aggregates should be included
    :return: A queryset with aggregate severity counts grouped by period
    """
    desired_values = ("grouped_date", "critical", "high", "medium", "low", "info", "total")

    severities_by_period = severity_count(
        # Group by desired period
        qs.annotate(grouped_date=period.db_method("date")).values("grouped_date"),
        "annotate",
        metrics_type.severity_lookup,
    )
    if include_closed:
        severities_by_period = severities_by_period.annotate(
            # Include 'closed' counts
            closed=Sum(Case(
                When(Q(**{metrics_type.closed_lookup: True}), then=Value(1)),
                output_field=IntegerField(), default=0),
            ),
        )
        desired_values += ("closed",)

    return severities_by_period.order_by("grouped_date").values(*desired_values)


def findings_by_product(
    findings: QuerySet[Finding],
) -> QuerySet[Finding]:
    """
    Groups the given Findings queryset around related product (name/ID)

    :param findings: A queryset of Findings
    :return: A queryset of Findings grouped by product (name/ID)
    """
    return findings.values(product_name=F("test__engagement__product__name"),
                           product_id=F("test__engagement__product__id"))


def get_in_period_details(
    findings: QuerySet[Finding],
) -> tuple[QuerySet[Finding], QuerySet[Finding], dict[str, int]]:
    """
    Gathers details for the given queryset, corresponding to metrics information for 'in period' Findings

    :param findings: A queryset of Findings
    :return: A tuple of (a queryset of severity aggregates, a queryset of severity aggregates by product, a dict of
        Findings by age)
    """
    in_period_counts = severity_count(findings, "aggregate", "severity")
    in_period_details = severity_count(
        findings_by_product(findings), "annotate", "severity",
    ).order_by("product_name")

    # Approach to age determination is db-engine dependent
    age_detail = findings.annotate(age=ExtractDay(Coalesce("mitigated", Now()) - F("date")))
    age_detail = age_detail.aggregate(
        age_under_30=Sum(Case(When(age__lte=30, then=Value(1))), default=Value(0), output_field=IntegerField()),
        age_31_60=Sum(Case(When(age__range=[31, 60], then=Value(1))), default=Value(0), output_field=IntegerField()),
        age_61_90=Sum(Case(When(age__range=[61, 90], then=Value(1))), default=Value(0), output_field=IntegerField()),
        age_90_plus=Sum(Case(When(age__gt=90, then=Value(1))), default=Value(0), output_field=IntegerField()),
    )

    return in_period_counts, in_period_details, age_detail


def get_accepted_in_period_details(
    findings: QuerySet[Finding],
) -> QuerySet[Finding]:
    """
    Gathers details for the given queryset, corresponding to metrics information for 'accepted' Findings

    :param findings: A queryset of Findings
    :return: A queryset of severity aggregates for Findings grouped by product (name/ID)
    """
    return severity_count(
        findings_by_product(findings), "annotate", "severity",
    ).order_by("product_name")


def get_closed_in_period_details(
    findings: QuerySet[Finding],
) -> tuple[QuerySet[Finding], QuerySet[Finding]]:
    """
    Gathers details for the given queryset, corresponding to metrics information for 'closed' Findings

    :param findings: A queryset of Findings
    :return: A tuple of (a queryset of severity aggregates, a queryset of severity aggregates for Findings grouped by
        product)
    """
    return (
        severity_count(findings, "aggregate", "severity"),
        severity_count(
            findings_by_product(findings), "annotate", "severity",
        ).order_by("product_name"),
    )


def findings_queryset(
    qs: MetricsQuerySet,
) -> QuerySet[Finding]:
    """
    Given a MetricsQuerySet, returns a QuerySet representing all its findings.

    :param qs: MetricsQuerySet (A queryset of either Findings or Endpoint_Statuses)
    :return: A queryset of Findings, related to the given queryset
    """
    if qs.model is Endpoint_Status:
        return Finding.objects.filter(status_finding__in=qs)
    return qs
