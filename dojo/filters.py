import collections
import decimal
import logging
import warnings
from datetime import datetime, timedelta

import pytz
import six
import tagulous
from auditlog.models import LogEntry
from django import forms
from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models import JSONField, Q
from django.forms import HiddenInput
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_filters import (
    BooleanFilter,
    CharFilter,
    DateFilter,
    DateFromToRangeFilter,
    DateTimeFilter,
    FilterSet,
    ModelChoiceFilter,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
    NumberFilter,
    OrderingFilter,
    RangeFilter,
)
from django_filters import rest_framework as filters
from django_filters.filters import ChoiceFilter, _truncate
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from polymorphic.base import ManagerInheritanceWarning

# from tagulous.forms import TagWidget
# import tagulous
from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.queries import get_authorized_endpoints
from dojo.engagement.queries import get_authorized_engagements
from dojo.finding.helper import (
    ACCEPTED_FINDINGS_QUERY,
    CLOSED_FINDINGS_QUERY,
    FALSE_POSITIVE_FINDINGS_QUERY,
    INACTIVE_FINDINGS_QUERY,
    NOT_ACCEPTED_FINDINGS_QUERY,
    OPEN_FINDINGS_QUERY,
    OUT_OF_SCOPE_FINDINGS_QUERY,
    UNDER_REVIEW_QUERY,
    VERIFIED_FINDINGS_QUERY,
    WAS_ACCEPTED_FINDINGS_QUERY,
)
from dojo.finding.queries import get_authorized_findings
from dojo.finding_group.queries import get_authorized_finding_groups
from dojo.models import (
    EFFORT_FOR_FIXING_CHOICES,
    ENGAGEMENT_STATUS_CHOICES,
    IMPORT_ACTIONS,
    SEVERITY_CHOICES,
    App_Analysis,
    ChoiceQuestion,
    Cred_Mapping,
    Development_Environment,
    Dojo_Group,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Survey,
    Finding,
    Finding_Group,
    Finding_Template,
    Note_Type,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Question,
    Risk_Acceptance,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    TextQuestion,
    Vulnerability_Id,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.test.queries import get_authorized_tests
from dojo.user.queries import get_authorized_users
from dojo.utils import get_system_setting, is_finding_groups_enabled

logger = logging.getLogger(__name__)

local_tz = pytz.timezone(get_system_setting("time_zone"))

BOOLEAN_CHOICES = (("false", "No"), ("true", "Yes"))
EARLIEST_FINDING = None


def custom_filter(queryset, name, value):
    values = value.split(",")
    filter = (f"{name}__in")
    return queryset.filter(Q(**{filter: values}))


def custom_vulnerability_id_filter(queryset, name, value):
    values = value.split(",")
    ids = Vulnerability_Id.objects \
        .filter(vulnerability_id__in=values) \
        .values_list("finding_id", flat=True)
    return queryset.filter(id__in=ids)


def vulnerability_id_filter(queryset, name, value):
    ids = Vulnerability_Id.objects \
        .filter(vulnerability_id=value) \
        .values_list("finding_id", flat=True)
    return queryset.filter(id__in=ids)


def now():
    return local_tz.localize(datetime.today())


class NumberInFilter(filters.BaseInFilter, filters.NumberFilter):
    pass


class CharFieldInFilter(filters.BaseInFilter, filters.CharFilter):
    def __init__(self, *args, **kwargs):
        super(CharFilter, self).__init__(*args, **kwargs)


class FindingStatusFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs

    def open(self, qs, name):
        return qs.filter(OPEN_FINDINGS_QUERY)

    def verified(self, qs, name):
        return qs.filter(VERIFIED_FINDINGS_QUERY)

    def out_of_scope(self, qs, name):
        return qs.filter(OUT_OF_SCOPE_FINDINGS_QUERY)

    def false_positive(self, qs, name):
        return qs.filter(FALSE_POSITIVE_FINDINGS_QUERY)

    def inactive(self, qs, name):
        return qs.filter(INACTIVE_FINDINGS_QUERY)

    def risk_accepted(self, qs, name):
        return qs.filter(ACCEPTED_FINDINGS_QUERY)

    def closed(self, qs, name):
        return qs.filter(CLOSED_FINDINGS_QUERY)

    def under_review(self, qs, name):
        return qs.filter(UNDER_REVIEW_QUERY)

    options = {
        None: (_("Any"), any),
        0: (_("Open"), open),
        1: (_("Verified"), verified),
        2: (_("Out Of Scope"), out_of_scope),
        3: (_("False Positive"), false_positive),
        4: (_("Inactive"), inactive),
        5: (_("Risk Accepted"), risk_accepted),
        6: (_("Closed"), closed),
        7: (_("Under Review"), under_review),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        earliest_finding = get_earliest_finding(qs)
        if earliest_finding is not None:
            start_date = local_tz.localize(datetime.combine(
                earliest_finding.date, datetime.min.time()),
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class FindingSLAFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs

    def sla_satisfied(self, qs, name):
        # return findings that have an sla expiration date after today or no sla expiration date
        return qs.filter(Q(sla_expiration_date__isnull=True) | Q(sla_expiration_date__gt=timezone.now().date()))

    def sla_violated(self, qs, name):
        # return active findings that have an sla expiration date before today
        return qs.filter(
            Q(
                active=True,
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                risk_accepted=False,
                is_mitigated=False,
                mitigated=None,
            ) & Q(sla_expiration_date__lt=timezone.now().date()),
        )

    options = {
        None: (_("Any"), any),
        0: (_("False"), sla_satisfied),
        1: (_("True"), sla_violated),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class FindingHasJIRAFilter(ChoiceFilter):
    def no_jira(self, qs, name):
        return qs.filter(Q(jira_issue=None) & Q(finding_group__jira_issue=None))

    def any_jira(self, qs, name):
        return qs.filter(~Q(jira_issue=None) | ~Q(finding_group__jira_issue=None))

    def all_items(self, qs, name):
        return qs

    options = {
        0: (_("Yes"), any_jira),
        1: (_("No"), no_jira),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            return self.all_items(qs, self.field_name)

        return self.options[value][1](self, qs, self.field_name)


class ProductSLAFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs

    def sla_satisifed(self, qs, name):
        for product in qs:
            if product.violates_sla():
                qs = qs.exclude(id=product.id)
        return qs

    def sla_violated(self, qs, name):
        for product in qs:
            if not product.violates_sla():
                qs = qs.exclude(id=product.id)
        return qs

    options = {
        None: (_("Any"), any),
        0: (_("False"), sla_satisifed),
        1: (_("True"), sla_violated),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


def get_earliest_finding(queryset=None):
    if queryset is None:  # don't to 'if not queryset' which will trigger the query
        queryset = Finding.objects.all()

    try:
        EARLIEST_FINDING = queryset.earliest("date")
    except (Finding.DoesNotExist, Endpoint_Status.DoesNotExist):
        EARLIEST_FINDING = None
    return EARLIEST_FINDING


def cwe_options(queryset):
    cwe = {}
    cwe = dict([cwe, cwe]
                for cwe in queryset.order_by().values_list("cwe", flat=True).distinct()
                if isinstance(cwe, int) and cwe is not None and cwe > 0)
    cwe = collections.OrderedDict(sorted(cwe.items()))
    return list(cwe.items())


class DojoFilter(FilterSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field in ["tags", "test__tags", "test__engagement__tags", "test__engagement__product__tags",
                        "not_tags", "not_test__tags", "not_test__engagement__tags", "not_test__engagement__product__tags"]:
            if field in self.form.fields:
                tags_filter = self.filters["tags"]
                model = tags_filter.model

                self.form.fields[field] = model._meta.get_field("tags").formfield()
                # we defer applying the select2 autocomplete because there can be multiple forms on the same page
                # and form.js would then apply select2 multiple times, resulting in duplicated fields
                # the initialization now happens in filter_js_snippet.html
                self.form.fields[field].widget.tag_options = \
                    self.form.fields[field].widget.tag_options + tagulous.models.options.TagOptions(autocomplete_settings={"width": "200px", "defer": True})
                tagged_model, exclude = get_tags_model_from_field_name(field)
                if tagged_model:  # only if not the normal tags field
                    self.form.fields[field].label = get_tags_label_from_model(tagged_model)
                    self.form.fields[field].autocomplete_tags = tagged_model.tags.tag_model.objects.all().order_by("name")

                if exclude:
                    self.form.fields[field].label = "Not " + self.form.fields[field].label


def get_tags_model_from_field_name(field):
    exclude = False
    if field.startswith("not_"):
        field = field.replace("not_", "")
        exclude = True
    try:
        parts = field.split("__")
        model_name = parts[-2]
        return apps.get_model(f"dojo.{model_name}", require_ready=True), exclude
    except Exception:
        return None, exclude


def get_tags_label_from_model(model):
    if model:
        return f"Tags ({model.__name__.title()})"
    return "Tags (Unknown)"


def get_finding_filterset_fields(*, metrics=False, similar=False, filter_string_matching=False):
    fields = []

    if similar:
        fields.extend([
            "id",
            "hash_code",
        ])

    fields.extend(["title", "component_name", "component_version"])

    if metrics:
        fields.extend([
            "start_date",
            "end_date",
        ])

    fields.extend([
        "date",
        "cwe",
        "severity",
        "last_reviewed",
        "last_status_update",
        "mitigated",
        "reporter",
        "reviewers",
    ])

    if filter_string_matching:
        fields.extend([
            "reporter",
            "reviewers",
            "test__engagement__product__prod_type__name",
            "test__engagement__product__name",
            "test__engagement__name",
            "test__title",
        ])
    else:
        fields.extend([
            "reporter",
            "reviewers",
            "test__engagement__product__prod_type",
            "test__engagement__product",
            "test__engagement",
            "test",
        ])

    fields.extend([
        "test__test_type",
        "test__engagement__version",
        "test__version",
        "endpoints",
        "status",
        "active",
        "verified",
        "duplicate",
        "is_mitigated",
        "out_of_scope",
        "false_p",
        "has_component",
        "has_notes",
        "file_path",
        "unique_id_from_tool",
        "vuln_id_from_tool",
        "service",
        "epss_score",
        "epss_score_range",
        "epss_percentile",
        "epss_percentile_range",
    ])

    if similar:
        fields.extend([
            "id",
        ])

    fields.extend([
        "param",
        "payload",
        "risk_acceptance",
    ])

    if get_system_setting("enable_jira"):
        fields.extend([
            "has_jira_issue",
            "jira_creation",
            "jira_change",
            "jira_issue__jira_key",
        ])

    if is_finding_groups_enabled():
        if filter_string_matching:
            fields.extend([
                "has_finding_group",
                "finding_group__name",
            ])
        else:
            fields.extend([
                "has_finding_group",
                "finding_group",
            ])

        if get_system_setting("enable_jira"):
            fields.extend([
                "has_jira_group_issue",
            ])

    return fields


class FindingTagFilter(DojoFilter):
    tag = CharFilter(
        field_name="tags__name",
        lookup_expr="icontains",
        label="Tag name contains",
        help_text="Search for tags on a Finding that contain a given pattern")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected tags")
    test__tags = ModelMultipleChoiceFilter(
        field_name="test__tags__name",
        to_field_name="name",
        queryset=Test.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Tests by the selected tags")
    test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Engagements by the selected tags")
    test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__product__tags__name",
        to_field_name="name",
        queryset=Product.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Products by the selected tags")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_test__tags = ModelMultipleChoiceFilter(
        field_name="test__tags__name",
        to_field_name="name",
        label="Test without tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"),
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__tags__name",
        to_field_name="name",
        label="Engagement without tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"),
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__product__tags__name",
        to_field_name="name",
        label="Product without tags",
        queryset=Product.tags.tag_model.objects.all().order_by("name"),
        help_text="Search for tags on a Product that contain a given pattern, and exclude them",
        exclude=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class FindingTagStringFilter(FilterSet):
    tags_contains = CharFilter(
        label="Finding Tag Contains",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    tags = CharFilter(
        label="Finding Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    test__tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    test__tags = CharFilter(
        label="Test Tag",
        field_name="test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Contains",
        field_name="test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    test__engagement__tags = CharFilter(
        label="Engagement Tag",
        field_name="test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    test__engagement__product__tags_contains = CharFilter(
        label="Product Tag Contains",
        field_name="test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    test__engagement__product__tags = CharFilter(
        label="Product Tag",
        field_name="test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")

    not_tags_contains = CharFilter(
        label="Finding Tag Does Not Contain",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_tags = CharFilter(
        label="Not Finding Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match, and exclude them",
        exclude=True)
    not_test__tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_test__tags = CharFilter(
        label="Not Test Tag",
        field_name="test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)
    not_test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Does Not Contain",
        field_name="test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_test__engagement__tags = CharFilter(
        label="Not Engagement Tag",
        field_name="test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Engagement that are an exact match, and exclude them",
        exclude=True)
    not_test__engagement__product__tags_contains = CharFilter(
        label="Product Tag Does Not Contain",
        field_name="test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Product that contain a given pattern, and exclude them",
        exclude=True)
    not_test__engagement__product__tags = CharFilter(
        label="Not Product Tag",
        field_name="test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Product that are an exact match, and exclude them",
        exclude=True)

    def delete_tags_from_form(self, tag_list: list):
        for tag in tag_list:
            self.form.fields.pop(tag, None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class DateRangeFilter(ChoiceFilter):
    options = {
        None: (_("Any date"), lambda qs, _: qs.all()),
        1: (_("Today"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
            f"{name}__day": now().day,
        })),
        2: (_("Past 7 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=7)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
        3: (_("Past 30 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=30)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
        4: (_("Past 90 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=90)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
        5: (_("Current month"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
        })),
        6: (_("Current year"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
        })),
        7: (_("Past year"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=365)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](qs, self.field_name)


class DateRangeOmniFilter(ChoiceFilter):
    options = {
        None: (_("Any date"), lambda qs, _: qs.all()),
        1: (_("Today"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
            f"{name}__day": now().day,
        })),
        2: (_("Next 7 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() + timedelta(days=1)),
            f"{name}__lt": _truncate(now() + timedelta(days=7)),
        })),
        3: (_("Next 30 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() + timedelta(days=1)),
            f"{name}__lt": _truncate(now() + timedelta(days=30)),
        })),
        4: (_("Next 90 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() + timedelta(days=1)),
            f"{name}__lt": _truncate(now() + timedelta(days=90)),
        })),
        5: (_("Past 7 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=7)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
        6: (_("Past 30 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=30)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
        7: (_("Past 90 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=90)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
        8: (_("Current month"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
        })),
        9: (_("Past year"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() - timedelta(days=365)),
            f"{name}__lt": _truncate(now() + timedelta(days=1)),
        })),
        10: (_("Current year"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
        })),
        11: (_("Next year"), lambda qs, name: qs.filter(**{
            f"{name}__gte": _truncate(now() + timedelta(days=1)),
            f"{name}__lt": _truncate(now() + timedelta(days=365)),
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](qs, self.field_name)


class ReportBooleanFilter(ChoiceFilter):
    options = {
        None: (_("Either"), lambda qs, _: qs.all()),
        1: (_("Yes"), lambda qs, name: qs.filter(**{
            f"{name}": True,
        })),
        2: (_("No"), lambda qs, name: qs.filter(**{
            f"{name}": False,
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](qs, self.field_name)


class ReportRiskAcceptanceFilter(ChoiceFilter):

    def any(self, qs, name):
        return qs.all()

    def accepted(self, qs, name):
        # return qs.filter(risk_acceptance__isnull=False)
        return qs.filter(ACCEPTED_FINDINGS_QUERY)

    def not_accepted(self, qs, name):
        return qs.filter(NOT_ACCEPTED_FINDINGS_QUERY)

    def was_accepted(self, qs, name):
        return qs.filter(WAS_ACCEPTED_FINDINGS_QUERY)

    options = {
        None: (_("Either"), any),
        1: (_("Yes"), accepted),
        2: (_("No"), not_accepted),
        3: (_("Expired"), was_accepted),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class MetricsDateRangeFilter(ChoiceFilter):
    def any(self, qs, name):
        earliest_finding = get_earliest_finding(qs)
        if earliest_finding is not None:
            start_date = local_tz.localize(datetime.combine(
                earliest_finding.date, datetime.min.time()),
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))
            return qs.all()
        return None

    def current_month(self, qs, name):
        self.start_date = local_tz.localize(
            datetime(now().year, now().month, 1, 0, 0, 0))
        self.end_date = now()
        return qs.filter(**{
            f"{name}__year": self.start_date.year,
            f"{name}__month": self.start_date.month,
        })

    def current_year(self, qs, name):
        self.start_date = local_tz.localize(
            datetime(now().year, 1, 1, 0, 0, 0))
        self.end_date = now()
        return qs.filter(**{
            f"{name}__year": now().year,
        })

    def past_x_days(self, qs, name, days):
        self.start_date = _truncate(now() - timedelta(days=days))
        self.end_date = _truncate(now() + timedelta(days=1))
        return qs.filter(**{
            f"{name}__gte": self.start_date,
            f"{name}__lt": self.end_date,
        })

    def past_seven_days(self, qs, name):
        return self.past_x_days(qs, name, 7)

    def past_thirty_days(self, qs, name):
        return self.past_x_days(qs, name, 30)

    def past_ninety_days(self, qs, name):
        return self.past_x_days(qs, name, 90)

    def past_six_months(self, qs, name):
        return self.past_x_days(qs, name, 183)

    def past_year(self, qs, name):
        return self.past_x_days(qs, name, 365)

    options = {
        None: (_("Past 30 days"), past_thirty_days),
        1: (_("Past 7 days"), past_seven_days),
        2: (_("Past 90 days"), past_ninety_days),
        3: (_("Current month"), current_month),
        4: (_("Current year"), current_year),
        5: (_("Past 6 Months"), past_six_months),
        6: (_("Past year"), past_year),
        7: (_("Any date"), any),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value == 8:
            return qs
        earliest_finding = get_earliest_finding(qs)
        if earliest_finding is not None:
            start_date = local_tz.localize(datetime.combine(
                earliest_finding.date, datetime.min.time()),
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class ProductComponentFilter(DojoFilter):
    component_name = CharFilter(lookup_expr="icontains", label="Module Name")
    component_version = CharFilter(lookup_expr="icontains", label="Module Version")

    o = OrderingFilter(
        fields=(
            ("component_name", "component_name"),
            ("component_version", "component_version"),
            ("active", "active"),
            ("duplicate", "duplicate"),
            ("total", "total"),
        ),
        field_labels={
            "component_name": "Component Name",
            "component_version": "Component Version",
            "active": "Active",
            "duplicate": "Duplicate",
            "total": "Total",
        },
    )


class ComponentFilterWithoutObjectLookups(ProductComponentFilter):
    test__engagement__product__prod_type__name = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="iexact",
        label="Product Type Name",
        help_text="Search for Product Type names that are an exact match")
    test__engagement__product__prod_type__name_contains = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="icontains",
        label="Product Type Name Contains",
        help_text="Search for Product Type names that contain a given pattern")
    test__engagement__product__name = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="iexact",
        label="Product Name",
        help_text="Search for Product names that are an exact match")
    test__engagement__product__name_contains = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="icontains",
        label="Product Name Contains",
        help_text="Search for Product names that contain a given pattern")


class ComponentFilter(ProductComponentFilter):
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label="Product Type")
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(),
        label="Product")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields[
            "test__engagement__product__prod_type"].queryset = get_authorized_product_types(Permissions.Product_Type_View)
        self.form.fields[
            "test__engagement__product"].queryset = get_authorized_products(Permissions.Product_View)


class EngagementDirectFilterHelper(FilterSet):
    name = CharFilter(lookup_expr="icontains", label="Engagement name contains")
    version = CharFilter(field_name="version", lookup_expr="icontains", label="Engagement version")
    test__version = CharFilter(field_name="test__version", lookup_expr="icontains", label="Test version")
    product__name = CharFilter(lookup_expr="icontains", label="Product name contains")
    status = MultipleChoiceFilter(choices=ENGAGEMENT_STATUS_CHOICES, label="Status")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    target_start = DateRangeFilter()
    target_end = DateRangeFilter()
    test__engagement__product__lifecycle = MultipleChoiceFilter(
        choices=Product.LIFECYCLE_CHOICES,
        label="Product lifecycle",
        null_label="Empty")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("target_start", "target_start"),
            ("name", "name"),
            ("product__name", "product__name"),
            ("product__prod_type__name", "product__prod_type__name"),
            ("lead__first_name", "lead__first_name"),
        ),
        field_labels={
            "target_start": "Start date",
            "name": "Engagement",
            "product__name": "Product Name",
            "product__prod_type__name": "Product Type",
            "lead__first_name": "Lead",
        },
    )


class EngagementDirectFilter(EngagementDirectFilterHelper, DojoFilter):
    lead = ModelChoiceFilter(queryset=Dojo_User.objects.none(), label="Lead")
    product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label="Product Type")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["product__prod_type"].queryset = get_authorized_product_types(Permissions.Product_Type_View)
        self.form.fields["lead"].queryset = get_authorized_users(Permissions.Product_Type_View) \
            .filter(engagement__lead__isnull=False).distinct()

    class Meta:
        model = Engagement
        fields = ["product__name", "product__prod_type"]


class EngagementDirectFilterWithoutObjectLookups(EngagementDirectFilterHelper):
    lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    lead_contains = CharFilter(
        field_name="lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")
    product__prod_type__name = CharFilter(
        field_name="product__prod_type__name",
        lookup_expr="iexact",
        label="Product Type Name",
        help_text="Search for Product Type names that are an exact match")
    product__prod_type__name_contains = CharFilter(
        field_name="product__prod_type__name",
        lookup_expr="icontains",
        label="Product Type Name Contains",
        help_text="Search for Product Type names that contain a given pattern")

    class Meta:
        model = Engagement
        fields = ["product__name"]


class EngagementFilterHelper(FilterSet):
    name = CharFilter(lookup_expr="icontains", label="Product name contains")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    engagement__name = CharFilter(lookup_expr="icontains", label="Engagement name contains")
    engagement__version = CharFilter(field_name="engagement__version", lookup_expr="icontains", label="Engagement version")
    engagement__test__version = CharFilter(field_name="engagement__test__version", lookup_expr="icontains", label="Test version")
    engagement__product__lifecycle = MultipleChoiceFilter(
        choices=Product.LIFECYCLE_CHOICES,
        label="Product lifecycle",
        null_label="Empty")
    engagement__status = MultipleChoiceFilter(
        choices=ENGAGEMENT_STATUS_CHOICES,
        label="Status")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("prod_type__name", "prod_type__name"),
        ),
        field_labels={
            "name": "Product Name",
            "prod_type__name": "Product Type",
        },
    )


class EngagementFilter(EngagementFilterHelper, DojoFilter):
    engagement__lead = ModelChoiceFilter(
        queryset=Dojo_User.objects.none(),
        label="Lead")
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label="Product Type")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["prod_type"].queryset = get_authorized_product_types(Permissions.Product_Type_View)
        self.form.fields["engagement__lead"].queryset = get_authorized_users(Permissions.Product_Type_View) \
            .filter(engagement__lead__isnull=False).distinct()

    class Meta:
        model = Product
        fields = ["name", "prod_type"]


class ProductEngagementsFilter(DojoFilter):
    engagement__name = CharFilter(field_name="name", lookup_expr="icontains", label="Engagement name contains")
    engagement__lead = ModelChoiceFilter(field_name="lead", queryset=Dojo_User.objects.none(), label="Lead")
    engagement__version = CharFilter(field_name="version", lookup_expr="icontains", label="Engagement version")
    engagement__test__version = CharFilter(field_name="test__version", lookup_expr="icontains", label="Test version")
    engagement__status = MultipleChoiceFilter(field_name="status", choices=ENGAGEMENT_STATUS_CHOICES,
                                              label="Status")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["engagement__lead"].queryset = get_authorized_users(Permissions.Product_Type_View) \
            .filter(engagement__lead__isnull=False).distinct()

    class Meta:
        model = Engagement
        fields = []


class ProductEngagementsFilterWithoutObjectLookups(ProductEngagementsFilter):
    engagement__lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")


class EngagementFilterWithoutObjectLookups(EngagementFilterHelper):
    engagement__lead = CharFilter(
        field_name="engagement__lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    engagement__lead_contains = CharFilter(
        field_name="engagement__lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")
    prod_type__name = CharFilter(
        field_name="prod_type__name",
        lookup_expr="iexact",
        label="Product Type Name",
        help_text="Search for Product Type names that are an exact match")
    prod_type__name_contains = CharFilter(
        field_name="prod_type__name",
        lookup_expr="icontains",
        label="Product Type Name Contains",
        help_text="Search for Product Type names that contain a given pattern")

    class Meta:
        model = Product
        fields = ["name"]


class ProductEngagementFilterHelper(FilterSet):
    version = CharFilter(lookup_expr="icontains", label="Engagement version")
    test__version = CharFilter(field_name="test__version", lookup_expr="icontains", label="Test version")
    name = CharFilter(lookup_expr="icontains")
    status = MultipleChoiceFilter(choices=ENGAGEMENT_STATUS_CHOICES, label="Status")
    target_start = DateRangeFilter()
    target_end = DateRangeFilter()
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("status", "status"),
            ("lead", "lead"),
        ),
        field_labels={
            "name": "Engagement Name",
        },
    )

    class Meta:
        model = Product
        fields = ["name"]


class ProductEngagementFilter(ProductEngagementFilterHelper, DojoFilter):
    lead = ModelChoiceFilter(queryset=Dojo_User.objects.none(), label="Lead")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["lead"].queryset = get_authorized_users(
            Permissions.Product_Type_View).filter(engagement__lead__isnull=False).distinct()


class ProductEngagementFilterWithoutObjectLookups(ProductEngagementFilterHelper, DojoFilter):
    lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    lead_contains = CharFilter(
        field_name="lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")


class ApiEngagementFilter(DojoFilter):
    product__prod_type = NumberInFilter(field_name="product__prod_type", lookup_expr="in")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                             help_text="Comma separated list of exact tags")
    product__tags = CharFieldInFilter(field_name="product__tags__name",
                                            lookup_expr="in",
                                            help_text="Comma separated list of exact tags present on product")

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    not_product__tags = CharFieldInFilter(field_name="product__tags__name",
                                                lookup_expr="in",
                                                help_text="Comma separated list of exact tags not present on product",
                                                exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("status", "status"),
            ("lead", "lead"),
            ("created", "created"),
            ("updated", "updated"),
        ),
        field_labels={
            "name": "Engagement Name",
        },

    )

    class Meta:
        model = Engagement
        fields = ["id", "active", "target_start",
                     "target_end", "requester", "report_type",
                     "updated", "threat_model", "api_test",
                     "pen_test", "status", "product", "name", "version", "tags"]


class ProductFilterHelper(FilterSet):
    name = CharFilter(lookup_expr="icontains", label="Product Name")
    name_exact = CharFilter(field_name="name", lookup_expr="iexact", label="Exact Product Name")
    business_criticality = MultipleChoiceFilter(choices=Product.BUSINESS_CRITICALITY_CHOICES, null_label="Empty")
    platform = MultipleChoiceFilter(choices=Product.PLATFORM_CHOICES, null_label="Empty")
    lifecycle = MultipleChoiceFilter(choices=Product.LIFECYCLE_CHOICES, null_label="Empty")
    origin = MultipleChoiceFilter(choices=Product.ORIGIN_CHOICES, null_label="Empty")
    external_audience = BooleanFilter(field_name="external_audience")
    internet_accessible = BooleanFilter(field_name="internet_accessible")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    outside_of_sla = ProductSLAFilter(label="Outside of SLA")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("name_exact", "name_exact"),
            ("prod_type__name", "prod_type__name"),
            ("business_criticality", "business_criticality"),
            ("platform", "platform"),
            ("lifecycle", "lifecycle"),
            ("origin", "origin"),
            ("external_audience", "external_audience"),
            ("internet_accessible", "internet_accessible"),
            ("findings_count", "findings_count"),
        ),
        field_labels={
            "name": "Product Name",
            "name_exact": "Exact Product Name",
            "prod_type__name": "Product Type",
            "business_criticality": "Business Criticality",
            "platform": "Platform ",
            "lifecycle": "Lifecycle ",
            "origin": "Origin ",
            "external_audience": "External Audience ",
            "internet_accessible": "Internet Accessible ",
            "findings_count": "Findings Count ",
        },
    )


class ProductFilter(ProductFilterHelper, DojoFilter):
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label="Product Type")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Product.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.form.fields["prod_type"].queryset = get_authorized_product_types(Permissions.Product_Type_View)

    class Meta:
        model = Product
        fields = [
            "name", "name_exact", "prod_type", "business_criticality",
            "platform", "lifecycle", "origin", "external_audience",
            "internet_accessible", "tags",
        ]


class ProductFilterWithoutObjectLookups(ProductFilterHelper):
    prod_type__name = CharFilter(
        field_name="prod_type__name",
        lookup_expr="iexact",
        label="Product Type Name",
        help_text="Search for Product Type names that are an exact match")
    prod_type__name_contains = CharFilter(
        field_name="prod_type__name",
        lookup_expr="icontains",
        label="Product Type Name Contains",
        help_text="Search for Product Type names that contain a given pattern")

    def __init__(self, *args, **kwargs):
        kwargs.pop("user", None)
        super().__init__(*args, **kwargs)

    class Meta:
        model = Product
        fields = [
            "name", "name_exact", "business_criticality", "platform",
            "lifecycle", "origin", "external_audience", "internet_accessible",
        ]


class ApiProductFilter(DojoFilter):
    # BooleanFilter
    external_audience = BooleanFilter(field_name="external_audience")
    internet_accessible = BooleanFilter(field_name="internet_accessible")
    # CharFilter
    name = CharFilter(lookup_expr="icontains")
    name_exact = CharFilter(field_name="name", lookup_expr="iexact")
    description = CharFilter(lookup_expr="icontains")
    business_criticality = CharFilter(method=custom_filter, field_name="business_criticality")
    platform = CharFilter(method=custom_filter, field_name="platform")
    lifecycle = CharFilter(method=custom_filter, field_name="lifecycle")
    origin = CharFilter(method=custom_filter, field_name="origin")
    # NumberInFilter
    id = NumberInFilter(field_name="id", lookup_expr="in")
    product_manager = NumberInFilter(field_name="product_manager", lookup_expr="in")
    technical_contact = NumberInFilter(field_name="technical_contact", lookup_expr="in")
    team_manager = NumberInFilter(field_name="team_manager", lookup_expr="in")
    prod_type = NumberInFilter(field_name="prod_type", lookup_expr="in")
    tid = NumberInFilter(field_name="tid", lookup_expr="in")
    prod_numeric_grade = NumberInFilter(field_name="prod_numeric_grade", lookup_expr="in")
    user_records = NumberInFilter(field_name="user_records", lookup_expr="in")
    regulations = NumberInFilter(field_name="regulations", lookup_expr="in")

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                             help_text="Comma separated list of exact tags")

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on product", exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    outside_of_sla = extend_schema_field(OpenApiTypes.NUMBER)(ProductSLAFilter())

    # DateRangeFilter
    created = DateRangeFilter()
    updated = DateRangeFilter()
    # NumberFilter
    revenue = NumberFilter()

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("id", "id"),
            ("tid", "tid"),
            ("name", "name"),
            ("created", "created"),
            ("prod_numeric_grade", "prod_numeric_grade"),
            ("business_criticality", "business_criticality"),
            ("platform", "platform"),
            ("lifecycle", "lifecycle"),
            ("origin", "origin"),
            ("revenue", "revenue"),
            ("external_audience", "external_audience"),
            ("internet_accessible", "internet_accessible"),
            ("product_manager", "product_manager"),
            ("product_manager__first_name", "product_manager__first_name"),
            ("product_manager__last_name", "product_manager__last_name"),
            ("technical_contact", "technical_contact"),
            ("technical_contact__first_name", "technical_contact__first_name"),
            ("technical_contact__last_name", "technical_contact__last_name"),
            ("team_manager", "team_manager"),
            ("team_manager__first_name", "team_manager__first_name"),
            ("team_manager__last_name", "team_manager__last_name"),
            ("prod_type", "prod_type"),
            ("prod_type__name", "prod_type__name"),
            ("updated", "updated"),
            ("user_records", "user_records"),
        ),
    )


class PercentageRangeFilter(RangeFilter):
    def filter(self, qs, value):
        if value is not None:
            start = value.start / decimal.Decimal("100.0") if value.start else None
            stop = value.stop / decimal.Decimal("100.0") if value.stop else None
            value = slice(start, stop)
        return super().filter(qs, value)


class ApiFindingFilter(DojoFilter):
    # BooleanFilter
    active = BooleanFilter(field_name="active")
    duplicate = BooleanFilter(field_name="duplicate")
    dynamic_finding = BooleanFilter(field_name="dynamic_finding")
    false_p = BooleanFilter(field_name="false_p")
    is_mitigated = BooleanFilter(field_name="is_mitigated")
    out_of_scope = BooleanFilter(field_name="out_of_scope")
    static_finding = BooleanFilter(field_name="static_finding")
    under_defect_review = BooleanFilter(field_name="under_defect_review")
    under_review = BooleanFilter(field_name="under_review")
    verified = BooleanFilter(field_name="verified")
    has_jira = BooleanFilter(field_name="jira_issue", lookup_expr="isnull", exclude=True)
    # CharFilter
    component_version = CharFilter(lookup_expr="icontains")
    component_name = CharFilter(lookup_expr="icontains")
    vulnerability_id = CharFilter(method=custom_vulnerability_id_filter)
    description = CharFilter(lookup_expr="icontains")
    file_path = CharFilter(lookup_expr="icontains")
    hash_code = CharFilter(lookup_expr="icontains")
    impact = CharFilter(lookup_expr="icontains")
    mitigation = CharFilter(lookup_expr="icontains")
    numerical_severity = CharFilter(method=custom_filter, field_name="numerical_severity")
    param = CharFilter(lookup_expr="icontains")
    payload = CharFilter(lookup_expr="icontains")
    references = CharFilter(lookup_expr="icontains")
    severity = CharFilter(method=custom_filter, field_name="severity")
    severity_justification = CharFilter(lookup_expr="icontains")
    steps_to_reproduce = CharFilter(lookup_expr="icontains")
    unique_id_from_tool = CharFilter(lookup_expr="icontains")
    title = CharFilter(lookup_expr="icontains")
    product_name = CharFilter(lookup_expr="engagement__product__name__iexact", field_name="test", label="exact product name")
    product_name_contains = CharFilter(lookup_expr="engagement__product__name__icontains", field_name="test", label="exact product name")
    product_lifecycle = CharFilter(method=custom_filter, lookup_expr="engagement__product__lifecycle",
                                   field_name="test__engagement__product__lifecycle", label="Comma separated list of exact product lifecycles")
    # DateRangeFilter
    created = DateRangeFilter()
    date = DateRangeFilter()
    discovered_on = DateFilter(field_name="date", lookup_expr="exact")
    discovered_before = DateFilter(field_name="date", lookup_expr="lt")
    discovered_after = DateFilter(field_name="date", lookup_expr="gt")
    jira_creation = DateRangeFilter(field_name="jira_issue__jira_creation")
    jira_change = DateRangeFilter(field_name="jira_issue__jira_change")
    last_reviewed = DateRangeFilter()
    mitigated = DateRangeFilter()
    mitigated_on = DateTimeFilter(field_name="mitigated", lookup_expr="exact", method="filter_mitigated_on")
    mitigated_before = DateTimeFilter(field_name="mitigated", lookup_expr="lt")
    mitigated_after = DateTimeFilter(field_name="mitigated", lookup_expr="gt", label="Mitigated After", method="filter_mitigated_after")
    # NumberInFilter
    cwe = NumberInFilter(field_name="cwe", lookup_expr="in")
    defect_review_requested_by = NumberInFilter(field_name="defect_review_requested_by", lookup_expr="in")
    endpoints = NumberInFilter(field_name="endpoints", lookup_expr="in")
    epss_score = PercentageRangeFilter(
        field_name="epss_score",
        label="EPSS score range",
        help_text=(
            "The range of EPSS score percentages to filter on; the min input is a lower bound, "
            "the max is an upper bound. Leaving one empty will skip that bound (e.g., leaving "
            "the min bound input empty will filter only on the max bound -- filtering on "
            '"less than or equal"). Leading 0 required.'
        ))
    epss_percentile = PercentageRangeFilter(
        field_name="epss_percentile",
        label="EPSS percentile range",
        help_text=(
            "The range of EPSS percentiles to filter on; the min input is a lower bound, the max "
            "is an upper bound. Leaving one empty will skip that bound (e.g., leaving the min bound "
            'input empty will filter only on the max bound -- filtering on "less than or equal"). Leading 0 required.'
        ))
    found_by = NumberInFilter(field_name="found_by", lookup_expr="in")
    id = NumberInFilter(field_name="id", lookup_expr="in")
    last_reviewed_by = NumberInFilter(field_name="last_reviewed_by", lookup_expr="in")
    mitigated_by = NumberInFilter(field_name="mitigated_by", lookup_expr="in")
    nb_occurences = NumberInFilter(field_name="nb_occurences", lookup_expr="in")
    reporter = NumberInFilter(field_name="reporter", lookup_expr="in")
    scanner_confidence = NumberInFilter(field_name="scanner_confidence", lookup_expr="in")
    review_requested_by = NumberInFilter(field_name="review_requested_by", lookup_expr="in")
    reviewers = NumberInFilter(field_name="reviewers", lookup_expr="in")
    sast_source_line = NumberInFilter(field_name="sast_source_line", lookup_expr="in")
    sonarqube_issue = NumberInFilter(field_name="sonarqube_issue", lookup_expr="in")
    test__test_type = NumberInFilter(field_name="test__test_type", lookup_expr="in", label="Test Type")
    test__engagement = NumberInFilter(field_name="test__engagement", lookup_expr="in")
    test__engagement__product = NumberInFilter(field_name="test__engagement__product", lookup_expr="in")
    test__engagement__product__prod_type = NumberInFilter(field_name="test__engagement__product__prod_type", lookup_expr="in")
    finding_group = NumberInFilter(field_name="finding_group", lookup_expr="in")

    # ReportRiskAcceptanceFilter
    risk_acceptance = extend_schema_field(OpenApiTypes.NUMBER)(ReportRiskAcceptanceFilter())

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                             help_text="Comma separated list of exact tags")
    test__tags = CharFieldInFilter(field_name="test__tags__name", lookup_expr="in", help_text="Comma separated list of exact tags present on test")
    test__engagement__tags = CharFieldInFilter(field_name="test__engagement__tags__name", lookup_expr="in",
                                               help_text="Comma separated list of exact tags present on engagement")
    test__engagement__product__tags = CharFieldInFilter(
        field_name="test__engagement__product__tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags present on product")

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    not_test__tags = CharFieldInFilter(field_name="test__tags__name", lookup_expr="in", exclude="True", help_text="Comma separated list of exact tags present on test")
    not_test__engagement__tags = CharFieldInFilter(field_name="test__engagement__tags__name", lookup_expr="in",
                                                   help_text="Comma separated list of exact tags not present on engagement",
                                                   exclude="True")
    not_test__engagement__product__tags = CharFieldInFilter(
        field_name="test__engagement__product__tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags not present on product",
        exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    outside_of_sla = extend_schema_field(OpenApiTypes.NUMBER)(FindingSLAFilter())

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("active", "active"),
            ("component_name", "component_name"),
            ("component_version", "component_version"),
            ("created", "created"),
            ("last_status_update", "last_status_update"),
            ("last_reviewed", "last_reviewed"),
            ("cwe", "cwe"),
            ("date", "date"),
            ("duplicate", "duplicate"),
            ("dynamic_finding", "dynamic_finding"),
            ("false_p", "false_p"),
            ("found_by", "found_by"),
            ("id", "id"),
            ("is_mitigated", "is_mitigated"),
            ("numerical_severity", "numerical_severity"),
            ("out_of_scope", "out_of_scope"),
            ("severity", "severity"),
            ("reviewers", "reviewers"),
            ("static_finding", "static_finding"),
            ("test__engagement__product__name", "test__engagement__product__name"),
            ("title", "title"),
            ("under_defect_review", "under_defect_review"),
            ("under_review", "under_review"),
            ("verified", "verified"),
        ),
    )

    class Meta:
        model = Finding
        exclude = ["url", "thread_id", "notes", "files",
                   "line", "cve"]

    def filter_mitigated_after(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            value = value.replace(hour=23, minute=59, second=59)

        return queryset.filter(mitigated__gt=value)

    def filter_mitigated_on(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            # we have a simple date without a time, lets get a range from this morning to tonight at 23:59:59:999
            nextday = value + timedelta(days=1)
            return queryset.filter(mitigated__gte=value, mitigated__lt=nextday)

        return queryset.filter(mitigated=value)


class PercentageFilter(NumberFilter):
    def __init__(self, *args, **kwargs):
        kwargs["method"] = self.filter_percentage
        super().__init__(*args, **kwargs)

    def filter_percentage(self, queryset, name, value):
        value = value / decimal.Decimal("100.0")
        # Provide some wiggle room for filtering since the UI rounds to two places (and because floats):
        # a user may enter 0.15, but we'll return everything in [0.0015, 0.0016).
        # To do this, add to our value 1^(whatever the exponent for our least significant digit place is), but ensure
        # that the exponent is at MOST the ten thousandths place so we don't show a range of e.g. [0.2, 0.3).
        exponent = min(value.normalize().as_tuple().exponent, -4)
        max_val = value + decimal.Decimal(f"1E{exponent}")
        lookup_kwargs = {
            f"{name}__gte": value,
            f"{name}__lt": max_val}
        return queryset.filter(**lookup_kwargs)


class FindingFilterHelper(FilterSet):
    title = CharFilter(lookup_expr="icontains")
    date = DateRangeFilter(field_name="date", label="Date Discovered")
    on = DateFilter(field_name="date", lookup_expr="exact", label="Discovered On")
    before = DateFilter(field_name="date", lookup_expr="lt", label="Discovered Before")
    after = DateFilter(field_name="date", lookup_expr="gt", label="Discovered After")
    last_reviewed = DateRangeFilter()
    last_status_update = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    vulnerability_id = CharFilter(method=vulnerability_id_filter, label="Vulnerability Id")
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    duplicate = ReportBooleanFilter()
    is_mitigated = ReportBooleanFilter()
    mitigated = DateRangeFilter(field_name="mitigated", label="Mitigated Date")
    mitigated_on = DateTimeFilter(field_name="mitigated", lookup_expr="exact", label="Mitigated On", method="filter_mitigated_on")
    mitigated_before = DateTimeFilter(field_name="mitigated", lookup_expr="lt", label="Mitigated Before")
    mitigated_after = DateTimeFilter(field_name="mitigated", lookup_expr="gt", label="Mitigated After", method="filter_mitigated_after")
    planned_remediation_date = DateRangeOmniFilter()
    planned_remediation_version = CharFilter(lookup_expr="icontains", label=_("Planned remediation version"))
    file_path = CharFilter(lookup_expr="icontains")
    param = CharFilter(lookup_expr="icontains")
    payload = CharFilter(lookup_expr="icontains")
    test__test_type = ModelMultipleChoiceFilter(queryset=Test_Type.objects.all(), label="Test Type")
    endpoints__host = CharFilter(lookup_expr="icontains", label="Endpoint Host")
    service = CharFilter(lookup_expr="icontains")
    test__engagement__version = CharFilter(lookup_expr="icontains", label="Engagement Version")
    test__version = CharFilter(lookup_expr="icontains", label="Test Version")
    risk_acceptance = ReportRiskAcceptanceFilter(label="Risk Accepted")
    effort_for_fixing = MultipleChoiceFilter(choices=EFFORT_FOR_FIXING_CHOICES)
    test_import_finding_action__test_import = NumberFilter(widget=HiddenInput())
    endpoints = NumberFilter(widget=HiddenInput())
    status = FindingStatusFilter(label="Status")

    has_component = BooleanFilter(
        field_name="component_name",
        lookup_expr="isnull",
        exclude=True,
        label="Has Component")
    has_notes = BooleanFilter(
        field_name="notes",
        lookup_expr="isnull",
        exclude=True,
        label="Has notes")

    if is_finding_groups_enabled():
        has_finding_group = BooleanFilter(
            field_name="finding_group",
            lookup_expr="isnull",
            exclude=True,
            label="Is Grouped")

    if get_system_setting("enable_jira"):
        has_jira_issue = BooleanFilter(
            field_name="jira_issue",
            lookup_expr="isnull",
            exclude=True,
            label="Has JIRA")
        jira_creation = DateRangeFilter(field_name="jira_issue__jira_creation", label="JIRA Creation")
        jira_change = DateRangeFilter(field_name="jira_issue__jira_change", label="JIRA Updated")
        jira_issue__jira_key = CharFilter(field_name="jira_issue__jira_key", lookup_expr="icontains", label="JIRA issue")

        if is_finding_groups_enabled():
            has_jira_group_issue = BooleanFilter(
                field_name="finding_group__jira_issue",
                lookup_expr="isnull",
                exclude=True,
                label="Has Group JIRA")
        has_any_jira = FindingHasJIRAFilter(label="Has Any JIRA")

    outside_of_sla = FindingSLAFilter(label="Outside of SLA")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    epss_score = PercentageFilter(field_name="epss_score", label="EPSS score")
    epss_score_range = PercentageRangeFilter(
        field_name="epss_score",
        label="EPSS score range",
        help_text=(
            "The range of EPSS score percentages to filter on; the left input is a lower bound, "
            "the right is an upper bound. Leaving one empty will skip that bound (e.g., leaving "
            "the lower bound input empty will filter only on the upper bound -- filtering on "
            '"less than or equal").'
        ))
    epss_percentile = PercentageFilter(field_name="epss_percentile", label="EPSS percentile")
    epss_percentile_range = PercentageRangeFilter(
        field_name="epss_percentile",
        label="EPSS percentile range",
        help_text=(
            "The range of EPSS percentiles to filter on; the left input is a lower bound, the right "
            "is an upper bound. Leaving one empty will skip that bound (e.g., leaving the lower bound "
            'input empty will filter only on the upper bound -- filtering on "less than or equal").'
        ))

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("numerical_severity", "numerical_severity"),
            ("date", "date"),
            ("mitigated", "mitigated"),
            ("risk_acceptance__created__date",
             "risk_acceptance__created__date"),
            ("last_reviewed", "last_reviewed"),
            ("title", "title"),
            ("test__engagement__product__name",
             "test__engagement__product__name"),
            ("service", "service"),
            ("epss_score", "epss_score"),
            ("epss_percentile", "epss_percentile"),
        ),
        field_labels={
            "numerical_severity": "Severity",
            "date": "Date",
            "risk_acceptance__created__date": "Acceptance Date",
            "mitigated": "Mitigated Date",
            "title": "Finding Name",
            "test__engagement__product__name": "Product Name",
            "epss_score": "EPSS Score",
            "epss_percentile": "EPSS Percentile",
        },
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def set_date_fields(self, *args: list, **kwargs: dict):
        date_input_widget = forms.DateInput(attrs={"class": "datepicker", "placeholder": "YYYY-MM-DD"}, format="%Y-%m-%d")
        self.form.fields["on"].widget = date_input_widget
        self.form.fields["before"].widget = date_input_widget
        self.form.fields["after"].widget = date_input_widget
        self.form.fields["mitigated_on"].widget = date_input_widget
        self.form.fields["mitigated_before"].widget = date_input_widget
        self.form.fields["mitigated_after"].widget = date_input_widget
        self.form.fields["cwe"].choices = cwe_options(self.queryset)

    def filter_mitigated_after(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            value = value.replace(hour=23, minute=59, second=59)

        return queryset.filter(mitigated__gt=value)

    def filter_mitigated_on(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            # we have a simple date without a time, lets get a range from this morning to tonight at 23:59:59:999
            nextday = value + timedelta(days=1)
            return queryset.filter(mitigated__gte=value, mitigated__lt=nextday)

        return queryset.filter(mitigated=value)


class FindingFilterWithoutObjectLookups(FindingFilterHelper, FindingTagStringFilter):
    test__engagement__product__prod_type = NumberFilter(widget=HiddenInput())
    test__engagement__product = NumberFilter(widget=HiddenInput())
    reporter = CharFilter(
        field_name="reporter__username",
        lookup_expr="iexact",
        label="Reporter Username",
        help_text="Search for Reporter names that are an exact match")
    reporter_contains = CharFilter(
        field_name="reporter__username",
        lookup_expr="icontains",
        label="Reporter Username Contains",
        help_text="Search for Reporter names that contain a given pattern")
    reviewers = CharFilter(
        field_name="reviewers__username",
        lookup_expr="iexact",
        label="Reviewer Username",
        help_text="Search for Reviewer names that are an exact match")
    reviewers_contains = CharFilter(
        field_name="reviewers__username",
        lookup_expr="icontains",
        label="Reviewer Username Contains",
        help_text="Search for Reviewer usernames that contain a given pattern")
    test__engagement__product__prod_type__name = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="iexact",
        label="Product Type Name",
        help_text="Search for Product Type names that are an exact match")
    test__engagement__product__prod_type__name_contains = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="icontains",
        label="Product Type Name Contains",
        help_text="Search for Product Type names that contain a given pattern")
    test__engagement__product__name = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="iexact",
        label="Product Name",
        help_text="Search for Product names that are an exact match")
    test__engagement__product__name_contains = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="icontains",
        label="Product name Contains",
        help_text="Search for Product Typ names that contain a given pattern")
    test__engagement__name = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="iexact",
        label="Engagement Name",
        help_text="Search for Engagement names that are an exact match")
    test__engagement__name_contains = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="icontains",
        label="Engagement name Contains",
        help_text="Search for Engagement names that contain a given pattern")
    test__name = CharFilter(
        field_name="test__name",
        lookup_expr="iexact",
        label="Test Name",
        help_text="Search for Test names that are an exact match")
    test__name_contains = CharFilter(
        field_name="test__name",
        lookup_expr="icontains",
        label="Test name Contains",
        help_text="Search for Test names that contain a given pattern")

    if is_finding_groups_enabled():
        finding_group__name = CharFilter(
            field_name="finding_group__name",
            lookup_expr="iexact",
            label="Finding Group Name",
            help_text="Search for Finding Group names that are an exact match")
        finding_group__name_contains = CharFilter(
            field_name="finding_group__name",
            lookup_expr="icontains",
            label="Finding Group Name Contains",
            help_text="Search for Finding Group names that contain a given pattern")

    class Meta:
        model = Finding
        fields = get_finding_filterset_fields(filter_string_matching=True)

        exclude = ["url", "description", "mitigation", "impact",
                   "endpoints", "references",
                   "thread_id", "notes", "scanner_confidence",
                   "numerical_severity", "line", "duplicate_finding",
                   "hash_code", "reviewers", "created", "files",
                   "sla_start_date", "sla_expiration_date", "cvssv3",
                   "severity_justification", "steps_to_reproduce"]

    def __init__(self, *args, **kwargs):
        self.user = None
        self.pid = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")

        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")
        super().__init__(*args, **kwargs)
        # Set some date fields
        self.set_date_fields(*args, **kwargs)
        # Don't show the product filter on the product finding view
        if self.pid:
            del self.form.fields["test__engagement__product__name"]
            del self.form.fields["test__engagement__product__name_contains"]
            del self.form.fields["test__engagement__product__prod_type__name"]
            del self.form.fields["test__engagement__product__prod_type__name_contains"]
        else:
            del self.form.fields["test__name"]
            del self.form.fields["test__name_contains"]


class FindingFilter(FindingFilterHelper, FindingTagFilter):
    reporter = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.none())
    reviewers = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.none())
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label="Product Type")
    test__engagement__product__lifecycle = MultipleChoiceFilter(
        choices=Product.LIFECYCLE_CHOICES,
        label="Product lifecycle")
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(),
        label="Product")
    test__engagement = ModelMultipleChoiceFilter(
        queryset=Engagement.objects.none(),
        label="Engagement")
    test = ModelMultipleChoiceFilter(
        queryset=Test.objects.none(),
        label="Test")

    if is_finding_groups_enabled():
        finding_group = ModelMultipleChoiceFilter(
            queryset=Finding_Group.objects.none(),
            label="Finding Group")

    class Meta:
        model = Finding
        fields = get_finding_filterset_fields()

        exclude = ["url", "description", "mitigation", "impact",
                   "endpoints", "references",
                   "thread_id", "notes", "scanner_confidence",
                   "numerical_severity", "line", "duplicate_finding",
                   "hash_code", "reviewers", "created", "files",
                   "sla_start_date", "sla_expiration_date", "cvssv3",
                   "severity_justification", "steps_to_reproduce"]

    def __init__(self, *args, **kwargs):
        self.user = None
        self.pid = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")

        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")
        super().__init__(*args, **kwargs)
        # Set some date fields
        self.set_date_fields(*args, **kwargs)
        # Don't show the product filter on the product finding view
        self.set_related_object_fields(*args, **kwargs)

    def set_related_object_fields(self, *args: list, **kwargs: dict):
        if self.pid is not None:
            del self.form.fields["test__engagement__product"]
            del self.form.fields["test__engagement__product__prod_type"]
            # TODO: add authorized check to be sure
            self.form.fields["test__engagement"].queryset = Engagement.objects.filter(
                product_id=self.pid,
            ).all()
            self.form.fields["test"].queryset = get_authorized_tests(Permissions.Test_View, product=self.pid).prefetch_related("test_type")
        else:
            self.form.fields[
                "test__engagement__product__prod_type"].queryset = get_authorized_product_types(Permissions.Product_Type_View)
            self.form.fields["test__engagement"].queryset = get_authorized_engagements(Permissions.Engagement_View)
            del self.form.fields["test"]

        if self.form.fields.get("test__engagement__product"):
            self.form.fields["test__engagement__product"].queryset = get_authorized_products(Permissions.Product_View)
        if self.form.fields.get("finding_group", None):
            self.form.fields["finding_group"].queryset = get_authorized_finding_groups(Permissions.Finding_Group_View)
        self.form.fields["reporter"].queryset = get_authorized_users(Permissions.Finding_View)
        self.form.fields["reviewers"].queryset = self.form.fields["reporter"].queryset


class AcceptedFindingFilter(FindingFilter):
    risk_acceptance__created__date = DateRangeFilter(label="Acceptance Date")
    risk_acceptance__owner = ModelMultipleChoiceFilter(
            queryset=Dojo_User.objects.none(),
            label="Risk Acceptance Owner")
    risk_acceptance = ModelMultipleChoiceFilter(
        queryset=Risk_Acceptance.objects.none(),
        label="Accepted By")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["risk_acceptance__owner"].queryset = get_authorized_users(Permissions.Finding_View)
        self.form.fields["risk_acceptance"].queryset = get_authorized_risk_acceptances(Permissions.Risk_Acceptance)


class AcceptedFindingFilterWithoutObjectLookups(FindingFilterWithoutObjectLookups):
    risk_acceptance__created__date = DateRangeFilter(label="Acceptance Date")
    risk_acceptance__owner = CharFilter(
        field_name="risk_acceptance__owner__username",
        lookup_expr="iexact",
        label="Risk Acceptance Owner Username",
        help_text="Search for Risk Acceptance Owners username that are an exact match")
    risk_acceptance__owner_contains = CharFilter(
        field_name="risk_acceptance__owner__username",
        lookup_expr="icontains",
        label="Risk Acceptance Owner Username Contains",
        help_text="Search for Risk Acceptance Owners username that contain a given pattern")
    risk_acceptance__name = CharFilter(
        field_name="risk_acceptance__name",
        lookup_expr="iexact",
        label="Risk Acceptance Name",
        help_text="Search for Risk Acceptance name that are an exact match")
    risk_acceptance__name_contains = CharFilter(
        field_name="risk_acceptance__name",
        lookup_expr="icontains",
        label="Risk Acceptance Name",
        help_text="Search for Risk Acceptance name contain a given pattern")


class SimilarFindingHelper(FilterSet):
    hash_code = MultipleChoiceFilter()
    vulnerability_ids = CharFilter(method=custom_vulnerability_id_filter, label="Vulnerability Ids")

    def update_data(self, data: dict, *args: list, **kwargs: dict):
        # if filterset is bound, use initial values as defaults
        # because of this, we can't rely on the self.form.has_changed
        self.has_changed = True
        if not data and self.finding:
            # get a mutable copy of the QueryDict
            data = data.copy()

            data["vulnerability_ids"] = ",".join(self.finding.vulnerability_ids)
            data["cwe"] = self.finding.cwe
            data["file_path"] = self.finding.file_path
            data["line"] = self.finding.line
            data["unique_id_from_tool"] = self.finding.unique_id_from_tool
            data["test__test_type"] = self.finding.test.test_type
            data["test__engagement__product"] = self.finding.test.engagement.product
            data["test__engagement__product__prod_type"] = self.finding.test.engagement.product.prod_type

            self.has_changed = False

    def set_hash_codes(self, *args: list, **kwargs: dict):
        if self.finding and self.finding.hash_code:
            self.form.fields["hash_code"] = forms.MultipleChoiceField(choices=[(self.finding.hash_code, self.finding.hash_code[:24] + "...")], required=False, initial=[])

    def filter_queryset(self, *args: list, **kwargs: dict):
        queryset = super().filter_queryset(*args, **kwargs)
        queryset = get_authorized_findings(Permissions.Finding_View, queryset, self.user)
        return queryset.exclude(pk=self.finding.pk)


class SimilarFindingFilter(FindingFilter, SimilarFindingHelper):
    class Meta(FindingFilter.Meta):
        model = Finding
        # slightly different fields from FindingFilter, but keep the same ordering for UI consistency
        fields = get_finding_filterset_fields(similar=True)

    def __init__(self, data=None, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        self.finding = None
        if "finding" in kwargs:
            self.finding = kwargs.pop("finding")
        self.update_data(data, *args, **kwargs)
        super().__init__(data, *args, **kwargs)
        self.set_hash_codes(*args, **kwargs)


class SimilarFindingFilterWithoutObjectLookups(FindingFilterWithoutObjectLookups, SimilarFindingHelper):
    class Meta(FindingFilterWithoutObjectLookups.Meta):
        model = Finding
        # slightly different fields from FindingFilter, but keep the same ordering for UI consistency
        fields = get_finding_filterset_fields(similar=True, filter_string_matching=True)

    def __init__(self, data=None, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        self.finding = None
        if "finding" in kwargs:
            self.finding = kwargs.pop("finding")
        self.update_data(data, *args, **kwargs)
        super().__init__(data, *args, **kwargs)
        self.set_hash_codes(*args, **kwargs)


class TemplateFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr="icontains")
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)

    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("cwe", "cwe"),
            ("title", "title"),
            ("numerical_severity", "numerical_severity"),
        ),
        field_labels={
            "numerical_severity": "Severity",
        },
    )

    class Meta:
        model = Finding_Template
        exclude = ["description", "mitigation", "impact",
                   "references", "numerical_severity"]

    not_test__tags = ModelMultipleChoiceFilter(
        field_name="test__tags__name",
        to_field_name="name",
        exclude=True,
        label="Test without tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__tags__name",
        to_field_name="name",
        exclude=True,
        label="Engagement without tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__product__tags__name",
        to_field_name="name",
        exclude=True,
        label="Product without tags",
        queryset=Product.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["cwe"].choices = cwe_options(self.queryset)


class ApiTemplateFindingFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                             help_text="Comma separated list of exact tags")

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("title", "title"),
            ("cwe", "cwe"),
        ),
    )

    class Meta:
        model = Finding_Template
        fields = ["id", "title", "cwe", "severity", "description",
                     "mitigation"]


class MetricsFindingFilter(FindingFilter):
    start_date = DateFilter(field_name="date", label="Start Date", lookup_expr=("gt"))
    end_date = DateFilter(field_name="date", label="End Date", lookup_expr=("lt"))
    date = MetricsDateRangeFilter()
    vulnerability_id = CharFilter(method=vulnerability_id_filter, label="Vulnerability Id")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") != "" or args[0].get("end_date", "") != "":
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False

        super().__init__(*args, **kwargs)

    class Meta(FindingFilter.Meta):
        model = Finding
        fields = get_finding_filterset_fields(metrics=True)


class MetricsFindingFilterWithoutObjectLookups(FindingFilterWithoutObjectLookups):
    start_date = DateFilter(field_name="date", label="Start Date", lookup_expr=("gt"))
    end_date = DateFilter(field_name="date", label="End Date", lookup_expr=("lt"))
    date = MetricsDateRangeFilter()
    vulnerability_id = CharFilter(method=vulnerability_id_filter, label="Vulnerability Id")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") != "" or args[0].get("end_date", "") != "":
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False

        super().__init__(*args, **kwargs)

    class Meta(FindingFilterWithoutObjectLookups.Meta):
        model = Finding
        fields = get_finding_filterset_fields(metrics=True, filter_string_matching=True)


class MetricsEndpointFilterHelper(FilterSet):
    start_date = DateFilter(field_name="date", label="Start Date", lookup_expr=("gt"))
    end_date = DateFilter(field_name="date", label="End Date", lookup_expr=("lt"))
    date = MetricsDateRangeFilter()
    finding__test__engagement__version = CharFilter(lookup_expr="icontains", label="Engagement Version")
    finding__severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES, label="Severity")
    endpoint__host = CharFilter(lookup_expr="icontains", label="Endpoint Host")
    finding_title = CharFilter(lookup_expr="icontains", label="Finding Title")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)


class MetricsEndpointFilter(MetricsEndpointFilterHelper):
    finding__test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label="Product Type")
    finding__test__engagement = ModelMultipleChoiceFilter(
        queryset=Engagement.objects.none(),
        label="Engagement")
    endpoint__tags = ModelMultipleChoiceFilter(
        field_name="endpoint__tags__name",
        to_field_name="name",
        label="Endpoint tags",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    finding__tags = ModelMultipleChoiceFilter(
        field_name="finding__tags__name",
        to_field_name="name",
        label="Finding tags",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    finding__test__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__tags__name",
        to_field_name="name",
        label="Test tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    finding__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__tags__name",
        to_field_name="name",
        label="Engagement tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    finding__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__product__tags__name",
        to_field_name="name",
        label="Product tags",
        queryset=Product.tags.tag_model.objects.all().order_by("name"))
    not_endpoint__tags = ModelMultipleChoiceFilter(
        field_name="endpoint__tags__name",
        to_field_name="name",
        exclude=True,
        label="Endpoint without tags",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    not_finding__tags = ModelMultipleChoiceFilter(
        field_name="finding__tags__name",
        to_field_name="name",
        exclude=True,
        label="Finding without tags",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    not_finding__test__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__tags__name",
        to_field_name="name",
        exclude=True,
        label="Test without tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    not_finding__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__tags__name",
        to_field_name="name",
        exclude=True,
        label="Engagement without tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_finding__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__product__tags__name",
        to_field_name="name",
        exclude=True,
        label="Product without tags",
        queryset=Product.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") != "" or args[0].get("end_date", "") != "":
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False

        self.pid = None
        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")

        super().__init__(*args, **kwargs)
        if self.pid:
            del self.form.fields["finding__test__engagement__product__prod_type"]
            self.form.fields["finding__test__engagement"].queryset = Engagement.objects.filter(
                product_id=self.pid,
            ).all()
        else:
            self.form.fields["finding__test__engagement"].queryset = get_authorized_engagements(Permissions.Engagement_View).order_by("name")

        if "finding__test__engagement__product__prod_type" in self.form.fields:
            self.form.fields[
                "finding__test__engagement__product__prod_type"].queryset = get_authorized_product_types(Permissions.Product_Type_View)

    class Meta:
        model = Endpoint_Status
        exclude = ["last_modified", "endpoint", "finding"]


class MetricsEndpointFilterWithoutObjectLookups(MetricsEndpointFilterHelper, FindingTagStringFilter):
    finding__test__engagement__product__prod_type = CharFilter(
        field_name="finding__test__engagement__product__prod_type",
        lookup_expr="iexact",
        label="Product Type Name",
        help_text="Search for Product Type names that are an exact match")
    finding__test__engagement__product__prod_type_contains = CharFilter(
        field_name="finding__test__engagement__product__prod_type",
        lookup_expr="icontains",
        label="Product Type Name Contains",
        help_text="Search for Product Type names that contain a given pattern")
    finding__test__engagement = CharFilter(
        field_name="finding__test__engagement",
        lookup_expr="iexact",
        label="Engagement Name",
        help_text="Search for Engagement names that are an exact match")
    finding__test__engagement_contains = CharFilter(
        field_name="finding__test__engagement",
        lookup_expr="icontains",
        label="Engagement Name Contains",
        help_text="Search for Engagement names that contain a given pattern")
    endpoint__tags_contains = CharFilter(
        label="Endpoint Tag Contains",
        field_name="endpoint__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern")
    endpoint__tags = CharFilter(
        label="Endpoint Tag",
        field_name="endpoint__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match")
    finding__tags_contains = CharFilter(
        label="Finding Tag Contains",
        field_name="finding__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    finding__tags = CharFilter(
        label="Finding Tag",
        field_name="finding__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    finding__test__tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="finding__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    finding__test__tags = CharFilter(
        label="Test Tag",
        field_name="finding__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    finding__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Contains",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    finding__test__engagement__tags = CharFilter(
        label="Engagement Tag",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    finding__test__engagement__product__tags_contains = CharFilter(
        label="Product Tag Contains",
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    finding__test__engagement__product__tags = CharFilter(
        label="Product Tag",
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")

    not_endpoint__tags_contains = CharFilter(
        label="Endpoint Tag Does Not Contain",
        field_name="endpoint__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern, and exclude them",
        exclude=True)
    not_endpoint__tags = CharFilter(
        label="Not Endpoint Tag",
        field_name="endpoint__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match, and exclude them",
        exclude=True)
    not_finding__tags_contains = CharFilter(
        label="Finding Tag Does Not Contain",
        field_name="finding__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_finding__tags = CharFilter(
        label="Not Finding Tag",
        field_name="finding__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match, and exclude them",
        exclude=True)
    not_finding__test__tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="finding__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_finding__test__tags = CharFilter(
        label="Not Test Tag",
        field_name="finding__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)
    not_finding__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Does Not Contain",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_finding__test__engagement__tags = CharFilter(
        label="Not Engagement Tag",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Engagement that are an exact match, and exclude them",
        exclude=True)
    not_finding__test__engagement__product__tags_contains = CharFilter(
        label="Product Tag Does Not Contain",
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Product that contain a given pattern, and exclude them",
        exclude=True)
    not_finding__test__engagement__product__tags = CharFilter(
        label="Not Product Tag",
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Product that are an exact match, and exclude them",
        exclude=True)

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") != "" or args[0].get("end_date", "") != "":
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False
        self.pid = None
        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")
        super().__init__(*args, **kwargs)
        if self.pid:
            del self.form.fields["finding__test__engagement__product__prod_type"]

    class Meta:
        model = Endpoint_Status
        exclude = ["last_modified", "endpoint", "finding"]


class EndpointFilterHelper(FilterSet):
    protocol = CharFilter(lookup_expr="icontains")
    userinfo = CharFilter(lookup_expr="icontains")
    host = CharFilter(lookup_expr="icontains")
    port = NumberFilter()
    path = CharFilter(lookup_expr="icontains")
    query = CharFilter(lookup_expr="icontains")
    fragment = CharFilter(lookup_expr="icontains")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("product", "product"),
            ("host", "host"),
            ("id", "id"),
        ),
    )


class EndpointFilter(EndpointFilterHelper, DojoFilter):
    product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(),
        label="Product")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        label="Endpoint Tags",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    findings__tags = ModelMultipleChoiceFilter(
        field_name="findings__tags__name",
        to_field_name="name",
        label="Finding Tags",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    findings__test__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__tags__name",
        to_field_name="name",
        label="Test Tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    findings__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__tags__name",
        to_field_name="name",
        label="Engagement Tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    findings__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__product__tags__name",
        to_field_name="name",
        label="Product Tags",
        queryset=Product.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        label="Not Endpoint Tags",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    not_findings__tags = ModelMultipleChoiceFilter(
        field_name="findings__tags__name",
        to_field_name="name",
        label="Not Finding Tags",
        exclude=True,
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__tags__name",
        to_field_name="name",
        label="Not Test Tags",
        exclude=True,
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__tags__name",
        to_field_name="name",
        label="Not Engagement Tags",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__product__tags__name",
        to_field_name="name",
        label="Not Product Tags",
        exclude=True,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.form.fields["product"].queryset = get_authorized_products(Permissions.Product_View)

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_endpoints(Permissions.Endpoint_View, parent)

    class Meta:
        model = Endpoint
        exclude = ["findings", "inherited_tags"]


class EndpointFilterWithoutObjectLookups(EndpointFilterHelper):
    product = NumberFilter(widget=HiddenInput())
    product__name = CharFilter(
        field_name="product__name",
        lookup_expr="iexact",
        label="Product Name",
        help_text="Search for Product names that are an exact match")
    product__name_contains = CharFilter(
        field_name="product__name",
        lookup_expr="icontains",
        label="Product Name Contains",
        help_text="Search for Product names that contain a given pattern")

    tags_contains = CharFilter(
        label="Endpoint Tag Contains",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern")
    tags = CharFilter(
        label="Endpoint Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match")
    findings__tags_contains = CharFilter(
        label="Finding Tag Contains",
        field_name="findings__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__tags = CharFilter(
        label="Finding Tag",
        field_name="findings__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="findings__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__test__tags = CharFilter(
        label="Test Tag",
        field_name="findings__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Contains",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__test__engagement__tags = CharFilter(
        label="Engagement Tag",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__engagement__product__tags_contains = CharFilter(
        label="Product Tag Contains",
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__test__engagement__product__tags = CharFilter(
        label="Product Tag",
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")

    not_tags_contains = CharFilter(
        label="Endpoint Tag Does Not Contain",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern, and exclude them",
        exclude=True)
    not_tags = CharFilter(
        label="Not Endpoint Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match, and exclude them",
        exclude=True)
    not_findings__tags_contains = CharFilter(
        label="Finding Tag Does Not Contain",
        field_name="findings__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__tags = CharFilter(
        label="Not Finding Tag",
        field_name="findings__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="findings__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__test__tags = CharFilter(
        label="Not Test Tag",
        field_name="findings__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Does Not Contain",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__test__engagement__tags = CharFilter(
        label="Not Engagement Tag",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Engagement that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__engagement__product__tags_contains = CharFilter(
        label="Product Tag Does Not Contain",
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Product that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__test__engagement__product__tags = CharFilter(
        label="Not Product Tag",
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Product that are an exact match, and exclude them",
        exclude=True)

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_endpoints(Permissions.Endpoint_View, parent)

    class Meta:
        model = Endpoint
        exclude = ["findings", "inherited_tags", "product"]


class ApiEndpointFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                             help_text="Comma separated list of exact tags")

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("host", "host"),
            ("product", "product"),
            ("id", "id"),
        ),
    )

    class Meta:
        model = Endpoint
        fields = ["id", "protocol", "userinfo", "host", "port", "path", "query", "fragment", "product"]


class ApiRiskAcceptanceFilter(DojoFilter):
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Risk_Acceptance
        fields = [
            "name", "accepted_findings", "recommendation", "recommendation_details",
            "decision", "decision_details", "accepted_by", "owner", "expiration_date",
            "expiration_date_warned", "expiration_date_handled", "reactivate_expired",
            "restart_sla_expired", "notes",
        ]


class EngagementTestFilterHelper(FilterSet):
    version = CharFilter(lookup_expr="icontains", label="Version")
    if settings.TRACK_IMPORT_HISTORY:
        test_import__version = CharFilter(field_name="test_import__version", lookup_expr="icontains", label="Reimported Version")
    target_start = DateRangeFilter()
    target_end = DateRangeFilter()
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("title", "title"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("lead", "lead"),
            ("api_scan_configuration", "api_scan_configuration"),
        ),
        field_labels={
            "name": "Test Name",
        },
    )


class EngagementTestFilter(EngagementTestFilterHelper, DojoFilter):
    lead = ModelChoiceFilter(queryset=Dojo_User.objects.none(), label="Lead")
    api_scan_configuration = ModelChoiceFilter(
        queryset=Product_API_Scan_Configuration.objects.none(),
        label="API Scan Configuration")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Test.tags.tag_model.objects.all().order_by("name"))

    class Meta:
        model = Test
        fields = [
            "title", "test_type", "target_start",
            "target_end", "percent_complete",
            "version", "api_scan_configuration",
        ]

    def __init__(self, *args, **kwargs):
        self.engagement = kwargs.pop("engagement")
        super(DojoFilter, self).__init__(*args, **kwargs)
        self.form.fields["test_type"].queryset = Test_Type.objects.filter(test__engagement=self.engagement).distinct().order_by("name")
        self.form.fields["api_scan_configuration"].queryset = Product_API_Scan_Configuration.objects.filter(product=self.engagement.product).distinct()
        self.form.fields["lead"].queryset = get_authorized_users(Permissions.Product_Type_View) \
            .filter(test__lead__isnull=False).distinct()


class EngagementTestFilterWithoutObjectLookups(EngagementTestFilterHelper):
    lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    lead_contains = CharFilter(
        field_name="lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")
    api_scan_configuration__tool_configuration__name = CharFilter(
        field_name="api_scan_configuration__tool_configuration__name",
        lookup_expr="iexact",
        label="API Scan Configuration Name",
        help_text="Search for Lead username that are an exact match")
    api_scan_configuration__tool_configuration__name_contains = CharFilter(
        field_name="api_scan_configuration__tool_configuration__name",
        lookup_expr="icontains",
        label="API Scan Configuration Name Contains",
        help_text="Search for Lead username that contain a given pattern")
    tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern")
    tags = CharFilter(
        label="Test Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match")
    not_tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_tags = CharFilter(
        label="Not Test Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)

    class Meta:
        model = Test
        fields = [
            "title", "test_type", "target_start",
            "target_end", "percent_complete", "version",
        ]

    def __init__(self, *args, **kwargs):
        self.engagement = kwargs.pop("engagement")
        super().__init__(*args, **kwargs)
        self.form.fields["test_type"].queryset = Test_Type.objects.filter(test__engagement=self.engagement).distinct().order_by("name")


class ApiTestFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                             help_text="Comma separated list of exact tags")
    engagement__tags = CharFieldInFilter(field_name="engagement__tags__name", lookup_expr="in",
                                               help_text="Comma separated list of exact tags present on engagement")
    engagement__product__tags = CharFieldInFilter(field_name="engagement__product__tags__name",
                                                              lookup_expr="in",
                                                              help_text="Comma separated list of exact tags present on product")

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    not_engagement__tags = CharFieldInFilter(field_name="engagement__tags__name", lookup_expr="in",
                                                   help_text="Comma separated list of exact tags not present on engagement",
                                                   exclude="True")
    not_engagement__product__tags = CharFieldInFilter(field_name="engagement__product__tags__name",
                                                                  lookup_expr="in",
                                                                  help_text="Comma separated list of exact tags not present on product",
                                                                  exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("title", "title"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("test_type", "test_type"),
            ("lead", "lead"),
            ("version", "version"),
            ("branch_tag", "branch_tag"),
            ("build_id", "build_id"),
            ("commit_hash", "commit_hash"),
            ("api_scan_configuration", "api_scan_configuration"),
            ("engagement", "engagement"),
            ("created", "created"),
            ("updated", "updated"),
        ),
        field_labels={
            "name": "Test Name",
        },
    )

    class Meta:
        model = Test
        fields = ["id", "title", "test_type", "target_start",
                     "target_end", "notes", "percent_complete",
                     "actual_time", "engagement", "version",
                     "branch_tag", "build_id", "commit_hash",
                     "api_scan_configuration", "scan_type"]


class ApiAppAnalysisFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                             help_text="Comma separated list of exact tags")

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")

    class Meta:
        model = App_Analysis
        fields = ["product", "name", "user", "version"]


class ApiCredentialsFilter(DojoFilter):
    class Meta:
        model = Cred_Mapping
        fields = "__all__"


class EndpointReportFilter(DojoFilter):
    protocol = CharFilter(lookup_expr="icontains")
    userinfo = CharFilter(lookup_expr="icontains")
    host = CharFilter(lookup_expr="icontains")
    port = NumberFilter()
    path = CharFilter(lookup_expr="icontains")
    query = CharFilter(lookup_expr="icontains")
    fragment = CharFilter(lookup_expr="icontains")
    finding__severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES, label="Severity")
    finding__mitigated = ReportBooleanFilter(label="Finding Mitigated")

    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    class Meta:
        model = Endpoint
        exclude = ["product"]


class ReportFindingFilterHelper(FilterSet):
    title = CharFilter(lookup_expr="icontains", label="Name")
    date = DateFromToRangeFilter(field_name="date", label="Date Discovered")
    date_recent = DateRangeFilter(field_name="date", label="Relative Date")
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    active = ReportBooleanFilter()
    is_mitigated = ReportBooleanFilter()
    mitigated = DateRangeFilter(label="Mitigated Date")
    verified = ReportBooleanFilter()
    false_p = ReportBooleanFilter(label="False Positive")
    risk_acceptance = ReportRiskAcceptanceFilter(label="Risk Accepted")
    duplicate = ReportBooleanFilter()
    out_of_scope = ReportBooleanFilter()
    outside_of_sla = FindingSLAFilter(label="Outside of SLA")
    file_path = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        fields=(
            ("title", "title"),
            ("date", "date"),
            ("numerical_severity", "numerical_severity"),
            ("epss_score", "epss_score"),
            ("epss_percentile", "epss_percentile"),
            ("test__engagement__product__name", "test__engagement__product__name"),
        ),
    )

    class Meta:
        model = Finding
        # exclude sonarqube issue as by default it will show all without checking permissions
        exclude = ["date", "cwe", "url", "description", "mitigation", "impact",
                   "references", "sonarqube_issue", "duplicate_finding",
                   "thread_id", "notes", "inherited_tags", "endpoints",
                   "numerical_severity", "reporter", "last_reviewed",
                   "jira_creation", "jira_change", "files"]

    def manage_kwargs(self, kwargs):
        self.prod_type = None
        self.product = None
        self.engagement = None
        self.test = None
        if "prod_type" in kwargs:
            self.prod_type = kwargs.pop("prod_type")
        if "product" in kwargs:
            self.product = kwargs.pop("product")
        if "engagement" in kwargs:
            self.engagement = kwargs.pop("engagement")
        if "test" in kwargs:
            self.test = kwargs.pop("test")

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_findings(Permissions.Finding_View, parent)


class ReportFindingFilter(ReportFindingFilterHelper, FindingTagFilter):
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(), label="Product")
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label="Product Type")
    test__engagement__product__lifecycle = MultipleChoiceFilter(choices=Product.LIFECYCLE_CHOICES, label="Product Lifecycle")
    test__engagement = ModelMultipleChoiceFilter(queryset=Engagement.objects.none(), label="Engagement")
    duplicate_finding = ModelChoiceFilter(queryset=Finding.objects.filter(original_finding__isnull=False).distinct())

    def __init__(self, *args, **kwargs):
        self.manage_kwargs(kwargs)
        super().__init__(*args, **kwargs)

        # duplicate_finding queryset needs to restricted in line with permissions
        # and inline with report scope to avoid a dropdown with 100K entries
        duplicate_finding_query_set = self.form.fields["duplicate_finding"].queryset
        duplicate_finding_query_set = get_authorized_findings(Permissions.Finding_View, duplicate_finding_query_set)

        if self.test:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test=self.test)
            del self.form.fields["test__tags"]
            del self.form.fields["test__engagement__tags"]
            del self.form.fields["test__engagement__product__tags"]
        if self.engagement:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test__engagement=self.engagement)
            del self.form.fields["test__engagement__tags"]
            del self.form.fields["test__engagement__product__tags"]
        elif self.product:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test__engagement__product=self.product)
            del self.form.fields["test__engagement__product"]
            del self.form.fields["test__engagement__product__tags"]
        elif self.prod_type:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test__engagement__product__prod_type=self.prod_type)
            del self.form.fields["test__engagement__product__prod_type"]

        self.form.fields["duplicate_finding"].queryset = duplicate_finding_query_set

        if "test__engagement__product__prod_type" in self.form.fields:
            self.form.fields[
                "test__engagement__product__prod_type"].queryset = get_authorized_product_types(Permissions.Product_Type_View)
        if "test__engagement__product" in self.form.fields:
            self.form.fields[
                "test__engagement__product"].queryset = get_authorized_products(Permissions.Product_View)
        if "test__engagement" in self.form.fields:
            self.form.fields["test__engagement"].queryset = get_authorized_engagements(Permissions.Engagement_View)


class ReportFindingFilterWithoutObjectLookups(ReportFindingFilterHelper, FindingTagStringFilter):
    test__engagement__product__prod_type = NumberFilter(widget=HiddenInput())
    test__engagement__product = NumberFilter(widget=HiddenInput())
    test__engagement = NumberFilter(widget=HiddenInput())
    test = NumberFilter(widget=HiddenInput())
    endpoint = NumberFilter(widget=HiddenInput())
    reporter = CharFilter(
        field_name="reporter__username",
        lookup_expr="iexact",
        label="Reporter Username",
        help_text="Search for Reporter names that are an exact match")
    reporter_contains = CharFilter(
        field_name="reporter__username",
        lookup_expr="icontains",
        label="Reporter Username Contains",
        help_text="Search for Reporter names that contain a given pattern")
    reviewers = CharFilter(
        field_name="reviewers__username",
        lookup_expr="iexact",
        label="Reviewer Username",
        help_text="Search for Reviewer names that are an exact match")
    reviewers_contains = CharFilter(
        field_name="reviewers__username",
        lookup_expr="icontains",
        label="Reviewer Username Contains",
        help_text="Search for Reviewer usernames that contain a given pattern")
    last_reviewed_by = CharFilter(
        field_name="last_reviewed_by__username",
        lookup_expr="iexact",
        label="Last Reviewed By Username",
        help_text="Search for Last Reviewed By names that are an exact match")
    last_reviewed_by_contains = CharFilter(
        field_name="last_reviewed_by__username",
        lookup_expr="icontains",
        label="Last Reviewed By Username Contains",
        help_text="Search for Last Reviewed By usernames that contain a given pattern")
    review_requested_by = CharFilter(
        field_name="review_requested_by__username",
        lookup_expr="iexact",
        label="Review Requested By Username",
        help_text="Search for Review Requested By names that are an exact match")
    review_requested_by_contains = CharFilter(
        field_name="review_requested_by__username",
        lookup_expr="icontains",
        label="Review Requested By Username Contains",
        help_text="Search for Review Requested By usernames that contain a given pattern")
    mitigated_by = CharFilter(
        field_name="mitigated_by__username",
        lookup_expr="iexact",
        label="Mitigator Username",
        help_text="Search for Mitigator names that are an exact match")
    mitigated_by_contains = CharFilter(
        field_name="mitigated_by__username",
        lookup_expr="icontains",
        label="Mitigator Username Contains",
        help_text="Search for Mitigator usernames that contain a given pattern")
    defect_review_requested_by = CharFilter(
        field_name="defect_review_requested_by__username",
        lookup_expr="iexact",
        label="Requester of Defect Review Username",
        help_text="Search for Requester of Defect Review names that are an exact match")
    defect_review_requested_by_contains = CharFilter(
        field_name="defect_review_requested_by__username",
        lookup_expr="icontains",
        label="Requester of Defect Review Username Contains",
        help_text="Search for Requester of Defect Review usernames that contain a given pattern")
    test__engagement__product__prod_type__name = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="iexact",
        label="Product Type Name",
        help_text="Search for Product Type names that are an exact match")
    test__engagement__product__prod_type__name_contains = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="icontains",
        label="Product Type Name Contains",
        help_text="Search for Product Type names that contain a given pattern")
    test__engagement__product__name = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="iexact",
        label="Product Name",
        help_text="Search for Product names that are an exact match")
    test__engagement__product__name_contains = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="icontains",
        label="Product name Contains",
        help_text="Search for Product names that contain a given pattern")
    test__engagement__name = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="iexact",
        label="Engagement Name",
        help_text="Search for Engagement names that are an exact match")
    test__engagement__name_contains = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="icontains",
        label="Engagement name Contains",
        help_text="Search for Engagement names that contain a given pattern")
    test__name = CharFilter(
        field_name="test__name",
        lookup_expr="iexact",
        label="Test Name",
        help_text="Search for Test names that are an exact match")
    test__name_contains = CharFilter(
        field_name="test__name",
        lookup_expr="icontains",
        label="Test name Contains",
        help_text="Search for Test names that contain a given pattern")

    def __init__(self, *args, **kwargs):
        self.manage_kwargs(kwargs)
        super().__init__(*args, **kwargs)

        product_type_refs = [
            "test__engagement__product__prod_type__name",
            "test__engagement__product__prod_type__name_contains",
        ]
        product_refs = [
            "test__engagement__product__name",
            "test__engagement__product__name_contains",
            "test__engagement__product__tags",
            "test__engagement__product__tags_contains",
            "not_test__engagement__product__tags",
            "not_test__engagement__product__tags_contains",
        ]
        engagement_refs = [
            "test__engagement__name",
            "test__engagement__name_contains",
            "test__engagement__tags",
            "test__engagement__tags_contains",
            "not_test__engagement__tags",
            "not_test__engagement__tags_contains",
        ]
        test_refs = [
            "test__name",
            "test__name_contains",
            "test__tags",
            "test__tags_contains",
            "not_test__tags",
            "not_test__tags_contains",
        ]

        if self.test:
            self.delete_tags_from_form(product_type_refs)
            self.delete_tags_from_form(product_refs)
            self.delete_tags_from_form(engagement_refs)
            self.delete_tags_from_form(test_refs)
        elif self.engagement:
            self.delete_tags_from_form(product_type_refs)
            self.delete_tags_from_form(product_refs)
            self.delete_tags_from_form(engagement_refs)
        elif self.product:
            self.delete_tags_from_form(product_type_refs)
            self.delete_tags_from_form(product_refs)
        elif self.prod_type:
            self.delete_tags_from_form(product_type_refs)


class UserFilter(DojoFilter):
    first_name = CharFilter(lookup_expr="icontains")
    last_name = CharFilter(lookup_expr="icontains")
    username = CharFilter(lookup_expr="icontains")
    email = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("username", "username"),
            ("last_name", "last_name"),
            ("first_name", "first_name"),
            ("email", "email"),
            ("is_active", "is_active"),
            ("is_superuser", "is_superuser"),
            ("date_joined", "date_joined"),
            ("last_login", "last_login"),
        ),
        field_labels={
            "username": "User Name",
            "is_active": "Active",
            "is_superuser": "Superuser",
        },
    )

    class Meta:
        model = Dojo_User
        fields = ["is_superuser", "is_active", "first_name", "last_name", "username", "email"]


class GroupFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")
    description = CharFilter(lookup_expr="icontains")

    class Meta:
        model = Dojo_Group
        fields = ["name", "description"]
        exclude = ["users"]


# This class is used exclusively by Findings
class TestImportFilter(DojoFilter):
    version = CharFilter(field_name="version", lookup_expr="icontains")
    version_exact = CharFilter(field_name="version", lookup_expr="iexact", label="Version Exact")
    branch_tag = CharFilter(lookup_expr="icontains", label="Branch/Tag")
    build_id = CharFilter(lookup_expr="icontains", label="Build ID")
    commit_hash = CharFilter(lookup_expr="icontains", label="Commit hash")

    findings_affected = BooleanFilter(field_name="findings_affected", lookup_expr="isnull", exclude=True, label="Findings affected")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("date", "date"),
            ("version", "version"),
            ("branch_tag", "branch_tag"),
            ("build_id", "build_id"),
            ("commit_hash", "commit_hash"),

        ),
    )

    class Meta:
        model = Test_Import
        fields = []


# This class is used exclusively by Findings
class TestImportFindingActionFilter(DojoFilter):
    action = MultipleChoiceFilter(choices=IMPORT_ACTIONS)
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("action", "action"),
        ),
    )

    class Meta:
        model = Test_Import_Finding_Action
        fields = []


# Used within the TestImport API
class TestImportAPIFilter(DojoFilter):
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("id", "id"),
            ("created", "created"),
            ("modified", "modified"),
            ("version", "version"),
            ("branch_tag", "branch_tag"),
            ("build_id", "build_id"),
            ("commit_hash", "commit_hash"),

        ),
    )

    class Meta:
        model = Test_Import
        fields = ["test",
        "findings_affected",
        "version",
        "branch_tag",
        "build_id",
        "commit_hash",
        "test_import_finding_action__action",
        "test_import_finding_action__finding",
        "test_import_finding_action__created"]


class LogEntryFilter(DojoFilter):
    from auditlog.models import LogEntry

    action = MultipleChoiceFilter(choices=LogEntry.Action.choices)
    actor = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.none())
    timestamp = DateRangeFilter()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["actor"].queryset = get_authorized_users(Permissions.Product_View)

    class Meta:
        model = LogEntry
        exclude = ["content_type", "object_pk", "object_id", "object_repr",
                   "changes", "additional_data", "remote_addr"]
        filter_overrides = {
            JSONField: {
                "filter_class": CharFilter,
                "extra": lambda _: {
                    "lookup_expr": "icontains",
                },
            },
        }


class ProductTypeFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Product_Type
        exclude = []
        include = ("name",)


class TestTypeFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Test_Type
        exclude = []
        include = ("name",)


class DevelopmentEnvironmentFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Development_Environment
        exclude = []
        include = ("name",)


class NoteTypesFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("description", "description"),
            ("is_single", "is_single"),
            ("is_mandatory", "is_mandatory"),
        ),
    )

    class Meta:
        model = Note_Type
        exclude = []
        include = ("name", "is_single", "description")

# ==============================
# Defect Dojo Engaegment Surveys
# ==============================


class QuestionnaireFilter(FilterSet):
    name = CharFilter(lookup_expr="icontains")
    description = CharFilter(lookup_expr="icontains")
    active = BooleanFilter()

    class Meta:
        model = Engagement_Survey
        exclude = ["questions"]

    survey_set = FilterSet


class QuestionTypeFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs.all()

    def text_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(TextQuestion))

    def choice_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(ChoiceQuestion))

    options = {
        None: (_("Any"), any),
        1: (_("Text Question"), text_question),
        2: (_("Choice Question"), choice_question),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.options[value][0])


with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class QuestionFilter(FilterSet):
        text = CharFilter(lookup_expr="icontains")
        type = QuestionTypeFilter()

        class Meta:
            model = Question
            exclude = ["polymorphic_ctype", "created", "modified", "order"]

        question_set = FilterSet
