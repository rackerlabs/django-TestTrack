import base64
import copy
import hashlib
import logging
import os
import re
import warnings
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import hyperlink
import tagulous.admin
from auditlog.registry import auditlog
from cvss import CVSS3
from dateutil.relativedelta import relativedelta
from django import forms
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator, validate_ipv46_address
from django.db import connection, models
from django.db.models import Count, JSONField, Q
from django.db.models.expressions import Case, When
from django.db.models.functions import Lower
from django.urls import reverse
from django.utils import timezone
from django.utils.deconstruct import deconstructible
from django.utils.functional import cached_property
from django.utils.html import escape
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django_extensions.db.models import TimeStampedModel
from multiselectfield import MultiSelectField
from polymorphic.base import ManagerInheritanceWarning
from polymorphic.managers import PolymorphicManager
from polymorphic.models import PolymorphicModel
from pytz import all_timezones
from tagulous.models import TagField
from tagulous.models.managers import FakeTagRelatedManager

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

SEVERITY_CHOICES = (("Info", "Info"), ("Low", "Low"), ("Medium", "Medium"),
                    ("High", "High"), ("Critical", "Critical"))

SEVERITIES = [s[0] for s in SEVERITY_CHOICES]

EFFORT_FOR_FIXING_CHOICES = (("", ""), ("Low", "Low"), ("Medium", "Medium"), ("High", "High"))

# fields returned in statistics, typically all status fields
STATS_FIELDS = ["active", "verified", "duplicate", "false_p", "out_of_scope", "is_mitigated", "risk_accepted", "total"]
# default template with all values set to 0
DEFAULT_STATS = {sev.lower(): dict.fromkeys(STATS_FIELDS, 0) for sev in SEVERITIES}

IMPORT_CREATED_FINDING = "N"
IMPORT_CLOSED_FINDING = "C"
IMPORT_REACTIVATED_FINDING = "R"
IMPORT_UNTOUCHED_FINDING = "U"

IMPORT_ACTIONS = [
    (IMPORT_CREATED_FINDING, "created"),
    (IMPORT_CLOSED_FINDING, "closed"),
    (IMPORT_REACTIVATED_FINDING, "reactivated"),
    (IMPORT_UNTOUCHED_FINDING, "left untouched"),
]


def _get_annotations_for_statistics():
    annotations = {stats_field.lower(): Count(Case(When(**{stats_field: True}, then=1))) for stats_field in STATS_FIELDS if stats_field != "total"}
    # add total
    annotations["total"] = Count("id")
    return annotations


def _get_statistics_for_queryset(qs, annotation_factory):
    # order by to get rid of default ordering that would mess with group_by
    # group by severity (lowercase)
    values = qs.annotate(sev=Lower("severity")).values("sev").order_by()
    # add annotation for each status field
    values = values.annotate(**annotation_factory())
    # make sure sev and total are included
    stat_fields = ["sev", "total", *STATS_FIELDS]
    # go for it
    values = values.values(*stat_fields)

    # not sure if there's a smarter way to convert a list of dicts into a dict of dicts
    # need to copy the DEFAULT_STATS otherwise it gets overwritten
    stats = copy.copy(DEFAULT_STATS)
    for row in values:
        sev = row.pop("sev")
        stats[sev] = row

    values_total = qs.values()
    values_total = values_total.aggregate(**annotation_factory())
    stats["total"] = values_total
    return stats


def _manage_inherited_tags(obj, incoming_inherited_tags, potentially_existing_tags=[]):
    # get copies of the current tag lists
    current_inherited_tags = [] if isinstance(obj.inherited_tags, FakeTagRelatedManager) else [tag.name for tag in obj.inherited_tags.all()]
    tag_list = potentially_existing_tags if isinstance(obj.tags, FakeTagRelatedManager) or len(potentially_existing_tags) > 0 else [tag.name for tag in obj.tags.all()]
    # Clean existing tag list from the old inherited tags. This represents the tags on the object and not the product
    cleaned_tag_list = [tag for tag in tag_list if tag not in current_inherited_tags]
    # Add the incoming inherited tag list
    if incoming_inherited_tags:
        for tag in incoming_inherited_tags:
            if tag not in cleaned_tag_list:
                cleaned_tag_list.append(tag)
    # Update the current list of inherited tags. iteratively do this because of tagulous object restraints
    if isinstance(obj.inherited_tags, FakeTagRelatedManager):
        obj.inherited_tags.set_tag_list(incoming_inherited_tags)
        if incoming_inherited_tags:
            obj.tags.set_tag_list(cleaned_tag_list)
    else:
        obj.inherited_tags.set(incoming_inherited_tags)
        if incoming_inherited_tags:
            obj.tags.set(cleaned_tag_list)


@deconstructible
class UniqueUploadNameProvider:

    """
    A callable to be passed as upload_to parameter to FileField.

    Uploaded files will get random names based on UUIDs inside the given directory;
    strftime-style formatting is supported within the directory path. If keep_basename
    is True, the original file name is prepended to the UUID. If keep_ext is disabled,
    the filename extension will be dropped.
    """

    def __init__(self, directory=None, keep_basename=False, keep_ext=True):
        self.directory = directory
        self.keep_basename = keep_basename
        self.keep_ext = keep_ext

    def __call__(self, model_instance, filename):
        path = Path(filename)
        base = path.parent / path.stem
        ext = path.suffix
        filename = f"{base}_{uuid4()}" if self.keep_basename else str(uuid4())
        if self.keep_ext:
            filename += ext
        if self.directory is None:
            return filename
        return os.path.join(now().strftime(self.directory), filename)


class Regulation(models.Model):
    PRIVACY_CATEGORY = "privacy"
    FINANCE_CATEGORY = "finance"
    EDUCATION_CATEGORY = "education"
    MEDICAL_CATEGORY = "medical"
    CORPORATE_CATEGORY = "corporate"
    OTHER_CATEGORY = "other"
    CATEGORY_CHOICES = (
        (PRIVACY_CATEGORY, _("Privacy")),
        (FINANCE_CATEGORY, _("Finance")),
        (EDUCATION_CATEGORY, _("Education")),
        (MEDICAL_CATEGORY, _("Medical")),
        (CORPORATE_CATEGORY, _("Corporate")),
        (OTHER_CATEGORY, _("Other")),
    )

    name = models.CharField(max_length=128, unique=True, help_text=_("The name of the regulation."))
    acronym = models.CharField(max_length=20, unique=True, help_text=_("A shortened representation of the name."))
    category = models.CharField(max_length=9, choices=CATEGORY_CHOICES, help_text=_("The subject of the regulation."))
    jurisdiction = models.CharField(max_length=64, help_text=_("The territory over which the regulation applies."))
    description = models.TextField(blank=True, help_text=_("Information about the regulation's purpose."))
    reference = models.URLField(blank=True, help_text=_("An external URL for more information."))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.acronym + " (" + self.jurisdiction + ")"


User = get_user_model()


# proxy class for convenience and UI
class Dojo_User(User):
    class Meta:
        proxy = True
        ordering = ["first_name"]

    def get_full_name(self):
        return Dojo_User.generate_full_name(self)

    def __str__(self):
        return self.get_full_name()

    @staticmethod
    def wants_block_execution(user):
        # this return False if there is no user, i.e. in celery processes, unittests, etc.
        return hasattr(user, "usercontactinfo") and user.usercontactinfo.block_execution

    @staticmethod
    def force_password_reset(user):
        return hasattr(user, "usercontactinfo") and user.usercontactinfo.force_password_reset

    def disable_force_password_reset(user):
        if hasattr(user, "usercontactinfo"):
            user.usercontactinfo.force_password_reset = False
            user.usercontactinfo.save()

    def enable_force_password_reset(user):
        if hasattr(user, "usercontactinfo"):
            user.usercontactinfo.force_password_reset = True
            user.usercontactinfo.save()

    @staticmethod
    def generate_full_name(user):
        """Returns the first_name plus the last_name, with a space in between."""
        full_name = f"{user.first_name} {user.last_name} ({user.username})"
        return full_name.strip()


class UserContactInfo(models.Model):
    user = models.OneToOneField(Dojo_User, on_delete=models.CASCADE)
    title = models.CharField(blank=True, null=True, max_length=150)
    phone_regex = RegexValidator(regex=r"^\+?1?\d{9,15}$",
                                 message=_("Phone number must be entered in the format: '+999999999'. "
                                         "Up to 15 digits allowed."))
    phone_number = models.CharField(validators=[phone_regex], blank=True,
                                    max_length=15,
                                    help_text=_("Phone number must be entered in the format: '+999999999'. "
                                              "Up to 15 digits allowed."))
    cell_number = models.CharField(validators=[phone_regex], blank=True,
                                   max_length=15,
                                   help_text=_("Phone number must be entered in the format: '+999999999'. "
                                             "Up to 15 digits allowed."))
    twitter_username = models.CharField(blank=True, null=True, max_length=150)
    github_username = models.CharField(blank=True, null=True, max_length=150)
    slack_username = models.CharField(blank=True, null=True, max_length=150, help_text=_("Email address associated with your slack account"), verbose_name=_("Slack Email Address"))
    slack_user_id = models.CharField(blank=True, null=True, max_length=25)
    block_execution = models.BooleanField(default=False, help_text=_("Instead of async deduping a finding the findings will be deduped synchronously and will 'block' the user until completion."))
    force_password_reset = models.BooleanField(default=False, help_text=_("Forces this user to reset their password on next login."))


class Dojo_Group(models.Model):
    AZURE = "AzureAD"
    REMOTE = "Remote"
    SOCIAL_CHOICES = (
        (AZURE, _("AzureAD")),
        (REMOTE, _("Remote")),
    )
    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000, null=True, blank=True)
    users = models.ManyToManyField(Dojo_User, through="Dojo_Group_Member", related_name="users", blank=True)
    auth_group = models.ForeignKey(Group, null=True, blank=True, on_delete=models.CASCADE)
    social_provider = models.CharField(max_length=10, choices=SOCIAL_CHOICES, blank=True, null=True, help_text=_("Group imported from a social provider."), verbose_name=_("Social Authentication Provider"))

    def __str__(self):
        return self.name


class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    is_owner = models.BooleanField(default=False)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class System_Settings(models.Model):
    enable_deduplication = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Deduplicate findings"),
        help_text=_("With this setting turned on, DefectDojo deduplicates findings by "
                  "comparing endpoints, cwe fields, and titles. "
                  "If two findings share a URL and have the same CWE or "
                  "title, DefectDojo marks the recent finding as a duplicate. "
                  "When deduplication is enabled, a list of "
                  "deduplicated findings is added to the engagement view."))
    delete_duplicates = models.BooleanField(default=False, blank=False, help_text=_("Requires next setting: maximum number of duplicates to retain."))
    max_dupes = models.IntegerField(blank=True, null=True, default=10,
                                    verbose_name=_("Max Duplicates"),
                                    help_text=_("When enabled, if a single "
                                              "issue reaches the maximum "
                                              "number of duplicates, the "
                                              "oldest will be deleted. Duplicate will not be deleted when left empty. A value of 0 will remove all duplicates."))

    email_from = models.CharField(max_length=200, default="no-reply@example.com", blank=True)

    enable_jira = models.BooleanField(default=False,
                                      verbose_name=_("Enable JIRA integration"),
                                      blank=False)

    enable_jira_web_hook = models.BooleanField(default=False,
                                      verbose_name=_("Enable JIRA web hook"),
                                      help_text=_("Please note: It is strongly recommended to use a secret below and / or IP whitelist the JIRA server using a proxy such as Nginx."),
                                      blank=False)

    disable_jira_webhook_secret = models.BooleanField(default=False,
                                      verbose_name=_("Disable web hook secret"),
                                      help_text=_("Allows incoming requests without a secret (discouraged legacy behaviour)"),
                                      blank=False)

    # will be set to random / uuid by initializer so null needs to be True
    jira_webhook_secret = models.CharField(max_length=64, blank=False, null=True, verbose_name=_("JIRA Webhook URL"),
                                           help_text=_("Secret needed in URL for incoming JIRA Webhook"))

    jira_choices = (("Critical", "Critical"),
                    ("High", "High"),
                    ("Medium", "Medium"),
                    ("Low", "Low"),
                    ("Info", "Info"))
    jira_minimum_severity = models.CharField(max_length=20, blank=True,
                                             null=True, choices=jira_choices,
                                             default="Low")
    jira_labels = models.CharField(max_length=200, blank=True, null=True,
                                   help_text=_("JIRA issue labels space seperated"))

    add_vulnerability_id_to_jira_label = models.BooleanField(default=False,
                                        verbose_name=_("Add vulnerability Id as a JIRA label"),
                                        blank=False)

    enable_linear = models.BooleanField(default=False,
                                        verbose_name=_("Enable Linear integration"),
                                        blank=False)

    enable_github = models.BooleanField(default=False,
                                      verbose_name=_("Enable GITHUB integration"),
                                      blank=False)

    enable_slack_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_("Enable Slack notifications"),
                            blank=False)
    slack_channel = models.CharField(max_length=100, default="", blank=True,
                    help_text=_("Optional. Needed if you want to send global notifications."))
    slack_token = models.CharField(max_length=100, default="", blank=True,
                                   help_text=_("Token required for interacting "
                                             "with Slack. Get one at "
                                             "https://api.slack.com/tokens"))
    slack_username = models.CharField(max_length=100, default="", blank=True,
                     help_text=_("Optional. Will take your bot name otherwise."))
    enable_msteams_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_("Enable Microsoft Teams notifications"),
                            blank=False)
    msteams_url = models.CharField(max_length=400, default="", blank=True,
                                    help_text=_("The full URL of the "
                                              "incoming webhook"))
    enable_mail_notifications = models.BooleanField(default=False, blank=False)
    mail_notifications_to = models.CharField(max_length=200, default="",
                                             blank=True)

    enable_webhooks_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_("Enable Webhook notifications"),
                            blank=False)
    webhooks_notifications_timeout = models.IntegerField(default=10,
                                          help_text=_("How many seconds will DefectDojo waits for response from webhook endpoint"))

    enforce_verified_status = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Verified Status"),
        help_text=_("When enabled, features such as product grading, jira "
                    "integration, metrics, and reports will only interact "
                    "with verified findings.",
        ),
    )

    false_positive_history = models.BooleanField(
        default=False, help_text=_(
            "(EXPERIMENTAL) DefectDojo will automatically mark the finding as a "
            "false positive if an equal finding (according to its dedupe algorithm) "
            "has been previously marked as a false positive on the same product. "
            "ATTENTION: Although the deduplication algorithm is used to determine "
            "if a finding should be marked as a false positive, this feature will "
            "not work if deduplication is enabled since it doesn't make sense to use both.",
        ),
    )

    retroactive_false_positive_history = models.BooleanField(
        default=False, help_text=_(
            "(EXPERIMENTAL) FP History will also retroactively mark/unmark all "
            "existing equal findings in the same product as a false positives. "
            "Only works if the False Positive History feature is also enabled.",
        ),
    )

    url_prefix = models.CharField(max_length=300, default="", blank=True, help_text=_("URL prefix if DefectDojo is installed in it's own virtual subdirectory."))
    team_name = models.CharField(max_length=100, default="", blank=True)
    time_zone = models.CharField(max_length=50,
                                 choices=[(tz, tz) for tz in all_timezones],
                                 default="UTC", blank=False)
    enable_product_grade = models.BooleanField(default=False, verbose_name=_("Enable Product Grading"), help_text=_("Displays a grade letter next to a product to show the overall health."))
    product_grade = models.CharField(max_length=800, blank=True)
    product_grade_a = models.IntegerField(default=90,
                                          verbose_name=_("Grade A"),
                                          help_text=_("Percentage score for an "
                                                    "'A' >="))
    product_grade_b = models.IntegerField(default=80,
                                          verbose_name=_("Grade B"),
                                          help_text=_("Percentage score for a "
                                                    "'B' >="))
    product_grade_c = models.IntegerField(default=70,
                                          verbose_name=_("Grade C"),
                                          help_text=_("Percentage score for a "
                                                    "'C' >="))
    product_grade_d = models.IntegerField(default=60,
                                          verbose_name=_("Grade D"),
                                          help_text=_("Percentage score for a "
                                                    "'D' >="))
    product_grade_f = models.IntegerField(default=59,
                                          verbose_name=_("Grade F"),
                                          help_text=_("Percentage score for an "
                                                    "'F' <="))
    enable_product_tag_inheritance = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Product Tag Inheritance"),
        help_text=_("Enables product tag inheritance globally for all products. Any tags added on a product will automatically be added to all Engagements, Tests, and Findings"))

    enable_benchmark = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Benchmarks"),
        help_text=_("Enables Benchmarks such as the OWASP ASVS "
                  "(Application Security Verification Standard)"))

    enable_template_match = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Remediation Advice"),
        help_text=_("Enables global remediation advice and matching on CWE and Title. The text will be replaced for mitigation, impact and references on a finding. Useful for providing consistent impact and remediation advice regardless of the scanner."))

    enable_similar_findings = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Similar Findings"),
        help_text=_("Enable the query of similar findings on the view finding page. This feature can involve potentially large queries and negatively impact performance"))

    engagement_auto_close = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Engagement Auto-Close"),
        help_text=_("Closes an engagement after 3 days (default) past due date including last update."))

    engagement_auto_close_days = models.IntegerField(
        default=3,
        blank=False,
        verbose_name=_("Engagement Auto-Close Days"),
        help_text=_("Closes an engagement after the specified number of days past due date including last update."))

    enable_finding_sla = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Finding SLA's"),
        help_text=_("Enables Finding SLA's for time to remediate."))

    enable_notify_sla_active = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notify SLA's Breach for active Findings"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for active Findings."))

    enable_notify_sla_active_verified = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notify SLA's Breach for active, verified Findings"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for active, verified Findings."))

    enable_notify_sla_jira_only = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notify SLA's Breach only for Findings linked to JIRA"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for Findings that are linked to JIRA issues. Notification is disabled for Findings not linked to JIRA issues"))

    enable_notify_sla_exponential_backoff = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable an exponential backoff strategy for SLA breach notifications."),
        help_text=_("Enable an exponential backoff strategy for SLA breach notifications, e.g. 1, 2, 4, 8, etc. Otherwise it alerts every day"))

    allow_anonymous_survey_repsonse = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Allow Anonymous Survey Responses"),
        help_text=_("Enable anyone with a link to the survey to answer a survey"),
    )
    credentials = models.TextField(max_length=3000, blank=True)
    disclaimer = models.TextField(max_length=3000, default="", blank=True,
                                  verbose_name=_("Custom Disclaimer"),
                                  help_text=_("Include this custom disclaimer on all notifications and generated reports"))
    risk_acceptance_form_default_days = models.IntegerField(null=True, blank=True, default=180, help_text=_("Default expiry period for risk acceptance form."))
    risk_acceptance_notify_before_expiration = models.IntegerField(null=True, blank=True, default=10,
                    verbose_name=_("Risk acceptance expiration heads up days"), help_text=_("Notify X days before risk acceptance expires. Leave empty to disable."))
    enable_credentials = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable credentials"),
        help_text=_("With this setting turned off, credentials will be disabled in the user interface."))
    enable_questionnaires = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable questionnaires"),
        help_text=_("With this setting turned off, questionnaires will be disabled in the user interface."))
    enable_checklists = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable checklists"),
        help_text=_("With this setting turned off, checklists will be disabled in the user interface."))
    enable_endpoint_metadata_import = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Endpoint Metadata Import"),
        help_text=_("With this setting turned off, endpoint metadata import will be disabled in the user interface."))
    enable_user_profile_editable = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable user profile for writing"),
        help_text=_("When turned on users can edit their profiles"))
    enable_product_tracking_files = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Product Tracking Files"),
        help_text=_("With this setting turned off, the product tracking files will be disabled in the user interface."))
    enable_finding_groups = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Finding Groups"),
        help_text=_("With this setting turned off, the Finding Groups will be disabled."))
    enable_ui_table_based_searching = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable UI Table Based Filtering/Sorting"),
        help_text=_("With this setting enabled, table headings will contain sort buttons for the current page of data in addition to sorting buttons that consider data from all pages."))
    enable_calendar = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Calendar"),
        help_text=_("With this setting turned off, the Calendar will be disabled in the user interface."))
    default_group = models.ForeignKey(
        Dojo_Group,
        null=True,
        blank=True,
        help_text=_("New users will be assigned to this group."),
        on_delete=models.RESTRICT)
    default_group_role = models.ForeignKey(
        Role,
        null=True,
        blank=True,
        help_text=_("New users will be assigned to their default group with this role."),
        on_delete=models.RESTRICT)
    default_group_email_pattern = models.CharField(
        max_length=200,
        default="",
        blank=True,
        help_text=_("New users will only be assigned to the default group, when their email address matches this regex pattern. This is optional condition."))
    minimum_password_length = models.IntegerField(
        default=9,
        verbose_name=_("Minimum password length"),
        help_text=_("Requires user to set passwords greater than minimum length."))
    maximum_password_length = models.IntegerField(
        default=48,
        verbose_name=_("Maximum password length"),
        help_text=_("Requires user to set passwords less than maximum length."))
    number_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one digit"),
        help_text=_("Requires user passwords to contain at least one digit (0-9)."))
    special_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one special character"),
        help_text=_("Requires user passwords to contain at least one special character (()[]{}|\\`~!@#$%^&*_-+=;:'\",<>./?)."))
    lowercase_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one lowercase letter"),
        help_text=_("Requires user passwords to contain at least one lowercase letter (a-z)."))
    uppercase_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one uppercase letter"),
        help_text=_("Requires user passwords to contain at least one uppercase letter (A-Z)."))
    non_common_password_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must not be common"),
        help_text=_("Requires user passwords to not be part of list of common passwords."))
    api_expose_error_details = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("API expose error details"),
        help_text=_("When turned on, the API will expose error details in the response."))
    filter_string_matching = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Filter String Matching Optimization"),
        help_text=_(
            "When turned on, all filter operations in the UI will require string matches rather than ID. "
            "This is a performance enhancement to avoid fetching objects unnecessarily.",
        ))

    from dojo.middleware import System_Settings_Manager
    objects = System_Settings_Manager()


class SystemSettingsFormAdmin(forms.ModelForm):
    product_grade = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = System_Settings
        fields = ["product_grade"]


class System_SettingsAdmin(admin.ModelAdmin):
    form = SystemSettingsFormAdmin
    fields = ("product_grade",)


def get_current_date():
    return timezone.now().date()


def get_current_datetime():
    return timezone.now()


class Dojo_Group_Member(models.Model):
    group = models.ForeignKey(Dojo_Group, on_delete=models.CASCADE)
    user = models.ForeignKey(Dojo_User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, help_text=_("This role determines the permissions of the user to manage the group."), verbose_name=_("Group role"))


class Global_Role(models.Model):
    user = models.OneToOneField(Dojo_User, null=True, blank=True, on_delete=models.CASCADE)
    group = models.OneToOneField(Dojo_Group, null=True, blank=True, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True, blank=True, help_text=_("The global role will be applied to all product types and products."), verbose_name=_("Global role"))


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    team = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)
    is_globally_read_only = models.BooleanField(default=False)
    updated = models.DateTimeField(auto_now=True)


class Note_Type(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=200)
    is_single = models.BooleanField(default=False, null=False)
    is_active = models.BooleanField(default=True, null=False)
    is_mandatory = models.BooleanField(default=True, null=False)

    def __str__(self):
        return self.name


class NoteHistory(models.Model):
    note_type = models.ForeignKey(Note_Type, null=True, blank=True, on_delete=models.CASCADE)
    data = models.TextField()
    time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    current_editor = models.ForeignKey(Dojo_User, editable=False, null=True, on_delete=models.CASCADE)

    def copy(self):
        copy = self
        copy.pk = None
        copy.id = None
        copy.save()
        return copy


class Notes(models.Model):
    note_type = models.ForeignKey(Note_Type, related_name="note_type", null=True, blank=True, on_delete=models.CASCADE)
    entry = models.TextField()
    date = models.DateTimeField(null=False, editable=False,
                                default=get_current_datetime)
    author = models.ForeignKey(Dojo_User, related_name="editor_notes_set", editable=False, on_delete=models.CASCADE)
    private = models.BooleanField(default=False)
    edited = models.BooleanField(default=False)
    editor = models.ForeignKey(Dojo_User, related_name="author_notes_set", editable=False, null=True, on_delete=models.CASCADE)
    edit_time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    history = models.ManyToManyField(NoteHistory, blank=True,
                                   editable=False)

    class Meta:
        ordering = ["-date"]

    def __str__(self):
        return self.entry

    def copy(self):
        copy = self
        # Save the necessary ManyToMany relationships
        old_history = list(self.history.all())
        # Wipe the IDs of the new object
        copy.pk = None
        copy.id = None
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the history
        for history in old_history:
            copy.history.add(history.copy())

        return copy


class FileUpload(models.Model):
    title = models.CharField(max_length=100, unique=True)
    file = models.FileField(upload_to=UniqueUploadNameProvider("uploaded_files"))

    def copy(self):
        copy = self
        # Wipe the IDs of the new object
        copy.pk = None
        copy.id = None
        # Add unique modifier to file name
        copy.title = f"{self.title} - clone-{str(uuid4())[:8]}"
        # Create new unique file name
        current_url = self.file.url
        _, current_full_filename = current_url.rsplit("/", 1)
        _, extension = current_full_filename.split(".", 1)
        new_file = ContentFile(self.file.read(), name=f"{uuid4()}.{extension}")
        copy.file = new_file
        copy.save()

        return copy

    def get_accessible_url(self, obj, obj_id):
        if isinstance(obj, Engagement):
            obj_type = "Engagement"
        elif isinstance(obj, Test):
            obj_type = "Test"
        elif isinstance(obj, Finding):
            obj_type = "Finding"

        return f"access_file/{self.id}/{obj_id}/{obj_type}"

    def clean(self):
        if not self.title:
            self.title = "<No Title>"

        valid_extensions = settings.FILE_UPLOAD_TYPES

        # why does this not work with self.file....
        file_name = self.file.url if self.file else self.title
        if Path(file_name).suffix.lower() not in valid_extensions:
            if accepted_extensions := f"{', '.join(valid_extensions)}":
                msg = (
                    _("Unsupported extension. Supported extensions are as follows: %s") % accepted_extensions
                )
            else:
                msg = (
                    _("File uploads are prohibited due to the list of acceptable file extensions being empty")
                )
            raise ValidationError(msg)


class Product_Type(models.Model):

    """
    Product types represent the top level model, these can be business unit divisions, different offices or locations, development teams, or any other logical way of distinguishing “types” of products.
    `
       Examples:
         * IAM Team
         * Internal / 3rd Party
         * Main company / Acquisition
         * San Francisco / New York offices
    """

    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000, null=True, blank=True)
    critical_product = models.BooleanField(default=False)
    key_product = models.BooleanField(default=False)
    updated = models.DateTimeField(auto_now=True, null=True)
    created = models.DateTimeField(auto_now_add=True, null=True)
    members = models.ManyToManyField(Dojo_User, through="Product_Type_Member", related_name="prod_type_members", blank=True)
    authorization_groups = models.ManyToManyField(Dojo_Group, through="Product_Type_Group", related_name="product_type_groups", blank=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("product_type", args=[str(self.id)])

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": reverse("edit_product_type", args=(self.id,))}]

    @cached_property
    def critical_present(self):
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="Critical")
        if c_findings.count() > 0:
            return True
        return None

    @cached_property
    def high_present(self):
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="High")
        if c_findings.count() > 0:
            return True
        return None

    @cached_property
    def calc_health(self):
        h_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="High")
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="Critical")
        health = 100
        if c_findings.count() > 0:
            health = 40
            health = health - ((c_findings.count() - 1) * 5)
        if h_findings.count() > 0:
            if health == 100:
                health = 60
            health = health - ((h_findings.count() - 1) * 2)
        if health < 5:
            return 5
        return health

    # only used by bulk risk acceptance api
    @property
    def unaccepted_open_findings(self):
        return Finding.objects.filter(risk_accepted=False, active=True, duplicate=False, test__engagement__product__prod_type=self)


class Product_Line(models.Model):
    name = models.CharField(max_length=300)
    description = models.CharField(max_length=2000)

    def __str__(self):
        return self.name


class Report_Type(models.Model):
    name = models.CharField(max_length=255)


class Test_Type(models.Model):
    name = models.CharField(max_length=200, unique=True)
    static_tool = models.BooleanField(default=False)
    dynamic_tool = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    dynamically_generated = models.BooleanField(
        default=False,
        help_text=_("Set to True for test types that are created at import time"))

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": None}]


class DojoMeta(models.Model):
    name = models.CharField(max_length=120)
    value = models.CharField(max_length=300)
    product = models.ForeignKey("Product",
                                on_delete=models.CASCADE,
                                null=True,
                                editable=False,
                                related_name="product_meta")
    endpoint = models.ForeignKey("Endpoint",
                                 on_delete=models.CASCADE,
                                 null=True,
                                 editable=False,
                                 related_name="endpoint_meta")
    finding = models.ForeignKey("Finding",
                                 on_delete=models.CASCADE,
                                 null=True,
                                 editable=False,
                                 related_name="finding_meta")

    class Meta:
        unique_together = (("product", "name"),
                           ("endpoint", "name"),
                           ("finding", "name"))

    def __str__(self):
        return f"{self.name}: {self.value}"

    """
    Verify that this metadata entry belongs only to one object.
    """
    def clean(self):

        ids = [self.product_id,
               self.endpoint_id,
               self.finding_id]
        ids_count = 0

        for id in ids:
            if id is not None:
                ids_count += 1

        if ids_count == 0:
            msg = "Metadata entries need either a product, an endpoint or a finding"
            raise ValidationError(msg)
        if ids_count > 1:
            msg = "Metadata entries may not have more than one relation, either a product, an endpoint either or a finding"
            raise ValidationError(msg)


class SLA_Configuration(models.Model):
    name = models.CharField(max_length=128, unique=True, blank=False, verbose_name=_("Custom SLA Name"),
        help_text=_("A unique name for the set of SLAs."))
    description = models.CharField(
        max_length=512,
        null=True,
        blank=True)
    critical = models.IntegerField(
        default=7,
        verbose_name=_("Critical Finding SLA Days"),
        help_text=_("The number of days to remediate a critical finding."))
    enforce_critical = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Critical Finding SLA Days"),
        help_text=_("When enabled, critical findings will be assigned an SLA expiration date based on the critical finding SLA days within this SLA configuration."))
    high = models.IntegerField(
        default=30,
        verbose_name=_("High Finding SLA Days"),
        help_text=_("The number of days to remediate a high finding."))
    enforce_high = models.BooleanField(
        default=True,
        verbose_name=_("Enforce High Finding SLA Days"),
        help_text=_("When enabled, high findings will be assigned an SLA expiration date based on the high finding SLA days within this SLA configuration."))
    medium = models.IntegerField(
        default=90,
        verbose_name=_("Medium Finding SLA Days"),
        help_text=_("The number of days to remediate a medium finding."))
    enforce_medium = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Medium Finding SLA Days"),
        help_text=_("When enabled, medium findings will be assigned an SLA expiration date based on the medium finding SLA days within this SLA configuration."))
    low = models.IntegerField(
        default=120,
        verbose_name=_("Low Finding SLA Days"),
        help_text=_("The number of days to remediate a low finding."))
    enforce_low = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Low Finding SLA Days"),
        help_text=_("When enabled, low findings will be assigned an SLA expiration date based on the low finding SLA days within this SLA configuration."))
    async_updating = models.BooleanField(
        default=False,
        help_text=_("Findings under this SLA configuration are asynchronously being updated"))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # get the initial sla config before saving (if this is an existing sla config)
        initial_sla_config = None
        if self.pk is not None:
            initial_sla_config = SLA_Configuration.objects.get(pk=self.pk)
            # if initial config exists and async finding update is already running, revert sla config before saving
            if initial_sla_config and self.async_updating:
                self.critical = initial_sla_config.critical
                self.enforce_critical = initial_sla_config.enforce_critical
                self.high = initial_sla_config.high
                self.enforce_high = initial_sla_config.enforce_high
                self.medium = initial_sla_config.medium
                self.enforce_medium = initial_sla_config.enforce_medium
                self.low = initial_sla_config.low
                self.enforce_low = initial_sla_config.enforce_low

        super().save(*args, **kwargs)

        # if the initial sla config exists and async finding update is not running
        if initial_sla_config is not None and not self.async_updating:
            # check which sla days fields changed based on severity
            severities = []
            if (initial_sla_config.critical != self.critical) or (initial_sla_config.enforce_critical != self.enforce_critical):
                severities.append("Critical")
            if (initial_sla_config.high != self.high) or (initial_sla_config.enforce_high != self.enforce_high):
                severities.append("High")
            if (initial_sla_config.medium != self.medium) or (initial_sla_config.enforce_medium != self.enforce_medium):
                severities.append("Medium")
            if (initial_sla_config.low != self.low) or (initial_sla_config.enforce_low != self.enforce_low):
                severities.append("Low")
            # if severities have changed, update finding sla expiration dates with those severities
            if len(severities):
                # set the async updating flag to true for this sla config
                self.async_updating = True
                super().save(*args, **kwargs)
                # set the async updating flag to true for all products using this sla config
                products = Product.objects.filter(sla_configuration=self)
                for product in products:
                    product.async_updating = True
                    super(Product, product).save()
                # launch the async task to update all finding sla expiration dates
                from dojo.sla_config.helpers import update_sla_expiration_dates_sla_config_async
                update_sla_expiration_dates_sla_config_async(self, tuple(severities), products)

    def clean(self):
        sla_days = [self.critical, self.high, self.medium, self.low]

        for sla_day in sla_days:
            if sla_day < 1:
                msg = "SLA Days must be at least 1"
                raise ValidationError(msg)

    def delete(self, *args, **kwargs):
        logger.debug("%d sla configuration delete", self.id)

        if self.id != 1:
            super().delete(*args, **kwargs)
        else:
            msg = "Unable to delete default SLA Configuration"
            raise ValidationError(msg)

    def get_summary(self):
        return f"{self.name} - Critical: {self.critical}, High: {self.high}, Medium: {self.medium}, Low: {self.low}"


class Product(models.Model):
    WEB_PLATFORM = "web"
    IOT = "iot"
    DESKTOP_PLATFORM = "desktop"
    MOBILE_PLATFORM = "mobile"
    WEB_SERVICE_PLATFORM = "web service"
    PLATFORM_CHOICES = (
        (WEB_SERVICE_PLATFORM, _("API")),
        (DESKTOP_PLATFORM, _("Desktop")),
        (IOT, _("Internet of Things")),
        (MOBILE_PLATFORM, _("Mobile")),
        (WEB_PLATFORM, _("Web")),
    )

    CONSTRUCTION = "construction"
    PRODUCTION = "production"
    RETIREMENT = "retirement"
    LIFECYCLE_CHOICES = (
        (CONSTRUCTION, _("Construction")),
        (PRODUCTION, _("Production")),
        (RETIREMENT, _("Retirement")),
    )

    THIRD_PARTY_LIBRARY_ORIGIN = "third party library"
    PURCHASED_ORIGIN = "purchased"
    CONTRACTOR_ORIGIN = "contractor"
    INTERNALLY_DEVELOPED_ORIGIN = "internal"
    OPEN_SOURCE_ORIGIN = "open source"
    OUTSOURCED_ORIGIN = "outsourced"
    ORIGIN_CHOICES = (
        (THIRD_PARTY_LIBRARY_ORIGIN, _("Third Party Library")),
        (PURCHASED_ORIGIN, _("Purchased")),
        (CONTRACTOR_ORIGIN, _("Contractor Developed")),
        (INTERNALLY_DEVELOPED_ORIGIN, _("Internally Developed")),
        (OPEN_SOURCE_ORIGIN, _("Open Source")),
        (OUTSOURCED_ORIGIN, _("Outsourced")),
    )

    VERY_HIGH_CRITICALITY = "very high"
    HIGH_CRITICALITY = "high"
    MEDIUM_CRITICALITY = "medium"
    LOW_CRITICALITY = "low"
    VERY_LOW_CRITICALITY = "very low"
    NONE_CRITICALITY = "none"
    BUSINESS_CRITICALITY_CHOICES = (
        (VERY_HIGH_CRITICALITY, _("Very High")),
        (HIGH_CRITICALITY, _("High")),
        (MEDIUM_CRITICALITY, _("Medium")),
        (LOW_CRITICALITY, _("Low")),
        (VERY_LOW_CRITICALITY, _("Very Low")),
        (NONE_CRITICALITY, _("None")),
    )

    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000)

    product_manager = models.ForeignKey(Dojo_User, null=True, blank=True,
                                        related_name="product_manager", on_delete=models.RESTRICT)
    technical_contact = models.ForeignKey(Dojo_User, null=True, blank=True,
                                          related_name="technical_contact", on_delete=models.RESTRICT)
    team_manager = models.ForeignKey(Dojo_User, null=True, blank=True,
                                     related_name="team_manager", on_delete=models.RESTRICT)

    created = models.DateTimeField(auto_now_add=True, null=True)
    prod_type = models.ForeignKey(Product_Type, related_name="prod_type",
                                  null=False, blank=False, on_delete=models.CASCADE)
    updated = models.DateTimeField(auto_now=True, null=True)
    sla_configuration = models.ForeignKey(SLA_Configuration,
                                          related_name="sla_config",
                                          null=False,
                                          blank=False,
                                          default=1,
                                          on_delete=models.RESTRICT)
    tid = models.IntegerField(default=0, editable=False)
    members = models.ManyToManyField(Dojo_User, through="Product_Member", related_name="product_members", blank=True)
    authorization_groups = models.ManyToManyField(Dojo_Group, through="Product_Group", related_name="product_groups", blank=True)
    prod_numeric_grade = models.IntegerField(null=True, blank=True)

    # Metadata
    business_criticality = models.CharField(max_length=9, choices=BUSINESS_CRITICALITY_CHOICES, blank=True, null=True)
    platform = models.CharField(max_length=11, choices=PLATFORM_CHOICES, blank=True, null=True)
    lifecycle = models.CharField(max_length=12, choices=LIFECYCLE_CHOICES, blank=True, null=True)
    origin = models.CharField(max_length=19, choices=ORIGIN_CHOICES, blank=True, null=True)
    user_records = models.PositiveIntegerField(blank=True, null=True, help_text=_("Estimate the number of user records within the application."))
    revenue = models.DecimalField(max_digits=15, decimal_places=2, blank=True, null=True, help_text=_("Estimate the application's revenue."))
    external_audience = models.BooleanField(default=False, help_text=_("Specify if the application is used by people outside the organization."))
    internet_accessible = models.BooleanField(default=False, help_text=_("Specify if the application is accessible from the public internet."))
    regulations = models.ManyToManyField(Regulation, blank=True)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this product. Choose from the list or add new tags. Press Enter key to add."))
    enable_product_tag_inheritance = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Product Tag Inheritance"),
        help_text=_("Enables product tag inheritance. Any tags added on a product will automatically be added to all Engagements, Tests, and Findings"))
    enable_simple_risk_acceptance = models.BooleanField(default=False, help_text=_("Allows simple risk acceptance by checking/unchecking a checkbox."))
    enable_full_risk_acceptance = models.BooleanField(default=True, help_text=_("Allows full risk acceptance using a risk acceptance form, expiration date, uploaded proof, etc."))

    disable_sla_breach_notifications = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Disable SLA breach notifications"),
        help_text=_("Disable SLA breach notifications if configured in the global settings"))
    async_updating = models.BooleanField(default=False,
                                            help_text=_("Findings under this Product or SLA configuration are asynchronously being updated"))

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # get the product's sla config before saving (if this is an existing product)
        initial_sla_config = None
        if self.pk is not None:
            initial_sla_config = getattr(Product.objects.get(pk=self.pk), "sla_configuration", None)
            # if initial sla config exists and async finding update is already running, revert sla config before saving
            if initial_sla_config and self.async_updating:
                self.sla_configuration = initial_sla_config

        super().save(*args, **kwargs)

        # if the initial sla config exists and async finding update is not running
        if initial_sla_config is not None and not self.async_updating:
            # get the new sla config from the saved product
            new_sla_config = getattr(self, "sla_configuration", None)
            # if the sla config has changed, update finding sla expiration dates within this product
            if new_sla_config and (initial_sla_config != new_sla_config):
                # set the async updating flag to true for this product
                self.async_updating = True
                super().save(*args, **kwargs)
                # set the async updating flag to true for the sla config assigned to this product
                sla_config = getattr(self, "sla_configuration", None)
                if sla_config:
                    sla_config.async_updating = True
                    super(SLA_Configuration, sla_config).save()
                # launch the async task to update all finding sla expiration dates
                from dojo.product.helpers import update_sla_expiration_dates_product_async
                update_sla_expiration_dates_product_async(self, sla_config)

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("view_product", args=[str(self.id)])

    @cached_property
    def findings_count(self):
        try:
            # if prefetched, it's already there
            return self.active_finding_count
        except AttributeError:
            # ideally it's always prefetched and we can remove this code in the future
            self.active_finding_count = Finding.objects.filter(active=True,
                                            test__engagement__product=self).count()
            return self.active_finding_count

    @cached_property
    def findings_active_verified_count(self):
        try:
            # if prefetched, it's already there
            return self.active_verified_finding_count
        except AttributeError:
            # ideally it's always prefetched and we can remove this code in the future
            self.active_verified_finding_count = Finding.objects.filter(active=True,
                                            verified=True,
                                            test__engagement__product=self).count()
            return self.active_verified_finding_count

    @cached_property
    def endpoint_host_count(self):
        # active_endpoints is (should be) prefetched
        endpoints = getattr(self, "active_endpoints", None)

        hosts = []
        for e in endpoints:
            if e.host in hosts:
                continue
            hosts.append(e.host)

        return len(hosts)

    @cached_property
    def endpoint_count(self):
        # active_endpoints is (should be) prefetched
        endpoints = getattr(self, "active_endpoints", None)
        if endpoints:
            return len(self.active_endpoints)
        return 0

    def open_findings(self, start_date=None, end_date=None):
        if start_date is None or end_date is None:
            return {}

        from dojo.utils import get_system_setting
        findings = Finding.objects.filter(test__engagement__product=self,
                                        mitigated__isnull=True,
                                        false_p=False,
                                        duplicate=False,
                                        out_of_scope=False,
                                        date__range=[start_date,
                                                    end_date])

        if get_system_setting("enforce_verified_status", True):
            findings = findings.filter(verified=True)

        critical = findings.filter(severity="Critical").count()
        high = findings.filter(severity="High").count()
        medium = findings.filter(severity="Medium").count()
        low = findings.filter(severity="Low").count()

        return {"Critical": critical,
                "High": high,
                "Medium": medium,
                "Low": low,
                "Total": (critical + high + medium + low)}

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": reverse("view_product", args=(self.id,))}]

    @property
    def get_product_type(self):
        return self.prod_type if self.prod_type is not None else "unknown"

    # only used in APIv2 serializers.py, query should be aligned with findings_count
    @cached_property
    def open_findings_list(self):
        findings = Finding.objects.filter(test__engagement__product=self,
                                          active=True)
        findings_list = []
        for i in findings:
            findings_list.append(i.id)
        return findings_list

    @property
    def has_jira_configured(self):
        import dojo.jira_link.helper as jira_helper
        return jira_helper.has_jira_configured(self)

    def violates_sla(self):
        findings = Finding.objects.filter(test__engagement__product=self,
                                          active=True,
                                          sla_expiration_date__lt=timezone.now().date())
        return findings.count() > 0


class Product_Member(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    user = models.ForeignKey(Dojo_User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)


class Product_Group(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    group = models.ForeignKey(Dojo_Group, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)


class Product_Type_Member(models.Model):
    product_type = models.ForeignKey(Product_Type, on_delete=models.CASCADE)
    user = models.ForeignKey(Dojo_User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)


class Product_Type_Group(models.Model):
    product_type = models.ForeignKey(Product_Type, on_delete=models.CASCADE)
    group = models.ForeignKey(Dojo_Group, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)


class Tool_Type(models.Model):
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=2000, null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Tool_Configuration(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True, blank=True)
    tool_type = models.ForeignKey(Tool_Type, related_name="tool_type", on_delete=models.CASCADE)
    authentication_type = models.CharField(max_length=15,
                                           choices=(
                                               ("API", "API Key"),
                                               ("Password",
                                                "Username/Password"),
                                               ("SSH", "SSH")),
                                           null=True, blank=True)
    extras = models.CharField(max_length=255, null=True, blank=True, help_text=_("Additional definitions that will be "
                                                                              "consumed by scanner"))
    username = models.CharField(max_length=200, null=True, blank=True)
    password = models.CharField(max_length=600, null=True, blank=True)
    auth_title = models.CharField(max_length=200, null=True, blank=True,
                                  verbose_name=_("Title for SSH/API Key"))
    ssh = models.CharField(max_length=6000, null=True, blank=True)
    api_key = models.CharField(max_length=600, null=True, blank=True,
                               verbose_name=_("API Key"))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Product_API_Scan_Configuration(models.Model):
    product = models.ForeignKey(Product, null=False, blank=False, on_delete=models.CASCADE)
    tool_configuration = models.ForeignKey(Tool_Configuration, null=False, blank=False, on_delete=models.CASCADE)
    service_key_1 = models.CharField(max_length=200, null=True, blank=True)
    service_key_2 = models.CharField(max_length=200, null=True, blank=True)
    service_key_3 = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        name = self.tool_configuration.name
        if self.service_key_1 or self.service_key_2 or self.service_key_3:
            name += f" ({self.details})"
        return name

    @property
    def details(self):
        details = ""
        if self.service_key_1:
            details += f"{self.service_key_1}"
        if self.service_key_2:
            details += f" | {self.service_key_2}"
        if self.service_key_3:
            details += f" | {self.service_key_3}"
        return details


# declare form here as we can't import forms.py due to circular imports not even locally
class ToolConfigForm_Admin(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=False)
    api_key = forms.CharField(widget=forms.PasswordInput, required=False)
    ssh = forms.CharField(widget=forms.PasswordInput, required=False)

    # django doesn't seem to have an easy way to handle password fields as PasswordInput requires reentry of passwords
    password_from_db = None
    ssh_from_db = None
    api_key_from_db = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # keep password from db to use if the user entered no password
            self.password_from_db = self.instance.password
            self.ssh_from_db = self.instance.ssh
            self.api_key = self.instance.api_key

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data["password"] and not cleaned_data["ssh"] and not cleaned_data["api_key"]:
            cleaned_data["password"] = self.password_from_db
            cleaned_data["ssh"] = self.ssh_from_db
            cleaned_data["api_key"] = self.api_key_from_db

        return cleaned_data


class Tool_Configuration_Admin(admin.ModelAdmin):
    form = ToolConfigForm_Admin


class Network_Locations(models.Model):
    location = models.CharField(max_length=500, help_text=_("Location of network testing: Examples: VPN, Internet or Internal."))

    def __str__(self):
        return self.location


class Engagement_Presets(models.Model):
    title = models.CharField(max_length=500, default=None, help_text=_("Brief description of preset."))
    test_type = models.ManyToManyField(Test_Type, default=None, blank=True)
    network_locations = models.ManyToManyField(Network_Locations, default=None, blank=True)
    notes = models.CharField(max_length=2000, help_text=_("Description of what needs to be tested or setting up environment for testing"), null=True, blank=True)
    scope = models.CharField(max_length=800, help_text=_("Scope of Engagement testing, IP's/Resources/URL's)"), default=None, blank=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, null=False)

    class Meta:
        ordering = ["title"]

    def __str__(self):
        return self.title


ENGAGEMENT_STATUS_CHOICES = (("Not Started", "Not Started"),
                             ("Blocked", "Blocked"),
                             ("Cancelled", "Cancelled"),
                             ("Completed", "Completed"),
                             ("In Progress", "In Progress"),
                             ("On Hold", "On Hold"),
                             ("Waiting for Resource", "Waiting for Resource"))


class Engagement(models.Model):
    name = models.CharField(max_length=300, null=True, blank=True)
    description = models.CharField(max_length=2000, null=True, blank=True)
    version = models.CharField(max_length=100, null=True, blank=True, help_text=_("Version of the product the engagement tested."))
    first_contacted = models.DateField(null=True, blank=True)
    target_start = models.DateField(null=False, blank=False)
    target_end = models.DateField(null=False, blank=False)
    lead = models.ForeignKey(Dojo_User, editable=True, null=True, blank=True, on_delete=models.RESTRICT)
    requester = models.ForeignKey(Contact, null=True, blank=True, on_delete=models.CASCADE)
    preset = models.ForeignKey(Engagement_Presets, null=True, blank=True, help_text=_("Settings and notes for performing this engagement."), on_delete=models.CASCADE)
    reason = models.CharField(max_length=2000, null=True, blank=True)
    report_type = models.ForeignKey(Report_Type, null=True, blank=True, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    updated = models.DateTimeField(auto_now=True, null=True)
    created = models.DateTimeField(auto_now_add=True, null=True)
    active = models.BooleanField(default=True, editable=False)
    tracker = models.URLField(max_length=200, help_text=_("Link to epic or ticket system with changes to version."), editable=True, blank=True, null=True)
    test_strategy = models.URLField(editable=True, blank=True, null=True)
    threat_model = models.BooleanField(default=True)
    api_test = models.BooleanField(default=True)
    pen_test = models.BooleanField(default=True)
    check_list = models.BooleanField(default=True)
    notes = models.ManyToManyField(Notes, blank=True, editable=False)
    files = models.ManyToManyField(FileUpload, blank=True, editable=False)
    status = models.CharField(editable=True, max_length=2000, default="",
                              null=True,
                              choices=ENGAGEMENT_STATUS_CHOICES)
    progress = models.CharField(max_length=100,
                                default="threat_model", editable=False)
    tmodel_path = models.CharField(max_length=1000, default="none",
                                   editable=False, blank=True, null=True)
    risk_acceptance = models.ManyToManyField("Risk_Acceptance",
                                             default=None,
                                             editable=False,
                                             blank=True)
    done_testing = models.BooleanField(default=False, editable=False)
    engagement_type = models.CharField(editable=True, max_length=30, default="Interactive",
                                       null=True,
                                       choices=(("Interactive", "Interactive"),
                                                ("CI/CD", "CI/CD")))
    build_id = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Build ID of the product the engagement tested."), verbose_name=_("Build ID"))
    commit_hash = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Commit hash from repo"), verbose_name=_("Commit Hash"))
    branch_tag = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Tag or branch of the product the engagement tested."), verbose_name=_("Branch/Tag"))
    build_server = models.ForeignKey(Tool_Configuration, verbose_name=_("Build Server"), help_text=_("Build server responsible for CI/CD test"), null=True, blank=True, related_name="build_server", on_delete=models.CASCADE)
    source_code_management_server = models.ForeignKey(Tool_Configuration, null=True, blank=True, verbose_name=_("SCM Server"), help_text=_("Source code server for CI/CD test"), related_name="source_code_management_server", on_delete=models.CASCADE)
    source_code_management_uri = models.URLField(max_length=600, null=True, blank=True, editable=True, verbose_name=_("Repo"), help_text=_("Resource link to source code"))
    orchestration_engine = models.ForeignKey(Tool_Configuration, verbose_name=_("Orchestration Engine"), help_text=_("Orchestration service responsible for CI/CD test"), null=True, blank=True, related_name="orchestration", on_delete=models.CASCADE)
    deduplication_on_engagement = models.BooleanField(default=False, verbose_name=_("Deduplication within this engagement only"), help_text=_("If enabled deduplication will only mark a finding in this engagement as duplicate of another finding if both findings are in this engagement. If disabled, deduplication is on the product level."))

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this engagement. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    class Meta:
        ordering = ["-target_start"]
        indexes = [
            models.Index(fields=["product", "active"]),
        ]

    def __str__(self):
        return "Engagement {}: {} ({})".format(self.id if id else 0, self.name or "",
                                        self.target_start.strftime(
                                            "%b %d, %Y"))

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("view_engagement", args=[str(self.id)])

    def copy(self):
        copy = self
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_files = list(self.files.all())
        old_tags = list(self.tags.all())
        old_risk_acceptances = list(self.risk_acceptance.all())
        old_tests = list(Test.objects.filter(engagement=self))
        # Wipe the IDs of the new object
        copy.pk = None
        copy.id = None
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Copy the files
        for files in old_files:
            copy.files.add(files.copy())
        # Copy the tests
        for test in old_tests:
            test.copy(engagement=copy)
        # Copy the risk_acceptances
        for risk_acceptance in old_risk_acceptances:
            copy.risk_acceptance.add(risk_acceptance.copy(engagement=copy))
        # Assign any tags
        copy.tags.set(old_tags)

        return copy

    def is_overdue(self):
        overdue_grace_days = 10 if self.engagement_type == "CI/CD" else 0

        max_end_date = timezone.now() - relativedelta(days=overdue_grace_days)

        return self.target_end < max_end_date.date()

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_engagement", args=(self.id,))}]
        return bc

    # only used by bulk risk acceptance api
    @property
    def unaccepted_open_findings(self):
        from dojo.utils import get_system_setting

        findings = Finding.objects.filter(risk_accepted=False, active=True, duplicate=False, test__engagement=self)
        if get_system_setting("enforce_verified_status", True):
            findings = findings.filter(verified=True)

        return findings

    def accept_risks(self, accepted_risks):
        self.risk_acceptance.add(*accepted_risks)

    @property
    def has_jira_issue(self):
        import dojo.jira_link.helper as jira_helper
        return jira_helper.has_jira_issue(self)

    @property
    def is_ci_cd(self):
        return self.engagement_type == "CI/CD"

    def delete(self, *args, **kwargs):
        logger.debug("%d engagement delete", self.id)
        import dojo.finding.helper as helper
        helper.prepare_duplicates_for_delete(engagement=self)
        super().delete(*args, **kwargs)
        calculate_grade(self.product)

    def inherit_tags(self, potentially_existing_tags):
        # get a copy of the tags to be inherited
        incoming_inherited_tags = [tag.name for tag in self.product.tags.all()]
        _manage_inherited_tags(self, incoming_inherited_tags, potentially_existing_tags=potentially_existing_tags)


class CWE(models.Model):
    url = models.CharField(max_length=1000)
    description = models.CharField(max_length=2000)
    number = models.IntegerField()


class Endpoint_Params(models.Model):
    param = models.CharField(max_length=150)
    value = models.CharField(max_length=150)
    method_type = (("GET", "GET"),
                   ("POST", "POST"))
    method = models.CharField(max_length=20, blank=False, null=True, choices=method_type)


class Endpoint_Status(models.Model):
    date = models.DateField(default=get_current_date)
    last_modified = models.DateTimeField(null=True, editable=False, default=get_current_datetime)
    mitigated = models.BooleanField(default=False, blank=True)
    mitigated_time = models.DateTimeField(editable=False, null=True, blank=True)
    mitigated_by = models.ForeignKey(Dojo_User, editable=True, null=True, on_delete=models.RESTRICT)
    false_positive = models.BooleanField(default=False, blank=True)
    out_of_scope = models.BooleanField(default=False, blank=True)
    risk_accepted = models.BooleanField(default=False, blank=True)
    endpoint = models.ForeignKey("Endpoint", null=False, blank=False, on_delete=models.CASCADE, related_name="status_endpoint")
    finding = models.ForeignKey("Finding", null=False, blank=False, on_delete=models.CASCADE, related_name="status_finding")

    class Meta:
        indexes = [
            models.Index(fields=["finding", "mitigated"]),
            models.Index(fields=["endpoint", "mitigated"]),
        ]
        constraints = [
            models.UniqueConstraint(fields=["finding", "endpoint"], name="endpoint-finding relation"),
        ]

    def __str__(self):
        return f"'{self.finding}' on '{self.endpoint}'"

    def copy(self, finding=None):
        copy = self
        current_endpoint = self.endpoint
        copy.pk = None
        copy.id = None
        if finding:
            copy.finding = finding
        copy.endpoint = current_endpoint
        copy.save()

        return copy

    @property
    def age(self):

        diff = self.mitigated_time.date() - self.date if self.mitigated else get_current_date() - self.date
        days = diff.days
        return max(0, days)


class Endpoint(models.Model):
    protocol = models.CharField(null=True, blank=True, max_length=20,
                                 help_text=_("The communication protocol/scheme such as 'http', 'ftp', 'dns', etc."))
    userinfo = models.CharField(null=True, blank=True, max_length=500,
                              help_text=_("User info as 'alice', 'bob', etc."))
    host = models.CharField(null=True, blank=True, max_length=500,
                            help_text=_("The host name or IP address. It must not include the port number. "
                                      "For example '127.0.0.1', 'localhost', 'yourdomain.com'."))
    port = models.IntegerField(null=True, blank=True,
                               help_text=_("The network port associated with the endpoint."))
    path = models.CharField(null=True, blank=True, max_length=500,
                            help_text=_("The location of the resource, it must not start with a '/'. For example "
                                      "endpoint/420/edit"))
    query = models.CharField(null=True, blank=True, max_length=1000,
                             help_text=_("The query string, the question mark should be omitted."
                                       "For example 'group=4&team=8'"))
    fragment = models.CharField(null=True, blank=True, max_length=500,
                                help_text=_("The fragment identifier which follows the hash mark. The hash mark should "
                                          "be omitted. For example 'section-13', 'paragraph-2'."))
    product = models.ForeignKey(Product, null=True, blank=True, on_delete=models.CASCADE)
    endpoint_params = models.ManyToManyField(Endpoint_Params, blank=True, editable=False)
    findings = models.ManyToManyField("Finding",
                                      blank=True,
                                      verbose_name=_("Findings"),
                                      through=Endpoint_Status)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this endpoint. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    class Meta:
        ordering = ["product", "host", "protocol", "port", "userinfo", "path", "query", "fragment"]
        indexes = [
            models.Index(fields=["product"]),
        ]

    def __str__(self):
        try:
            if self.host:
                dummy_scheme = "dummy-scheme"  # workaround for https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L988
                url = hyperlink.EncodedURL(
                    scheme=self.protocol or dummy_scheme,
                    userinfo=self.userinfo or "",
                    host=self.host,
                    port=self.port,
                    path=tuple(self.path.split("/")) if self.path else (),
                    query=tuple(
                        (
                            qe.split("=", 1)
                            if "=" in qe
                            else (qe, None)
                        )
                        for qe in self.query.split("&")
                    ) if self.query else (),  # inspired by https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L1427
                    fragment=self.fragment or "",
                )
                # Return a normalized version of the URL to avoid differences where there shouldn't be any difference.
                # Example: https://google.com and https://google.com:443
                normalize_path = self.path  # it used to add '/' at the end of host
                clean_url = url.normalize(scheme=True, host=True, path=normalize_path, query=True, fragment=True, userinfo=True, percents=True).to_uri().to_text()
                if not self.protocol:
                    if clean_url[:len(dummy_scheme) + 3] == (dummy_scheme + "://"):
                        clean_url = clean_url[len(dummy_scheme) + 3:]
                    else:
                        msg = "hyperlink lib did not create URL as was expected"
                        raise ValueError(msg)
                return clean_url
            msg = "Missing host"
            raise ValueError(msg)
        except:
            url = ""
            if self.protocol:
                url += f"{self.protocol}://"
            if self.userinfo:
                url += f"{self.userinfo}@"
            if self.host:
                url += self.host
            if self.port:
                url += f":{self.port}"
            if self.path:
                url += "{}{}".format("/" if self.path[0] != "/" else "", self.path)
            if self.query:
                url += f"?{self.query}"
            if self.fragment:
                url += f"#{self.fragment}"
            return url

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("view_endpoint", args=[str(self.id)])

    def clean(self):
        errors = []
        null_char_list = ["0x00", "\x00"]
        db_type = connection.vendor
        if self.protocol or self.protocol == "":
            if not re.match(r"^[A-Za-z][A-Za-z0-9\.\-\+]+$", self.protocol):  # https://tools.ietf.org/html/rfc3986#section-3.1
                errors.append(ValidationError(f'Protocol "{self.protocol}" has invalid format'))
            if self.protocol == "":
                self.protocol = None

        if self.userinfo or self.userinfo == "":
            if not re.match(r"^[A-Za-z0-9\.\-_~%\!\$&\'\(\)\*\+,;=:]+$", self.userinfo):  # https://tools.ietf.org/html/rfc3986#section-3.2.1
                errors.append(ValidationError(f'Userinfo "{self.userinfo}" has invalid format'))
            if self.userinfo == "":
                self.userinfo = None

        if self.host:
            if not re.match(r"^[A-Za-z0-9_\-\+][A-Za-z0-9_\.\-\+]+$", self.host):
                try:
                    validate_ipv46_address(self.host)
                except ValidationError:
                    errors.append(ValidationError(f'Host "{self.host}" has invalid format'))
        else:
            errors.append(ValidationError("Host must not be empty"))

        if self.port or self.port == 0:
            try:
                int_port = int(self.port)
                if not (0 <= int_port < 65536):
                    errors.append(ValidationError(f'Port "{self.port}" has invalid format - out of range'))
                self.port = int_port
            except ValueError:
                errors.append(ValidationError(f'Port "{self.port}" has invalid format - it is not a number'))

        if self.path or self.path == "":
            while len(self.path) > 0 and self.path[0] == "/":  # Endpoint store "root-less" path
                self.path = self.path[1:]
            if any(null_char in self.path for null_char in null_char_list):
                old_value = self.path
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.path = self.path.replace(remove_str, "%00")
                    logger.error(f'Path "{old_value}" has invalid format - It contains the NULL character. The following action was taken: {action_string}')
            if self.path == "":
                self.path = None

        if self.query or self.query == "":
            if len(self.query) > 0 and self.query[0] == "?":
                self.query = self.query[1:]
            if any(null_char in self.query for null_char in null_char_list):
                old_value = self.query
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.query = self.query.replace(remove_str, "%00")
                    logger.error(f'Query "{old_value}" has invalid format - It contains the NULL character. The following action was taken: {action_string}')
            if self.query == "":
                self.query = None

        if self.fragment or self.fragment == "":
            if len(self.fragment) > 0 and self.fragment[0] == "#":
                self.fragment = self.fragment[1:]
            if any(null_char in self.fragment for null_char in null_char_list):
                old_value = self.fragment
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.fragment = self.fragment.replace(remove_str, "%00")
                    logger.error(f'Fragment "{old_value}" has invalid format - It contains the NULL character. The following action was taken: {action_string}')
            if self.fragment == "":
                self.fragment = None

        if errors:
            raise ValidationError(errors)

    def __hash__(self):
        return self.__str__().__hash__()

    def __eq__(self, other):
        if isinstance(other, Endpoint):
            # Check if the contents of the endpoint match
            contents_match = str(self) == str(other)
            # Determine if products should be used in the equation
            if self.product is not None and other.product is not None:
                # Check if the products are the same
                products_match = (self.product) == other.product
                # Check if the contents match
                return products_match and contents_match
            return contents_match

        return NotImplemented

    @property
    def is_broken(self):
        try:
            self.clean()
        except:
            return True
        else:
            return not self.product

    @property
    def mitigated(self):
        return not self.vulnerable

    @property
    def vulnerable(self):
        return Endpoint_Status.objects.filter(
            endpoint=self,
            mitigated=False,
            false_positive=False,
            out_of_scope=False,
            risk_accepted=False,
        ).count() > 0

    @property
    def findings_count(self):
        return self.findings.all().count()

    def active_findings(self):
        return self.findings.filter(
            active=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
        ).order_by("numerical_severity")

    def active_verified_findings(self):
        return self.findings.filter(
            active=True,
            verified=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
        ).order_by("numerical_severity")

    @property
    def active_findings_count(self):
        return self.active_findings().count()

    @property
    def active_verified_findings_count(self):
        return self.active_verified_findings().count()

    def host_endpoints(self):
        return Endpoint.objects.filter(host=self.host,
                                       product=self.product).distinct()

    @property
    def host_endpoints_count(self):
        return self.host_endpoints().count()

    def host_mitigated_endpoints(self):
        meps = Endpoint_Status.objects \
                  .filter(endpoint__in=self.host_endpoints()) \
                  .filter(Q(mitigated=True)
                          | Q(false_positive=True)
                          | Q(out_of_scope=True)
                          | Q(risk_accepted=True)
                          | Q(finding__out_of_scope=True)
                          | Q(finding__mitigated__isnull=False)
                          | Q(finding__false_p=True)
                          | Q(finding__duplicate=True)
                          | Q(finding__active=False))
        return Endpoint.objects.filter(status_endpoint__in=meps).distinct()

    @property
    def host_mitigated_endpoints_count(self):
        return self.host_mitigated_endpoints().count()

    def host_findings(self):
        return Finding.objects.filter(endpoints__in=self.host_endpoints()).distinct()

    @property
    def host_findings_count(self):
        return self.host_findings().count()

    def host_active_findings(self):
        return Finding.objects.filter(
            active=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
            endpoints__in=self.host_endpoints(),
        ).order_by("numerical_severity")

    def host_active_verified_findings(self):
        return Finding.objects.filter(
            active=True,
            verified=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
            endpoints__in=self.host_endpoints(),
        ).order_by("numerical_severity")

    @property
    def host_active_findings_count(self):
        return self.host_active_findings().count()

    @property
    def host_active_verified_findings_count(self):
        return self.host_active_verified_findings().count()

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{"title": self.host,
                "url": reverse("view_endpoint", args=(self.id,))}]
        return bc

    @staticmethod
    def from_uri(uri):
        try:
            url = hyperlink.parse(url=uri)
        except UnicodeDecodeError:
            from urllib.parse import urlparse
            url = hyperlink.parse(url="//" + urlparse(uri).netloc)
        except hyperlink.URLParseError as e:
            msg = f"Invalid URL format: {e}"
            raise ValidationError(msg)

        query_parts = []  # inspired by https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L1768
        for k, v in url.query:
            if v is None:
                query_parts.append(k)
            else:
                query_parts.append(f"{k}={v}")
        query_string = "&".join(query_parts)

        protocol = url.scheme if url.scheme != "" else None
        userinfo = ":".join(url.userinfo) if url.userinfo not in [(), ("",)] else None
        host = url.host if url.host != "" else None
        port = url.port
        path = "/".join(url.path)[:500] if url.path not in [None, (), ("",)] else None
        query = query_string[:1000] if query_string is not None and query_string != "" else None
        fragment = url.fragment[:500] if url.fragment is not None and url.fragment != "" else None

        return Endpoint(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
        )

    def inherit_tags(self, potentially_existing_tags):
        # get a copy of the tags to be inherited
        incoming_inherited_tags = [tag.name for tag in self.product.tags.all()]
        _manage_inherited_tags(self, incoming_inherited_tags, potentially_existing_tags=potentially_existing_tags)


class Development_Environment(models.Model):
    name = models.CharField(max_length=200)

    def __str__(self):
        return self.name

    def get_breadcrumbs(self):
        return [{"title": str(self),
                 "url": reverse("edit_dev_env", args=(self.id,))}]


class Sonarqube_Issue(models.Model):
    key = models.CharField(max_length=60, unique=True, help_text=_("SonarQube issue key"))
    status = models.CharField(max_length=20, help_text=_("SonarQube issue status"))
    type = models.CharField(max_length=20, help_text=_("SonarQube issue type"))

    def __str__(self):
        return self.key


class Sonarqube_Issue_Transition(models.Model):
    sonarqube_issue = models.ForeignKey(Sonarqube_Issue, on_delete=models.CASCADE, db_index=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    finding_status = models.CharField(max_length=100)
    sonarqube_status = models.CharField(max_length=50)
    transitions = models.CharField(max_length=100)

    class Meta:
        ordering = ("-created", )


class Test(models.Model):
    engagement = models.ForeignKey(Engagement, editable=False, on_delete=models.CASCADE)
    lead = models.ForeignKey(Dojo_User, editable=True, null=True, blank=True, on_delete=models.RESTRICT)
    test_type = models.ForeignKey(Test_Type, on_delete=models.CASCADE)
    scan_type = models.TextField(null=True)
    title = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    target_start = models.DateTimeField()
    target_end = models.DateTimeField()
    estimated_time = models.TimeField(null=True, blank=True, editable=False)
    actual_time = models.TimeField(null=True, blank=True, editable=False)
    percent_complete = models.IntegerField(null=True, blank=True,
                                           editable=True)
    notes = models.ManyToManyField(Notes, blank=True,
                                   editable=False)
    files = models.ManyToManyField(FileUpload, blank=True, editable=False)
    environment = models.ForeignKey(Development_Environment, null=True,
                                    blank=False, on_delete=models.RESTRICT)

    updated = models.DateTimeField(auto_now=True, null=True)
    created = models.DateTimeField(auto_now_add=True, null=True)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this test. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    version = models.CharField(max_length=100, null=True, blank=True)

    build_id = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Build ID that was tested, a reimport may update this field."), verbose_name=_("Build ID"))
    commit_hash = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Commit hash tested, a reimport may update this field."), verbose_name=_("Commit Hash"))
    branch_tag = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Tag or branch that was tested, a reimport may update this field."), verbose_name=_("Branch/Tag"))
    api_scan_configuration = models.ForeignKey(Product_API_Scan_Configuration, null=True, editable=True, blank=True, on_delete=models.CASCADE, verbose_name=_("API Scan Configuration"))

    class Meta:
        indexes = [
            models.Index(fields=["engagement", "test_type"]),
        ]

    def __str__(self):
        if self.title:
            return f"{self.title} ({self.test_type})"
        return str(self.test_type)

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("view_test", args=[str(self.id)])

    def test_type_name(self) -> str:
        return self.test_type.name

    def get_breadcrumbs(self):
        bc = self.engagement.get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_test", args=(self.id,))}]
        return bc

    def copy(self, engagement=None):
        copy = self
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_files = list(self.files.all())
        old_tags = list(self.tags.all())
        old_findings = list(Finding.objects.filter(test=self))
        # Wipe the IDs of the new object
        copy.pk = None
        copy.id = None
        if engagement:
            copy.engagement = engagement
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Copy the files
        for files in old_files:
            copy.files.add(files.copy())
        # Copy the Findings
        for finding in old_findings:
            finding.copy(test=copy)
        # Assign any tags
        copy.tags.set(old_tags)

        return copy

    # only used by bulk risk acceptance api
    @property
    def unaccepted_open_findings(self):
        from dojo.utils import get_system_setting
        findings = Finding.objects.filter(risk_accepted=False, active=True, duplicate=False, test=self)
        if get_system_setting("enforce_verified_status", True):
            findings = findings.filter(verified=True)

        return findings

    def accept_risks(self, accepted_risks):
        self.engagement.risk_acceptance.add(*accepted_risks)

    @property
    def deduplication_algorithm(self):
        deduplicationAlgorithm = settings.DEDUPE_ALGO_LEGACY

        if hasattr(settings, "DEDUPLICATION_ALGORITHM_PER_PARSER"):
            if (self.test_type.name in settings.DEDUPLICATION_ALGORITHM_PER_PARSER):
                deduplicationLogger.debug(f"using DEDUPLICATION_ALGORITHM_PER_PARSER for test_type.name: {self.test_type.name}")
                deduplicationAlgorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER[self.test_type.name]
            elif (self.scan_type in settings.DEDUPLICATION_ALGORITHM_PER_PARSER):
                deduplicationLogger.debug(f"using DEDUPLICATION_ALGORITHM_PER_PARSER for scan_type: {self.scan_type}")
                deduplicationAlgorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER[self.scan_type]
        else:
            deduplicationLogger.debug("Section DEDUPLICATION_ALGORITHM_PER_PARSER not found in settings.dist.py")

        deduplicationLogger.debug(f"DEDUPLICATION_ALGORITHM_PER_PARSER is: {deduplicationAlgorithm}")
        return deduplicationAlgorithm

    @property
    def hash_code_fields(self):
        hashCodeFields = None

        if hasattr(settings, "HASHCODE_FIELDS_PER_SCANNER"):
            if (self.test_type.name in settings.HASHCODE_FIELDS_PER_SCANNER):
                deduplicationLogger.debug(f"using HASHCODE_FIELDS_PER_SCANNER for test_type.name: {self.test_type.name}")
                hashCodeFields = settings.HASHCODE_FIELDS_PER_SCANNER[self.test_type.name]
            elif (self.scan_type in settings.HASHCODE_FIELDS_PER_SCANNER):
                deduplicationLogger.debug(f"using HASHCODE_FIELDS_PER_SCANNER for scan_type: {self.scan_type}")
                hashCodeFields = settings.HASHCODE_FIELDS_PER_SCANNER[self.scan_type]
        else:
            deduplicationLogger.debug("Section HASHCODE_FIELDS_PER_SCANNER not found in settings.dist.py")

        deduplicationLogger.debug(f"HASHCODE_FIELDS_PER_SCANNER is: {hashCodeFields}")
        return hashCodeFields

    @property
    def hash_code_allows_null_cwe(self):
        hashCodeAllowsNullCwe = True

        if hasattr(settings, "HASHCODE_ALLOWS_NULL_CWE"):
            if (self.test_type.name in settings.HASHCODE_ALLOWS_NULL_CWE):
                deduplicationLogger.debug(f"using HASHCODE_ALLOWS_NULL_CWE for test_type.name: {self.test_type.name}")
                hashCodeAllowsNullCwe = settings.HASHCODE_ALLOWS_NULL_CWE[self.test_type.name]
            elif (self.scan_type in settings.HASHCODE_ALLOWS_NULL_CWE):
                deduplicationLogger.debug(f"using HASHCODE_ALLOWS_NULL_CWE for scan_type: {self.scan_type}")
                hashCodeAllowsNullCwe = settings.HASHCODE_ALLOWS_NULL_CWE[self.scan_type]
        else:
            deduplicationLogger.debug("Section HASHCODE_ALLOWS_NULL_CWE not found in settings.dist.py")

        deduplicationLogger.debug(f"HASHCODE_ALLOWS_NULL_CWE is: {hashCodeAllowsNullCwe}")
        return hashCodeAllowsNullCwe

    def delete(self, *args, **kwargs):
        logger.debug("%d test delete", self.id)
        super().delete(*args, **kwargs)
        calculate_grade(self.engagement.product)

    @property
    def statistics(self):
        """Queries the database, no prefetching, so could be slow for lists of model instances"""
        return _get_statistics_for_queryset(Finding.objects.filter(test=self), _get_annotations_for_statistics)

    def inherit_tags(self, potentially_existing_tags):
        # get a copy of the tags to be inherited
        incoming_inherited_tags = [tag.name for tag in self.engagement.product.tags.all()]
        _manage_inherited_tags(self, incoming_inherited_tags, potentially_existing_tags=potentially_existing_tags)


class Test_Import(TimeStampedModel):

    IMPORT_TYPE = "import"
    REIMPORT_TYPE = "reimport"

    test = models.ForeignKey(Test, editable=False, null=False, blank=False, on_delete=models.CASCADE)
    findings_affected = models.ManyToManyField("Finding", through="Test_Import_Finding_Action")
    import_settings = JSONField(null=True)
    type = models.CharField(max_length=64, null=False, blank=False, default="unknown")

    version = models.CharField(max_length=100, null=True, blank=True)
    build_id = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Build ID that was tested, a reimport may update this field."), verbose_name=_("Build ID"))
    commit_hash = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Commit hash tested, a reimport may update this field."), verbose_name=_("Commit Hash"))
    branch_tag = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Tag or branch that was tested, a reimport may update this field."), verbose_name=_("Branch/Tag"))

    def get_queryset(self):
        logger.debug("prefetch test_import counts")
        super_query = super().get_queryset()
        super_query = super_query.annotate(created_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_CREATED_FINDING)))
        super_query = super_query.annotate(closed_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_CLOSED_FINDING)))
        super_query = super_query.annotate(reactivated_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_REACTIVATED_FINDING)))
        return super_query.annotate(untouched_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_UNTOUCHED_FINDING)))

    class Meta:
        ordering = ("-id",)
        indexes = [
            models.Index(fields=["created", "test", "type"]),
        ]

    def __str__(self):
        return self.created.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def statistics(self):
        """Queries the database, no prefetching, so could be slow for lists of model instances"""
        stats = {}
        for action in IMPORT_ACTIONS:
            stats[action[1].lower()] = _get_statistics_for_queryset(Finding.objects.filter(test_import_finding_action__test_import=self, test_import_finding_action__action=action[0]), _get_annotations_for_statistics)
        return stats


class Test_Import_Finding_Action(TimeStampedModel):
    test_import = models.ForeignKey(Test_Import, editable=False, null=False, blank=False, on_delete=models.CASCADE)
    finding = models.ForeignKey("Finding", editable=False, null=False, blank=False, on_delete=models.CASCADE)
    action = models.CharField(max_length=100, null=True, blank=True, choices=IMPORT_ACTIONS)

    class Meta:
        indexes = [
            models.Index(fields=["finding", "action", "test_import"]),
        ]
        unique_together = (("test_import", "finding"))
        ordering = ("test_import", "action", "finding")

    def __str__(self):
        return f"{self.finding.id}: {self.action}"


class Finding(models.Model):
    title = models.CharField(max_length=511,
                             verbose_name=_("Title"),
                             help_text=_("A short description of the flaw."))
    date = models.DateField(default=get_current_date,
                            verbose_name=_("Date"),
                            help_text=_("The date the flaw was discovered."))
    sla_start_date = models.DateField(
                            blank=True,
                            null=True,
                            verbose_name=_("SLA Start Date"),
                            help_text=_("(readonly)The date used as start date for SLA calculation. Set by expiring risk acceptances. Empty by default, causing a fallback to 'date'."))
    sla_expiration_date = models.DateField(
                            blank=True,
                            null=True,
                            verbose_name=_("SLA Expiration Date"),
                            help_text=_("(readonly)The date SLA expires for this finding. Empty by default, causing a fallback to 'date'."))
    cwe = models.IntegerField(default=0, null=True, blank=True,
                              verbose_name=_("CWE"),
                              help_text=_("The CWE number associated with this flaw."))
    cve = models.CharField(max_length=50,
                           null=True,
                           blank=False,
                           verbose_name=_("Vulnerability Id"),
                           help_text=_("An id of a vulnerability in a security advisory associated with this finding. Can be a Common Vulnerabilities and Exposures (CVE) or from other sources."))
    epss_score = models.FloatField(default=None, null=True, blank=True,
                              verbose_name=_("EPSS Score"),
                              help_text=_("EPSS score for the CVE. Describes how likely it is the vulnerability will be exploited in the next 30 days."),
                              validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    epss_percentile = models.FloatField(default=None, null=True, blank=True,
                              verbose_name=_("EPSS percentile"),
                              help_text=_("EPSS percentile for the CVE. Describes how many CVEs are scored at or below this one."),
                              validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    cvssv3_regex = RegexValidator(regex=r"^AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]", message="CVSS must be entered in format: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'")
    cvssv3 = models.TextField(validators=[cvssv3_regex],
                              max_length=117,
                              null=True,
                              verbose_name=_("CVSS v3"),
                              help_text=_("Common Vulnerability Scoring System version 3 (CVSSv3) score associated with this flaw."))
    cvssv3_score = models.FloatField(null=True,
                                        blank=True,
                                        verbose_name=_("CVSSv3 score"),
                                        help_text=_("Numerical CVSSv3 score for the vulnerability. If the vector is given, the score is updated while saving the finding. The value must be between 0-10."),
                                        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)])

    url = models.TextField(null=True,
                           blank=True,
                           editable=False,
                           verbose_name=_("URL"),
                           help_text=_("External reference that provides more information about this flaw."))  # not displayed and pretty much the same as references. To remove?
    severity = models.CharField(max_length=200,
                                verbose_name=_("Severity"),
                                help_text=_("The severity level of this flaw (Critical, High, Medium, Low, Info)."))
    description = models.TextField(verbose_name=_("Description"),
                                help_text=_("Longer more descriptive information about the flaw."))
    mitigation = models.TextField(verbose_name=_("Mitigation"),
                                null=True,
                                blank=True,
                                help_text=_("Text describing how to best fix the flaw."))
    impact = models.TextField(verbose_name=_("Impact"),
                                null=True,
                                blank=True,
                                help_text=_("Text describing the impact this flaw has on systems, products, enterprise, etc."))
    steps_to_reproduce = models.TextField(null=True,
                                          blank=True,
                                          verbose_name=_("Steps to Reproduce"),
                                          help_text=_("Text describing the steps that must be followed in order to reproduce the flaw / bug."))
    severity_justification = models.TextField(null=True,
                                              blank=True,
                                              verbose_name=_("Severity Justification"),
                                              help_text=_("Text describing why a certain severity was associated with this flaw."))
    endpoints = models.ManyToManyField(Endpoint,
                                       blank=True,
                                       verbose_name=_("Endpoints"),
                                       help_text=_("The hosts within the product that are susceptible to this flaw. + The status of the endpoint associated with this flaw (Vulnerable, Mitigated, ...)."),
                                       through=Endpoint_Status)
    references = models.TextField(null=True,
                                  blank=True,
                                  db_column="refs",
                                  verbose_name=_("References"),
                                  help_text=_("The external documentation available for this flaw."))
    test = models.ForeignKey(Test,
                             editable=False,
                             on_delete=models.CASCADE,
                             verbose_name=_("Test"),
                             help_text=_("The test that is associated with this flaw."))
    active = models.BooleanField(default=True,
                                 verbose_name=_("Active"),
                                 help_text=_("Denotes if this flaw is active or not."))
    # note that false positive findings cannot be verified
    # in defectdojo verified means: "we have verified the finding and it turns out that it's not a false positive"
    verified = models.BooleanField(default=False,
                                   verbose_name=_("Verified"),
                                   help_text=_("Denotes if this flaw has been manually verified by the tester."))
    false_p = models.BooleanField(default=False,
                                  verbose_name=_("False Positive"),
                                  help_text=_("Denotes if this flaw has been deemed a false positive by the tester."))
    duplicate = models.BooleanField(default=False,
                                    verbose_name=_("Duplicate"),
                                    help_text=_("Denotes if this flaw is a duplicate of other flaws reported."))
    duplicate_finding = models.ForeignKey("self",
                                          editable=False,
                                          null=True,
                                          related_name="original_finding",
                                          blank=True, on_delete=models.DO_NOTHING,
                                          verbose_name=_("Duplicate Finding"),
                                          help_text=_("Link to the original finding if this finding is a duplicate."))
    out_of_scope = models.BooleanField(default=False,
                                       verbose_name=_("Out Of Scope"),
                                       help_text=_("Denotes if this flaw falls outside the scope of the test and/or engagement."))
    risk_accepted = models.BooleanField(default=False,
                                       verbose_name=_("Risk Accepted"),
                                       help_text=_("Denotes if this finding has been marked as an accepted risk."))
    under_review = models.BooleanField(default=False,
                                       verbose_name=_("Under Review"),
                                       help_text=_("Denotes is this flaw is currently being reviewed."))

    last_status_update = models.DateTimeField(editable=False,
                                            null=True,
                                            blank=True,
                                            auto_now_add=True,
                                            verbose_name=_("Last Status Update"),
                                            help_text=_("Timestamp of latest status update (change in status related fields)."))

    review_requested_by = models.ForeignKey(Dojo_User,
                                            null=True,
                                            blank=True,
                                            related_name="review_requested_by",
                                            on_delete=models.RESTRICT,
                                            verbose_name=_("Review Requested By"),
                                            help_text=_("Documents who requested a review for this finding."))
    reviewers = models.ManyToManyField(Dojo_User,
                                       blank=True,
                                       verbose_name=_("Reviewers"),
                                       help_text=_("Documents who reviewed the flaw."))

    # Defect Tracking Review
    under_defect_review = models.BooleanField(default=False,
                                              verbose_name=_("Under Defect Review"),
                                              help_text=_("Denotes if this finding is under defect review."))
    defect_review_requested_by = models.ForeignKey(Dojo_User,
                                                   null=True,
                                                   blank=True,
                                                   related_name="defect_review_requested_by",
                                                   on_delete=models.RESTRICT,
                                                   verbose_name=_("Defect Review Requested By"),
                                                   help_text=_("Documents who requested a defect review for this flaw."))
    is_mitigated = models.BooleanField(default=False,
                                       verbose_name=_("Is Mitigated"),
                                       help_text=_("Denotes if this flaw has been fixed."))
    thread_id = models.IntegerField(default=0,
                                    editable=False,
                                    verbose_name=_("Thread ID"))
    mitigated = models.DateTimeField(editable=False,
                                     null=True,
                                     blank=True,
                                     verbose_name=_("Mitigated"),
                                     help_text=_("Denotes if this flaw has been fixed by storing the date it was fixed."))
    mitigated_by = models.ForeignKey(Dojo_User,
                                     null=True,
                                     editable=False,
                                     related_name="mitigated_by",
                                     on_delete=models.RESTRICT,
                                     verbose_name=_("Mitigated By"),
                                     help_text=_("Documents who has marked this flaw as fixed."))
    reporter = models.ForeignKey(Dojo_User,
                                 editable=False,
                                 default=1,
                                 related_name="reporter",
                                 on_delete=models.RESTRICT,
                                 verbose_name=_("Reporter"),
                                 help_text=_("Documents who reported the flaw."))
    notes = models.ManyToManyField(Notes,
                                   blank=True,
                                   editable=False,
                                   verbose_name=_("Notes"),
                                   help_text=_("Stores information pertinent to the flaw or the mitigation."))
    numerical_severity = models.CharField(max_length=4,
                                          verbose_name=_("Numerical Severity"),
                                          help_text=_("The numerical representation of the severity (S0, S1, S2, S3, S4)."))
    last_reviewed = models.DateTimeField(null=True,
                                         editable=False,
                                         verbose_name=_("Last Reviewed"),
                                         help_text=_("Provides the date the flaw was last 'touched' by a tester."))
    last_reviewed_by = models.ForeignKey(Dojo_User,
                                         null=True,
                                         editable=False,
                                         related_name="last_reviewed_by",
                                         on_delete=models.RESTRICT,
                                         verbose_name=_("Last Reviewed By"),
                                         help_text=_("Provides the person who last reviewed the flaw."))
    files = models.ManyToManyField(FileUpload,
                                   blank=True,
                                   editable=False,
                                   verbose_name=_("Files"),
                                   help_text=_("Files(s) related to the flaw."))
    param = models.TextField(null=True,
                             blank=True,
                             editable=False,
                             verbose_name=_("Parameter"),
                             help_text=_("Parameter used to trigger the issue (DAST)."))
    payload = models.TextField(null=True,
                               blank=True,
                               editable=False,
                               verbose_name=_("Payload"),
                               help_text=_("Payload used to attack the service / application and trigger the bug / problem."))
    hash_code = models.CharField(null=True,
                                 blank=True,
                                 editable=False,
                                 max_length=64,
                                 verbose_name=_("Hash Code"),
                                 help_text=_("A hash over a configurable set of fields that is used for findings deduplication."))
    line = models.IntegerField(null=True,
                               blank=True,
                               verbose_name=_("Line number"),
                               help_text=_("Source line number of the attack vector."))
    file_path = models.CharField(null=True,
                                 blank=True,
                                 max_length=4000,
                                 verbose_name=_("File path"),
                                 help_text=_("Identified file(s) containing the flaw."))
    component_name = models.CharField(null=True,
                                      blank=True,
                                      max_length=500,
                                      verbose_name=_("Component name"),
                                      help_text=_("Name of the affected component (library name, part of a system, ...)."))
    component_version = models.CharField(null=True,
                                         blank=True,
                                         max_length=100,
                                         verbose_name=_("Component version"),
                                         help_text=_("Version of the affected component."))
    found_by = models.ManyToManyField(Test_Type,
                                      editable=False,
                                      verbose_name=_("Found by"),
                                      help_text=_("The name of the scanner that identified the flaw."))
    static_finding = models.BooleanField(default=False,
                                         verbose_name=_("Static finding (SAST)"),
                                         help_text=_("Flaw has been detected from a Static Application Security Testing tool (SAST)."))
    dynamic_finding = models.BooleanField(default=True,
                                          verbose_name=_("Dynamic finding (DAST)"),
                                          help_text=_("Flaw has been detected from a Dynamic Application Security Testing tool (DAST)."))
    created = models.DateTimeField(auto_now_add=True,
                                   null=True,
                                   verbose_name=_("Created"),
                                   help_text=_("The date the finding was created inside DefectDojo."))
    scanner_confidence = models.IntegerField(null=True,
                                             blank=True,
                                             default=None,
                                             editable=False,
                                             verbose_name=_("Scanner confidence"),
                                             help_text=_("Confidence level of vulnerability which is supplied by the scanner."))
    sonarqube_issue = models.ForeignKey(Sonarqube_Issue,
                                        null=True,
                                        blank=True,
                                        help_text=_("The SonarQube issue associated with this finding."),
                                        verbose_name=_("SonarQube issue"),
                                        on_delete=models.CASCADE)
    unique_id_from_tool = models.CharField(null=True,
                                           blank=True,
                                           max_length=500,
                                           verbose_name=_("Unique ID from tool"),
                                           help_text=_("Vulnerability technical id from the source tool. Allows to track unique vulnerabilities."))
    vuln_id_from_tool = models.CharField(null=True,
                                         blank=True,
                                         max_length=500,
                                         verbose_name=_("Vulnerability ID from tool"),
                                         help_text=_("Non-unique technical id from the source tool associated with the vulnerability type."))
    sast_source_object = models.CharField(null=True,
                                          blank=True,
                                          max_length=500,
                                          verbose_name=_("SAST Source Object"),
                                          help_text=_("Source object (variable, function...) of the attack vector."))
    sast_sink_object = models.CharField(null=True,
                                        blank=True,
                                        max_length=500,
                                        verbose_name=_("SAST Sink Object"),
                                        help_text=_("Sink object (variable, function...) of the attack vector."))
    sast_source_line = models.IntegerField(null=True,
                                           blank=True,
                                           verbose_name=_("SAST Source Line number"),
                                           help_text=_("Source line number of the attack vector."))
    sast_source_file_path = models.CharField(null=True,
                                             blank=True,
                                             max_length=4000,
                                             verbose_name=_("SAST Source File Path"),
                                             help_text=_("Source file path of the attack vector."))
    nb_occurences = models.IntegerField(null=True,
                                        blank=True,
                                        verbose_name=_("Number of occurences"),
                                        help_text=_("Number of occurences in the source tool when several vulnerabilites were found and aggregated by the scanner."))

    # this is useful for vulnerabilities on dependencies : helps answer the question "Did I add this vulnerability or was it discovered recently?"
    publish_date = models.DateField(null=True,
                                         blank=True,
                                         verbose_name=_("Publish date"),
                                         help_text=_("Date when this vulnerability was made publicly available."))

    # The service is used to generate the hash_code, so that it gets part of the deduplication of findings.
    service = models.CharField(null=True,
                               blank=True,
                               max_length=200,
                               verbose_name=_("Service"),
                               help_text=_("A service is a self-contained piece of functionality within a Product. This is an optional field which is used in deduplication of findings when set."))

    planned_remediation_date = models.DateField(null=True,
                                                editable=True,
                                                verbose_name=_("Planned Remediation Date"),
                                                help_text=_("The date the flaw is expected to be remediated."))

    planned_remediation_version = models.CharField(null=True,
                                        blank=True,
                                        max_length=99,
                                        verbose_name=_("Planned remediation version"),
                                        help_text=_("The target version when the vulnerability should be fixed / remediated"))

    effort_for_fixing = models.CharField(null=True,
                                blank=True,
                                max_length=99,
                                verbose_name=_("Effort for fixing"),
                                help_text=_("Effort for fixing / remediating the vulnerability (Low, Medium, High)"))

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this finding. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    SEVERITIES = {"Info": 4, "Low": 3, "Medium": 2,
                  "High": 1, "Critical": 0}

    class Meta:
        ordering = ("numerical_severity", "-date", "title", "epss_score", "epss_percentile")
        indexes = [
            models.Index(fields=["test", "active", "verified"]),

            models.Index(fields=["test", "is_mitigated"]),
            models.Index(fields=["test", "duplicate"]),
            models.Index(fields=["test", "out_of_scope"]),
            models.Index(fields=["test", "false_p"]),

            models.Index(fields=["test", "unique_id_from_tool", "duplicate"]),
            models.Index(fields=["test", "hash_code", "duplicate"]),

            models.Index(fields=["test", "component_name"]),

            models.Index(fields=["cve"]),
            models.Index(fields=["epss_score"]),
            models.Index(fields=["epss_percentile"]),
            models.Index(fields=["cwe"]),
            models.Index(fields=["out_of_scope"]),
            models.Index(fields=["false_p"]),
            models.Index(fields=["verified"]),
            models.Index(fields=["mitigated"]),
            models.Index(fields=["active"]),
            models.Index(fields=["numerical_severity"]),
            models.Index(fields=["date"]),
            models.Index(fields=["title"]),
            models.Index(fields=["hash_code"]),
            models.Index(fields=["unique_id_from_tool"]),
            # models.Index(fields=['file_path']), # can't add index because the field has max length 4000.
            models.Index(fields=["line"]),
            models.Index(fields=["component_name"]),
            models.Index(fields=["duplicate"]),
            models.Index(fields=["is_mitigated"]),
            models.Index(fields=["duplicate_finding", "id"]),
        ]

    def __str__(self):
        return self.title

    def save(self, dedupe_option=True, rules_option=True, product_grading_option=True,
             issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):

        from dojo.finding import helper as finding_helper

        if not user:
            from dojo.utils import get_current_user
            user = get_current_user()
        # Title Casing
        from titlecase import titlecase
        self.title = titlecase(self.title[:511])
        # Set the date of the finding if nothing is supplied
        if self.date is None:
            self.date = timezone.now()
        # Assign the numerical severity for correct sorting order
        self.numerical_severity = Finding.get_numerical_severity(self.severity)

        # Synchronize cvssv3 score using cvssv3 vector
        if self.cvssv3:
            try:
                cvss_object = CVSS3(self.cvssv3)
                # use the environmental score, which is the most refined score
                self.cvssv3_score = cvss_object.scores()[2]
            except Exception as ex:
                logger.error("Can't compute cvssv3 score for finding id %i. Invalid cvssv3 vector found: '%s'. Exception: %s", self.id, self.cvssv3, ex)

        self.set_hash_code(dedupe_option)

        if self.pk is None:
            # We enter here during the first call from serializers.py
            from dojo.utils import apply_cwe_to_template
            self = apply_cwe_to_template(self)

            if (self.file_path is not None) and (len(self.unsaved_endpoints) == 0):
                self.static_finding = True
                self.dynamic_finding = False
            elif (self.file_path is not None):
                self.static_finding = True

            # because we have reduced the number of (super()).save() calls, the helper is no longer called for new findings
            # so we call it manually
            finding_helper.update_finding_status(self, user, changed_fields={"id": (None, None)})

        else:
            # logger.debug('setting static / dynamic in save')
            # need to have an id/pk before we can access endpoints
            if (self.file_path is not None) and (self.endpoints.count() == 0):
                self.static_finding = True
                self.dynamic_finding = False
            elif (self.file_path is not None):
                self.static_finding = True

        # update the SLA expiration date last, after all other finding fields have been updated
        self.set_sla_expiration_date()

        logger.debug("Saving finding of id " + str(self.id) + " dedupe_option:" + str(dedupe_option) + " (self.pk is %s)", "None" if self.pk is None else "not None")
        super().save(*args, **kwargs)

        self.found_by.add(self.test.test_type)

        # only perform post processing (in celery task) if needed. this check avoids submitting 1000s of tasks to celery that will do nothing
        if dedupe_option or issue_updater_option or product_grading_option or push_to_jira:
            finding_helper.post_process_finding_save(self, dedupe_option=dedupe_option, rules_option=rules_option, product_grading_option=product_grading_option,
                issue_updater_option=issue_updater_option, push_to_jira=push_to_jira, user=user, *args, **kwargs)
        else:
            logger.debug("no options selected that require finding post processing")

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("view_finding", args=[str(self.id)])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.unsaved_endpoints = []
        self.unsaved_request = None
        self.unsaved_response = None
        self.unsaved_tags = None
        self.unsaved_files = None
        self.unsaved_vulnerability_ids = None

    def copy(self, test=None):
        copy = self
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_files = list(self.files.all())
        old_status_findings = list(self.status_finding.all())
        old_reviewers = list(self.reviewers.all())
        old_found_by = list(self.found_by.all())
        old_tags = list(self.tags.all())
        # Wipe the IDs of the new object
        copy.pk = None
        copy.id = None
        if test:
            copy.test = test
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Copy the files
        for files in old_files:
            copy.files.add(files.copy())
        # Copy the endpoint_status
        for endpoint_status in old_status_findings:
            endpoint_status.copy(finding=copy)  # adding or setting is not necessary, link is created by Endpoint_Status.copy()
        # Assign any reviewers
        copy.reviewers.set(old_reviewers)
        # Assign any found_by
        copy.found_by.set(old_found_by)
        # Assign any tags
        copy.tags.set(old_tags)

        return copy

    def delete(self, *args, **kwargs):
        logger.debug("%d finding delete", self.id)
        import dojo.finding.helper as helper
        helper.finding_delete(self)
        super().delete(*args, **kwargs)
        calculate_grade(self.test.engagement.product)

    # only used by bulk risk acceptance api
    @classmethod
    def unaccepted_open_findings(cls):
        from dojo.utils import get_system_setting
        results = cls.objects.filter(active=True, duplicate=False, risk_accepted=False)
        if get_system_setting("enforce_verified_status", True):
            results = results.filter(verified=True)

        return results

    @property
    def risk_acceptance(self):
        ras = self.risk_acceptance_set.all()
        if ras:
            return ras[0]

        return None

    def compute_hash_code(self):

        # Check if all needed settings are defined
        if not hasattr(settings, "HASHCODE_FIELDS_PER_SCANNER") or not hasattr(settings, "HASHCODE_ALLOWS_NULL_CWE") or not hasattr(settings, "HASHCODE_ALLOWED_FIELDS"):
            deduplicationLogger.debug("no or incomplete configuration per hash_code found; using legacy algorithm")
            return self.compute_hash_code_legacy()

        hash_code_fields = self.test.hash_code_fields

        # Check if hash_code fields are found in the settings
        if not hash_code_fields:
            deduplicationLogger.debug(
                "No configuration for hash_code computation found; using default fields for " + ("dynamic" if self.dynamic_finding else "static") + " scanners")
            return self.compute_hash_code_legacy()

        # Check if all elements of HASHCODE_FIELDS_PER_SCANNER are in HASHCODE_ALLOWED_FIELDS
        if not (all(elem in settings.HASHCODE_ALLOWED_FIELDS for elem in hash_code_fields)):
            deduplicationLogger.debug(
                "compute_hash_code - configuration error: some elements of HASHCODE_FIELDS_PER_SCANNER are not in the allowed list HASHCODE_ALLOWED_FIELDS. "
                "Using default fields")
            return self.compute_hash_code_legacy()

        # Make sure that we have a cwe if we need one
        if self.cwe == 0 and not self.test.hash_code_allows_null_cwe:
            deduplicationLogger.warning(
                "Cannot compute hash_code based on configured fields because cwe is 0 for finding of title '" + self.title + "' found in file '" + str(self.file_path)
                + "'. Fallback to legacy mode for this finding.")
            return self.compute_hash_code_legacy()

        deduplicationLogger.debug("computing hash_code for finding id " + str(self.id) + " based on: " + ", ".join(hash_code_fields))

        fields_to_hash = ""
        for hashcodeField in hash_code_fields:
            if hashcodeField == "endpoints":
                # For endpoints, need to compute the field
                myEndpoints = self.get_endpoints()
                fields_to_hash = fields_to_hash + myEndpoints
                deduplicationLogger.debug(hashcodeField + " : " + myEndpoints)
            elif hashcodeField == "vulnerability_ids":
                # For vulnerability_ids, need to compute the field
                my_vulnerability_ids = self.get_vulnerability_ids()
                fields_to_hash = fields_to_hash + my_vulnerability_ids
                deduplicationLogger.debug(hashcodeField + " : " + my_vulnerability_ids)
            else:
                # Generically use the finding attribute having the same name, converts to str in case it's integer
                fields_to_hash = fields_to_hash + str(getattr(self, hashcodeField))
                deduplicationLogger.debug(hashcodeField + " : " + str(getattr(self, hashcodeField)))
        deduplicationLogger.debug("compute_hash_code - fields_to_hash = " + fields_to_hash)
        return self.hash_fields(fields_to_hash)

    def compute_hash_code_legacy(self):
        fields_to_hash = self.title + str(self.cwe) + str(self.line) + str(self.file_path) + self.description
        deduplicationLogger.debug("compute_hash_code_legacy - fields_to_hash = " + fields_to_hash)
        return self.hash_fields(fields_to_hash)

    # Get vulnerability_ids to use for hash_code computation
    def get_vulnerability_ids(self):
        vulnerability_id_str = ""
        if self.id is None:
            if self.unsaved_vulnerability_ids:
                deduplicationLogger.debug("get_vulnerability_ids before the finding was saved")
                # convert list of unsaved vulnerability_ids to the list of their canonical representation
                vulnerability_id_str_list = [str(vulnerability_id) for vulnerability_id in self.unsaved_vulnerability_ids]
                # deduplicate (usually done upon saving finding) and sort endpoints
                vulnerability_id_str = "".join(sorted(dict.fromkeys(vulnerability_id_str_list)))
            else:
                deduplicationLogger.debug("finding has no unsaved vulnerability references")
        else:
            vulnerability_ids = Vulnerability_Id.objects.filter(finding=self)
            deduplicationLogger.debug("get_vulnerability_ids after the finding was saved. Vulnerability references count: " + str(vulnerability_ids.count()))
            # convert list of vulnerability_ids to the list of their canonical representation
            vulnerability_id_str_list = [str(vulnerability_id) for vulnerability_id in vulnerability_ids.all()]
            # sort vulnerability_ids strings
            vulnerability_id_str = "".join(sorted(vulnerability_id_str_list))
        return vulnerability_id_str

    # Get endpoints to use for hash_code computation
    # (This sometimes reports "None")
    def get_endpoints(self):
        endpoint_str = ""
        if (self.id is None):
            if len(self.unsaved_endpoints) > 0:
                deduplicationLogger.debug("get_endpoints before the finding was saved")
                # convert list of unsaved endpoints to the list of their canonical representation
                endpoint_str_list = [str(endpoint) for endpoint in self.unsaved_endpoints]
                # deduplicate (usually done upon saving finding) and sort endpoints
                endpoint_str = "".join(
                    sorted(
                        dict.fromkeys(endpoint_str_list)))
            else:
                # we can get here when the parser defines static_finding=True but leaves dynamic_finding defaulted
                # In this case, before saving the finding, both static_finding and dynamic_finding are True
                # After saving dynamic_finding may be set to False probably during the saving process (observed on Bandit scan before forcing dynamic_finding=False at parser level)
                deduplicationLogger.debug("trying to get endpoints on a finding before it was saved but no endpoints found (static parser wrongly identified as dynamic?")
        else:
            deduplicationLogger.debug("get_endpoints: after the finding was saved. Endpoints count: " + str(self.endpoints.count()))
            # convert list of endpoints to the list of their canonical representation
            endpoint_str_list = [str(endpoint) for endpoint in self.endpoints.all()]
            # sort endpoints strings
            endpoint_str = "".join(
                sorted(
                    endpoint_str_list,
                ))
        return endpoint_str

    # Compute the hash_code from the fields to hash
    def hash_fields(self, fields_to_hash):
        if hasattr(settings, "HASH_CODE_FIELDS_ALWAYS"):
            for field in settings.HASH_CODE_FIELDS_ALWAYS:
                if getattr(self, field):
                    fields_to_hash += str(getattr(self, field))

        logger.debug("fields_to_hash      : %s", fields_to_hash)
        logger.debug("fields_to_hash lower: %s", fields_to_hash.lower())
        return hashlib.sha256(fields_to_hash.casefold().encode("utf-8").strip()).hexdigest()

    def duplicate_finding_set(self):
        if self.duplicate:
            if self.duplicate_finding is not None:
                return Finding.objects.get(
                    id=self.duplicate_finding.id).original_finding.all().order_by("title")
            return []
        return self.original_finding.all().order_by("title")

    def get_scanner_confidence_text(self):
        if self.scanner_confidence and isinstance(self.scanner_confidence, int):
            if self.scanner_confidence <= 2:
                return "Certain"
            if self.scanner_confidence >= 3 and self.scanner_confidence <= 5:
                return "Firm"
            return "Tentative"
        return ""

    @staticmethod
    def get_numerical_severity(severity):
        if severity == "Critical":
            return "S0"
        if severity == "High":
            return "S1"
        if severity == "Medium":
            return "S2"
        if severity == "Low":
            return "S3"
        if severity == "Info":
            return "S4"
        return "S5"

    @staticmethod
    def get_number_severity(severity):
        if severity == "Critical":
            return 4
        if severity == "High":
            return 3
        if severity == "Medium":
            return 2
        if severity == "Low":
            return 1
        if severity == "Info":
            return 0
        return 5

    @staticmethod
    def get_severity(num_severity):
        severities = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        if num_severity in severities:
            return severities[num_severity]

        return None

    def status(self):
        status = []
        if self.under_review:
            status += ["Under Review"]
        if self.active:
            status += ["Active"]
        else:
            status += ["Inactive"]
        if self.verified:
            status += ["Verified"]
        if self.mitigated or self.is_mitigated:
            status += ["Mitigated"]
        if self.false_p:
            status += ["False Positive"]
        if self.out_of_scope:
            status += ["Out Of Scope"]
        if self.duplicate:
            status += ["Duplicate"]
        if self.risk_accepted:
            status += ["Risk Accepted"]
        if not len(status):
            status += ["Initial"]

        return ", ".join([str(s) for s in status])

    def _age(self, start_date):
        from dateutil.parser import parse
        if start_date and isinstance(start_date, str):
            start_date = parse(start_date).date()

        from dojo.utils import get_work_days
        if settings.SLA_BUSINESS_DAYS:
            if self.mitigated:
                mitigated_date = self.mitigated
                if isinstance(mitigated_date, datetime):
                    mitigated_date = self.mitigated.date()
                days = get_work_days(self.date, mitigated_date)
            else:
                days = get_work_days(self.date, get_current_date())
        else:
            if isinstance(start_date, datetime):
                start_date = start_date.date()

            if self.mitigated:
                mitigated_date = self.mitigated
                if isinstance(mitigated_date, datetime):
                    mitigated_date = self.mitigated.date()
                diff = mitigated_date - start_date
            else:
                diff = get_current_date() - start_date
            days = diff.days
        return max(0, days)

    @property
    def age(self):
        return self._age(self.date)

    @property
    def sla_age(self):
        return self._age(self.get_sla_start_date())

    def get_sla_start_date(self):
        if self.sla_start_date:
            return self.sla_start_date
        return self.date

    def get_sla_period(self):
        sla_configuration = SLA_Configuration.objects.filter(id=self.test.engagement.product.sla_configuration_id).first()
        sla_period = getattr(sla_configuration, self.severity.lower(), None)
        enforce_period = getattr(sla_configuration, str("enforce_" + self.severity.lower()), None)
        return sla_period, enforce_period

    def set_sla_expiration_date(self):
        system_settings = System_Settings.objects.get()
        if not system_settings.enable_finding_sla:
            return

        days_remaining = None
        sla_period, enforce_period = self.get_sla_period()
        if sla_period is not None and enforce_period:
            days_remaining = sla_period - self.sla_age
        else:
            self.sla_expiration_date = Finding().sla_expiration_date
            return

        if days_remaining:
            if self.mitigated:
                mitigated_date = self.mitigated
                if isinstance(mitigated_date, datetime):
                    mitigated_date = self.mitigated.date()
                self.sla_expiration_date = mitigated_date + relativedelta(days=days_remaining)
            else:
                self.sla_expiration_date = get_current_date() + relativedelta(days=days_remaining)

    def sla_days_remaining(self):
        if self.sla_expiration_date:
            if self.mitigated:
                mitigated_date = self.mitigated
                if isinstance(mitigated_date, datetime):
                    mitigated_date = self.mitigated.date()
                return (self.sla_expiration_date - mitigated_date).days
            return (self.sla_expiration_date - get_current_date()).days
        return None

    def sla_deadline(self):
        return self.sla_expiration_date

    def github(self):
        try:
            return self.github_issue
        except GITHUB_Issue.DoesNotExist:
            return None

    def has_github_issue(self):
        try:
            # Attempt to access the github issue if it exists. If not, an exception will be caught
            _ = self.github_issue
            return True
        except GITHUB_Issue.DoesNotExist:
            return False

    def github_conf(self):
        try:
            github_product_key = GITHUB_PKey.objects.get(product=self.test.engagement.product)
            github_conf = github_product_key.conf
        except:
            github_conf = None
        return github_conf

    # newer version that can work with prefetching
    def github_conf_new(self):
        try:
            return self.test.engagement.product.github_pkey_set.all()[0].git_conf
        except:
            return None

    @property
    def has_jira_issue(self):
        import dojo.jira_link.helper as jira_helper
        return jira_helper.has_jira_issue(self)

    @cached_property
    def finding_group(self):
        return self.finding_group_set.all().first()
        # logger.debug('finding.finding_group: %s', group)

    @cached_property
    def has_jira_group_issue(self):
        if not self.has_finding_group:
            return False

        import dojo.jira_link.helper as jira_helper
        return jira_helper.has_jira_issue(self.finding_group)

    @property
    def has_jira_configured(self):
        import dojo.jira_link.helper as jira_helper
        return jira_helper.has_jira_configured(self)

    @cached_property
    def has_finding_group(self):
        return self.finding_group is not None

    def save_no_options(self, *args, **kwargs):
        return self.save(dedupe_option=False, rules_option=False, product_grading_option=False,
             issue_updater_option=False, push_to_jira=False, user=None, *args, **kwargs)

    # Check if a mandatory field is empty. If it's the case, fill it with "no <fieldName> given"
    def clean(self):
        no_check = ["test", "reporter"]
        bigfields = ["description"]
        for field_obj in self._meta.fields:
            field = field_obj.name
            if field not in no_check:
                val = getattr(self, field)
                if not val and field == "title":
                    setattr(self, field, "No title given")
                if not val and field in bigfields:
                    setattr(self, field, f"No {field} given")

    def severity_display(self):
        return self.severity

    def get_breadcrumbs(self):
        bc = self.test.get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_finding", args=(self.id,))}]
        return bc

    def get_valid_request_response_pairs(self):
        empty_value = base64.b64encode(b"")
        # Get a list of all req/resp pairs
        all_req_resps = self.burprawrequestresponse_set.all()
        # Filter away those that do not have any contents
        return all_req_resps.exclude(
            burpRequestBase64__exact=empty_value,
            burpResponseBase64__exact=empty_value,
        )

    def get_report_requests(self):
        # Get the list of request response pairs that are non empty
        request_response_pairs = self.get_valid_request_response_pairs()
        # Determine how many to return
        if request_response_pairs.count() >= 3:
            return request_response_pairs[0:3]
        if request_response_pairs.count() > 0:
            return request_response_pairs
        return None

    def get_request(self):
        # Get the list of request response pairs that are non empty
        request_response_pairs = self.get_valid_request_response_pairs()
        # Determine what to return
        if request_response_pairs.count() > 0:
            reqres = request_response_pairs.first()
        return base64.b64decode(reqres.burpRequestBase64)

    def get_response(self):
        # Get the list of request response pairs that are non empty
        request_response_pairs = self.get_valid_request_response_pairs()
        # Determine what to return
        if request_response_pairs.count() > 0:
            reqres = request_response_pairs.first()
        res = base64.b64decode(reqres.burpResponseBase64)
        # Removes all blank lines
        return re.sub(r"\n\s*\n", "\n", res)

    def latest_note(self):
        if self.notes.all():
            note = self.notes.all()[0]
            return note.date.strftime("%Y-%m-%d %H:%M:%S") + ": " + note.author.get_full_name() + " : " + note.entry

        return ""

    def get_sast_source_file_path_with_link(self):
        from dojo.utils import create_bleached_link
        if self.sast_source_file_path is None:
            return None
        if self.test.engagement.source_code_management_uri is None:
            return escape(self.sast_source_file_path)
        link = self.test.engagement.source_code_management_uri + "/" + self.sast_source_file_path
        if self.sast_source_line:
            link = link + "#L" + str(self.sast_source_line)
        return create_bleached_link(link, self.sast_source_file_path)

    def get_file_path_with_link(self):
        from dojo.utils import create_bleached_link
        if self.file_path is None:
            return None
        if self.test.engagement.source_code_management_uri is None:
            return escape(self.file_path)
        link = self.get_file_path_with_raw_link()
        return create_bleached_link(link, self.file_path)

    def get_scm_type(self):
        # extract scm type from product custom field 'scm-type'

        if hasattr(self.test.engagement, "product"):
            dojo_meta = DojoMeta.objects.filter(product=self.test.engagement.product, name="scm-type").first()
            if dojo_meta:
                st = dojo_meta.value.strip()
                if st:
                    return st.lower()
        return ""

    def scm_public_prepare_base_link(self, uri):
        # scm public (https://scm-domain.org) url template for browse is:
        # https://scm-domain.org/<username>/<repository-slug>
        # but when you get repo url for git, its template is:
        # https://scm-domain.org/<username>/<repository-slug>.git
        # so to create browser url - git url should be recomposed like below:

        parts_uri = uri.split(".git")
        return parts_uri[0]

    def git_public_prepare_scm_link(self, uri, scm_type):
        # if commit hash or branch/tag is set for engagement/test -
        # hash or branch/tag should be appended to base browser link
        intermediate_path = "/blob/" if scm_type in ["github", "gitlab"] else "/src/"

        link = self.scm_public_prepare_base_link(uri)
        if self.test.commit_hash:
            link += intermediate_path + self.test.commit_hash + "/" + self.file_path
        elif self.test.engagement.commit_hash:
            link += intermediate_path + self.test.engagement.commit_hash + "/" + self.file_path
        elif self.test.branch_tag:
            link += intermediate_path + self.test.branch_tag + "/" + self.file_path
        elif self.test.engagement.branch_tag:
            link += intermediate_path + self.test.engagement.branch_tag + "/" + self.file_path
        else:
            link += intermediate_path + "master/" + self.file_path

        return link

    def bitbucket_standalone_prepare_scm_base_link(self, uri):
        # bitbucket onpremise/standalone url template for browse is:
        # https://bb.example.com/projects/<project-key>/repos/<repository-slug>
        # but when you get repo url for git, its template is:
        # https://bb.example.com/scm/<project-key>/<repository-slug>.git
        # or for user public repo^
        # https://bb.example.com/users/<username>/repos/<repository-slug>
        # but when you get repo url for git, its template is:
        # https://bb.example.com/scm/<username>/<repository-slug>.git (username often could be prefixed with ~)
        # so to create borwser url - git url should be recomposed like below:

        parts_uri = uri.split(".git")
        parts_scm = parts_uri[0].split("/scm/")
        parts_project = parts_scm[1].split("/")
        project = parts_project[0]
        if project.startswith("~"):
            return parts_scm[0] + "/users/" + parts_project[0][1:] + "/repos/" + parts_project[1] + "/browse"
        return parts_scm[0] + "/projects/" + parts_project[0] + "/repos/" + parts_project[1] + "/browse"

    def bitbucket_standalone_prepare_scm_link(self, uri):
        # if commit hash or branch/tag is set for engagement/test -
        # hash or barnch/tag should be appended to base browser link

        link = self.bitbucket_standalone_prepare_scm_base_link(uri)
        if self.test.commit_hash:
            link += "/" + self.file_path + "?at=" + self.test.commit_hash
        elif self.test.engagement.commit_hash:
            link += "/" + self.file_path + "?at=" + self.test.engagement.commit_hash
        elif self.test.branch_tag:
            link += "/" + self.file_path + "?at=" + self.test.branch_tag
        elif self.test.engagement.branch_tag:
            link += "/" + self.file_path + "?at=" + self.test.engagement.branch_tag
        else:
            link += "/" + self.file_path

        return link

    def get_file_path_with_raw_link(self):
        if self.file_path is None:
            return None

        link = self.test.engagement.source_code_management_uri
        scm_type = self.get_scm_type()
        if (self.test.engagement.source_code_management_uri is not None):
            if scm_type == "bitbucket-standalone":
                link = self.bitbucket_standalone_prepare_scm_link(link)
            elif scm_type in ["github", "gitlab", "gitea", "codeberg", "bitbucket"]:
                link = self.git_public_prepare_scm_link(link, scm_type)
            elif "https://github.com/" in self.test.engagement.source_code_management_uri:
                link = self.git_public_prepare_scm_link(link, "github")
            else:
                link += "/" + self.file_path
        else:
            link += "/" + self.file_path

        # than - add line part to browser url
        if self.line:
            if scm_type in ["github", "gitlab", "gitea", "codeberg"] or "https://github.com/" in self.test.engagement.source_code_management_uri:
                link = link + "#L" + str(self.line)
            elif scm_type == "bitbucket-standalone":
                link = link + "#" + str(self.line)
            elif scm_type == "bitbucket":
                link = link + "#lines-" + str(self.line)
        return link

    def get_references_with_links(self):
        import re

        from dojo.utils import create_bleached_link
        if self.references is None:
            return None
        matches = re.findall(r"([\(|\[]?(https?):((//)|(\\\\))+([\w\d:#@%/;$~_?\+-=\\\.&](#!)?)*[\)|\]]?)", self.references)

        processed_matches = []
        for match in matches:
            # Check if match isn't already a markdown link
            # Only replace the same matches one time, otherwise the links will be corrupted
            if not (match[0].startswith("[") or match[0].startswith("(")) and match[0] not in processed_matches:
                self.references = self.references.replace(match[0], create_bleached_link(match[0], match[0]), 1)
                processed_matches.append(match[0])

        return self.references

    @cached_property
    def vulnerability_ids(self):
        # Get vulnerability ids from database and convert to list of strings
        vulnerability_ids_model = self.vulnerability_id_set.all()
        vulnerability_ids = []
        for vulnerability_id in vulnerability_ids_model:
            vulnerability_ids.append(vulnerability_id.vulnerability_id)

        # Synchronize the cve field with the unsaved_vulnerability_ids
        # We do this to be as flexible as possible to handle the fields until
        # the cve field is not needed anymore and can be removed.
        if vulnerability_ids and self.cve:
            # Make sure the first entry of the list is the value of the cve field
            vulnerability_ids.insert(0, self.cve)
        elif not vulnerability_ids and self.cve:
            # If there is no list, make one with the value of the cve field
            vulnerability_ids = [self.cve]

        # Remove duplicates
        return list(dict.fromkeys(vulnerability_ids))

    def inherit_tags(self, potentially_existing_tags):
        # get a copy of the tags to be inherited
        incoming_inherited_tags = [tag.name for tag in self.test.engagement.product.tags.all()]
        _manage_inherited_tags(self, incoming_inherited_tags, potentially_existing_tags=potentially_existing_tags)

    @property
    def violates_sla(self):
        return (self.sla_expiration_date and self.sla_expiration_date < timezone.now().date())

    def set_hash_code(self, dedupe_option):
        from dojo.utils import get_custom_method
        if hash_method := get_custom_method("FINDING_HASH_METHOD"):
            hash_method(self, dedupe_option)
        else:
            # Finding.save is called once from serializers.py with dedupe_option=False because the finding is not ready yet, for example the endpoints are not built
            # It is then called a second time with dedupe_option defaulted to true; now we can compute the hash_code and run the deduplication
            if dedupe_option:
                if self.hash_code is not None:
                    deduplicationLogger.debug("Hash_code already computed for finding")
                else:
                    self.hash_code = self.compute_hash_code()
                    deduplicationLogger.debug("Hash_code computed for finding: %s", self.hash_code)


class FindingAdmin(admin.ModelAdmin):
    # For efficiency with large databases, display many-to-many fields with raw
    # IDs rather than multi-select
    raw_id_fields = (
        "endpoints",
    )


class Vulnerability_Id(models.Model):
    finding = models.ForeignKey(Finding, editable=False, on_delete=models.CASCADE)
    vulnerability_id = models.TextField(max_length=50, blank=False, null=False)

    def __str__(self):
        return self.vulnerability_id

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("view_finding", args=[str(self.finding.id)])


class Stub_Finding(models.Model):
    title = models.TextField(max_length=1000, blank=False, null=False)
    date = models.DateField(default=get_current_date, blank=False, null=False)
    severity = models.CharField(max_length=200, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    test = models.ForeignKey(Test, editable=False, on_delete=models.CASCADE)
    reporter = models.ForeignKey(Dojo_User, editable=False, default=1, on_delete=models.RESTRICT)

    class Meta:
        ordering = ("-date", "title")

    def __str__(self):
        return self.title

    def get_breadcrumbs(self):
        bc = self.test.get_breadcrumbs()
        bc += [{"title": "Potential Finding: " + str(self),
                "url": reverse("view_potential_finding", args=(self.id,))}]
        return bc


class Finding_Group(TimeStampedModel):

    GROUP_BY_OPTIONS = [("component_name", "Component Name"),
                        ("component_name+component_version", "Component Name + Version"),
                        ("file_path", "File path"),
                        ("finding_title", "Finding Title")]

    name = models.CharField(max_length=255, blank=False, null=False)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    findings = models.ManyToManyField(Finding)
    creator = models.ForeignKey(Dojo_User, on_delete=models.RESTRICT)

    def __str__(self):
        return self.name

    @property
    def has_jira_issue(self):
        import dojo.jira_link.helper as jira_helper
        return jira_helper.has_jira_issue(self)

    @cached_property
    def severity(self):
        if not self.findings.all():
            return None
        max_number_severity = max(Finding.get_number_severity(find.severity) for find in self.findings.all())
        return Finding.get_severity(max_number_severity)

    @cached_property
    def components(self):
        components: dict[str, set[str | None]] = {}
        for finding in self.findings.all():
            if finding.component_name is not None:
                components.setdefault(finding.component_name, set()).add(finding.component_version)
        return "; ".join(f"""{name}: {", ".join(map(str, versions))}""" for name, versions in components.items())

    @property
    def age(self):
        if not self.findings.all():
            return None

        return max(find.age for find in self.findings.all())

    @cached_property
    def sla_days_remaining_internal(self):
        if not self.findings.all():
            return None

        return min([find.sla_days_remaining() for find in self.findings.all() if find.sla_days_remaining()], default=None)

    def sla_days_remaining(self):
        return self.sla_days_remaining_internal

    def sla_deadline(self):
        if not self.findings.all():
            return None

        return min([find.sla_deadline() for find in self.findings.all() if find.sla_deadline()], default=None)

    def status(self):
        if not self.findings.all():
            return None

        if any(find.active for find in self.findings.all()):
            return "Active"

        if all(find.is_mitigated for find in self.findings.all()):
            return "Mitigated"

        return "Inactive"

    @cached_property
    def mitigated(self):
        return all(find.mitigated is not None for find in self.findings.all())

    def get_sla_start_date(self):
        return min(find.get_sla_start_date() for find in self.findings.all())

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("view_test", args=[str(self.test.id)])

    class Meta:
        ordering = ["id"]


class Finding_Template(models.Model):
    title = models.TextField(max_length=1000)
    cwe = models.IntegerField(default=None, null=True, blank=True)
    cve = models.CharField(max_length=50,
                           null=True,
                           blank=False,
                           verbose_name="Vulnerability Id",
                           help_text="An id of a vulnerability in a security advisory associated with this finding. Can be a Common Vulnerabilities and Exposures (CVE) or from other sources.")
    cvssv3_regex = RegexValidator(regex=r"^AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]", message="CVSS must be entered in format: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'")
    cvssv3 = models.TextField(validators=[cvssv3_regex], max_length=117, null=True)
    severity = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    mitigation = models.TextField(null=True, blank=True)
    impact = models.TextField(null=True, blank=True)
    references = models.TextField(null=True, blank=True, db_column="refs")
    last_used = models.DateTimeField(null=True, editable=False)
    numerical_severity = models.CharField(max_length=4, null=True, blank=True, editable=False)
    template_match = models.BooleanField(default=False, verbose_name=_("Template Match Enabled"), help_text=_("Enables this template for matching remediation advice. Match will be applied to all active, verified findings by CWE."))
    template_match_title = models.BooleanField(default=False, verbose_name=_("Match Template by Title and CWE"), help_text=_("Matches by title text (contains search) and CWE."))

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this finding template. Choose from the list or add new tags. Press Enter key to add."))

    SEVERITIES = {"Info": 4, "Low": 3, "Medium": 2,
                  "High": 1, "Critical": 0}

    class Meta:
        ordering = ["-cwe"]

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse("edit_template", args=[str(self.id)])

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": reverse("view_template", args=(self.id,))}]

    @cached_property
    def vulnerability_ids(self):
        # Get vulnerability ids from database and convert to list of strings
        vulnerability_ids_model = self.vulnerability_id_template_set.all()
        vulnerability_ids = []
        for vulnerability_id in vulnerability_ids_model:
            vulnerability_ids.append(vulnerability_id.vulnerability_id)

        # Synchronize the cve field with the unsaved_vulnerability_ids
        # We do this to be as flexible as possible to handle the fields until
        # the cve field is not needed anymore and can be removed.
        if vulnerability_ids and self.cve:
            # Make sure the first entry of the list is the value of the cve field
            vulnerability_ids.insert(0, self.cve)
        elif not vulnerability_ids and self.cve:
            # If there is no list, make one with the value of the cve field
            vulnerability_ids = [self.cve]

        # Remove duplicates
        return list(dict.fromkeys(vulnerability_ids))


class Vulnerability_Id_Template(models.Model):
    finding_template = models.ForeignKey(Finding_Template, editable=False, on_delete=models.CASCADE)
    vulnerability_id = models.TextField(max_length=50, blank=False, null=False)


class Check_List(models.Model):
    session_management = models.CharField(max_length=50, default="none")
    session_issues = models.ManyToManyField(Finding,
                                            related_name="session_issues",
                                            blank=True)
    encryption_crypto = models.CharField(max_length=50, default="none")
    crypto_issues = models.ManyToManyField(Finding,
                                           related_name="crypto_issues",
                                           blank=True)
    configuration_management = models.CharField(max_length=50, default="")
    config_issues = models.ManyToManyField(Finding,
                                           related_name="config_issues",
                                           blank=True)
    authentication = models.CharField(max_length=50, default="none")
    auth_issues = models.ManyToManyField(Finding,
                                         related_name="auth_issues",
                                         blank=True)
    authorization_and_access_control = models.CharField(max_length=50,
                                                        default="none")
    author_issues = models.ManyToManyField(Finding,
                                           related_name="author_issues",
                                           blank=True)
    data_input_sanitization_validation = models.CharField(max_length=50,
                                                          default="none")
    data_issues = models.ManyToManyField(Finding, related_name="data_issues",
                                         blank=True)
    sensitive_data = models.CharField(max_length=50, default="none")
    sensitive_issues = models.ManyToManyField(Finding,
                                              related_name="sensitive_issues",
                                              blank=True)
    other = models.CharField(max_length=50, default="none")
    other_issues = models.ManyToManyField(Finding, related_name="other_issues",
                                          blank=True)
    engagement = models.ForeignKey(Engagement, editable=False,
                                   related_name="eng_for_check", on_delete=models.CASCADE)

    @staticmethod
    def get_status(pass_fail):
        if pass_fail == "Pass":  # noqa: S105
            return "success"
        if pass_fail == "Fail":  # noqa: S105
            return "danger"
        return "warning"

    def get_breadcrumb(self):
        bc = self.engagement.get_breadcrumb()
        bc += [{"title": "Check List",
                "url": reverse("complete_checklist",
                               args=(self.engagement.id,))}]
        return bc


class BurpRawRequestResponse(models.Model):
    finding = models.ForeignKey(Finding, blank=True, null=True, on_delete=models.CASCADE)
    burpRequestBase64 = models.BinaryField()
    burpResponseBase64 = models.BinaryField()

    def get_request(self):
        return str(base64.b64decode(self.burpRequestBase64), errors="ignore")

    def get_response(self):
        res = str(base64.b64decode(self.burpResponseBase64), errors="ignore")
        # Removes all blank lines
        return re.sub(r"\n\s*\n", "\n", res)


class Risk_Acceptance(models.Model):
    TREATMENT_ACCEPT = "A"
    TREATMENT_AVOID = "V"
    TREATMENT_MITIGATE = "M"
    TREATMENT_FIX = "F"
    TREATMENT_TRANSFER = "T"

    TREATMENT_TRANSLATIONS = {
        TREATMENT_ACCEPT: _("Accept (The risk is acknowledged, yet remains)"),
        TREATMENT_AVOID: _("Avoid (Do not engage with whatever creates the risk)"),
        TREATMENT_MITIGATE: _("Mitigate (The risk still exists, yet compensating controls make it less of a threat)"),
        TREATMENT_FIX: _("Fix (The risk is eradicated)"),
        TREATMENT_TRANSFER: _("Transfer (The risk is transferred to a 3rd party)"),
    }

    TREATMENT_CHOICES = [
        (TREATMENT_ACCEPT, TREATMENT_TRANSLATIONS[TREATMENT_ACCEPT]),
        (TREATMENT_AVOID, TREATMENT_TRANSLATIONS[TREATMENT_AVOID]),
        (TREATMENT_MITIGATE, TREATMENT_TRANSLATIONS[TREATMENT_MITIGATE]),
        (TREATMENT_FIX, TREATMENT_TRANSLATIONS[TREATMENT_FIX]),
        (TREATMENT_TRANSFER, TREATMENT_TRANSLATIONS[TREATMENT_TRANSFER]),
    ]

    name = models.CharField(max_length=300, null=False, blank=False, help_text=_("Descriptive name which in the future may also be used to group risk acceptances together across engagements and products"))

    accepted_findings = models.ManyToManyField(Finding)

    recommendation = models.CharField(choices=TREATMENT_CHOICES, max_length=2, null=False, default=TREATMENT_FIX, help_text=_("Recommendation from the security team."), verbose_name=_("Security Recommendation"))

    recommendation_details = models.TextField(null=True,
                                      blank=True,
                                      help_text=_("Explanation of security recommendation"), verbose_name=_("Security Recommendation Details"))

    decision = models.CharField(choices=TREATMENT_CHOICES, max_length=2, null=False, default=TREATMENT_ACCEPT, help_text=_("Risk treatment decision by risk owner"))
    decision_details = models.TextField(default=None, blank=True, null=True, help_text=_("If a compensating control exists to mitigate the finding or reduce risk, then list the compensating control(s)."))

    accepted_by = models.CharField(max_length=200, default=None, null=True, blank=True, verbose_name=_("Accepted By"), help_text=_("The person that accepts the risk, can be outside of DefectDojo."))
    path = models.FileField(upload_to="risk/%Y/%m/%d",
                            editable=True, null=True,
                            blank=True, verbose_name=_("Proof"))
    owner = models.ForeignKey(Dojo_User, editable=True, on_delete=models.RESTRICT, help_text=_("User in DefectDojo owning this acceptance. Only the owner and staff users can edit the risk acceptance."))

    expiration_date = models.DateTimeField(default=None, null=True, blank=True, help_text=_("When the risk acceptance expires, the findings will be reactivated (unless disabled below)."))
    expiration_date_warned = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) Date at which notice about the risk acceptance expiration was sent."))
    expiration_date_handled = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) When the risk acceptance expiration was handled (manually or by the daily job)."))
    reactivate_expired = models.BooleanField(null=False, blank=False, default=True, verbose_name=_("Reactivate findings on expiration"), help_text=_("Reactivate findings when risk acceptance expires?"))
    restart_sla_expired = models.BooleanField(default=False, null=False, verbose_name=_("Restart SLA on expiration"), help_text=_("When enabled, the SLA for findings is restarted when the risk acceptance expires."))

    notes = models.ManyToManyField(Notes, editable=False)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True, editable=False)

    def __str__(self):
        return str(self.name)

    def filename(self):
        # logger.debug('path: "%s"', self.path)
        if not self.path:
            return None
        return Path(self.path.name).name

    @property
    def name_and_expiration_info(self):
        return str(self.name) + (" (expired " if self.is_expired else " (expires ") + (timezone.localtime(self.expiration_date).strftime("%b %d, %Y") if self.expiration_date else "Never") + ")"

    def get_breadcrumbs(self):
        bc = self.engagement_set.first().get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_risk_acceptance", args=(
                    self.engagement_set.first().product.id, self.id))}]
        return bc

    @property
    def is_expired(self):
        return self.expiration_date_handled is not None

    # relationship is many to many, but we use it as one-to-many
    @property
    def engagement(self):
        engs = self.engagement_set.all()
        if engs:
            return engs[0]

        return None

    def copy(self, engagement=None):
        copy = self
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_accepted_findings_hash_codes = [finding.hash_code for finding in self.accepted_findings.all()]
        # Wipe the IDs of the new object
        copy.pk = None
        copy.id = None
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Assign any accepted findings
        if engagement:
            new_accepted_findings = Finding.objects.filter(test__engagement=engagement, hash_code__in=old_accepted_findings_hash_codes, risk_accepted=True).distinct()
            copy.accepted_findings.set(new_accepted_findings)
        return copy


class FileAccessToken(models.Model):

    """
    This will allow reports to request the images without exposing the
    media root to the world without
    authentication
    """

    user = models.ForeignKey(Dojo_User, null=False, blank=False, on_delete=models.CASCADE)
    file = models.ForeignKey(FileUpload, null=False, blank=False, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    size = models.CharField(max_length=9,
                            choices=(
                                ("small", "Small"),
                                ("medium", "Medium"),
                                ("large", "Large"),
                                ("thumbnail", "Thumbnail"),
                                ("original", "Original")),
                            default="medium")

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = uuid4()
        return super().save(*args, **kwargs)


ANNOUNCEMENT_STYLE_CHOICES = (
    ("info", "Info"),
    ("success", "Success"),
    ("warning", "Warning"),
    ("danger", "Danger"),
)


class Announcement(models.Model):
    message = models.CharField(max_length=500,
                                help_text=_("This dismissable message will be displayed on all pages for authenticated users. It can contain basic html tags, for example <a href='https://www.fred.com' style='color: #337ab7;' target='_blank'>https://example.com</a>"),
                                default="")
    style = models.CharField(max_length=64, choices=ANNOUNCEMENT_STYLE_CHOICES, default="info",
                            help_text=_("The style of banner to display. (info, success, warning, danger)"))
    dismissable = models.BooleanField(default=False,
                                      null=False,
                                      blank=True,
                                      verbose_name=_("Dismissable?"),
                                      help_text=_("Ticking this box allows users to dismiss the current announcement"),
                                      )


class UserAnnouncement(models.Model):
    announcement = models.ForeignKey(Announcement, null=True, editable=False, on_delete=models.CASCADE, related_name="user_announcement")
    user = models.ForeignKey(Dojo_User, null=True, editable=False, on_delete=models.CASCADE)


class BannerConf(models.Model):
    banner_enable = models.BooleanField(default=False, null=True, blank=True)
    banner_message = models.CharField(max_length=500, help_text=_("This message will be displayed on the login page. It can contain basic html tags, for example <a href='https://www.fred.com' style='color: #337ab7;' target='_blank'>https://example.com</a>"), default="")


class GITHUB_Conf(models.Model):
    configuration_name = models.CharField(max_length=2000, help_text=_("Enter a name to give to this configuration"), default="")
    api_key = models.CharField(max_length=2000, help_text=_("Enter your Github API Key"), default="")

    def __str__(self):
        return self.configuration_name


class GITHUB_Issue(models.Model):
    issue_id = models.CharField(max_length=200)
    issue_url = models.URLField(max_length=2000, verbose_name=_("GitHub issue URL"))
    finding = models.OneToOneField(Finding, null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.issue_id) + "| GitHub Issue URL: " + str(self.issue_url)


class GITHUB_Clone(models.Model):
    github_id = models.CharField(max_length=200)
    github_clone_id = models.CharField(max_length=200)


class GITHUB_Details_Cache(models.Model):
    github_id = models.CharField(max_length=200)
    github_key = models.CharField(max_length=200)
    github_status = models.CharField(max_length=200)
    github_resolution = models.CharField(max_length=200)


class GITHUB_PKey(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)

    git_project = models.CharField(max_length=200, blank=True, verbose_name=_("Github project"), help_text=_("Specify your project location. (:user/:repo)"))
    git_conf = models.ForeignKey(GITHUB_Conf, verbose_name=_("Github Configuration"),
                                 null=True, blank=True, on_delete=models.CASCADE)
    git_push_notes = models.BooleanField(default=False, blank=True, help_text=_("Notes added to findings will be automatically added to the corresponding github issue"))

    def __str__(self):
        return self.product.name + " | " + self.git_project


class JIRA_Instance(models.Model):
    configuration_name = models.CharField(max_length=2000, help_text=_("Enter a name to give to this configuration"), default="")
    url = models.URLField(max_length=2000, verbose_name=_("JIRA URL"), help_text=_("For more information how to configure Jira, read the DefectDojo documentation."))
    username = models.CharField(max_length=2000)
    password = models.CharField(max_length=2000)

    if hasattr(settings, "JIRA_ISSUE_TYPE_CHOICES_CONFIG"):
        default_issue_type_choices = settings.JIRA_ISSUE_TYPE_CHOICES_CONFIG
    else:
        default_issue_type_choices = (
                                        ("Task", "Task"),
                                        ("Story", "Story"),
                                        ("Epic", "Epic"),
                                        ("Spike", "Spike"),
                                        ("Bug", "Bug"),
                                        ("Security", "Security"),
                                    )
    default_issue_type = models.CharField(max_length=255,
                                          choices=default_issue_type_choices,
                                          default="Bug",
                                          help_text=_("You can define extra issue types in settings.py"))
    issue_template_dir = models.CharField(max_length=255,
                                      null=True,
                                      blank=True,
                                      help_text=_("Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates."))
    epic_name_id = models.IntegerField(help_text=_("To obtain the 'Epic name id' visit https://<YOUR JIRA URL>/rest/api/2/field and search for Epic Name. Copy the number out of cf[number] and paste it here."))
    open_status_key = models.IntegerField(verbose_name=_("Reopen Transition ID"), help_text=_("Transition ID to Re-Open JIRA issues, visit https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand=transitions.fields to find the ID for your JIRA instance"))
    close_status_key = models.IntegerField(verbose_name=_("Close Transition ID"), help_text=_("Transition ID to Close JIRA issues, visit https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand=transitions.fields to find the ID for your JIRA instance"))
    info_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Info"))
    low_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Low"))
    medium_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Medium"))
    high_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: High"))
    critical_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Critical"))
    finding_text = models.TextField(null=True, blank=True, help_text=_("Additional text that will be added to the finding in Jira. For example including how the finding was created or who to contact for more information."))
    accepted_mapping_resolution = models.CharField(null=True, blank=True, max_length=300, help_text=_("JIRA resolution names (comma-separated values) that maps to an Accepted Finding"))
    false_positive_mapping_resolution = models.CharField(null=True, blank=True, max_length=300, help_text=_("JIRA resolution names (comma-separated values) that maps to a False Positive Finding"))
    global_jira_sla_notification = models.BooleanField(default=True, blank=False, verbose_name=_("Globally send SLA notifications as comment?"), help_text=_("This setting can be overidden at the Product level"))
    finding_jira_sync = models.BooleanField(default=False, blank=False, verbose_name=_("Automatically sync Findings with JIRA?"), help_text=_("If enabled, this will sync changes to a Finding automatically to JIRA"))

    def __str__(self):
        return self.configuration_name + " | " + self.url + " | " + self.username

    @property
    def accepted_resolutions(self):
        return [m.strip() for m in (self.accepted_mapping_resolution or "").split(",")]

    @property
    def false_positive_resolutions(self):
        return [m.strip() for m in (self.false_positive_mapping_resolution or "").split(",")]

    def get_priority(self, status):
        if status == "Info":
            return self.info_mapping_severity
        if status == "Low":
            return self.low_mapping_severity
        if status == "Medium":
            return self.medium_mapping_severity
        if status == "High":
            return self.high_mapping_severity
        if status == "Critical":
            return self.critical_mapping_severity
        return "N/A"


# declare form here as we can't import forms.py due to circular imports not even locally
class JIRAForm_Admin(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)

    # django doesn't seem to have an easy way to handle password fields as PasswordInput requires reentry of passwords
    password_from_db = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # keep password from db to use if the user entered no password
            self.password_from_db = self.instance.password
            self.fields["password"].required = False

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data["password"]:
            cleaned_data["password"] = self.password_from_db

        return cleaned_data


class JIRA_Instance_Admin(admin.ModelAdmin):
    form = JIRAForm_Admin


class JIRA_Project(models.Model):
    jira_instance = models.ForeignKey(JIRA_Instance, verbose_name=_("JIRA Instance"),
                             null=True, blank=True, on_delete=models.PROTECT)
    project_key = models.CharField(max_length=200, blank=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, null=True)
    issue_template_dir = models.CharField(max_length=255,
                                      null=True,
                                      blank=True,
                                      help_text=_("Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates."))
    engagement = models.OneToOneField(Engagement, on_delete=models.CASCADE, null=True, blank=True)
    component = models.CharField(max_length=200, blank=True)
    custom_fields = models.JSONField(max_length=200, blank=True, null=True,
                                   help_text=_('JIRA custom field JSON mapping of Id to value, e.g. {"customfield_10122": [{"name": "8.0.1"}]}'))
    default_assignee = models.CharField(max_length=200, blank=True, null=True,
                                     help_text=_("JIRA default assignee (name). If left blank then it defaults to whatever is configured in JIRA."))
    jira_labels = models.CharField(max_length=200, blank=True, null=True,
                                   help_text=_("JIRA issue labels space seperated"))
    add_vulnerability_id_to_jira_label = models.BooleanField(default=False,
                                                             verbose_name=_("Add vulnerability Id as a JIRA label"),
                                                             blank=False)
    push_all_issues = models.BooleanField(default=False, blank=True,
         help_text=_("Automatically create JIRA tickets for verified findings, assuming enforce_verified_status is True, or for all findings otherwise. Once linked, the JIRA ticket will continue to sync, regardless of status in DefectDojo."))
    enable_engagement_epic_mapping = models.BooleanField(default=False,
                                                         blank=True)
    epic_issue_type_name = models.CharField(max_length=64, blank=True, default="Epic", help_text=_("The name of the of structure that represents an Epic"))
    push_notes = models.BooleanField(default=False, blank=True)
    product_jira_sla_notification = models.BooleanField(default=False, blank=True, verbose_name=_("Send SLA notifications as comment?"))
    risk_acceptance_expiration_notification = models.BooleanField(default=False, blank=True, verbose_name=_("Send Risk Acceptance expiration notifications as comment?"))
    enabled = models.BooleanField(
        verbose_name=_("Enable Connection With Jira Project"),
        help_text=_("When disabled, Findings will no longer be pushed to Jira, even if they have already been pushed previously."),
        default=True,
        blank=True)

    def __str__(self):
        value = f"{self.id}: {self.project_key} ({self.jira_instance.url if self.jira_instance else 'None'})"
        if not self.enabled:
            value += " - Not Connected"
        return value

    def clean(self):
        if not self.jira_instance:
            msg = "Cannot save JIRA Project Configuration without JIRA Instance"
            raise ValidationError(msg)


# declare form here as we can't import forms.py due to circular imports not even locally
class JIRAForm_Admin(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)

    # django doesn't seem to have an easy way to handle password fields as PasswordInput requires reentry of passwords
    password_from_db = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # keep password from db to use if the user entered no password
            self.password_from_db = self.instance.password
            self.fields["password"].required = False

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data["password"]:
            cleaned_data["password"] = self.password_from_db

        return cleaned_data


class JIRA_Conf_Admin(admin.ModelAdmin):
    form = JIRAForm_Admin


class JIRA_Issue(models.Model):
    jira_project = models.ForeignKey(JIRA_Project, on_delete=models.CASCADE, null=True)
    jira_id = models.CharField(max_length=200)
    jira_key = models.CharField(max_length=200)
    finding = models.OneToOneField(Finding, null=True, blank=True, on_delete=models.CASCADE)
    engagement = models.OneToOneField(Engagement, null=True, blank=True, on_delete=models.CASCADE)
    finding_group = models.OneToOneField(Finding_Group, null=True, blank=True, on_delete=models.CASCADE)

    jira_creation = models.DateTimeField(editable=True,
                                         null=True,
                                         verbose_name=_("Jira creation"),
                                         help_text=_("The date a Jira issue was created from this finding."))
    jira_change = models.DateTimeField(editable=True,
                                       null=True,
                                       verbose_name=_("Jira last update"),
                                       help_text=_("The date the linked Jira issue was last modified."))

    def __str__(self):
        text = ""
        if self.finding:
            text = self.finding.test.engagement.product.name + " | Finding: " + self.finding.title + ", ID: " + str(self.finding.id)
        elif self.engagement:
            text = self.engagement.product.name + " | Engagement: " + self.engagement.name + ", ID: " + str(self.engagement.id)
        return text + " | Jira Key: " + str(self.jira_key)

    def set_obj(self, obj):
        if isinstance(obj, Finding):
            self.finding = obj
        elif isinstance(obj, Finding_Group):
            self.finding_group = obj
        elif isinstance(obj, Engagement):
            self.engagement = obj
        else:
            msg = f"unknown object type while creating JIRA_Issue: {to_str_typed(obj)}"
            raise TypeError(msg)


class Linear_Instance(models.Model):
    LINEAR_API_URL = "https://api.linear.app/graphql"

    instance_name = models.CharField(
        max_length=2000,
        help_text=_("Enter a name to give to this configuration"),
        default="",
        unique=True
    )
    team_id = models.CharField(
        max_length=64,
        help_text=_("Enter the UUID of the Team where you want to file Issues"),
        default=""
    )
    addl_json_input = models.JSONField(
        max_length=2000,
        blank=True,
        null=True,
        default=dict,
        help_text=_('Enter any additional JSON input you want to use when creating new Issues, e.g. { "labelIds": ["your-label-uuid"] }')
    )
    api_key = models.CharField(max_length=2000)

    def __str__(self):
        return self.instance_name

class Linear_Issue(models.Model):
    url = models.URLField(max_length=2000, unique=True)
    findings = models.ManyToManyField(Finding, related_name="linear_issues")

NOTIFICATION_CHOICE_SLACK = ("slack", "slack")
NOTIFICATION_CHOICE_MSTEAMS = ("msteams", "msteams")
NOTIFICATION_CHOICE_MAIL = ("mail", "mail")
NOTIFICATION_CHOICE_WEBHOOKS = ("webhooks", "webhooks")
NOTIFICATION_CHOICE_ALERT = ("alert", "alert")

NOTIFICATION_CHOICES = (
    NOTIFICATION_CHOICE_SLACK,
    NOTIFICATION_CHOICE_MSTEAMS,
    NOTIFICATION_CHOICE_MAIL,
    NOTIFICATION_CHOICE_WEBHOOKS,
    NOTIFICATION_CHOICE_ALERT,
)

DEFAULT_NOTIFICATION = NOTIFICATION_CHOICE_ALERT


class Notifications(models.Model):
    product_type_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    product_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    engagement_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    test_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)

    scan_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True, help_text=_("Triggered whenever an (re-)import has been done that created/updated/closed findings."))
    scan_added_empty = MultiSelectField(choices=NOTIFICATION_CHOICES, default=[], blank=True, help_text=_("Triggered whenever an (re-)import has been done (even if that created/updated/closed no findings)."))
    jira_update = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True, verbose_name=_("JIRA problems"), help_text=_("JIRA sync happens in the background, errors will be shown as notifications/alerts so make sure to subscribe"))
    upcoming_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    stale_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    auto_close_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    close_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    user_mentioned = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    code_review = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    review_requested = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    other = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    user = models.ForeignKey(Dojo_User, default=None, null=True, editable=False, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, default=None, null=True, editable=False, on_delete=models.CASCADE)
    template = models.BooleanField(default=False)
    sla_breach = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True,
        verbose_name=_("SLA breach"),
        help_text=_("Get notified of (upcoming) SLA breaches"))
    risk_acceptance_expiration = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True,
        verbose_name=_("Risk Acceptance Expiration"),
        help_text=_("Get notified of (upcoming) Risk Acceptance expiries"))
    sla_breach_combined = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True,
        verbose_name=_("SLA breach (combined)"),
        help_text=_("Get notified of (upcoming) SLA breaches (a message per project)"))

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "product"], name="notifications_user_product"),
        ]
        indexes = [
            models.Index(fields=["user", "product"]),
        ]

    def __str__(self):
        return f"Notifications about {self.product or 'all projects'} for {self.user or 'system notifications'}"

    @classmethod
    def merge_notifications_list(cls, notifications_list):
        if not notifications_list:
            return []

        result = None
        for notifications in notifications_list:
            if result is None:
                # we start by copying the first instance, because creating a new instance would set all notification columns to 'alert' :-()
                result = notifications
                # result.pk = None # detach from db
            else:
                result.product_type_added = {*result.product_type_added, *notifications.product_type_added}
                result.product_added = {*result.product_added, *notifications.product_added}
                result.engagement_added = {*result.engagement_added, *notifications.engagement_added}
                result.test_added = {*result.test_added, *notifications.test_added}
                result.scan_added = {*result.scan_added, *notifications.scan_added}
                result.jira_update = {*result.jira_update, *notifications.jira_update}
                result.upcoming_engagement = {*result.upcoming_engagement, *notifications.upcoming_engagement}
                result.stale_engagement = {*result.stale_engagement, *notifications.stale_engagement}
                result.auto_close_engagement = {*result.auto_close_engagement, *notifications.auto_close_engagement}
                result.close_engagement = {*result.close_engagement, *notifications.close_engagement}
                result.user_mentioned = {*result.user_mentioned, *notifications.user_mentioned}
                result.code_review = {*result.code_review, *notifications.code_review}
                result.review_requested = {*result.review_requested, *notifications.review_requested}
                result.other = {*result.other, *notifications.other}
                result.sla_breach = {*result.sla_breach, *notifications.sla_breach}
                result.sla_breach_combined = {*result.sla_breach_combined, *notifications.sla_breach_combined}
                result.risk_acceptance_expiration = {*result.risk_acceptance_expiration, *notifications.risk_acceptance_expiration}
        return result


class NotificationsAdmin(admin.ModelAdmin):
    list_filter = ("user", "product")

    def get_list_display(self, request):
        list_fields = ["user", "product"]
        list_fields += [field.name for field in self.model._meta.fields if field.name not in list_fields]
        return list_fields


class Notification_Webhooks(models.Model):
    class Status(models.TextChoices):
        __STATUS_ACTIVE = "active"
        __STATUS_INACTIVE = "inactive"
        STATUS_ACTIVE = f"{__STATUS_ACTIVE}", _("Active")
        STATUS_ACTIVE_TMP = f"{__STATUS_ACTIVE}_tmp", _("Active but 5xx (or similar) error detected")
        STATUS_INACTIVE_TMP = f"{__STATUS_INACTIVE}_tmp", _("Temporary inactive because of 5xx (or similar) error")
        STATUS_INACTIVE_PERMANENT = f"{__STATUS_INACTIVE}_permanent", _("Permanently inactive")

    name = models.CharField(max_length=100, default="", blank=False, unique=True,
                                    help_text=_("Name of the incoming webhook"))
    url = models.URLField(max_length=200, default="", blank=False,
                                    help_text=_("The full URL of the incoming webhook"))
    header_name = models.CharField(max_length=100, default="", blank=True, null=True,
                                   help_text=_("Name of the header required for interacting with Webhook endpoint"))
    header_value = models.CharField(max_length=100, default="", blank=True, null=True,
                                   help_text=_("Content of the header required for interacting with Webhook endpoint"))
    status = models.CharField(max_length=20, choices=Status, default="active", blank=False,
                              help_text=_("Status of the incoming webhook"), editable=False)
    first_error = models.DateTimeField(help_text=_("If endpoint is active, when error happened first time"), blank=True, null=True, editable=False)
    last_error = models.DateTimeField(help_text=_("If endpoint is active, when error happened last time"), blank=True, null=True, editable=False)
    note = models.CharField(max_length=1000, default="", blank=True, null=True, help_text=_("Description of the latest error"), editable=False)
    owner = models.ForeignKey(Dojo_User, editable=True, null=True, blank=True, on_delete=models.CASCADE,
                              help_text=_("Owner/receiver of notification, if empty processed as system notification"))
    # TODO: Test that `editable` will block editing via API


class Tool_Product_Settings(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True, blank=True)
    product = models.ForeignKey(Product, default=1, editable=False, on_delete=models.CASCADE)
    tool_configuration = models.ForeignKey(Tool_Configuration, null=False,
                                           related_name="tool_configuration", on_delete=models.CASCADE)
    tool_project_id = models.CharField(max_length=200, null=True, blank=True)
    notes = models.ManyToManyField(Notes, blank=True, editable=False)

    class Meta:
        ordering = ["name"]


class Tool_Product_History(models.Model):
    product = models.ForeignKey(Tool_Product_Settings, editable=False, on_delete=models.CASCADE)
    last_scan = models.DateTimeField(null=False, editable=False, default=now)
    succesfull = models.BooleanField(default=True, verbose_name=_("Succesfully"))
    configuration_details = models.CharField(max_length=2000, null=True,
                                             blank=True)


class Alerts(models.Model):
    title = models.CharField(max_length=250, default="", null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.URLField(max_length=2000, null=True, blank=True)
    source = models.CharField(max_length=100, default="Generic")
    icon = models.CharField(max_length=25, default="icon-user-check")
    user_id = models.ForeignKey(Dojo_User, null=True, editable=False, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, null=False)

    class Meta:
        ordering = ["-created"]


class Cred_User(models.Model):
    name = models.CharField(max_length=200, null=False)
    username = models.CharField(max_length=200, null=False)
    password = models.CharField(max_length=600, null=False)
    role = models.CharField(max_length=200, null=False)
    authentication = models.CharField(max_length=15,
                                      choices=(
                                          ("Form", "Form Authentication"),
                                          ("SSO", "SSO Redirect")),
                                      default="Form")
    http_authentication = models.CharField(max_length=15,
                                           choices=(
                                               ("Basic", "Basic"),
                                               ("NTLM", "NTLM")),
                                           null=True, blank=True)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.URLField(max_length=2000, null=False)
    environment = models.ForeignKey(Development_Environment, null=False, on_delete=models.RESTRICT)
    login_regex = models.CharField(max_length=200, null=True, blank=True)
    logout_regex = models.CharField(max_length=200, null=True, blank=True)
    notes = models.ManyToManyField(Notes, blank=True, editable=False)
    is_valid = models.BooleanField(default=True, verbose_name=_("Login is valid"))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name + " (" + self.role + ")"


class Cred_Mapping(models.Model):
    cred_id = models.ForeignKey(Cred_User, null=False,
                                related_name="cred_user",
                                verbose_name=_("Credential"), on_delete=models.CASCADE)
    product = models.ForeignKey(Product, null=True, blank=True,
                                related_name="product", on_delete=models.CASCADE)
    finding = models.ForeignKey(Finding, null=True, blank=True,
                                related_name="finding", on_delete=models.CASCADE)
    engagement = models.ForeignKey(Engagement, null=True, blank=True,
                                   related_name="engagement", on_delete=models.CASCADE)
    test = models.ForeignKey(Test, null=True, blank=True, related_name="test", on_delete=models.CASCADE)
    is_authn_provider = models.BooleanField(default=False,
                                            verbose_name=_("Authentication Provider"))
    url = models.URLField(max_length=2000, null=True, blank=True)

    def __str__(self):
        return self.cred_id.name + " (" + self.cred_id.role + ")"


class Language_Type(models.Model):
    language = models.CharField(max_length=100, null=False)
    color = models.CharField(max_length=7, null=True, blank=True, verbose_name=_("HTML color"))

    def __str__(self):
        return self.language


class Languages(models.Model):
    language = models.ForeignKey(Language_Type, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    user = models.ForeignKey(Dojo_User, editable=True, blank=True, null=True, on_delete=models.RESTRICT)
    files = models.IntegerField(blank=True, null=True, verbose_name=_("Number of files"))
    blank = models.IntegerField(blank=True, null=True, verbose_name=_("Number of blank lines"))
    comment = models.IntegerField(blank=True, null=True, verbose_name=_("Number of comment lines"))
    code = models.IntegerField(blank=True, null=True, verbose_name=_("Number of code lines"))
    created = models.DateTimeField(auto_now_add=True, null=False)

    class Meta:
        unique_together = [("language", "product")]

    def __str__(self):
        return self.language.language


class App_Analysis(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, null=False)
    user = models.ForeignKey(Dojo_User, editable=True, on_delete=models.RESTRICT)
    confidence = models.IntegerField(blank=True, null=True, verbose_name=_("Confidence level"))
    version = models.CharField(max_length=200, null=True, blank=True, verbose_name=_("Version Number"))
    icon = models.CharField(max_length=200, null=True, blank=True)
    website = models.URLField(max_length=400, null=True, blank=True)
    website_found = models.URLField(max_length=400, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)

    tags = TagField(blank=True, force_lowercase=True)

    def __str__(self):
        return self.name + " | " + self.product.name


class Objects_Review(models.Model):
    name = models.CharField(max_length=100, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)

    def __str__(self):
        return self.name


class Objects_Product(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, null=True, blank=True)
    path = models.CharField(max_length=600, verbose_name=_("Full file path"),
                            null=True, blank=True)
    folder = models.CharField(max_length=400, verbose_name=_("Folder"),
                              null=True, blank=True)
    artifact = models.CharField(max_length=400, verbose_name=_("Artifact"),
                                null=True, blank=True)
    review_status = models.ForeignKey(Objects_Review, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, null=False)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this object. Choose from the list or add new tags. Press Enter key to add."))

    def __str__(self):
        name = None
        if self.path is not None:
            name = self.path
        elif self.folder is not None:
            name = self.folder
        elif self.artifact is not None:
            name = self.artifact

        return name


class Testing_Guide_Category(models.Model):
    name = models.CharField(max_length=300)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class Testing_Guide(models.Model):
    testing_guide_category = models.ForeignKey(Testing_Guide_Category, on_delete=models.CASCADE)
    identifier = models.CharField(max_length=20, blank=True, null=True, help_text=_("Test Unique Identifier"))
    name = models.CharField(max_length=400, help_text=_("Name of the test"))
    summary = models.CharField(max_length=800, help_text=_("Summary of the test"))
    objective = models.CharField(max_length=800, help_text=_("Objective of the test"))
    how_to_test = models.TextField(default=None, help_text=_("How to test the objective"))
    results_expected = models.CharField(max_length=800, help_text=_("What the results look like for a test"))
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.testing_guide_category.name + ": " + self.name


class Benchmark_Type(models.Model):
    name = models.CharField(max_length=300)
    version = models.CharField(max_length=15)
    source = (("PCI", "PCI"),
              ("OWASP ASVS", "OWASP ASVS"),
              ("OWASP Mobile ASVS", "OWASP Mobile ASVS"))
    benchmark_source = models.CharField(max_length=20, blank=False,
                                        null=True, choices=source,
                                        default="OWASP ASVS")
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name + " " + self.version


class Benchmark_Category(models.Model):
    type = models.ForeignKey(Benchmark_Type, verbose_name=_("Benchmark Type"), on_delete=models.CASCADE)
    name = models.CharField(max_length=300)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name + ": " + self.type.name


class Benchmark_Requirement(models.Model):
    category = models.ForeignKey(Benchmark_Category, on_delete=models.CASCADE)
    objective_number = models.CharField(max_length=15, null=True, blank=True)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    level_1 = models.BooleanField(default=False)
    level_2 = models.BooleanField(default=False)
    level_3 = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    cwe_mapping = models.ManyToManyField(CWE, blank=True)
    testing_guide = models.ManyToManyField(Testing_Guide, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.objective_number) + ": " + self.category.name


class Benchmark_Product(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    control = models.ForeignKey(Benchmark_Requirement, on_delete=models.CASCADE)
    pass_fail = models.BooleanField(default=False, verbose_name=_("Pass"),
                                    help_text=_("Does the product meet the requirement?"))
    enabled = models.BooleanField(default=True,
                                  help_text=_("Applicable for this specific product."))
    notes = models.ManyToManyField(Notes, blank=True, editable=False)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("product", "control")]

    def __str__(self):
        return self.product.name + ": " + self.control.objective_number + ": " + self.control.category.name


class Benchmark_Product_Summary(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    benchmark_type = models.ForeignKey(Benchmark_Type, on_delete=models.CASCADE)
    asvs_level = (("Level 1", "Level 1"),
                    ("Level 2", "Level 2"),
                    ("Level 3", "Level 3"))
    desired_level = models.CharField(max_length=15,
                                     null=False, choices=asvs_level,
                                     default="Level 1")
    current_level = models.CharField(max_length=15, blank=True,
                                     null=True, choices=asvs_level,
                                     default="None")
    asvs_level_1_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_1_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 1 Score"))
    asvs_level_2_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_2_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 2 Score"))
    asvs_level_3_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_3_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 3 Score"))
    publish = models.BooleanField(default=False, help_text=_("Publish score to Product."))
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("product", "benchmark_type")]

    def __str__(self):
        return self.product.name + ": " + self.benchmark_type.name


# ==========================
# Defect Dojo Engaegment Surveys
# ==============================
with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class Question(PolymorphicModel, TimeStampedModel):

        """Represents a question."""

        class Meta:
            ordering = ["order"]

        order = models.PositiveIntegerField(default=1,
                                            help_text=_("The render order"))

        optional = models.BooleanField(
            default=False,
            help_text=_("If selected, user doesn't have to answer this question"))

        text = models.TextField(blank=False, help_text=_("The question text"), default="")
        objects = models.Manager()
        polymorphic = PolymorphicManager()

        def __str__(self):
            return self.text


class TextQuestion(Question):

    """Question with a text answer"""

    objects = PolymorphicManager()

    def get_form(self):
        """Returns the form for this model"""
        from .forms import TextQuestionForm
        return TextQuestionForm


class Choice(TimeStampedModel):

    """Model to store the choices for multi choice questions"""

    order = models.PositiveIntegerField(default=1)

    label = models.TextField(default="")

    class Meta:
        ordering = ["order"]

    def __str__(self):
        return self.label


class ChoiceQuestion(Question):

    """
    Question with answers that are chosen from a list of choices defined
    by the user.
    """

    multichoice = models.BooleanField(default=False,
                                      help_text=_("Select one or more"))
    choices = models.ManyToManyField(Choice)
    objects = PolymorphicManager()

    def get_form(self):
        """Returns the form for this model"""
        from .forms import ChoiceQuestionForm
        return ChoiceQuestionForm


# meant to be a abstract survey, identified by name for purpose
class Engagement_Survey(models.Model):
    name = models.CharField(max_length=200, null=False, blank=False,
                            editable=True, default="")
    description = models.TextField(editable=True, default="")
    questions = models.ManyToManyField(Question)
    active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _("Engagement Survey")
        verbose_name_plural = "Engagement Surveys"
        ordering = ("-active", "name")

    def __str__(self):
        return self.name


# meant to be an answered survey tied to an engagement

class Answered_Survey(models.Model):
    # tie this to a specific engagement
    engagement = models.ForeignKey(Engagement, related_name="engagement+",
                                   null=True, blank=False, editable=True,
                                   on_delete=models.CASCADE)
    # what surveys have been answered
    survey = models.ForeignKey(Engagement_Survey, on_delete=models.CASCADE)
    assignee = models.ForeignKey(Dojo_User, related_name="assignee",
                                  null=True, blank=True, editable=True,
                                  default=None, on_delete=models.RESTRICT)
    # who answered it
    responder = models.ForeignKey(Dojo_User, related_name="responder",
                                  null=True, blank=True, editable=True,
                                  default=None, on_delete=models.RESTRICT)
    completed = models.BooleanField(default=False)
    answered_on = models.DateField(null=True)

    class Meta:
        verbose_name = _("Answered Engagement Survey")
        verbose_name_plural = _("Answered Engagement Surveys")

    def __str__(self):
        return self.survey.name


class General_Survey(models.Model):
    survey = models.ForeignKey(Engagement_Survey, on_delete=models.CASCADE)
    num_responses = models.IntegerField(default=0)
    generated = models.DateTimeField(auto_now_add=True, null=True)
    expiration = models.DateTimeField(null=False, blank=False)

    class Meta:
        verbose_name = _("General Engagement Survey")
        verbose_name_plural = _("General Engagement Surveys")

    def __str__(self):
        return self.survey.name


with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class Answer(PolymorphicModel, TimeStampedModel):

        """Base Answer model"""

        question = models.ForeignKey(Question, on_delete=models.CASCADE)

        answered_survey = models.ForeignKey(Answered_Survey,
                                            null=False,
                                            blank=False,
                                            on_delete=models.CASCADE)
        objects = models.Manager()
        polymorphic = PolymorphicManager()


class TextAnswer(Answer):
    answer = models.TextField(
        blank=False,
        help_text=_("The answer text"),
        default="")
    objects = PolymorphicManager()

    def __str__(self):
        return self.answer


class ChoiceAnswer(Answer):
    answer = models.ManyToManyField(
        Choice,
        help_text=_("The selected choices as the answer"))
    objects = PolymorphicManager()

    def __str__(self):
        if len(self.answer.all()):
            return str(self.answer.all()[0])
        return "No Response"


if settings.ENABLE_AUDITLOG:
    # Register for automatic logging to database
    logger.info("enabling audit logging")
    auditlog.register(Dojo_User, exclude_fields=["password"])
    auditlog.register(Endpoint)
    auditlog.register(Engagement)
    auditlog.register(Finding, m2m_fields={"reviewers"})
    auditlog.register(Finding_Group)
    auditlog.register(Product_Type)
    auditlog.register(Product)
    auditlog.register(Test)
    auditlog.register(Risk_Acceptance)
    auditlog.register(Finding_Template)
    auditlog.register(Cred_User, exclude_fields=["password"])
    auditlog.register(Notification_Webhooks, exclude_fields=["header_name", "header_value"])


from dojo.utils import calculate_grade, to_str_typed  # noqa: E402  # there is issue due to a circular import

tagulous.admin.register(Product.tags)
tagulous.admin.register(Test.tags)
tagulous.admin.register(Test.inherited_tags)
tagulous.admin.register(Finding.tags)
tagulous.admin.register(Finding.inherited_tags)
tagulous.admin.register(Engagement.tags)
tagulous.admin.register(Engagement.inherited_tags)
tagulous.admin.register(Endpoint.tags)
tagulous.admin.register(Endpoint.inherited_tags)
tagulous.admin.register(Finding_Template.tags)
tagulous.admin.register(App_Analysis.tags)
tagulous.admin.register(Objects_Product.tags)

# Benchmarks
admin.site.register(Benchmark_Type)
admin.site.register(Benchmark_Requirement)
admin.site.register(Benchmark_Category)
admin.site.register(Benchmark_Product)
admin.site.register(Benchmark_Product_Summary)

# Testing
admin.site.register(Testing_Guide_Category)
admin.site.register(Testing_Guide)

admin.site.register(Engagement_Presets)
admin.site.register(Network_Locations)
admin.site.register(Objects_Product)
admin.site.register(Objects_Review)
admin.site.register(Languages)
admin.site.register(Language_Type)
admin.site.register(App_Analysis)
admin.site.register(Test)
admin.site.register(Finding, FindingAdmin)
admin.site.register(FileUpload)
admin.site.register(FileAccessToken)
admin.site.register(Stub_Finding)
admin.site.register(Engagement)
admin.site.register(Risk_Acceptance)
admin.site.register(Check_List)
admin.site.register(Test_Type)
admin.site.register(Endpoint_Params)
admin.site.register(Endpoint_Status)
admin.site.register(Endpoint)
admin.site.register(Product)
admin.site.register(Product_Type)
admin.site.register(UserContactInfo)
admin.site.register(Notes)
admin.site.register(Note_Type)
admin.site.register(Alerts)
admin.site.register(JIRA_Issue)
admin.site.register(JIRA_Instance, JIRA_Instance_Admin)
admin.site.register(JIRA_Project)
admin.site.register(Linear_Instance)
admin.site.register(Linear_Issue)
admin.site.register(GITHUB_Conf)
admin.site.register(GITHUB_Issue)
admin.site.register(GITHUB_Clone)
admin.site.register(GITHUB_Details_Cache)
admin.site.register(GITHUB_PKey)
admin.site.register(Tool_Configuration, Tool_Configuration_Admin)
admin.site.register(Notification_Webhooks)
admin.site.register(Tool_Product_Settings)
admin.site.register(Tool_Type)
admin.site.register(Cred_User)
admin.site.register(Cred_Mapping)
admin.site.register(System_Settings, System_SettingsAdmin)
admin.site.register(SLA_Configuration)
admin.site.register(CWE)
admin.site.register(Regulation)
admin.site.register(Global_Role)
admin.site.register(Role)
admin.site.register(Dojo_Group)

# SonarQube Integration
admin.site.register(Sonarqube_Issue)
admin.site.register(Sonarqube_Issue_Transition)

admin.site.register(Dojo_Group_Member)
admin.site.register(Product_Member)
admin.site.register(Product_Group)
admin.site.register(Product_Type_Member)
admin.site.register(Product_Type_Group)

admin.site.register(Contact)
admin.site.register(NoteHistory)
admin.site.register(Product_Line)
admin.site.register(Report_Type)
admin.site.register(DojoMeta)
admin.site.register(Product_API_Scan_Configuration)
admin.site.register(Development_Environment)
admin.site.register(Finding_Template)
admin.site.register(Vulnerability_Id)
admin.site.register(Vulnerability_Id_Template)
admin.site.register(BurpRawRequestResponse)
admin.site.register(Announcement)
admin.site.register(UserAnnouncement)
admin.site.register(BannerConf)
admin.site.register(Notifications, NotificationsAdmin)
admin.site.register(Tool_Product_History)
admin.site.register(General_Survey)
admin.site.register(Test_Import)
admin.site.register(Test_Import_Finding_Action)
admin.site.register(Finding_Group)
