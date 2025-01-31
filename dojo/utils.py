import binascii
import calendar as tcalendar
import hashlib
import importlib
import logging
import mimetypes
import os
import pathlib
import re
from calendar import monthrange
from collections.abc import Callable
from datetime import date, datetime, timedelta
from math import pi, sqrt
from pathlib import Path

import bleach
import crum
import hyperlink
import vobject
from asteval import Interpreter
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dateutil.parser import parse
from dateutil.relativedelta import MO, SU, relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.core.paginator import Paginator
from django.db.models import Case, Count, IntegerField, Q, Sum, Value, When
from django.db.models.query import QuerySet
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import FileResponse, HttpResponseRedirect
from django.urls import get_resolver, get_script_prefix, reverse
from django.utils import timezone
from django.utils.translation import gettext as _

from dojo.authorization.roles_permissions import Permissions
from dojo.celery import app
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
from dojo.finding.queries import get_authorized_findings
from dojo.github import (
    add_external_issue_github,
    close_external_issue_github,
    reopen_external_issue_github,
    update_external_issue_github,
)
from dojo.models import (
    NOTIFICATION_CHOICES,
    Benchmark_Type,
    Dojo_Group_Member,
    Dojo_User,
    Endpoint,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    Finding_Template,
    Language_Type,
    Languages,
    Notifications,
    Product,
    System_Settings,
    Test,
    User,
)
from dojo.notifications.helper import create_notification

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")
WEEKDAY_FRIDAY = 4  # date.weekday() starts with 0

"""
Helper functions for DefectDojo
"""


def do_false_positive_history(finding, *args, **kwargs):
    """
    Replicate false positives across product.

    Mark finding as false positive if the same finding was previously marked
    as false positive in the same product, beyond that, retroactively mark
    all equal findings in the product as false positive (if they weren't already).
    The retroactively replication will be also trigerred if the finding passed as
    an argument already is a false positive. With this feature we can assure that
    on each call of this method all findings in the product complies to the rule
    (if one finding is a false positive, all equal findings in the same product also are).

    Args:
        finding (:model:`dojo.Finding`): Finding to be replicated

    """
    to_mark_as_fp = set()

    existing_findings = match_finding_to_existing_findings(finding, product=finding.test.engagement.product)
    deduplicationLogger.debug(
        "FALSE_POSITIVE_HISTORY: Found %i existing findings in the same product",
        len(existing_findings),
    )

    existing_fp_findings = existing_findings.filter(false_p=True)
    deduplicationLogger.debug(
        "FALSE_POSITIVE_HISTORY: Found %i existing findings in the same product "
        + "that were previously marked as false positive",
        len(existing_fp_findings),
    )

    if existing_fp_findings:
        finding.false_p = True
        to_mark_as_fp.add(finding)

    system_settings = System_Settings.objects.get()
    if system_settings.retroactive_false_positive_history:
        # Retroactively mark all active existing findings as false positive if this one
        # is being (or already was) marked as a false positive
        if finding.false_p:
            existing_non_fp_findings = existing_findings.filter(active=True).exclude(false_p=True)
            to_mark_as_fp.update(set(existing_non_fp_findings))

    # Remove the async user kwarg because save() really does not like it
    # Would rather not add anything to Finding.save()
    if "async_user" in kwargs:
        kwargs.pop("async_user")

    for find in to_mark_as_fp:
        deduplicationLogger.debug(
            "FALSE_POSITIVE_HISTORY: Marking Finding %i:%s from %s as false positive",
            find.id, find.title, find.test.engagement,
        )
        try:
            find.false_p = True
            find.active = False
            find.verified = False
            super(Finding, find).save(*args, **kwargs)
        except Exception as e:
            deduplicationLogger.debug(str(e))


def match_finding_to_existing_findings(finding, product=None, engagement=None, test=None):
    """
    Customizable lookup that returns all existing findings for a given finding.

    Takes one finding as an argument and returns all findings that are equal to it
    on the same product, engagement or test. For now, only one custom filter can
    be used, so you should choose between product, engagement or test.
    The lookup is done based on the deduplication_algorithm of the given finding test.

    Args:
        finding (:model:`dojo.Finding`): Finding to be matched
        product (:model:`dojo.Product`, optional): Product to filter findings by
        engagement (:model:`dojo.Engagement`, optional): Engagement to filter findings by
        test (:model:`dojo.Test`, optional): Test to filter findings by

    """
    if product:
        custom_filter_type = "product"
        custom_filter = {"test__engagement__product": product}

    elif engagement:
        custom_filter_type = "engagement"
        custom_filter = {"test__engagement": engagement}

    elif test:
        custom_filter_type = "test"
        custom_filter = {"test": test}

    else:
        msg = "No product, engagement or test provided as argument."
        raise ValueError(msg)

    deduplication_algorithm = finding.test.deduplication_algorithm

    deduplicationLogger.debug(
        "Matching finding %i:%s to existing findings in %s %s using %s as deduplication algorithm.",
        finding.id, finding.title, custom_filter_type, list(custom_filter.values())[0], deduplication_algorithm,
    )

    if deduplication_algorithm == "hash_code":
        return (
            Finding.objects.filter(
                **custom_filter,
                hash_code=finding.hash_code,
            ).exclude(hash_code=None)
            .exclude(id=finding.id)
            .order_by("id")
        )

    if deduplication_algorithm == "unique_id_from_tool":
        return (
            Finding.objects.filter(
                **custom_filter,
                unique_id_from_tool=finding.unique_id_from_tool,
            ).exclude(unique_id_from_tool=None)
            .exclude(id=finding.id)
            .order_by("id")
        )

    if deduplication_algorithm == "unique_id_from_tool_or_hash_code":
        query = Finding.objects.filter(
            Q(**custom_filter),
            (
                (Q(hash_code__isnull=False) & Q(hash_code=finding.hash_code))
                | (Q(unique_id_from_tool__isnull=False) & Q(unique_id_from_tool=finding.unique_id_from_tool))
            ),
        ).exclude(id=finding.id).order_by("id")
        deduplicationLogger.debug(query.query)
        return query

    if deduplication_algorithm == "legacy":
        # This is the legacy reimport behavior. Although it's pretty flawed and
        # doesn't match the legacy algorithm for deduplication, this is left as is for simplicity.
        # Re-writing the legacy deduplication here would be complicated and counter-productive.
        # If you have use cases going through this section, you're advised to create a deduplication configuration for your parser
        logger.debug("Legacy dedupe. In case of issue, you're advised to create a deduplication configuration in order not to go through this section")
        return (
            Finding.objects.filter(
                **custom_filter,
                title=finding.title,
                severity=finding.severity,
                numerical_severity=Finding.get_numerical_severity(finding.severity),
            ).order_by("id")
        )

    logger.error("Internal error: unexpected deduplication_algorithm: '%s' ", deduplication_algorithm)
    return None


# true if both findings are on an engagement that have a different "deduplication on engagement" configuration
def is_deduplication_on_engagement_mismatch(new_finding, to_duplicate_finding):
    return not new_finding.test.engagement.deduplication_on_engagement and to_duplicate_finding.test.engagement.deduplication_on_engagement


def get_endpoints_as_url(finding):
    list1 = []
    for e in finding.endpoints.all():
        list1.append(hyperlink.parse(str(e)))
    return list1


def are_urls_equal(url1, url2, fields):
    # Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
    # For a details description see https://hyperlink.readthedocs.io/en/latest/api.html#attributes
    deduplicationLogger.debug("Check if url %s and url %s are equal in terms of %s.", url1, url2, fields)
    for field in fields:
        if field == "scheme":
            if url1.scheme != url2.scheme:
                return False
        elif field == "host":
            if url1.host != url2.host:
                return False
        elif field == "port":
            if url1.port != url2.port:
                return False
        elif field == "path":
            if url1.path != url2.path:
                return False
        elif field == "query":
            if url1.query != url2.query:
                return False
        elif field == "fragment":
            if url1.fragment != url2.fragment:
                return False
        elif field == "userinfo":
            if url1.userinfo != url2.userinfo:
                return False
        elif field == "user":
            if url1.user != url2.user:
                return False
        else:
            logger.warning("Field " + field + " is not supported by the endpoint dedupe algorithm, ignoring it.")
    return True


def are_endpoints_duplicates(new_finding, to_duplicate_finding):
    fields = settings.DEDUPE_ALGO_ENDPOINT_FIELDS
    # shortcut if fields list is empty/feature is disabled
    if len(fields) == 0:
        deduplicationLogger.debug("deduplication by endpoint fields is disabled")
        return True

    list1 = get_endpoints_as_url(new_finding)
    list2 = get_endpoints_as_url(to_duplicate_finding)

    deduplicationLogger.debug(f"Starting deduplication by endpoint fields for finding {new_finding.id} with urls {list1} and finding {to_duplicate_finding.id} with urls {list2}")
    if list1 == [] and list2 == []:
        return True

    for l1 in list1:
        for l2 in list2:
            if are_urls_equal(l1, l2, fields):
                return True
    return False


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def do_dedupe_finding_task(new_finding, *args, **kwargs):
    return do_dedupe_finding(new_finding, *args, **kwargs)


def do_dedupe_finding(new_finding, *args, **kwargs):
    if dedupe_method := get_custom_method("FINDING_DEDUPE_METHOD"):
        return dedupe_method(new_finding, *args, **kwargs)

    try:
        enabled = System_Settings.objects.get(no_cache=True).enable_deduplication
    except System_Settings.DoesNotExist:
        logger.warning("system settings not found")
        enabled = False
    if enabled:
        deduplicationLogger.debug("dedupe for: " + str(new_finding.id)
                    + ":" + str(new_finding.title))
        deduplicationAlgorithm = new_finding.test.deduplication_algorithm
        deduplicationLogger.debug("deduplication algorithm: " + deduplicationAlgorithm)
        if deduplicationAlgorithm == settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL:
            deduplicate_unique_id_from_tool(new_finding)
        elif deduplicationAlgorithm == settings.DEDUPE_ALGO_HASH_CODE:
            deduplicate_hash_code(new_finding)
        elif deduplicationAlgorithm == settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE:
            deduplicate_uid_or_hash_code(new_finding)
        else:
            deduplicationLogger.debug("no configuration per parser found; using legacy algorithm")
            deduplicate_legacy(new_finding)
    else:
        deduplicationLogger.debug("dedupe: skipping dedupe because it's disabled in system settings get()")
    return None


def deduplicate_legacy(new_finding):
    # ---------------------------------------------------------
    # 1) Collects all the findings that have the same:
    #      (title  and static_finding and dynamic_finding)
    #      or (CWE and static_finding and dynamic_finding)
    #    as the new one
    #    (this is "cond1")
    # ---------------------------------------------------------
    if new_finding.test.engagement.deduplication_on_engagement:
        eng_findings_cwe = Finding.objects.filter(
            test__engagement=new_finding.test.engagement,
            cwe=new_finding.cwe).exclude(id=new_finding.id).exclude(cwe=0).exclude(duplicate=True).values("id")
        eng_findings_title = Finding.objects.filter(
            test__engagement=new_finding.test.engagement,
            title=new_finding.title).exclude(id=new_finding.id).exclude(duplicate=True).values("id")
    else:
        eng_findings_cwe = Finding.objects.filter(
            test__engagement__product=new_finding.test.engagement.product,
            cwe=new_finding.cwe).exclude(id=new_finding.id).exclude(cwe=0).exclude(duplicate=True).values("id")
        eng_findings_title = Finding.objects.filter(
            test__engagement__product=new_finding.test.engagement.product,
            title=new_finding.title).exclude(id=new_finding.id).exclude(duplicate=True).values("id")

    total_findings = Finding.objects.filter(Q(id__in=eng_findings_cwe) | Q(id__in=eng_findings_title)).prefetch_related("endpoints", "test", "test__engagement", "found_by", "original_finding", "test__test_type")
    deduplicationLogger.debug("Found "
        + str(len(eng_findings_cwe)) + " findings with same cwe, "
        + str(len(eng_findings_title)) + " findings with same title: "
        + str(len(total_findings)) + " findings with either same title or same cwe")

    # total_findings = total_findings.order_by('date')
    for find in total_findings.order_by("id"):
        flag_endpoints = False
        flag_line_path = False
        flag_hash = False
        if is_deduplication_on_engagement_mismatch(new_finding, find):
            deduplicationLogger.debug(
                "deduplication_on_engagement_mismatch, skipping dedupe.")
            continue

        # ---------------------------------------------------------
        # 2) If existing and new findings have endpoints: compare them all
        #    Else look at line+file_path
        #    (if new finding is not static, do not deduplicate)
        # ---------------------------------------------------------

        if find.endpoints.count() != 0 and new_finding.endpoints.count() != 0:
            list1 = [str(e) for e in new_finding.endpoints.all()]
            list2 = [str(e) for e in find.endpoints.all()]

            if all(x in list1 for x in list2):
                deduplicationLogger.debug("%s: existing endpoints are present in new finding", find.id)
                flag_endpoints = True
        elif new_finding.static_finding and new_finding.file_path and len(new_finding.file_path) > 0:
            if str(find.line) == str(new_finding.line) and find.file_path == new_finding.file_path:
                deduplicationLogger.debug("%s: file_path and line match", find.id)
                flag_line_path = True
            else:
                deduplicationLogger.debug("no endpoints on one of the findings and file_path doesn't match; Deduplication will not occur")
        else:
            deduplicationLogger.debug("find.static/dynamic: %s/%s", find.static_finding, find.dynamic_finding)
            deduplicationLogger.debug("new_finding.static/dynamic: %s/%s", new_finding.static_finding, new_finding.dynamic_finding)
            deduplicationLogger.debug("find.file_path: %s", find.file_path)
            deduplicationLogger.debug("new_finding.file_path: %s", new_finding.file_path)

            deduplicationLogger.debug("no endpoints on one of the findings and the new finding is either dynamic or doesn't have a file_path; Deduplication will not occur")

        if find.hash_code == new_finding.hash_code:
            flag_hash = True

        deduplicationLogger.debug(
            "deduplication flags for new finding (" + ("dynamic" if new_finding.dynamic_finding else "static") + ") " + str(new_finding.id) + " and existing finding " + str(find.id)
            + " flag_endpoints: " + str(flag_endpoints) + " flag_line_path:" + str(flag_line_path) + " flag_hash:" + str(flag_hash))

        # ---------------------------------------------------------
        # 3) Findings are duplicate if (cond1 is true) and they have the same:
        #    hash
        #    and (endpoints or (line and file_path)
        # ---------------------------------------------------------
        if ((flag_endpoints or flag_line_path) and flag_hash):
            try:
                set_duplicate(new_finding, find)
            except Exception as e:
                deduplicationLogger.debug(str(e))
                continue

            break


def deduplicate_unique_id_from_tool(new_finding):
    if new_finding.test.engagement.deduplication_on_engagement:
        existing_findings = Finding.objects.filter(
            test__engagement=new_finding.test.engagement,
            unique_id_from_tool=new_finding.unique_id_from_tool).exclude(
                id=new_finding.id).exclude(
                    unique_id_from_tool=None).exclude(
                        duplicate=True).order_by("id")
    else:
        existing_findings = Finding.objects.filter(
            test__engagement__product=new_finding.test.engagement.product,
            # the unique_id_from_tool is unique for a given tool: do not compare with other tools
            test__test_type=new_finding.test.test_type,
            unique_id_from_tool=new_finding.unique_id_from_tool).exclude(
                id=new_finding.id).exclude(
                    unique_id_from_tool=None).exclude(
                        duplicate=True).order_by("id")

    deduplicationLogger.debug("Found "
        + str(len(existing_findings)) + " findings with same unique_id_from_tool")
    for find in existing_findings:
        if is_deduplication_on_engagement_mismatch(new_finding, find):
            deduplicationLogger.debug(
                "deduplication_on_engagement_mismatch, skipping dedupe.")
            continue
        try:
            set_duplicate(new_finding, find)
            break
        except Exception as e:
            deduplicationLogger.debug(str(e))
            continue


def deduplicate_hash_code(new_finding):
    if new_finding.test.engagement.deduplication_on_engagement:
        existing_findings = Finding.objects.filter(
            test__engagement=new_finding.test.engagement,
            hash_code=new_finding.hash_code).exclude(
                id=new_finding.id).exclude(
                    hash_code=None).exclude(
                        duplicate=True).order_by("id")
    else:
        existing_findings = Finding.objects.filter(
            test__engagement__product=new_finding.test.engagement.product,
            hash_code=new_finding.hash_code).exclude(
                id=new_finding.id).exclude(
                    hash_code=None).exclude(
                        duplicate=True).order_by("id")

    deduplicationLogger.debug("Found "
        + str(len(existing_findings)) + " findings with same hash_code")
    for find in existing_findings:
        if is_deduplication_on_engagement_mismatch(new_finding, find):
            deduplicationLogger.debug(
                "deduplication_on_engagement_mismatch, skipping dedupe.")
            continue
        try:
            if are_endpoints_duplicates(new_finding, find):
                set_duplicate(new_finding, find)
                break
        except Exception as e:
            deduplicationLogger.debug(str(e))
            continue


def deduplicate_uid_or_hash_code(new_finding):
    if new_finding.test.engagement.deduplication_on_engagement:
        existing_findings = Finding.objects.filter(
            (Q(hash_code__isnull=False) & Q(hash_code=new_finding.hash_code))
            # unique_id_from_tool can only apply to the same test_type because it is parser dependent
            | (Q(unique_id_from_tool__isnull=False) & Q(unique_id_from_tool=new_finding.unique_id_from_tool) & Q(test__test_type=new_finding.test.test_type)),
            test__engagement=new_finding.test.engagement).exclude(
                id=new_finding.id).exclude(
                        duplicate=True).order_by("id")
    else:
        # same without "test__engagement=new_finding.test.engagement" condition
        existing_findings = Finding.objects.filter(
            (Q(hash_code__isnull=False) & Q(hash_code=new_finding.hash_code))
            | (Q(unique_id_from_tool__isnull=False) & Q(unique_id_from_tool=new_finding.unique_id_from_tool) & Q(test__test_type=new_finding.test.test_type)),
            test__engagement__product=new_finding.test.engagement.product).exclude(
                id=new_finding.id).exclude(
                        duplicate=True).order_by("id")
    deduplicationLogger.debug("Found "
        + str(len(existing_findings)) + " findings with either the same unique_id_from_tool or hash_code")
    for find in existing_findings:
        if is_deduplication_on_engagement_mismatch(new_finding, find):
            deduplicationLogger.debug(
                "deduplication_on_engagement_mismatch, skipping dedupe.")
            continue
        try:
            if are_endpoints_duplicates(new_finding, find):
                set_duplicate(new_finding, find)
        except Exception as e:
            deduplicationLogger.debug(str(e))
            continue
        break


def set_duplicate(new_finding, existing_finding):
    deduplicationLogger.debug(f"new_finding.status(): {new_finding.id} {new_finding.status()}")
    deduplicationLogger.debug(f"existing_finding.status(): {existing_finding.id} {existing_finding.status()}")
    if existing_finding.duplicate:
        deduplicationLogger.debug("existing finding: %s:%s:duplicate=%s;duplicate_finding=%s", existing_finding.id, existing_finding.title, existing_finding.duplicate, existing_finding.duplicate_finding.id if existing_finding.duplicate_finding else "None")
        msg = "Existing finding is a duplicate"
        raise Exception(msg)
    if existing_finding.id == new_finding.id:
        msg = "Can not add duplicate to itself"
        raise Exception(msg)
    if is_duplicate_reopen(new_finding, existing_finding):
        msg = "Found a regression. Ignore this so that a new duplicate chain can be made"
        raise Exception(msg)
    if new_finding.duplicate and finding_mitigated(existing_finding):
        msg = "Skip this finding as we do not want to attach a new duplicate to a mitigated finding"
        raise Exception(msg)

    deduplicationLogger.debug("Setting new finding " + str(new_finding.id) + " as a duplicate of existing finding " + str(existing_finding.id))
    new_finding.duplicate = True
    new_finding.active = False
    new_finding.verified = False
    new_finding.duplicate_finding = existing_finding

    # Make sure transitive duplication is flattened
    # if A -> B and B is made a duplicate of C here, aferwards:
    # A -> C and B -> C should be true
    for find in new_finding.original_finding.all().order_by("-id"):
        new_finding.original_finding.remove(find)
        set_duplicate(find, existing_finding)
    existing_finding.found_by.add(new_finding.test.test_type)
    logger.debug("saving new finding: %d", new_finding.id)
    super(Finding, new_finding).save()
    logger.debug("saving existing finding: %d", existing_finding.id)
    super(Finding, existing_finding).save()


def is_duplicate_reopen(new_finding, existing_finding) -> bool:
    return finding_mitigated(existing_finding) and finding_not_human_set_status(existing_finding) and not finding_mitigated(new_finding)


def finding_mitigated(finding: Finding) -> bool:
    return finding.active is False and (finding.is_mitigated is True or finding.mitigated is not None)


def finding_not_human_set_status(finding: Finding) -> bool:
    return finding.out_of_scope is False and finding.false_p is False


def set_duplicate_reopen(new_finding, existing_finding):
    logger.debug("duplicate reopen existing finding")
    existing_finding.mitigated = new_finding.mitigated
    existing_finding.is_mitigated = new_finding.is_mitigated
    existing_finding.active = new_finding.active
    existing_finding.verified = new_finding.verified
    existing_finding.notes.create(author=existing_finding.reporter,
                                    entry="This finding has been automatically re-opened as it was found in recent scans.")
    existing_finding.save()


def count_findings(findings):
    product_count = {}
    finding_count = {"low": 0, "med": 0, "high": 0, "crit": 0}
    for f in findings:
        product = f.test.engagement.product
        if product in product_count:
            product_count[product][4] += 1
            if f.severity == "Low":
                product_count[product][3] += 1
                finding_count["low"] += 1
            if f.severity == "Medium":
                product_count[product][2] += 1
                finding_count["med"] += 1
            if f.severity == "High":
                product_count[product][1] += 1
                finding_count["high"] += 1
            if f.severity == "Critical":
                product_count[product][0] += 1
                finding_count["crit"] += 1
        else:
            product_count[product] = [0, 0, 0, 0, 0]
            product_count[product][4] += 1
            if f.severity == "Low":
                product_count[product][3] += 1
                finding_count["low"] += 1
            if f.severity == "Medium":
                product_count[product][2] += 1
                finding_count["med"] += 1
            if f.severity == "High":
                product_count[product][1] += 1
                finding_count["high"] += 1
            if f.severity == "Critical":
                product_count[product][0] += 1
                finding_count["crit"] += 1
    return product_count, finding_count


def findings_this_period(findings, period_type, stuff, o_stuff, a_stuff):
    # periodType: 0 - weeks
    # 1 - months
    now = timezone.now()
    for i in range(6):
        counts = []
        # Weeks start on Monday
        if period_type == 0:
            curr = now - relativedelta(weeks=i)
            start_of_period = curr - relativedelta(
                weeks=1, weekday=0, hour=0, minute=0, second=0)
            end_of_period = curr + relativedelta(
                weeks=0, weekday=0, hour=0, minute=0, second=0)
        else:
            curr = now - relativedelta(months=i)
            start_of_period = curr - relativedelta(
                day=1, hour=0, minute=0, second=0)
            end_of_period = curr + relativedelta(
                day=31, hour=23, minute=59, second=59)

        o_count = {
            "closed": 0,
            "zero": 0,
            "one": 0,
            "two": 0,
            "three": 0,
            "total": 0,
        }
        a_count = {
            "closed": 0,
            "zero": 0,
            "one": 0,
            "two": 0,
            "three": 0,
            "total": 0,
        }
        for f in findings:
            if f.mitigated is not None and end_of_period >= f.mitigated >= start_of_period:
                o_count["closed"] += 1
            elif f.mitigated is not None and f.mitigated > end_of_period and f.date <= end_of_period.date():
                if f.severity == "Critical":
                    o_count["zero"] += 1
                elif f.severity == "High":
                    o_count["one"] += 1
                elif f.severity == "Medium":
                    o_count["two"] += 1
                elif f.severity == "Low":
                    o_count["three"] += 1
            elif f.mitigated is None and f.date <= end_of_period.date():
                if f.severity == "Critical":
                    o_count["zero"] += 1
                    a_count["zero"] += 1
                elif f.severity == "High":
                    o_count["one"] += 1
                    a_count["one"] += 1
                elif f.severity == "Medium":
                    o_count["two"] += 1
                    a_count["two"] += 1
                elif f.severity == "Low":
                    o_count["three"] += 1
                    a_count["three"] += 1

        total = sum(o_count.values()) - o_count["closed"]
        if period_type == 0:
            counts.append(
                start_of_period.strftime("%b %d") + " - "
                + end_of_period.strftime("%b %d"))
        else:
            counts.append(start_of_period.strftime("%b %Y"))
        counts.extend((
            o_count["zero"],
            o_count["one"],
            o_count["two"],
            o_count["three"],
            total,
            o_count["closed"],
        ))

        stuff.append(counts)
        o_stuff.append(counts[:-1])

        a_counts = []
        a_total = sum(a_count.values())
        if period_type == 0:
            a_counts.append(
                start_of_period.strftime("%b %d") + " - "
                + end_of_period.strftime("%b %d"))
        else:
            a_counts.append(start_of_period.strftime("%b %Y"))
        a_counts.extend((
            a_count["zero"],
            a_count["one"],
            a_count["two"],
            a_count["three"],
            a_total,
        ))
        a_stuff.append(a_counts)


def add_breadcrumb(parent=None,
                   title=None,
                   *,
                   top_level=True,
                   url=None,
                   request=None,
                   clear=False):
    if clear:
        request.session["dojo_breadcrumbs"] = None
        return
    crumbs = request.session.get("dojo_breadcrumbs", None)

    if top_level or crumbs is None:
        crumbs = [
            {
                "title": _("Home"),
                "url": reverse("home"),
            },
        ]
        if parent is not None and getattr(parent, "get_breadcrumbs", None):
            crumbs += parent.get_breadcrumbs()
        else:
            crumbs += [{
                "title": title,
                "url": request.get_full_path() if url is None else url,
            }]
    else:
        resolver = get_resolver(None).resolve
        if parent is not None and getattr(parent, "get_breadcrumbs", None):
            obj_crumbs = parent.get_breadcrumbs()
            if title is not None:
                obj_crumbs += [{
                    "title": title,
                    "url": request.get_full_path() if url is None else url,
                }]
        else:
            obj_crumbs = [{
                "title": title,
                "url": request.get_full_path() if url is None else url,
            }]

        for crumb in crumbs:
            crumb_to_resolve = crumb["url"] if "?" not in crumb[
                "url"] else crumb["url"][:crumb["url"].index("?")]
            crumb_view = resolver(crumb_to_resolve)
            for obj_crumb in obj_crumbs:
                obj_crumb_to_resolve = obj_crumb[
                    "url"] if "?" not in obj_crumb["url"] else obj_crumb[
                        "url"][:obj_crumb["url"].index("?")]
                obj_crumb_view = resolver(obj_crumb_to_resolve)

                if crumb_view.view_name == obj_crumb_view.view_name:
                    if crumb_view.kwargs == obj_crumb_view.kwargs:
                        if len(obj_crumbs) == 1 and crumb in crumbs:
                            crumbs = crumbs[:crumbs.index(crumb)]
                        else:
                            obj_crumbs.remove(obj_crumb)
                    else:
                        if crumb in crumbs:
                            crumbs = crumbs[:crumbs.index(crumb)]

        crumbs += obj_crumbs

    request.session["dojo_breadcrumbs"] = crumbs


def is_title_in_breadcrumbs(title):
    request = crum.get_current_request()
    if request is None:
        return False

    breadcrumbs = request.session.get("dojo_breadcrumbs")
    if breadcrumbs is None:
        return False

    return any(breadcrumb.get("title") == title for breadcrumb in breadcrumbs)


def get_punchcard_data(objs, start_date, weeks, view="Finding"):
    # use try catch to make sure any teething bugs in the bunchcard don't break the dashboard
    try:
        # gather findings over past half year, make sure to start on a sunday
        first_sunday = start_date - relativedelta(weekday=SU(-1))
        last_sunday = start_date + relativedelta(weeks=weeks)

        # reminder: The first week of a year is the one that contains the year's first Thursday
        # so we could have for 29/12/2019: week=1 and year=2019 :-D. So using week number from db is not practical
        if view == "Finding":
            severities_by_day = objs.filter(created__date__gte=first_sunday).filter(created__date__lt=last_sunday) \
                                        .values("created__date") \
                                        .annotate(count=Count("id")) \
                                        .order_by("created__date")
        elif view == "Endpoint":
            severities_by_day = objs.filter(date__gte=first_sunday).filter(date__lt=last_sunday) \
                                        .values("date") \
                                        .annotate(count=Count("id")) \
                                        .order_by("date")
        # return empty stuff if no findings to be statted
        if severities_by_day.count() <= 0:
            return None, None

        # day of the week numbers:
        # javascript  database python
        # sun 6         1       6
        # mon 5         2       0
        # tue 4         3       1
        # wed 3         4       2
        # thu 2         5       3
        # fri 1         6       4
        # sat 0         7       5

        # map from python to javascript, do not use week numbers or day numbers from database.
        day_offset = {0: 5, 1: 4, 2: 3, 3: 2, 4: 1, 5: 0, 6: 6}

        punchcard = []
        ticks = []
        highest_day_count = 0
        tick = 0
        day_counts = [0, 0, 0, 0, 0, 0, 0]

        start_of_week = timezone.make_aware(datetime.combine(first_sunday, datetime.min.time()))
        start_of_next_week = start_of_week + relativedelta(weeks=1)

        for day in severities_by_day:
            if view == "Finding":
                created = day["created__date"]
            elif view == "Endpoint":
                created = day["date"]
            day_count = day["count"]

            created = timezone.make_aware(datetime.combine(created, datetime.min.time()))

            if created < start_of_week:
                raise ValueError("date found outside supported range: " + str(created))
            if created >= start_of_week and created < start_of_next_week:
                # add day count to current week data
                day_counts[day_offset[created.weekday()]] = day_count
                highest_day_count = max(highest_day_count, day_count)
            else:
                # created >= start_of_next_week, so store current week, prepare for next
                while created >= start_of_next_week:
                    week_data, label = get_week_data(start_of_week, tick, day_counts)
                    punchcard.extend(week_data)
                    ticks.append(label)
                    tick += 1

                    # new week, new values!
                    day_counts = [0, 0, 0, 0, 0, 0, 0]
                    start_of_week = start_of_next_week
                    start_of_next_week += relativedelta(weeks=1)

                # finally a day that falls into the week bracket
                day_counts[day_offset[created.weekday()]] = day_count
                highest_day_count = max(highest_day_count, day_count)

        # add week in progress + empty weeks on the end if needed
        while tick < weeks + 1:
            week_data, label = get_week_data(start_of_week, tick, day_counts)
            punchcard.extend(week_data)
            ticks.append(label)
            tick += 1

            day_counts = [0, 0, 0, 0, 0, 0, 0]
            start_of_week = start_of_next_week
            start_of_next_week += relativedelta(weeks=1)

        # adjust the size or circles
        ratio = (sqrt(highest_day_count / pi))
        for punch in punchcard:
            # front-end needs both the count for the label and the ratios of the radii of the circles
            punch.append(punch[2])
            punch[2] = (sqrt(punch[2] / pi)) / ratio

        return punchcard, ticks

    except Exception:
        logger.exception("Not showing punchcard graph due to exception gathering data")
        return None, None


def get_week_data(week_start_date, tick, day_counts):
    data = []
    for i in range(len(day_counts)):
        data.append([tick, i, day_counts[i]])
    label = [tick, week_start_date.strftime("<span class='small'>%m/%d<br/>%Y</span>")]
    return data, label


# 5 params
def get_period_counts_legacy(findings,
                             findings_closed,
                             accepted_findings,
                             period_interval,
                             start_date,
                             relative_delta="months"):
    opened_in_period = []
    accepted_in_period = []
    opened_in_period.append(
        ["Timestamp", "Date", "S0", "S1", "S2", "S3", "Total", "Closed"])
    accepted_in_period.append(
        ["Timestamp", "Date", "S0", "S1", "S2", "S3", "Total", "Closed"])

    for x in range(-1, period_interval):
        if relative_delta == "months":
            # make interval the first through last of month
            end_date = (start_date + relativedelta(months=x)) + relativedelta(
                day=1, months=+1, days=-1)
            new_date = (
                start_date + relativedelta(months=x)) + relativedelta(day=1)
        else:
            # week starts the monday before
            new_date = start_date + relativedelta(weeks=x, weekday=MO(1))
            end_date = new_date + relativedelta(weeks=1, weekday=MO(1))

        closed_in_range_count = findings_closed.filter(
            mitigated__date__range=[new_date, end_date]).count()

        if accepted_findings:
            risks_a = accepted_findings.filter(
                risk_acceptance__created__date__range=[
                    datetime(
                        new_date.year,
                        new_date.month,
                        1,
                        tzinfo=timezone.get_current_timezone()),
                    datetime(
                        new_date.year,
                        new_date.month,
                        monthrange(new_date.year, new_date.month)[1],
                        tzinfo=timezone.get_current_timezone()),
                ])
        else:
            risks_a = None

        crit_count, high_count, med_count, low_count, _ = [
            0, 0, 0, 0, 0,
        ]
        for finding in findings:
            if new_date <= datetime.combine(finding.date, datetime.min.time(
            )).replace(tzinfo=timezone.get_current_timezone()) <= end_date:
                if finding.severity == "Critical":
                    crit_count += 1
                elif finding.severity == "High":
                    high_count += 1
                elif finding.severity == "Medium":
                    med_count += 1
                elif finding.severity == "Low":
                    low_count += 1

        total = crit_count + high_count + med_count + low_count
        opened_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             crit_count, high_count, med_count, low_count, total,
             closed_in_range_count])
        crit_count, high_count, med_count, low_count, _ = [
            0, 0, 0, 0, 0,
        ]
        if risks_a is not None:
            for finding in risks_a:
                if finding.severity == "Critical":
                    crit_count += 1
                elif finding.severity == "High":
                    high_count += 1
                elif finding.severity == "Medium":
                    med_count += 1
                elif finding.severity == "Low":
                    low_count += 1

        total = crit_count + high_count + med_count + low_count
        accepted_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             crit_count, high_count, med_count, low_count, total])

    return {
        "opened_per_period": opened_in_period,
        "accepted_per_period": accepted_in_period,
    }


def get_period_counts(findings,
                      findings_closed,
                      accepted_findings,
                      period_interval,
                      start_date,
                      relative_delta="months"):

    tz = timezone.get_current_timezone()

    start_date = datetime(start_date.year, start_date.month, start_date.day, tzinfo=tz)

    opened_in_period = []
    active_in_period = []
    accepted_in_period = []
    opened_in_period.append(
        ["Timestamp", "Date", "S0", "S1", "S2", "S3", "Total", "Closed"])
    active_in_period.append(
        ["Timestamp", "Date", "S0", "S1", "S2", "S3", "Total", "Closed"])
    accepted_in_period.append(
        ["Timestamp", "Date", "S0", "S1", "S2", "S3", "Total", "Closed"])

    for x in range(-1, period_interval):
        if relative_delta == "months":
            # make interval the first through last of month
            end_date = (start_date + relativedelta(months=x)) + relativedelta(
                day=1, months=+1, days=-1)
            new_date = (
                start_date + relativedelta(months=x)) + relativedelta(day=1)
        else:
            # week starts the monday before
            new_date = start_date + relativedelta(weeks=x, weekday=MO(1))
            end_date = new_date + relativedelta(weeks=1, weekday=MO(1))

        try:
            closed_in_range_count = findings_closed.filter(
                mitigated__date__range=[new_date, end_date]).count()
        except:
            closed_in_range_count = findings_closed.filter(
                mitigated_time__range=[new_date, end_date]).count()

        if accepted_findings:
            date_range = [
                datetime(new_date.year, new_date.month, new_date.day, tzinfo=tz),
                datetime(end_date.year, end_date.month, end_date.day, tzinfo=tz),
            ]
            try:
                risks_a = accepted_findings.filter(risk_acceptance__created__date__range=date_range)
            except:
                risks_a = accepted_findings.filter(date__range=date_range)
        else:
            risks_a = None

        f_crit_count, f_high_count, f_med_count, f_low_count, _ = [
            0, 0, 0, 0, 0,
        ]
        ra_crit_count, ra_high_count, ra_med_count, ra_low_count, _ = [
            0, 0, 0, 0, 0,
        ]
        active_crit_count, active_high_count, active_med_count, active_low_count, _ = [
            0, 0, 0, 0, 0,
        ]

        for finding in findings:
            try:
                severity = finding.severity
                active = finding.active
#                risk_accepted = finding.risk_accepted TODO: in future release
            except:
                severity = finding.finding.severity
                active = finding.finding.active
#                risk_accepted = finding.finding.risk_accepted

            try:
                f_time = datetime.combine(finding.date, datetime.min.time()).replace(tzinfo=tz)
            except:
                f_time = finding.date

            if f_time <= end_date:
                if severity == "Critical":
                    if new_date <= f_time:
                        f_crit_count += 1
                    if active:
                        active_crit_count += 1
                elif severity == "High":
                    if new_date <= f_time:
                        f_high_count += 1
                    if active:
                        active_high_count += 1
                elif severity == "Medium":
                    if new_date <= f_time:
                        f_med_count += 1
                    if active:
                        active_med_count += 1
                elif severity == "Low":
                    if new_date <= f_time:
                        f_low_count += 1
                    if active:
                        active_low_count += 1

        if risks_a is not None:
            for finding in risks_a:
                try:
                    severity = finding.severity
                except:
                    severity = finding.finding.severity
                if severity == "Critical":
                    ra_crit_count += 1
                elif severity == "High":
                    ra_high_count += 1
                elif severity == "Medium":
                    ra_med_count += 1
                elif severity == "Low":
                    ra_low_count += 1

        total = f_crit_count + f_high_count + f_med_count + f_low_count
        opened_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             f_crit_count, f_high_count, f_med_count, f_low_count, total,
             closed_in_range_count])

        total = ra_crit_count + ra_high_count + ra_med_count + ra_low_count
        accepted_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             ra_crit_count, ra_high_count, ra_med_count, ra_low_count, total])

        total = active_crit_count + active_high_count + active_med_count + active_low_count
        active_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             active_crit_count, active_high_count, active_med_count, active_low_count, total])

    return {
        "opened_per_period": opened_in_period,
        "accepted_per_period": accepted_in_period,
        "active_per_period": active_in_period,
    }


def opened_in_period(start_date, end_date, **kwargs):
    start_date = datetime(
        start_date.year,
        start_date.month,
        start_date.day,
        tzinfo=timezone.get_current_timezone())
    end_date = datetime(
        end_date.year,
        end_date.month,
        end_date.day,
        tzinfo=timezone.get_current_timezone())
    if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
        opened_in_period = Finding.objects.filter(
            date__range=[start_date, end_date],
            **kwargs,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated__isnull=True,
            severity__in=(
                "Critical", "High", "Medium",
                "Low")).values("numerical_severity").annotate(
                    Count("numerical_severity")).order_by("numerical_severity")
        total_opened_in_period = Finding.objects.filter(
            date__range=[start_date, end_date],
            **kwargs,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated__isnull=True,
            severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                total=Sum(
                    Case(
                        When(
                            severity__in=("Critical", "High", "Medium", "Low"),
                            then=Value(1)),
                        output_field=IntegerField())))["total"]

        oip = {
            "S0":
            0,
            "S1":
            0,
            "S2":
            0,
            "S3":
            0,
            "Total":
            total_opened_in_period,
            "start_date":
            start_date,
            "end_date":
            end_date,
            "closed":
            Finding.objects.filter(
                mitigated__date__range=[start_date, end_date],
                **kwargs,
                severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                    total=Sum(
                        Case(
                            When(
                                severity__in=("Critical", "High", "Medium", "Low"),
                                then=Value(1)),
                            output_field=IntegerField())))["total"],
            "to_date_total":
            Finding.objects.filter(
                date__lte=end_date.date(),
                verified=True,
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                mitigated__isnull=True,
                **kwargs,
                severity__in=("Critical", "High", "Medium", "Low")).count(),
        }
    else:
        opened_in_period = Finding.objects.filter(
            date__range=[start_date, end_date],
            **kwargs,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated__isnull=True,
            severity__in=(
                "Critical", "High", "Medium",
                "Low")).values("numerical_severity").annotate(
                    Count("numerical_severity")).order_by("numerical_severity")
        total_opened_in_period = Finding.objects.filter(
            date__range=[start_date, end_date],
            **kwargs,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated__isnull=True,
            severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                total=Sum(
                    Case(
                        When(
                            severity__in=("Critical", "High", "Medium", "Low"),
                            then=Value(1)),
                        output_field=IntegerField())))["total"]

        oip = {
            "S0":
            0,
            "S1":
            0,
            "S2":
            0,
            "S3":
            0,
            "Total":
            total_opened_in_period,
            "start_date":
            start_date,
            "end_date":
            end_date,
            "closed":
            Finding.objects.filter(
                mitigated__date__range=[start_date, end_date],
                **kwargs,
                severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                    total=Sum(
                        Case(
                            When(
                                severity__in=("Critical", "High", "Medium", "Low"),
                                then=Value(1)),
                            output_field=IntegerField())))["total"],
            "to_date_total":
            Finding.objects.filter(
                date__lte=end_date.date(),
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                mitigated__isnull=True,
                **kwargs,
                severity__in=("Critical", "High", "Medium", "Low")).count(),
        }

    for o in opened_in_period:
        oip[o["numerical_severity"]] = o["numerical_severity__count"]

    return oip


class FileIterWrapper:
    def __init__(self, flo, chunk_size=1024**2):
        self.flo = flo
        self.chunk_size = chunk_size

    def __next__(self):
        data = self.flo.read(self.chunk_size)
        if data:
            return data
        raise StopIteration

    def __iter__(self):
        return self


def get_cal_event(start_date, end_date, summary, description, uid):
    cal = vobject.iCalendar()
    cal.add("vevent")
    cal.vevent.add("summary").value = summary
    cal.vevent.add("description").value = description
    start = cal.vevent.add("dtstart")
    start.value = start_date
    end = cal.vevent.add("dtend")
    end.value = end_date
    cal.vevent.add("uid").value = uid
    return cal


def named_month(month_number):
    """Return the name of the month, given the number."""
    return date(1900, month_number, 1).strftime("%B")


def normalize_query(query_string,
                    findterms=re.compile(r'"([^"]+)"|(\S+)').findall,
                    normspace=re.compile(r"\s{2,}").sub):
    return [
        normspace(" ", (t[0] or t[1]).strip()) for t in findterms(query_string)
    ]


def build_query(query_string, search_fields):
    """
    Returns a query, that is a combination of Q objects. That combination
    aims to search keywords within a model by testing the given search fields.

    """
    query = None  # Query to search for every search term
    terms = normalize_query(query_string)
    for term in terms:
        or_query = None  # Query to search for a given term in each field
        for field_name in search_fields:
            q = Q(**{f"{field_name}__icontains": term})

            or_query = or_query | q if or_query else q

        query = query & or_query if query else or_query
    return query


def template_search_helper(fields=None, query_string=None):
    if not fields:
        fields = [
            "title",
            "description",
        ]
    findings = Finding_Template.objects.all()

    if not query_string:
        return findings

    entry_query = build_query(query_string, fields)
    return findings.filter(entry_query)


def get_page_items(request, items, page_size, prefix=""):
    return get_page_items_and_count(request, items, page_size, prefix=prefix, do_count=False)


def get_page_items_and_count(request, items, page_size, prefix="", *, do_count=True):
    page_param = prefix + "page"
    page_size_param = prefix + "page_size"

    page = request.GET.get(page_param, 1)
    size = request.GET.get(page_size_param, page_size)
    paginator = Paginator(items, size)

    # new get_page method will handle invalid page value, out of bounds pages, etc
    page = paginator.get_page(page)

    # we add the total_count here which is usually before prefetching
    # which is goog in this case because for counting we don't want to join too many tables
    if do_count:
        page.total_count = paginator.count

    return page


def handle_uploaded_threat(f, eng):
    path = Path(f.name)
    extension = path.suffix
    # Check if threat folder exist.
    if not Path(settings.MEDIA_ROOT + "/threat/").is_dir():
        # Create the folder
        Path(settings.MEDIA_ROOT + "/threat/").mkdir()
    with open(settings.MEDIA_ROOT + f"/threat/{eng.id}{extension}",
              "wb+") as destination:
        destination.writelines(chunk for chunk in f.chunks())
    eng.tmodel_path = settings.MEDIA_ROOT + f"/threat/{eng.id}{extension}"
    eng.save()


def handle_uploaded_selenium(f, cred):
    path = Path(f.name)
    extension = path.suffix
    with open(settings.MEDIA_ROOT + f"/selenium/{cred.id}{extension}",
              "wb+") as destination:
        destination.writelines(chunk for chunk in f.chunks())
    cred.selenium_script = settings.MEDIA_ROOT + f"/selenium/{cred.id}{extension}"
    cred.save()


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def add_external_issue(find, external_issue_provider, **kwargs):
    eng = Engagement.objects.get(test=find.test)
    prod = Product.objects.get(engagement=eng)
    logger.debug("adding external issue with provider: " + external_issue_provider)

    if external_issue_provider == "github":
        add_external_issue_github(find, prod, eng)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def update_external_issue(find, old_status, external_issue_provider, **kwargs):
    prod = Product.objects.get(engagement=Engagement.objects.get(test=find.test))
    eng = Engagement.objects.get(test=find.test)

    if external_issue_provider == "github":
        update_external_issue_github(find, prod, eng)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def close_external_issue(find, note, external_issue_provider, **kwargs):
    prod = Product.objects.get(engagement=Engagement.objects.get(test=find.test))
    eng = Engagement.objects.get(test=find.test)

    if external_issue_provider == "github":
        close_external_issue_github(find, note, prod, eng)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def reopen_external_issue(find, note, external_issue_provider, **kwargs):
    prod = Product.objects.get(engagement=Engagement.objects.get(test=find.test))
    eng = Engagement.objects.get(test=find.test)

    if external_issue_provider == "github":
        reopen_external_issue_github(find, note, prod, eng)


def process_tag_notifications(request, note, parent_url, parent_title):
    regex = re.compile(r"(?:\A|\s)@(\w+)\b")

    usernames_to_check = set(un.lower() for un in regex.findall(note.entry))  # noqa: C401

    users_to_notify = [
        User.objects.filter(username=username).get()
        for username in usernames_to_check
        if User.objects.filter(is_active=True, username=username).exists()
    ]

    if len(note.entry) > 200:
        note.entry = note.entry[:200]
        note.entry += "..."

    create_notification(
        event="user_mentioned",
        section=parent_title,
        note=note,
        title=f"{request.user} jotted a note",
        url=parent_url,
        icon="commenting",
        recipients=users_to_notify)


def encrypt(key, iv, plaintext):
    text = ""
    if plaintext and plaintext is not None:
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
        encryptor = cipher.encryptor()
        plaintext = _pad_string(plaintext)
        encrypted_text = encryptor.update(plaintext) + encryptor.finalize()
        text = binascii.b2a_hex(encrypted_text).rstrip()
    return text


def decrypt(key, iv, encrypted_text):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
    encrypted_text_bytes = binascii.a2b_hex(encrypted_text)
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text_bytes) + decryptor.finalize()
    return _unpad_string(decrypted_text)


def _pad_string(value):
    length = len(value)
    pad_size = 16 - (length % 16)
    return value.ljust(length + pad_size, b"\x00")


def _unpad_string(value):
    if value and value is not None:
        value = value.rstrip(b"\x00")
    return value


def dojo_crypto_encrypt(plaintext):
    data = None
    if plaintext:
        key = None
        key = get_db_key()

        iv = os.urandom(16)
        data = prepare_for_save(
            iv, encrypt(key, iv, plaintext.encode("utf-8")))

    return data


def prepare_for_save(iv, encrypted_value):
    stored_value = None

    if encrypted_value and encrypted_value is not None:
        binascii.b2a_hex(encrypted_value).rstrip()
        stored_value = "AES.1:" + binascii.b2a_hex(iv).decode("utf-8") + ":" + encrypted_value.decode("utf-8")
    return stored_value


def get_db_key():
    db_key = None
    if hasattr(settings, "DB_KEY"):
        db_key = settings.DB_KEY
        db_key = binascii.b2a_hex(
            hashlib.sha256(db_key.encode("utf-8")).digest().rstrip())[:32]

    return db_key


def prepare_for_view(encrypted_value):

    key = None
    decrypted_value = ""
    if encrypted_value is not NotImplementedError and encrypted_value is not None:
        key = get_db_key()
        encrypted_values = encrypted_value.split(":")

        if len(encrypted_values) > 1:
            iv = binascii.a2b_hex(encrypted_values[1])
            value = encrypted_values[2]

            try:
                decrypted_value = decrypt(key, iv, value)
                decrypted_value = decrypted_value.decode("utf-8")
            except UnicodeDecodeError:
                decrypted_value = ""

    return decrypted_value


def get_system_setting(setting, default=None):
    system_settings = System_Settings.objects.get()
    return getattr(system_settings, setting, (default if default is not None else None))


def get_setting(setting):
    return getattr(settings, setting)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Product)
def calculate_grade(product, *args, **kwargs):
    system_settings = System_Settings.objects.get()
    if not product:
        logger.warning("ignoring calculate product for product None!")
        return

    if system_settings.enable_product_grade:
        logger.debug("calculating product grade for %s:%s", product.id, product.name)
        findings = Finding.objects.filter(
                ~Q(severity="Info"),
                active=True,
                duplicate=False,
                false_p=False,
                test__engagement__product=product)

        if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_product_grading", True):
            findings = findings.filter(verified=True)

        severity_values = findings.values("severity").annotate(
                    Count("numerical_severity")).order_by()

        low = 0
        medium = 0
        high = 0
        critical = 0
        for severity_count in severity_values:
            if severity_count["severity"] == "Critical":
                critical = severity_count["numerical_severity__count"]
            elif severity_count["severity"] == "High":
                high = severity_count["numerical_severity__count"]
            elif severity_count["severity"] == "Medium":
                medium = severity_count["numerical_severity__count"]
            elif severity_count["severity"] == "Low":
                low = severity_count["numerical_severity__count"]
        aeval = Interpreter()
        aeval(system_settings.product_grade)
        grade_product = f"grade_product({critical}, {high}, {medium}, {low})"
        product.prod_numeric_grade = aeval(grade_product)
        super(Product, product).save()


def get_celery_worker_status():
    from .tasks import celery_status
    res = celery_status.apply_async()

    # Wait 5 seconds for a response from Celery
    try:
        return res.get(timeout=5)
    except:
        return False


def get_work_days(start: date, end: date):
    """
    Math function to get workdays between 2 dates.
    Can be used only as fallback as it doesn't know
    about specific country holidays or extra working days.
    https://stackoverflow.com/questions/3615375/number-of-days-between-2-dates-excluding-weekends/71977946#71977946
    """
    # if the start date is on a weekend, forward the date to next Monday
    if start.weekday() > WEEKDAY_FRIDAY:
        start = start + timedelta(days=7 - start.weekday())

    # if the end date is on a weekend, rewind the date to the previous Friday
    if end.weekday() > WEEKDAY_FRIDAY:
        end = end - timedelta(days=end.weekday() - WEEKDAY_FRIDAY)

    if start > end:
        return 0
    # that makes the difference easy, no remainders etc
    diff_days = (end - start).days + 1
    weeks = int(diff_days / 7)

    remainder = end.weekday() - start.weekday() + 1

    if remainder != 0 and end.weekday() < start.weekday():
        remainder = 5 + remainder

    return weeks * 5 + remainder


# Used to display the counts and enabled tabs in the product view
class Product_Tab:
    def __init__(self, product, title=None, tab=None):
        self.product = product
        self.title = title
        self.tab = tab
        self.engagement_count = Engagement.objects.filter(
            product=self.product, active=True).count()
        self.open_findings_count = Finding.objects.filter(test__engagement__product=self.product,
                                                          false_p=False,
                                                          duplicate=False,
                                                          out_of_scope=False,
                                                          active=True,
                                                          mitigated__isnull=True).count()
        active_endpoints = Endpoint.objects.filter(
            product=self.product,
            status_endpoint__mitigated=False,
            status_endpoint__false_positive=False,
            status_endpoint__out_of_scope=False,
            status_endpoint__risk_accepted=False,
        )
        self.endpoints_count = active_endpoints.distinct().count()
        self.endpoint_hosts_count = active_endpoints.values("host").distinct().count()
        self.benchmark_type = Benchmark_Type.objects.filter(
            enabled=True).order_by("name")
        self.engagement = None

    def setTab(self, tab):
        self.tab = tab

    def setEngagement(self, engagement):
        self.engagement = engagement

    def engagement(self):
        return self.engagement

    def tab(self):
        return self.tab

    def setTitle(self, title):
        self.title = title

    def title(self):
        return self.title

    def product(self):
        return self.product

    def engagements(self):
        return self.engagement_count

    def findings(self):
        return self.open_findings_count

    def endpoints(self):
        return self.endpoints_count

    def endpoint_hosts(self):
        return self.endpoint_hosts_count

    def benchmark_type(self):
        return self.benchmark_type


# Used to display the counts and enabled tabs in the product view
def tab_view_count(product_id):
    product = Product.objects.get(id=product_id)
    engagements = Engagement.objects.filter(
        product=product, active=True).count()
    open_findings = Finding.objects.filter(test__engagement__product=product,
                                           false_p=False,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           mitigated__isnull=True).count()
    endpoints = Endpoint.objects.filter(product=product).count()
    # benchmarks = Benchmark_Product_Summary.objects.filter(product=product, publish=True, benchmark_type__enabled=True).order_by('benchmark_type__name')
    benchmark_type = Benchmark_Type.objects.filter(
        enabled=True).order_by("name")
    return product, engagements, open_findings, endpoints, benchmark_type


def add_language(product, language, files=1, code=1):
    """Add a language to product"""
    prod_language = Languages.objects.filter(
        language__language__iexact=language, product=product)

    if not prod_language:
        try:
            language_type = Language_Type.objects.get(
                language__iexact=language)

            if language_type:
                lang = Languages(language=language_type, product=product, files=files, code=code)
                lang.save()
        except Language_Type.DoesNotExist:
            pass


# Apply finding template data by matching CWE + Title or CWE
def apply_cwe_to_template(finding, *, override=False):
    if System_Settings.objects.get().enable_template_match or override:
        # Attempt to match on CWE and Title First
        template = Finding_Template.objects.filter(
            cwe=finding.cwe, title__icontains=finding.title, template_match=True).first()

        # If none then match on CWE
        template = Finding_Template.objects.filter(
            cwe=finding.cwe, template_match=True).first()

        if template:
            finding.mitigation = template.mitigation
            finding.impact = template.impact
            finding.references = template.references
            template.last_used = timezone.now()
            template.save()

    return finding


def truncate_with_dots(the_string, max_length_including_dots):
    if not the_string:
        return the_string
    return (the_string[:max_length_including_dots - 3] + "..." if len(the_string) > max_length_including_dots else the_string)


def max_safe(list):
    return max(i for i in list if i is not None)


def get_full_url(relative_url):
    return f"{get_site_url()}{relative_url}"


def get_site_url():
    if settings.SITE_URL:
        return settings.SITE_URL
    logger.warning("SITE URL undefined in settings, full_url cannot be created")
    return "settings.SITE_URL"


@receiver(post_save, sender=User)
@receiver(post_save, sender=Dojo_User)
def user_post_save(sender, instance, created, **kwargs):
    # For new users we create a Notifications object so the default 'alert' notifications work and
    # assign them to a default group if specified in the system settings.
    # This needs to be a signal to make it also work for users created via ldap, oauth and other
    # authentication backends
    if created:
        try:
            notifications = Notifications.objects.get(template=True)
            notifications.pk = None
            notifications.template = False
            notifications.user = instance
            logger.info("creating default set (from template) of notifications for: " + str(instance))
        except Exception:
            notifications = Notifications(user=instance)
            logger.info("creating default set of notifications for: " + str(instance))

        notifications.save()

        system_settings = System_Settings.objects.get()
        if system_settings.default_group and system_settings.default_group_role:
            if (system_settings.default_group_email_pattern and re.fullmatch(system_settings.default_group_email_pattern, instance.email)) or \
               not system_settings.default_group_email_pattern:
                logger.info("setting default group for: " + str(instance))
                dojo_group_member = Dojo_Group_Member(
                    group=system_settings.default_group,
                    user=instance,
                    role=system_settings.default_group_role)
                dojo_group_member.save()

    # Superusers shall always be staff
    if instance.is_superuser and not instance.is_staff:
        instance.is_staff = True
        instance.save()


def is_safe_url(url):
    try:
        # available in django 3+
        from django.utils.http import url_has_allowed_host_and_scheme
    except ImportError:
        # django < 3
        from django.utils.http import is_safe_url as url_has_allowed_host_and_scheme

    return url_has_allowed_host_and_scheme(url, allowed_hosts=None)


def get_return_url(request):
    return_url = request.POST.get("return_url", None)
    if return_url is None or not return_url.strip():
        # for some reason using request.GET.get('return_url') never works
        return_url = request.GET["return_url"] if "return_url" in request.GET else None  # noqa: SIM401

    return return_url or None


def redirect_to_return_url_or_else(request, or_else):
    return_url = get_return_url(request)

    if return_url:
        # logger.debug('redirecting to %s: ', return_url.strip())
        return redirect(request, return_url.strip())
    if or_else:
        return redirect(request, or_else)
    messages.add_message(request, messages.ERROR, "Unable to redirect anywhere.", extra_tags="alert-danger")
    return redirect(request, request.get_full_path())


def redirect(request, redirect_to):
    """Only allow redirects to allowed_hosts to prevent open redirects"""
    if is_safe_url(redirect_to):
        return HttpResponseRedirect(redirect_to)
    msg = "invalid redirect, host and scheme not in allowed_hosts"
    raise ValueError(msg)


def file_size_mb(file_obj):
    if file_obj:
        file_obj.seek(0, 2)
        size = file_obj.tell()
        file_obj.seek(0, 0)
        if size > 0:
            return size / 1048576
    return 0


def is_scan_file_too_large(scan_file):
    if hasattr(settings, "SCAN_FILE_MAX_SIZE"):
        size = file_size_mb(scan_file)
        if size > settings.SCAN_FILE_MAX_SIZE:
            return True
    return False


def queryset_check(query):
    return query if isinstance(query, QuerySet) else query.qs


def sla_compute_and_notify(*args, **kwargs):
    """
    The SLA computation and notification will be disabled if the user opts out
    of the Findings SLA on the System Settings page.

    Notifications are managed the usual way, so you'd have to opt-in.
    Exception is for JIRA issues, which would get a comment anyways.
    """
    import dojo.jira_link.helper as jira_helper

    class NotificationEntry:
        def __init__(self, finding=None, jira_issue=None, *, do_jira_sla_comment=False):
            self.finding = finding
            self.jira_issue = jira_issue
            self.do_jira_sla_comment = do_jira_sla_comment

    def _add_notification(finding, kind):
        # jira_issue, do_jira_sla_comment are taken from the context
        # kind can be one of: breached, prebreach, breaching
        if finding.test.engagement.product.disable_sla_breach_notifications:
            return

        notification = NotificationEntry(finding=finding,
                                         jira_issue=jira_issue,
                                         do_jira_sla_comment=do_jira_sla_comment)

        pt = finding.test.engagement.product.prod_type.name
        p = finding.test.engagement.product.name

        if pt in combined_notifications:
            if p in combined_notifications[pt]:
                if kind in combined_notifications[pt][p]:
                    combined_notifications[pt][p][kind].append(notification)
                else:
                    combined_notifications[pt][p][kind] = [notification]
            else:
                combined_notifications[pt][p] = {kind: [notification]}
        else:
            combined_notifications[pt] = {p: {kind: [notification]}}

    def _notification_title_for_finding(finding, kind, sla_age):
        title = f"Finding {finding.id} - "
        if kind == "breached":
            abs_sla_age = abs(sla_age)
            period = "day"
            if abs_sla_age > 1:
                period = "days"
            title += f"SLA breached by {abs_sla_age} {period}! Overdue notice"
        elif kind == "prebreach":
            title += f"SLA pre-breach warning - {sla_age} day(s) left"
        elif kind == "breaching":
            title += "SLA is breaching today"

        return title

    def _create_notifications():
        for pt in combined_notifications:
            for p in combined_notifications[pt]:
                for kind in combined_notifications[pt][p]:
                    # creating notifications on per-finding basis

                    # we need this list for combined notification feature as we
                    # can not supply references to local objects as
                    # create_notification() arguments
                    findings_list = []

                    for n in combined_notifications[pt][p][kind]:
                        title = _notification_title_for_finding(n.finding, kind, n.finding.sla_days_remaining())

                        create_notification(
                            event="sla_breach",
                            title=title,
                            finding=n.finding,
                            url=reverse("view_finding", args=(n.finding.id,)),
                        )

                        if n.do_jira_sla_comment:
                            logger.info("Creating JIRA comment to notify of SLA breach information.")
                            jira_helper.add_simple_jira_comment(jira_instance, n.jira_issue, title)

                        findings_list.append(n.finding)

                    # producing a "combined" SLA breach notification
                    title_combined = f"SLA alert ({kind}): product type '{pt}', product '{p}'"
                    product = combined_notifications[pt][p][kind][0].finding.test.engagement.product
                    create_notification(
                        event="sla_breach_combined",
                        title=title_combined,
                        product=product,
                        findings=findings_list,
                        breach_kind=kind,
                        base_url=get_script_prefix(),
                    )

    # exit early on flags
    system_settings = System_Settings.objects.get()
    if not system_settings.enable_notify_sla_active and not system_settings.enable_notify_sla_active_verified:
        logger.info("Will not notify on SLA breach per user configured settings")
        return

    jira_issue = None
    jira_instance = None
    # notifications list per product per product type
    combined_notifications = {}
    try:
        if system_settings.enable_finding_sla:
            logger.info("About to process findings for SLA notifications.")
            logger.debug(f"Active {system_settings.enable_notify_sla_active}, Verified {system_settings.enable_notify_sla_active_verified}, Has JIRA {system_settings.enable_notify_sla_jira_only}, pre-breach {settings.SLA_NOTIFY_PRE_BREACH}, post-breach {settings.SLA_NOTIFY_POST_BREACH}")

            query = None
            if system_settings.enable_notify_sla_active_verified:
                query = Q(active=True, verified=True, is_mitigated=False, duplicate=False)
            elif system_settings.enable_notify_sla_active:
                query = Q(active=True, is_mitigated=False, duplicate=False)
            logger.debug(f"My query: {query}")

            no_jira_findings = {}
            if system_settings.enable_notify_sla_jira_only:
                logger.debug("Ignoring findings that are not linked to a JIRA issue")
                no_jira_findings = Finding.objects.exclude(jira_issue__isnull=False)

            total_count = 0
            pre_breach_count = 0
            post_breach_count = 0
            post_breach_no_notify_count = 0
            jira_count = 0
            at_breach_count = 0

            # Taking away for now, since the prefetch is not efficient
            # .select_related('jira_issue') \
            # .prefetch_related(Prefetch('test__engagement__product__jira_project_set__jira_instance')) \
            # A finding with 'Info' severity will not be considered for SLA notifications (not in model)
            findings = Finding.objects \
                .filter(query) \
                .exclude(severity="Info") \
                .exclude(id__in=no_jira_findings)

            for finding in findings:
                total_count += 1
                sla_age = finding.sla_days_remaining()

                # get the sla enforcement for the severity and, if the severity setting is not enforced, do not notify
                # resolves an issue where notifications are always sent for the severity of SLA that is not enforced
                severity, enforce = finding.get_sla_period()
                if not enforce:
                    logger.debug(f"SLA is not enforced for Finding {finding.id} of {severity} severity, skipping notification.")
                    continue

                # if SLA is set to 0 in settings, it's a null. And setting at 0 means no SLA apparently.
                if sla_age is None:
                    sla_age = 0

                if (sla_age < 0) and (abs(sla_age) > settings.SLA_NOTIFY_POST_BREACH):
                    post_breach_no_notify_count += 1
                    # Skip finding notification if breached for too long
                    logger.debug(f"Finding {finding.id} breached the SLA {abs(sla_age)} days ago. Skipping notifications.")
                    continue

                do_jira_sla_comment = False
                jira_issue = None
                if finding.has_jira_issue:
                    jira_issue = finding.jira_issue
                elif finding.has_jira_group_issue:
                    jira_issue = finding.finding_group.jira_issue

                if jira_issue:
                    jira_count += 1
                    jira_instance = jira_helper.get_jira_instance(finding)
                    if jira_instance is not None:
                        logger.debug(f"JIRA config for finding is {jira_instance}")
                        # global config or product config set, product level takes precedence
                        try:
                            # TODO: see new property from #2649 to then replace, somehow not working with prefetching though.
                            product_jira_sla_comment_enabled = jira_helper.get_jira_project(finding).product_jira_sla_notification
                        except Exception as e:
                            logger.error("The product is not linked to a JIRA configuration! Something is weird here.")
                            logger.error(f"Error is: {e}")

                        jiraconfig_sla_notification_enabled = jira_instance.global_jira_sla_notification

                        if jiraconfig_sla_notification_enabled or product_jira_sla_comment_enabled:
                            logger.debug(f"Global setting {jiraconfig_sla_notification_enabled} -- Product setting {product_jira_sla_comment_enabled}")
                            do_jira_sla_comment = True
                            logger.debug(f"JIRA issue is {jira_issue.jira_key}")

                logger.debug(f"Finding {finding.id} has {sla_age} days left to breach SLA.")
                if (sla_age < 0):
                    post_breach_count += 1
                    logger.info(f"Finding {finding.id} has breached by {abs(sla_age)} days.")
                    abs_sla_age = abs(sla_age)
                    if not system_settings.enable_notify_sla_exponential_backoff or abs_sla_age == 1 or (abs_sla_age & (abs_sla_age - 1) == 0):
                        _add_notification(finding, "breached")
                    else:
                        logger.info("Skipping notification as exponential backoff is enabled and the SLA is not a power of two")
                # The finding is within the pre-breach period
                elif (sla_age > 0) and (sla_age <= settings.SLA_NOTIFY_PRE_BREACH):
                    pre_breach_count += 1
                    logger.info(f"Security SLA pre-breach warning for finding ID {finding.id}. Days remaining: {sla_age}")
                    _add_notification(finding, "prebreach")
                # The finding breaches the SLA today
                elif (sla_age == 0):
                    at_breach_count += 1
                    logger.info(f"Security SLA breach warning. Finding ID {finding.id} breaching today ({sla_age})")
                    _add_notification(finding, "breaching")

            _create_notifications()
            logger.info(f"SLA run results: Pre-breach: {pre_breach_count}, at-breach: {at_breach_count}, post-breach: {post_breach_count}, post-breach-no-notify: {post_breach_no_notify_count}, with-jira: {jira_count}, TOTAL: {total_count}")

    except System_Settings.DoesNotExist:
        logger.info("Findings SLA is not enabled.")


def get_words_for_field(model, fieldname):
    max_results = getattr(settings, "MAX_AUTOCOMPLETE_WORDS", 20000)
    models = None
    if model == Finding:
        models = get_authorized_findings(Permissions.Finding_View, user=get_current_user())
    elif model == Finding_Template:
        models = Finding_Template.objects.all()

    if models is not None:
        words = [
            word for field_value in models.order_by().filter(**{f"{fieldname}__isnull": False}).values_list(fieldname, flat=True).distinct()[:max_results] for word in (field_value.split() if field_value else []) if len(word) > 2
        ]
    else:
        words = []

    return sorted(set(words))


def get_current_user():
    return crum.get_current_user()


def get_current_request():
    return crum.get_current_request()


def create_bleached_link(url, title):
    link = '<a href="'
    link += url
    link += '" target="_blank" title="'
    link += title
    link += '">'
    link += title
    link += "</a>"
    return bleach.clean(link, tags={"a"}, attributes={"a": ["href", "target", "title"]})


def get_object_or_none(klass, *args, **kwargs):
    """
    Use get() to return an object, or return None
    does not exist.
    klass may be a Model, Manager, or QuerySet object. All other passed
    arguments and keyword arguments are used in the get() query.
    Like with QuerySet.get(), MultipleObjectsReturned is raised if more than
    one object is found.
    """
    queryset = klass

    if hasattr(klass, "_default_manager"):
        queryset = klass._default_manager.all()

    if not hasattr(queryset, "get"):
        klass__name = klass.__name__ if isinstance(klass, type) else klass.__class__.__name__
        msg = (
            "First argument to get_object_or_None() must be a Model, Manager, "
            f"or QuerySet, not '{klass__name}'."
        )
        raise ValueError(msg)
    try:
        return queryset.get(*args, **kwargs)
    except queryset.model.DoesNotExist:
        return None


def get_last_object_or_none(klass, *args, **kwargs):
    """
    Use last() to return an object, or return None
    does not exist.
    klass may be a Model, Manager, or QuerySet object. All other passed
    arguments and keyword arguments are used in the get() query.
    Like with QuerySet.get(), MultipleObjectsReturned is raised if more than
    one object is found.
    """
    queryset = klass

    if hasattr(klass, "_default_manager"):
        queryset = klass._default_manager.all()

    if not hasattr(queryset, "get"):
        klass__name = klass.__name__ if isinstance(klass, type) else klass.__class__.__name__
        msg = (
            "First argument to get_last_object_or_None() must be a Model, Manager, "
            f"or QuerySet, not '{klass__name}'."
        )
        raise ValueError(msg)
    try:
        results = queryset.filter(*args, **kwargs).order_by("id")
        logger.debug("last_object_or_none: %s", results.query)
        return results.last()
    except queryset.model.DoesNotExist:
        return None


def add_success_message_to_response(message):
    if get_current_request():
        messages.add_message(get_current_request(),
                            messages.SUCCESS,
                            message,
                            extra_tags="alert-success")


def add_error_message_to_response(message):
    if get_current_request():
        messages.add_message(get_current_request(),
                            messages.ERROR,
                            message,
                            extra_tags="alert-danger")


def add_field_errors_to_response(form):
    if form and get_current_request():
        for field, error in form.errors.items():
            add_error_message_to_response(error)


def mass_model_updater(model_type, models, function, fields, page_size=1000, order="asc", log_prefix=""):
    """
    Using the default for model in queryset can be slow for large querysets. Even
    when using paging as LIMIT and OFFSET are slow on database. In some cases we can optimize
    this process very well if we can process the models ordered by id.
    In that case we don't need LIMIT or OFFSET, but can keep track of the latest id that
    was processed and continue from there on the next page. This is fast because
    it results in an index seek instead of executing the whole query again and skipping
    the first X items.
    """
    # force ordering by id to make our paging work
    last_id = None
    models = models.order_by()
    if order == "asc":
        logger.debug("ordering ascending")
        models = models.order_by("id")
        last_id = 0
    elif order == "desc":
        logger.debug("ordering descending")
        models = models.order_by("-id")
        # get maximum, which is the first due to descending order
        last_id = models.first().id + 1
    else:
        msg = "order must be asc or desc"
        raise ValueError(msg)
    # use filter to make count fast on mysql
    total_count = models.filter(id__gt=0).count()
    logger.debug("%s found %d models for mass update:", log_prefix, total_count)

    i = 0
    batch = []
    total_pages = (total_count // page_size) + 2
    # logger.info('pages to process: %d', total_pages)
    logger.debug("%s%s out of %s models processed ...", log_prefix, i, total_count)
    for p in range(1, total_pages):
        # logger.info('page: %d', p)
        if order == "asc":
            page = models.filter(id__gt=last_id)[:page_size]
        else:
            page = models.filter(id__lt=last_id)[:page_size]

        # logger.info('page query: %s', page.query)
        # if p == 23:
        #     raise ValueError('bla')
        for model in page:
            i += 1
            last_id = model.id
            # logger.info('last_id: %s', last_id)

            function(model)

            batch.append(model)

            if (i > 0 and i % page_size == 0):
                if fields:
                    model_type.objects.bulk_update(batch, fields)
                batch = []
                logger.debug("%s%s out of %s models processed ...", log_prefix, i, total_count)

        logger.info("%s%s out of %s models processed ...", log_prefix, i, total_count)

    if fields:
        model_type.objects.bulk_update(batch, fields)
    batch = []
    logger.info("%s%s out of %s models processed ...", log_prefix, i, total_count)


def to_str_typed(obj):
    """For code that handles multiple types of objects, print not only __str__ but prefix the type of the object"""
    return f"{type(obj)}: {obj}"


def get_product(obj):
    logger.debug("getting product for %s:%s", type(obj), obj)
    if not obj:
        return None

    if isinstance(obj, Finding | Finding_Group):
        return obj.test.engagement.product

    if isinstance(obj, Test):
        return obj.engagement.product

    if isinstance(obj, Engagement):
        return obj.product

    if isinstance(obj, Product):
        return obj
    return None


def prod_name(obj):
    if not obj:
        return "Unknown"

    return get_product(obj).name


# Returns image locations by default (i.e. uploaded_files/09577eb1-6ccb-430b-bc82-0742d4c97a09.png)
# if return_objects=True, return the FileUPload object instead of just the file location
def get_file_images(obj, *, return_objects=False):
    logger.debug("getting images for %s:%s", type(obj), obj)
    files = None
    if not obj:
        return files
    files = obj.files.all()

    images = []
    for file in files:
        file_name = file.file.name
        file_type = mimetypes.guess_type(file_name)[0]
        if file_type and "image" in file_type:
            if return_objects:
                images.append(file)
            else:
                images.append(file_name)
    return images


def get_enabled_notifications_list():
    # Alerts need to enabled by default
    enabled = ["alert"]
    for choice in NOTIFICATION_CHOICES:
        if get_system_setting(f"enable_{choice[0]}_notifications"):
            enabled.append(choice[0])
    return enabled


def is_finding_groups_enabled():
    """Returns true is feature is enabled otherwise false"""
    return get_system_setting("enable_finding_groups")


class async_delete:
    def __init__(self, *args, **kwargs):
        self.mapping = {
            "Product_Type": [
                (Endpoint, "product__prod_type"),
                (Finding, "test__engagement__product__prod_type"),
                (Test, "engagement__product__prod_type"),
                (Engagement, "product__prod_type"),
                (Product, "prod_type")],
            "Product": [
                (Endpoint, "product"),
                (Finding, "test__engagement__product"),
                (Test, "engagement__product"),
                (Engagement, "product")],
            "Engagement": [
                (Finding, "test__engagement"),
                (Test, "engagement")],
            "Test": [(Finding, "test")],
        }

    @dojo_async_task
    @app.task
    def delete_chunk(self, objects, **kwargs):
        for object in objects:
            try:
                object.delete()
            except AssertionError:
                logger.debug("ASYNC_DELETE: object has already been deleted elsewhere. Skipping")
                # The id must be None
                # The object has already been deleted elsewhere

    @dojo_async_task
    @app.task
    def delete(self, object, **kwargs):
        logger.debug("ASYNC_DELETE: Deleting " + self.get_object_name(object) + ": " + str(object))
        model_list = self.mapping.get(self.get_object_name(object), None)
        if model_list:
            # The object to be deleted was found in the object list
            self.crawl(object, model_list)
        else:
            # The object is not supported in async delete, delete normally
            logger.debug("ASYNC_DELETE: " + self.get_object_name(object) + " async delete not supported. Deleteing normally: " + str(object))
            object.delete()

    @dojo_async_task
    @app.task
    def crawl(self, object, model_list, **kwargs):
        logger.debug("ASYNC_DELETE: Crawling " + self.get_object_name(object) + ": " + str(object))
        for model_info in model_list:
            model = model_info[0]
            model_query = model_info[1]
            filter_dict = {model_query: object}
            objects_to_delete = model.objects.filter(**filter_dict)
            logger.debug("ASYNC_DELETE: Deleting " + str(len(objects_to_delete)) + " " + self.get_object_name(model) + "s in chunks")
            chunks = self.chunk_list(model, objects_to_delete)
            for chunk in chunks:
                logger.debug(f"deleting {len(chunk)} {self.get_object_name(model)}")
                self.delete_chunk(chunk)
        self.delete_chunk([object])
        logger.debug("ASYNC_DELETE: Successfully deleted " + self.get_object_name(object) + ": " + str(object))

    def chunk_list(self, model, list):
        chunk_size = get_setting("ASYNC_OBEJECT_DELETE_CHUNK_SIZE")
        # Break the list of objects into "chunk_size" lists
        chunk_list = [list[i:i + chunk_size] for i in range(0, len(list), chunk_size)]
        logger.debug("ASYNC_DELETE: Split " + self.get_object_name(model) + " into " + str(len(chunk_list)) + " chunks of " + str(chunk_size))
        return chunk_list

    def get_object_name(self, object):
        if object.__class__.__name__ == "ModelBase":
            return object.__name__
        return object.__class__.__name__


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    # to cover more complex cases:
    # http://stackoverflow.com/questions/4581789/how-do-i-get-user-ip-address-in-django

    logger.info("login user: %s via ip: %s", user.username, request.META.get("REMOTE_ADDR"))


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):

    logger.info("logout user: %s via ip: %s", user.username, request.META.get("REMOTE_ADDR"))


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):

    if "username" in credentials:
        logger.warning("login failed for: %s via ip: %s", credentials["username"], request.META["REMOTE_ADDR"])
    else:
        logger.error("login failed because of missing username via ip: %s", request.META["REMOTE_ADDR"])


def get_password_requirements_string():
    s = "Password must contain {minimum_length} to {maximum_length} characters".format(
        minimum_length=int(get_system_setting("minimum_password_length")),
        maximum_length=int(get_system_setting("maximum_password_length")))

    if bool(get_system_setting("lowercase_character_required")):
        s += ", one lowercase letter (a-z)"
    if bool(get_system_setting("uppercase_character_required")):
        s += ", one uppercase letter (A-Z)"
    if bool(get_system_setting("number_character_required")):
        s += ", one number (0-9)"
    if bool(get_system_setting("special_character_required")):
        s += ', one special character (()[]{}|\\`~!@#$%^&*_-+=;:\'",<>./?)'

    if s.count(", ") == 1:
        password_requirements_string = s.rsplit(", ", 1)[0] + " and " + s.rsplit(", ", 1)[1]
    elif s.count(", ") > 1:
        password_requirements_string = s.rsplit(", ", 1)[0] + ", and " + s.rsplit(", ", 1)[1]
    else:
        password_requirements_string = s

    return password_requirements_string + "."


def get_zero_severity_level():
    return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}


def sum_by_severity_level(metrics):
    values = get_zero_severity_level()

    for m in metrics:
        if values.get(m.get("severity")) is not None:
            values[m.get("severity")] += 1

    return values


def calculate_finding_age(f):
    start_date = f.get("date", None)
    if start_date and isinstance(start_date, str):
        start_date = parse(start_date).date()

    if settings.SLA_BUSINESS_DAYS:
        if f.get("mitigated"):
            mitigated_date = f.get("mitigated")
            if isinstance(mitigated_date, datetime):
                mitigated_date = f.get("mitigated").date()
            days = get_work_days(f.get("date"), mitigated_date)
        else:
            days = get_work_days(f.get("date"), timezone.now().date())
    else:
        if isinstance(start_date, datetime):
            start_date = start_date.date()

        if f.get("mitigated"):
            mitigated_date = f.get("mitigated")
            if isinstance(mitigated_date, datetime):
                mitigated_date = f.get("mitigated").date()
            diff = mitigated_date - start_date
        else:
            diff = timezone.now().date() - start_date
        days = diff.days
    return max(0, days)


def get_open_findings_burndown(product):
    findings = Finding.objects.filter(test__engagement__product=product, duplicate=False)
    f_list = list(findings)

    curr_date = datetime.combine(datetime.now(), datetime.min.time())
    start_date = curr_date - timedelta(days=90)

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    # count all findings older than 90 days that are still active OR will be mitigated/risk-accepted in the next 90 days
    for f in list(findings.filter(date__lt=start_date)):
        if f.active:
            if f.severity == "Critical":
                critical_count += 1
            if f.severity == "High":
                high_count += 1
            if f.severity == "Medium":
                medium_count += 1
            if f.severity == "Low":
                low_count += 1
            if f.severity == "Info":
                info_count += 1
        elif f.is_mitigated:
            f_mitigated_date = f.mitigated.timestamp()
            if f_mitigated_date >= start_date.timestamp():
                if f.severity == "Critical":
                    critical_count += 1
                if f.severity == "High":
                    high_count += 1
                if f.severity == "Medium":
                    medium_count += 1
                if f.severity == "Low":
                    low_count += 1
                if f.severity == "Info":
                    info_count += 1
        elif f.risk_accepted:
            # simple risk acceptance does not have a risk acceptance object, so we fall back to creation date.
            f_risk_accepted_date = f.created.timestamp()
            if f.risk_acceptance:
                f_risk_accepted_date = f.risk_acceptance.created.timestamp()
            if f_risk_accepted_date >= start_date.timestamp():
                if f.severity == "Critical":
                    critical_count += 1
                if f.severity == "High":
                    high_count += 1
                if f.severity == "Medium":
                    medium_count += 1
                if f.severity == "Low":
                    low_count += 1
                if f.severity == "Info":
                    info_count += 1

    running_min, running_max = float("inf"), float("-inf")
    past_90_days = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Info": [],
    }

    # count the number of open findings for the 90-day window
    for i in range(90, -1, -1):
        start = (curr_date - timedelta(days=i))

        d_start = start.timestamp()
        d_end = (start + timedelta(days=1)).timestamp()

        for f in f_list:
            # If a finding was opened on this day we add it to the counter of that day
            f_open_date = datetime.combine(f.date, datetime.min.time()).timestamp()
            if f_open_date >= d_start and f_open_date < d_end:
                if f.severity == "Critical":
                    critical_count += 1
                if f.severity == "High":
                    high_count += 1
                if f.severity == "Medium":
                    medium_count += 1
                if f.severity == "Low":
                    low_count += 1
                if f.severity == "Info":
                    info_count += 1

            # If a finding was mitigated on this day we subtract it
            if f.is_mitigated:
                f_mitigated_date = f.mitigated.timestamp()
                if f_mitigated_date >= d_start and f_mitigated_date < d_end:
                    if f.severity == "Critical":
                        critical_count -= 1
                    if f.severity == "High":
                        high_count -= 1
                    if f.severity == "Medium":
                        medium_count -= 1
                    if f.severity == "Low":
                        low_count -= 1
                    if f.severity == "Info":
                        info_count -= 1

            # If a finding was risk accepted on this day we subtract it
            elif f.risk_accepted:
                f_risk_accepted_date = f.created.timestamp()
                if f.risk_acceptance:
                    f_risk_accepted_date = f.risk_acceptance.created.timestamp()
                if f_risk_accepted_date >= d_start and f_risk_accepted_date < d_end:
                    if f.severity == "Critical":
                        critical_count -= 1
                    if f.severity == "High":
                        high_count -= 1
                    if f.severity == "Medium":
                        medium_count -= 1
                    if f.severity == "Low":
                        low_count -= 1
                    if f.severity == "Info":
                        info_count -= 1

        f_day = [critical_count, high_count, medium_count, low_count, info_count]
        if min(f_day) < running_min:
            running_min = min(f_day)
        if max(f_day) > running_max:
            running_max = max(f_day)

        past_90_days["Critical"].append([d_start * 1000, critical_count])
        past_90_days["High"].append([d_start * 1000, high_count])
        past_90_days["Medium"].append([d_start * 1000, medium_count])
        past_90_days["Low"].append([d_start * 1000, low_count])
        past_90_days["Info"].append([d_start * 1000, info_count])

    past_90_days["y_max"] = running_max
    past_90_days["y_min"] = running_min

    return past_90_days


def get_custom_method(setting_name: str) -> Callable | None:
    """
    Attempts to load and return the method specified by fully-qualified name at the given setting.

    :param setting_name: The name of the setting that holds the fqname of the Python method we want to load
    :return: The callable if it was able to be loaded, else None
    """
    if fq_name := getattr(settings, setting_name, None):
        try:
            mn, _, fn = fq_name.rpartition(".")
            m = importlib.import_module(mn)
            return getattr(m, fn)
        except ModuleNotFoundError:
            pass
    return None


def generate_file_response(file_object: FileUpload) -> FileResponse:
    """
    Serve an uploaded file in a uniformed way.

    This function assumes all permissions have previously validated/verified
    by the caller of this function.
    """
    # Quick check to ensure we have the right type of object
    if not isinstance(file_object, FileUpload):
        msg = f"FileUpload object expected but type <{type(file_object)}> received."
        raise TypeError(msg)
    # Determine the path of the file on disk within the MEDIA_ROOT
    file_path = f"{settings.MEDIA_ROOT}/{file_object.file.url.lstrip(settings.MEDIA_URL)}"

    return generate_file_response_from_file_path(
        file_path, file_name=file_object.title, file_size=file_object.file.size,
    )


def generate_file_response_from_file_path(
    file_path: str, file_name: str | None = None, file_size: int | None = None,
) -> FileResponse:
    """Serve an local file in a uniformed way."""
    # Determine the file path
    path = Path(file_path)
    file_path_without_extension = path.parent / path.stem
    file_extension = path.suffix
    # Determine the file name if not supplied
    if file_name is None:
        file_name = file_path_without_extension.rsplit("/")[-1]
    # Determine the file size if not supplied
    if file_size is None:
        file_size = pathlib.Path(file_path).stat().st_size
    # Generate the FileResponse
    full_file_name = f"{file_name}{file_extension}"
    response = FileResponse(
        open(file_path, "rb"),
        filename=full_file_name,
        content_type=f"{mimetypes.guess_type(file_path)}",
    )
    # Add some important headers
    response["Content-Disposition"] = f'attachment; filename="{full_file_name}"'
    response["Content-Length"] = file_size
    return response
