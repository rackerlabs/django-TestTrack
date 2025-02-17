import logging
from datetime import date, timedelta

from auditlog.models import LogEntry
from celery.utils.log import get_task_logger
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.core.management import call_command
from django.db.models import Count, Prefetch
from django.urls import reverse
from django.utils import timezone

from dojo.celery import app
from dojo.models import Alerts, Announcement, Endpoint, Engagement, Finding, Product, System_Settings, User
from dojo.notifications.helper import create_notification
from dojo.utils import calculate_grade, sla_compute_and_notify

logger = get_task_logger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


# Logs the error to the alerts table, which appears in the notification toolbar
def log_generic_alert(source, title, description):
    create_notification(event="other", title=title, description=description,
                        icon="bullseye", source=source)


@app.task(bind=True)
def add_alerts(self, runinterval):
    now = timezone.now()

    upcoming_engagements = Engagement.objects.filter(target_start__gt=now + timedelta(days=3), target_start__lt=now + timedelta(days=3) + runinterval).order_by("target_start")
    for engagement in upcoming_engagements:
        create_notification(event="upcoming_engagement",
                            title=f"Upcoming engagement: {engagement.name}",
                            engagement=engagement,
                            recipients=[engagement.lead],
                            url=reverse("view_engagement", args=(engagement.id,)))

    stale_engagements = Engagement.objects.filter(
        target_start__gt=now - runinterval,
        target_end__lt=now,
        status="In Progress").order_by("-target_end")
    for eng in stale_engagements:
        create_notification(event="stale_engagement",
                            title=f"Stale Engagement: {eng.name}",
                            description='The engagement "{}" is stale. Target end was {}.'.format(eng.name, eng.target_end.strftime("%b. %d, %Y")),
                            url=reverse("view_engagement", args=(eng.id,)),
                            recipients=[eng.lead])

    system_settings = System_Settings.objects.get()
    if system_settings.engagement_auto_close:
        # Close Engagements older than user defined days
        close_days = system_settings.engagement_auto_close_days
        unclosed_engagements = Engagement.objects.filter(target_end__lte=now - timedelta(days=close_days),
                                                        status="In Progress").order_by("target_end")

        for eng in unclosed_engagements:
            create_notification(event="auto_close_engagement",
                                title=eng.name,
                                description='The engagement "{}" has auto-closed. Target end was {}.'.format(eng.name, eng.target_end.strftime("%b. %d, %Y")),
                                url=reverse("view_engagement", args=(eng.id,)),
                                recipients=[eng.lead])

        unclosed_engagements.update(status="Completed", active=False, updated=timezone.now())

    # Calculate grade
    if system_settings.enable_product_grade:
        products = Product.objects.all()
        for product in products:
            calculate_grade(product)


@app.task(bind=True)
def cleanup_alerts(*args, **kwargs):
    try:
        max_alerts_per_user = settings.MAX_ALERTS_PER_USER
    except System_Settings.DoesNotExist:
        max_alerts_per_user = -1

    if max_alerts_per_user > -1:
        total_deleted_count = 0
        logger.info("start deleting oldest alerts if a user has more than %s alerts", max_alerts_per_user)
        users = User.objects.all()
        for user in users:
            alerts_to_delete = Alerts.objects.filter(user_id=user.id).order_by("-created")[max_alerts_per_user:].values_list("id", flat=True)
            total_deleted_count += len(alerts_to_delete)
            Alerts.objects.filter(pk__in=list(alerts_to_delete)).delete()
        logger.info("total number of alerts deleted: %s", total_deleted_count)


@app.task(bind=True)
def flush_auditlog(*args, **kwargs):
    retention_period = settings.AUDITLOG_FLUSH_RETENTION_PERIOD

    if retention_period < 0:
        logger.info("Flushing auditlog is disabled")
        return

    logger.info("Running Cleanup Task for Logentries with %d Months retention", retention_period)
    retention_date = date.today() - relativedelta(months=retention_period)
    subset = LogEntry.objects.filter(timestamp__date__lt=retention_date)
    event_count = subset.count()
    logger.debug("Initially received %d Logentries", event_count)
    if event_count > 0:
        subset._raw_delete(subset.db)
        logger.debug("Total number of audit log entries deleted: %s", event_count)
    else:
        logger.debug("No outdated Logentries found")


@app.task(bind=True)
def async_dupe_delete(*args, **kwargs):
    try:
        system_settings = System_Settings.objects.get()
        enabled = system_settings.delete_duplicates
        dupe_max = system_settings.max_dupes
        total_duplicate_delete_count_max_per_run = settings.DUPE_DELETE_MAX_PER_RUN
    except System_Settings.DoesNotExist:
        enabled = False

    if enabled and dupe_max is None:
        logger.info("skipping deletion of excess duplicates: max_dupes not configured")
        return

    if enabled:
        logger.info("delete excess duplicates (max_dupes per finding: %s, max deletes per run: %s)", dupe_max, total_duplicate_delete_count_max_per_run)
        deduplicationLogger.info("delete excess duplicates (max_dupes per finding: %s, max deletes per run: %s)", dupe_max, total_duplicate_delete_count_max_per_run)

        # limit to 100 to prevent overlapping jobs
        results = Finding.objects \
                .filter(duplicate=True) \
                .order_by() \
                .values("duplicate_finding") \
                .annotate(num_dupes=Count("id")) \
                .filter(num_dupes__gt=dupe_max)[:total_duplicate_delete_count_max_per_run]

        originals_with_too_many_duplicates_ids = [result["duplicate_finding"] for result in results]

        originals_with_too_many_duplicates = Finding.objects.filter(id__in=originals_with_too_many_duplicates_ids).order_by("id")

        # prefetch to make it faster
        originals_with_too_many_duplicates = originals_with_too_many_duplicates.prefetch_related(Prefetch("original_finding",
            queryset=Finding.objects.filter(duplicate=True).order_by("date")))

        total_deleted_count = 0
        for original in originals_with_too_many_duplicates:
            duplicate_list = original.original_finding.all()
            dupe_count = len(duplicate_list) - dupe_max

            for finding in duplicate_list:
                deduplicationLogger.debug(f"deleting finding {finding.id}:{finding.title} ({finding.hash_code}))")
                finding.delete()
                total_deleted_count += 1
                dupe_count -= 1
                if dupe_count <= 0:
                    break
                if total_deleted_count >= total_duplicate_delete_count_max_per_run:
                    break

            if total_deleted_count >= total_duplicate_delete_count_max_per_run:
                break

        logger.info("total number of excess duplicates deleted: %s", total_deleted_count)


@app.task(ignore_result=False)
def celery_status():
    return True


@app.task
def async_sla_compute_and_notify_task(*args, **kwargs):
    logger.debug("Computing SLAs and notifying as needed")
    try:
        system_settings = System_Settings.objects.get()
        if system_settings.enable_finding_sla:
            sla_compute_and_notify(*args, **kwargs)
    except Exception:
        logger.exception("An unexpected error was thrown calling the SLA code")


@app.task
def jira_status_reconciliation_task(*args, **kwargs):
    from dojo.management.commands.jira_status_reconciliation import jira_status_reconciliation
    return jira_status_reconciliation(*args, **kwargs)


@app.task
def fix_loop_duplicates_task(*args, **kwargs):
    from dojo.finding.helper import fix_loop_duplicates
    return fix_loop_duplicates()


@app.task
def evaluate_pro_proposition(*args, **kwargs):
    # Ensure we should be doing this
    if not settings.CREATE_CLOUD_BANNER:
        return
    # Get the announcement object
    announcement = Announcement.objects.get_or_create(id=1)[0]
    # Quick check for a user has modified the current banner - if not, exit early as we dont want to stomp
    if not any(
        entry in announcement.message
        for entry in [
            "",
            "Cloud and On-Premise Subscriptions Now Available!",
            "Findings/Endpoints in their systems",
        ]
    ):
        return
    # Count the objects the determine if the banner should be updated
    object_count = Finding.objects.count() + Endpoint.objects.count()
    # Unless the count is greater than 100k, exit early
    if object_count < 100000:
        return
    # Update the announcement
    announcement.message = f'Only professionals have {object_count:,} Findings and Endpoints in their systems... <a href="https://www.defectdojo.com/pricing" target="_blank">Get DefectDojo Pro</a> today!'
    announcement.save()


@app.task
def clear_sessions(*args, **kwargs):
    call_command("clearsessions")
