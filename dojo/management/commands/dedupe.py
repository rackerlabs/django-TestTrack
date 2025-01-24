import logging

from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Finding, Product
from dojo.utils import (
    calculate_grade,
    do_dedupe_finding,
    do_dedupe_finding_task,
    get_system_setting,
    mass_model_updater,
)

locale = timezone(get_system_setting("time_zone"))

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def generate_hash_code(f):
    old_hash_code = f.hash_code
    f.hash_code = f.compute_hash_code()
    if f.hash_code != old_hash_code:
        logger.debug("%d: hash_code changed from %s to %s", f.id, old_hash_code, f.hash_code)
    return f


class Command(BaseCommand):

    """
    Updates hash codes and/or runs deduplication for findings. Hashcode calculation always runs in the foreground, dedupe by default runs in the background.
    Usage: manage.py dedupe [--parser "Parser1 Scan" --parser "Parser2 Scan"...] [--hash_code_only] [--dedupe_only] [--dedupe_sync]'
    """

    help = 'Usage: manage.py dedupe [--parser "Parser1 Scan" --parser "Parser2 Scan"...] [--hash_code_only] [--dedupe_only] [--dedupe_sync]'

    def add_arguments(self, parser):
        parser.add_argument(
            "--parser",
            dest="parser",
            action="append",
            help="""List of parsers for which hash_code needs recomputing (defaults to all parsers)""",
        )

        parser.add_argument("--hash_code_only", action="store_true", help="Only compute hash codes")
        parser.add_argument("--dedupe_only", action="store_true", help="Only run deduplication")
        parser.add_argument("--dedupe_sync", action="store_true", help="Run dedupe in the foreground, default false")

    def handle(self, *args, **options):
        restrict_to_parsers = options["parser"]
        hash_code_only = options["hash_code_only"]
        dedupe_only = options["dedupe_only"]
        dedupe_sync = options["dedupe_sync"]

        if restrict_to_parsers is not None:
            findings = Finding.objects.filter(test__test_type__name__in=restrict_to_parsers)
            logger.info("######## Will process only parsers %s and %d findings ########", *restrict_to_parsers, findings.count())
        else:
            # add filter on id to make counts not slow on mysql
            findings = Finding.objects.all().filter(id__gt=0)
            logger.info("######## Will process the full database with %d findings ########", findings.count())

        # Phase 1: update hash_codes without deduplicating
        if not dedupe_only:
            logger.info("######## Start Updating Hashcodes (foreground) ########")

            # only prefetch here for hash_code calculation
            finds = findings.prefetch_related("endpoints", "test__test_type")
            mass_model_updater(Finding, finds, generate_hash_code, fields=["hash_code"], order="asc", log_prefix="hash_code computation ")

            logger.info("######## Done Updating Hashcodes########")

        # Phase 2: deduplicate synchronously
        if not hash_code_only:
            if get_system_setting("enable_deduplication"):
                logger.info("######## Start deduplicating (%s) ########", ("foreground" if dedupe_sync else "background"))
                if dedupe_sync:
                    mass_model_updater(Finding, findings, do_dedupe_finding, fields=None, order="desc", page_size=100, log_prefix="deduplicating ")
                else:
                    # async tasks only need the id
                    mass_model_updater(Finding, findings.only("id"), lambda f: do_dedupe_finding_task(f.id), fields=None, order="desc", log_prefix="deduplicating ")

                # update the grading (if enabled)
                logger.debug("Updating grades for products...")
                for product in Product.objects.all():
                    calculate_grade(product)

                logger.info("######## Done deduplicating (%s) ########", ("foreground" if dedupe_sync else "tasks submitted to celery"))
            else:
                logger.debug("skipping dedupe because it's disabled in system settings")
