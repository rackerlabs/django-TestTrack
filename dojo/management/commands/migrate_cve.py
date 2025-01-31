import logging

from django.core.management.base import BaseCommand

from dojo.models import (
    Finding,
    Finding_Template,
    Vulnerability_Id,
    Vulnerability_Id_Template,
)
from dojo.utils import mass_model_updater

logger = logging.getLogger(__name__)


def create_vulnerability_id(finding):
    Vulnerability_Id.objects.get_or_create(
        finding=finding, vulnerability_id=finding.cve,
    )


def create_vulnerability_id_template(finding_template):
    Vulnerability_Id_Template.objects.get_or_create(
        finding_template=finding_template, vulnerability_id=finding_template.cve,
    )


class Command(BaseCommand):

    """This management command creates vulnerability ids for all findings / findings_templates with cve's."""

    help = "Usage: manage.py migrate_cve"

    def handle(self, *args, **options):

        logger.info("Starting migration of cves for Findings")
        findings = Finding.objects.filter(cve__isnull=False)
        mass_model_updater(
            Finding,
            findings,
            create_vulnerability_id,
            fields=None,
            page_size=100,
            log_prefix="creating vulnerability ids: ",
        )

        logger.info("Starting migration of cves for Finding_Templates")
        finding_templates = Finding_Template.objects.filter(cve__isnull=False)
        mass_model_updater(
            Finding_Template,
            finding_templates,
            create_vulnerability_id_template,
            fields=None,
            page_size=100,
            log_prefix="creating vulnerability ids: ",
        )
