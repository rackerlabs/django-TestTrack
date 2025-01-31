from datetime import datetime, timedelta
from unittest.mock import patch

from dateutil.relativedelta import relativedelta
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from dojo.models import Engagement, Finding, Risk_Acceptance, System_Settings, Test

from .dojo_test_case import DojoTestCase

User = get_user_model()


def create(when: datetime, product_id: int, titles_and_severities: list[tuple[str, str]]):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        engagement = Engagement.objects.create(product_id=product_id, target_start=when.date(), target_end=when.date())
        test = Test.objects.create(engagement=engagement, test_type_id=120, target_start=when, target_end=when)
        Finding.objects.bulk_create(
            (Finding(title=title, test=test, severity=severity, verified=False)
             for title, severity in titles_and_severities),
        )


def create_with_duplicates(when: datetime, product_id: int, titles_and_severities: list[tuple[str, str]]):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        engagement = Engagement.objects.create(product_id=product_id, target_start=when.date(), target_end=when.date())
        test = Test.objects.create(engagement=engagement, test_type_id=120, target_start=when, target_end=when)
        originals = Finding.objects.filter(test__engagement__product_id=product_id, duplicate=False,
                                           title__in=[title for title, _ in titles_and_severities])
        originals_map = {original.title: original for original in originals}
        Finding.objects.bulk_create(
            (Finding(title=title, test=test, severity=severity, verified=False,
                     duplicate=(title in originals_map), duplicate_finding=originals_map.get(title))
             for title, severity in titles_and_severities),
        )


def mitigate(when: datetime, product_id: int, title: str):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        Finding.objects.filter(test__engagement__product_id=product_id, title=title).update(is_mitigated=True, mitigated=when)


def accept(when: datetime, product_id: int, title: str):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        findings = Finding.objects.filter(test__engagement__product_id=product_id, title=title)
        ra = Risk_Acceptance.objects.create(name="My Risk Acceptance", owner_id=1)
        ra.accepted_findings.add(*findings)
        findings.update(risk_accepted=True)


def verify(when: datetime, product_id: int, title: str):
    with patch("django.db.models.fields.timezone.now") as mock_now:
        mock_now.return_value = when
        Finding.objects.filter(test__engagement__product_id=product_id, title=title).update(verified=True)


class TestDashboard(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.now = timezone.now()
        cls.week_ago = cls.now - timedelta(weeks=1)
        cls.month_ago = cls.now - relativedelta(months=1)
        cls.year_ago = cls.now - relativedelta(years=1)

    @classmethod
    def setUpTestData(cls) -> None:
        System_Settings.objects.update(enable_deduplication=False)  # The default deduplication does not work.
        Engagement.objects.all().delete()

    def _setup_test_counters_findings(self, product_id: int):
        when = self.week_ago
        create(when, product_id, [
            ("My Findind 1.1", "Medium"),
            ("My Findind 1.2", "Medium"),
            ("My Findind 1.3", "Medium"),
            ("My Findind 1.4", "Medium"),
            ("My Findind 1.5", "Medium"),
            ("My Findind 1.6", "Medium"),
            ("My Findind 1.7", "Medium"),
        ])
        mitigate(when, product_id, "My Findind 1.1")
        accept  (when, product_id, "My Findind 1.2")  # noqa: E211
        verify  (when, product_id, "My Findind 1.3")  # noqa: E211

        when = self.now
        create(when, product_id, [
            ("My Findind 2.1", "Medium"),
            ("My Findind 2.2", "Medium"),
            ("My Findind 2.3", "Medium"),
            ("My Findind 2.4", "Medium"),
        ])
        create_with_duplicates(when, product_id, [
            ("My Findind 2.1", "Medium"),
            ("My Findind 2.2", "Medium"),
            ("My Findind 2.3", "Medium"),
            ("My Findind 2.4", "Medium"),
        ])
        mitigate(when, product_id, "My Findind 1.4")
        accept  (when, product_id, "My Findind 1.5")  # noqa: E211
        verify  (when, product_id, "My Findind 1.6")  # noqa: E211
        mitigate(when, product_id, "My Findind 2.1")
        accept  (when, product_id, "My Findind 2.2")  # noqa: E211
        verify  (when, product_id, "My Findind 2.3")  # noqa: E211

    def test_counters_as_staff(self):
        self._setup_test_counters_findings(product_id=2)

        response = self._request("admin")

        self.assertEqual(3, response.context["engagement_count"])
        self.assertEqual(11, response.context["finding_count"])
        self.assertEqual(3, response.context["mitigated_count"])
        self.assertEqual(3, response.context["accepted_count"])

    def test_counters_as_user(self):
        self._setup_test_counters_findings(product_id=2)
        self._setup_test_counters_findings(product_id=3)

        response = self._request("user1")

        self.assertEqual(3, response.context["engagement_count"])
        self.assertEqual(11, response.context["finding_count"])
        self.assertEqual(3, response.context["mitigated_count"])
        self.assertEqual(3, response.context["accepted_count"])

    def _setup_test_charts_findings(self, product_id: int):
        when = self.year_ago
        create(when, product_id, [
            ("My Findind 0.1", "Medium"),
        ])

        when = self.month_ago
        create(when, product_id, [
            ("My Findind 1.1", "Critical"),
            ("My Findind 1.2", "High"),
            ("My Findind 1.3", "Medium"),
            ("My Findind 1.4", "Low"),
            ("My Findind 1.5", "Info"),
            ("My Findind 1.6", ""),
            ("My Findind 1.7", "Foo"),
        ])
        create_with_duplicates(when, product_id, [
            ("My Findind 1.3", "Medium"),
        ])

        when = self.now
        create(when, product_id, [
            ("My Findind 2.1", "Critical"),
        ])

    def test_charts_as_staff(self):
        self._setup_test_charts_findings(product_id=2)

        response = self._request("admin")

        self.assertEqual(2, response.context["critical"])
        self.assertEqual(1, response.context["high"])
        self.assertEqual(2, response.context["medium"])
        self.assertEqual(1, response.context["low"])
        self.assertEqual(1, response.context["info"])

        expected = [
            {"y": f"{self.month_ago.year}-{self.month_ago.month:02}", "a": 1, "b": 1, "c": 1, "d": 1, "e": 1, None: 2},
            {"y": f"{self.now.year}-{self.now.month:02}",             "a": 1, "b": 0, "c": 0, "d": 0, "e": 0, None: 0},  # noqa: E241
        ]
        self.assertEqual(expected, response.context["by_month"])

    def test_charts_as_user(self):
        self._setup_test_charts_findings(product_id=2)
        self._setup_test_charts_findings(product_id=3)

        response = self._request("user1")

        self.assertEqual(2, response.context["critical"])
        self.assertEqual(1, response.context["high"])
        self.assertEqual(2, response.context["medium"])
        self.assertEqual(1, response.context["low"])
        self.assertEqual(1, response.context["info"])

        expected = [
            {"y": f"{self.month_ago.year}-{self.month_ago.month:02}", "a": 1, "b": 1, "c": 1, "d": 1, "e": 1, None: 2},
            {"y": f"{self.now.year}-{self.now.month:02}",             "a": 1, "b": 0, "c": 0, "d": 0, "e": 0, None: 0},  # noqa: E241
        ]
        self.assertEqual(expected, response.context["by_month"])

    def _request(self, username: str):
        user = User.objects.get(username=username)
        self.client.force_login(user)
        return self.client.get(reverse("dashboard"))
