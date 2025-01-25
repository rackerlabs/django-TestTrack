import importlib
import json
import logging
from contextlib import suppress
from datetime import timedelta

import requests
import yaml
from django.conf import settings
from django.core.exceptions import FieldDoesNotExist
from django.core.mail import EmailMessage
from django.db.models import Count, Prefetch, Q, QuerySet
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo import __version__ as dd_version
from dojo.authorization.roles_permissions import Permissions
from dojo.celery import app
from dojo.decorators import dojo_async_task, we_want_async
from dojo.models import (
    Alerts,
    Dojo_User,
    Engagement,
    Finding,
    Notification_Webhooks,
    Notifications,
    Product,
    Product_Type,
    System_Settings,
    Test,
    UserContactInfo,
    get_current_datetime,
)
from dojo.user.queries import (
    get_authorized_users_for_product_and_product_type,
    get_authorized_users_for_product_type,
)

logger = logging.getLogger(__name__)


def create_notification(
    event: str | None = None,
    title: str | None = None,
    finding: Finding | None = None,
    test: Test | None = None,
    engagement: Engagement | None = None,
    product: Product | None = None,
    requested_by: Dojo_User | None = None,
    reviewers: list[Dojo_User] | list[str] | None = None,
    recipients: list[Dojo_User] | list[str] | None = None,
    no_users: bool = False,  # noqa: FBT001
    url: str | None = None,
    url_api: str | None = None,
    **kwargs: dict,
) -> None:
    """Create an instance of a NotificationManager and dispatch the notification."""
    default_manager = NotificationManager
    notification_manager_class = default_manager
    if isinstance(
        (
            notification_manager := getattr(
                settings,
                "NOTIFICATION_MANAGER",
                default_manager,
            )
        ),
        str,
    ):
        with suppress(ModuleNotFoundError):
            module_name, _separator, class_name = notification_manager.rpartition(".")
            module = importlib.import_module(module_name)
            notification_manager_class = getattr(module, class_name)
    notification_manager_class().create_notification(
        event=event,
        title=title,
        finding=finding,
        test=test,
        engagement=engagement,
        product=product,
        requested_by=requested_by,
        reviewers=reviewers,
        recipients=recipients,
        no_users=no_users,
        url=url,
        url_api=url_api,
        **kwargs,
    )


class NotificationManagerHelpers:

    """Common functions for use in the Mangers."""

    def __init__(
        self,
        *_args: list,
        system_notifications: Notifications | None = None,
        system_settings: System_Settings | None = None,
        **_kwargs: dict,
    ) -> None:
        self.system_notifications = system_notifications or self._get_notifications_object()
        self.system_settings = system_settings or self._get_system_settings()

    def _get_notifications_object(self) -> Notifications:
        """Set the system Notifications object on the class."""
        try:
            return Notifications.objects.get(user=None, template=False)
        except Exception:
            return Notifications()

    def _get_system_settings(self) -> System_Settings:
        """Set the system settings object in the class."""
        return System_Settings.objects.get()

    def _create_description(self, event: str, kwargs: dict) -> str:
        if kwargs.get("description") is None:
            if event == "product_added":
                kwargs["description"] = _("Product %s has been created successfully.") % kwargs["title"]
            elif event == "product_type_added":
                kwargs["description"] = _("Product Type %s has been created successfully.") % kwargs["title"]
            else:
                kwargs["description"] = _("Event %s has occurred.") % str(event)

        return kwargs["description"]

    def _create_notification_message(
        self,
        event: str,
        user: Dojo_User,
        notification_type: str,
        kwargs: dict,
    ) -> str:
        template = f"notifications/{notification_type}/{event.replace('/', '')}.tpl"
        kwargs.update({"user": user})
        notification_message = None

        # TODO: This may be deleted
        # if (title := kwargs.get("title")) is not None:
        #     kwargs.update({"title": title})

        if kwargs.get("description") is None:
            kwargs.update({"description": self._create_description(event, kwargs)})

        try:
            notification_message = render_to_string(template, kwargs)
            logger.debug("Rendering from the template %s", template)
        except TemplateDoesNotExist as e:
            # In some cases, template includes another templates, if the interior one is missing, we will see it in "specifically" section
            logger.debug(
                f"template not found or not implemented yet: {template} (specifically: {e.args})",
            )
        except Exception as e:
            logger.error(
                "error during rendering of template %s exception is %s",
                template,
                e,
            )
        finally:
            if not notification_message:
                kwargs["description"] = self._create_description(event, kwargs)
                notification_message = render_to_string(
                    f"notifications/{notification_type}/other.tpl",
                    kwargs,
                )

        return notification_message or ""

    def _log_alert(
        self,
        exception: Exception,
        notification_type: str | None = None,
        **kwargs: dict,
    ) -> None:
        # no try catch here, if this fails we need to show an error
        for user in Dojo_User.objects.filter(is_superuser=True):
            alert = Alerts(
                user_id=user,
                url=kwargs.get("url", reverse("alerts")),
                title=kwargs.get("title", "Notification issue")[:250],
                description=kwargs.get("description", str(exception))[:2000],
                icon="exclamation-triangle",
                source=notification_type[:100] if notification_type else kwargs.get("source", "unknown")[:100],
            )
            # relative urls will fail validation
            alert.clean_fields(exclude=["url"])
            alert.save()


class SlackNotificationManger(NotificationManagerHelpers):

    """Manger for slack notifications and their helpers."""

    @dojo_async_task
    @app.task
    def send_slack_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        try:
            # If the user has slack information on profile and chooses to receive slack notifications
            # Will receive a DM
            if user is not None:
                logger.debug("personal notification to slack for user %s", user)
                if hasattr(user, "usercontactinfo") and user.usercontactinfo.slack_username is not None:
                    slack_user_id = user.usercontactinfo.slack_user_id
                    if not slack_user_id:
                        # Lookup the slack userid the first time, then save it.
                        slack_user_id = self._get_slack_user_id(
                            user.usercontactinfo.slack_username,
                        )
                        if slack_user_id:
                            slack_user_save = UserContactInfo.objects.get(
                                user_id=user.id,
                            )
                            slack_user_save.slack_user_id = slack_user_id
                            slack_user_save.save()
                    # only send notification if we managed to find the slack_user_id
                    if slack_user_id:
                        channel = f"@{slack_user_id}"
                        self._post_slack_message(event, user, channel, **kwargs)
                else:
                    logger.info(
                        "The user %s does not have a email address informed for Slack in profile.",
                        user,
                    )
            else:
                # System scope slack notifications, and not personal would still see this go through
                if self.system_settings.slack_channel is not None:
                    channel = self.system_settings.slack_channel
                    logger.info(
                        f"Sending system notification to system channel {channel}.",
                    )
                    self._post_slack_message(event, user, channel, **kwargs)
                else:
                    logger.debug(
                        "slack_channel not configured: skipping system notification",
                    )

        except Exception as exception:
            logger.exception("Unable to send Slack notification")
            self._log_alert(
                exception,
                "Slack Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs.get("url"),
            )

    def _get_slack_user_id(self, user_email: str) -> str:
        user_id = None
        res = requests.request(
            method="POST",
            url="https://slack.com/api/users.lookupByEmail",
            data={"token": self.system_settings.slack_token, "email": user_email},
            timeout=settings.REQUESTS_TIMEOUT,
        )

        user = json.loads(res.text)
        slack_user_is_found = False
        if user:
            if "error" in user:
                logger.error("Slack is complaining. See error message below.")
                logger.error(user)
                raise RuntimeError("Error getting user list from Slack: " + res.text)
            if "email" in user["user"]["profile"]:
                if user_email == user["user"]["profile"]["email"]:
                    if "id" in user["user"]:
                        user_id = user["user"]["id"]
                        logger.debug(f"Slack user ID is {user_id}")
                        slack_user_is_found = True
                else:
                    logger.warning(
                        f"A user with email {user_email} could not be found in this Slack workspace.",
                    )

            if not slack_user_is_found:
                logger.warning("The Slack user was not found.")

        return user_id

    def _post_slack_message(
        self,
        event: str,
        user: Dojo_User,
        channel: str,
        **kwargs: dict,
    ) -> None:
        res = requests.request(
            method="POST",
            url="https://slack.com/api/chat.postMessage",
            data={
                "token": self.system_settings.slack_token,
                "channel": channel,
                "username": self.system_settings.slack_username,
                "text": self._create_notification_message(event, user, "slack", kwargs),
            },
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if "error" in res.text:
            logger.error("Slack is complaining. See raw text below.")
            logger.error(res.text)
            raise RuntimeError("Error posting message to Slack: " + res.text)


class MSTeamsNotificationManger(NotificationManagerHelpers):

    """Manger for Microsoft Teams notifications and their helpers."""

    @dojo_async_task
    @app.task
    def send_msteams_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        try:
            # Microsoft Teams doesn't offer direct message functionality, so no MS Teams PM functionality here...
            if user is None:
                if self.system_settings.msteams_url is not None:
                    logger.debug("sending MSTeams message")
                    res = requests.request(
                        method="POST",
                        url=self.system_settings.msteams_url,
                        data=self._create_notification_message(
                            event,
                            None,
                            "msteams",
                            kwargs,
                        ),
                        timeout=settings.REQUESTS_TIMEOUT,
                    )
                    if res.status_code != 200:
                        logger.error("Error when sending message to Microsoft Teams")
                        logger.error(res.status_code)
                        logger.error(res.text)
                        raise RuntimeError(
                            "Error posting message to Microsoft Teams: " + res.text,
                        )
                else:
                    logger.info(
                        "Webhook URL for Microsoft Teams not configured: skipping system notification",
                    )
        except Exception as exception:
            logger.exception("Unable to send Microsoft Teams Notification")
            self._log_alert(
                exception,
                "Microsoft Teams Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs["url"],
            )


class EmailNotificationManger(NotificationManagerHelpers):

    """Manger for email notifications and their helpers."""

    @dojo_async_task
    @app.task
    def send_mail_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        # Attempt to get the "to" address
        if (recipient := kwargs.get("recipient")) is not None:
            address = recipient
        elif user:
            address = user.email
        else:
            address = self.system_settings.mail_notifications_to

        logger.debug("notification email for user %s to %s", user, address)

        try:
            subject = f"{self.system_settings.team_name} notification"
            if (title := kwargs.get("title")) is not None:
                subject += f": {title}"

            email = EmailMessage(
                subject,
                self._create_notification_message(event, user, "mail", kwargs),
                self.system_settings.email_from,
                [address],
                headers={"From": f"{self.system_settings.email_from}"},
            )
            email.content_subtype = "html"
            logger.debug("sending email alert")
            email.send(fail_silently=False)

        except Exception as exception:
            logger.exception("Unable to send Email Notification")
            self._log_alert(
                exception,
                "Email Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs["url"],
            )


class WebhookNotificationManger(NotificationManagerHelpers):

    """Manger for webhook notifications and their helpers."""

    ERROR_PERMANENT = "permanent"
    ERROR_TEMPORARY = "temporary"

    @dojo_async_task
    @app.task
    def send_webhooks_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        for endpoint in self._get_webhook_endpoints(user=user):
            error = None
            if endpoint.status not in [
                Notification_Webhooks.Status.STATUS_ACTIVE,
                Notification_Webhooks.Status.STATUS_ACTIVE_TMP,
            ]:
                logger.info(
                    f"URL for Webhook '{endpoint.name}' is not active: {endpoint.get_status_display()} ({endpoint.status})",
                )
                continue

            try:
                logger.debug(f"Sending webhook message to endpoint '{endpoint.name}'")
                res = self._webhooks_notification_request(endpoint, event, **kwargs)
                if 200 <= res.status_code < 300:
                    logger.debug(
                        f"Message sent to endpoint '{endpoint.name}' successfully.",
                    )
                    continue
                # HTTP request passed successfully but we still need to check status code
                if 500 <= res.status_code < 600 or res.status_code == 429:
                    error = self.ERROR_TEMPORARY
                else:
                    error = self.ERROR_PERMANENT

                endpoint.note = f"Response status code: {res.status_code}"
                logger.error(
                    f"Error when sending message to Webhooks '{endpoint.name}' (status: {res.status_code}): {res.text}",
                )
            except requests.exceptions.Timeout as e:
                error = self.ERROR_TEMPORARY
                endpoint.note = f"Requests exception: {e}"
                logger.error(
                    f"Timeout when sending message to Webhook '{endpoint.name}'",
                )
            except Exception as exception:
                error = self.ERROR_PERMANENT
                endpoint.note = f"Exception: {exception}"[:1000]
                logger.exception("Unable to send Webhooks Notification")
                self._log_alert(exception, "Webhooks Notification")

            now = get_current_datetime()
            if error == self.ERROR_TEMPORARY:
                # If endpoint is unstable for more then one day, it needs to be deactivated
                if endpoint.first_error is not None and (now - endpoint.first_error).total_seconds() > 60 * 60 * 24:
                    endpoint.status = Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT
                else:
                    # We need to monitor when outage started
                    if endpoint.status == Notification_Webhooks.Status.STATUS_ACTIVE:
                        endpoint.first_error = now
                    endpoint.status = Notification_Webhooks.Status.STATUS_INACTIVE_TMP
                    # In case of failure within one day, endpoint can be deactivated temporally only for one minute
                    self._webhook_reactivation.apply_async(
                        args=[self],
                        kwargs={"endpoint_id": endpoint.pk},
                        countdown=60,
                    )
            # There is no reason to keep endpoint active if it is returning 4xx errors
            else:
                endpoint.status = Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT
                endpoint.first_error = now

            endpoint.last_error = now
            endpoint.save()

    def _get_webhook_endpoints(
        self,
        user: Dojo_User | None = None,
    ) -> QuerySet[Notification_Webhooks]:
        endpoints = Notification_Webhooks.objects.filter(owner=user)
        if not endpoints.exists():
            if user:
                logger.info(
                    f"URLs for Webhooks not configured for user '{user}': skipping user notification",
                )
            else:
                logger.info(
                    "URLs for Webhooks not configured: skipping system notification",
                )
            return Notification_Webhooks.objects.none()
        return endpoints

    def _generate_request_details(
        self,
        endpoint: Notification_Webhooks,
        event: str | None = None,
        **kwargs: dict,
    ) -> tuple[dict, dict]:
        headers = {
            "User-Agent": f"DefectDojo-{dd_version}",
            "X-DefectDojo-Event": event,
            "X-DefectDojo-Instance": settings.SITE_URL,
            "Accept": "application/json",
        }
        if endpoint.header_name is not None:
            headers[endpoint.header_name] = endpoint.header_value
        yaml_data = self._create_notification_message(
            event,
            endpoint.owner,
            "webhooks",
            kwargs,
        )
        data = yaml.safe_load(yaml_data)

        return headers, data

    def _webhooks_notification_request(
        self,
        endpoint: Notification_Webhooks,
        event: str | None = None,
        **kwargs: dict,
    ) -> requests.Response:
        headers, data = self._generate_request_details(endpoint, event=event, **kwargs)
        return requests.request(
            method="POST",
            url=endpoint.url,
            headers=headers,
            json=data,
            timeout=self.system_settings.webhooks_notifications_timeout,
        )

    def _test_webhooks_notification(self, endpoint: Notification_Webhooks) -> None:
        res = self._webhooks_notification_request(
            endpoint,
            "ping",
            description="Test webhook notification",
        )
        res.raise_for_status()
        # in "send_webhooks_notification", we are doing deeper analysis, why it failed
        # for now, "raise_for_status" should be enough

    @app.task(ignore_result=True)
    def _webhook_reactivation(self, endpoint_id: int, **_kwargs: dict):
        endpoint = Notification_Webhooks.objects.get(pk=endpoint_id)
        # User already changed status of endpoint
        if endpoint.status != Notification_Webhooks.Status.STATUS_INACTIVE_TMP:
            return
        endpoint.status = Notification_Webhooks.Status.STATUS_ACTIVE_TMP
        endpoint.save()
        logger.debug(
            f"Webhook endpoint '{endpoint.name}' reactivated to '{Notification_Webhooks.Status.STATUS_ACTIVE_TMP}'",
        )


class AlertNotificationManger(NotificationManagerHelpers):

    """Manger for alert notifications and their helpers."""

    def send_alert_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        logger.debug("sending alert notification to %s", user)
        try:
            # no need to differentiate between user/no user
            icon = kwargs.get("icon", "info-circle")
            try:
                source = Notifications._meta.get_field(event).verbose_name.title()[:100]
            except FieldDoesNotExist:
                source = event.replace("_", " ").title()[:100]
            alert = Alerts(
                user_id=user,
                title=kwargs.get("title")[:250],
                description=self._create_notification_message(
                    event,
                    user,
                    "alert",
                    kwargs,
                )[:2000],
                url=kwargs.get("url", reverse("alerts")),
                icon=icon[:25],
                source=source,
            )
            # relative urls will fail validation
            alert.clean_fields(exclude=["url"])
            alert.save()
        except Exception as exception:
            logger.exception("Unable to create Alert Notification")
            self._log_alert(
                exception,
                "Alert Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs["url"],
            )


class NotificationManager(NotificationManagerHelpers):

    """Manage the construction and dispatch of notifications."""

    def __init__(self, *args: list, **kwargs: dict) -> None:
        NotificationManagerHelpers.__init__(self, *args, **kwargs)

    def create_notification(self, event: str | None = None, **kwargs: dict) -> None:
        # Process the notifications for a given list of recipients
        if kwargs.get("recipients") is not None:
            self._process_recipients(event=event, **kwargs)
        else:
            logger.debug("creating system notifications for event: %s", event)
            # send system notifications to all admin users
            self._process_objects(**kwargs)
            # System notifications are sent one with user=None, which will trigger email to configured system email, to global slack channel, etc.
            self._process_notifications(
                event,
                notifications=self.system_notifications,
                **kwargs,
            )
            # All admins will also receive system notifications, but as part of the person global notifications section below
            # This time user is set, so will trigger email to personal email, to personal slack channel (mention), etc.
            # only retrieve users which have at least one notification type enabled for this event type.
            logger.debug("creating personal notifications for event: %s", event)
            # There are notification like deleting a product type that shall not be sent to users.
            # These notifications will have the parameter no_users=True
            if kwargs.get("no_users", False) is False:
                # get users with either global notifications, or a product specific notification
                # and all admin/superuser, they will always be notified
                for user in self._get_user_to_send_notifications_to():
                    self._send_single_notification_to_user(user, event=event, **kwargs)

    def _process_recipients(self, event: str | None = None, **kwargs: dict) -> None:
        # mimic existing code so that when recipients is specified, no other system or personal notifications are sent.
        logger.debug("creating notifications for recipients: %s", kwargs["recipients"])
        for recipient_notifications in Notifications.objects.filter(
            user__username__in=kwargs["recipients"],
            user__is_active=True,
            product=None,
        ):
            if event in settings.NOTIFICATIONS_SYSTEM_LEVEL_TRUMP:
                # merge the system level notifications with the personal level
                # this allows for system to trump the personal
                merged_notifications = Notifications.merge_notifications_list(
                    [self.system_notifications, recipient_notifications],
                )
                merged_notifications.user = recipient_notifications.user
                logger.debug("Sent notification to %s", merged_notifications.user)
                self._process_notifications(
                    event,
                    notifications=merged_notifications,
                    **kwargs,
                )
            else:
                # Do not trump user preferences and send notifications as usual
                logger.debug("Sent notification to %s", recipient_notifications.user)
                self._process_notifications(
                    event,
                    notifications=recipient_notifications,
                    **kwargs,
                )

    def _process_objects(self, **kwargs: dict) -> None:
        """Extract the product and product type from the kwargs."""
        self.product_type: Product_Type = None
        self.product: Product = None
        if (product_type := kwargs.get("product_type")) is not None:
            self.product_type = product_type
            logger.debug("Defined product type %s", self.product_type)
        if (product := kwargs.get("product")) is not None:
            self.product = product
            logger.debug("Defined product  %s", self.product)
        elif (engagement := kwargs.get("engagement")) is not None:
            self.product = engagement.product
            logger.debug("Defined product of engagement %s", self.product)
        elif (test := kwargs.get("test")) is not None:
            self.product = test.engagement.product
            logger.debug("Defined product of test %s", self.product)
        elif (finding := kwargs.get("finding")) is not None:
            self.product = finding.test.engagement.product
            logger.debug("Defined product of finding %s", self.product)
        elif (obj := kwargs.get("obj")) is not None:
            from dojo.utils import get_product

            self.product = get_product(obj)
            logger.debug("Defined product of obj %s", self.product)

    def _get_user_to_send_notifications_to(
        self,
    ) -> QuerySet[Dojo_User]:
        """Determine the users we should send notifications to based on product and product type permissions."""
        users = (
            Dojo_User.objects.filter(is_active=True)
            .prefetch_related(
                Prefetch(
                    "notifications_set",
                    queryset=Notifications.objects.filter(
                        Q(product_id=self.product) | Q(product__isnull=True),
                    ),
                    to_attr="applicable_notifications",
                ),
            )
            .annotate(
                applicable_notifications_count=Count(
                    "notifications__id",
                    filter=Q(notifications__product_id=self.product) | Q(notifications__product__isnull=True),
                ),
            )
            .filter(Q(applicable_notifications_count__gt=0) | Q(is_superuser=True))
        )
        # only send to authorized users or admin/superusers
        logger.debug("Filtering users for the product %s", self.product)
        if self.product is not None:
            users = get_authorized_users_for_product_and_product_type(
                users,
                self.product,
                Permissions.Product_View,
            )
        elif self.product_type is not None:
            users = get_authorized_users_for_product_type(
                users,
                self.product_type,
                Permissions.Product_Type_View,
            )
        else:
            # nor product_type nor product defined, we should not make noise and send only notifications to admins
            logger.debug("Product is not specified, making it silent")
            users = users.filter(is_superuser=True)
        return users

    def _send_single_notification_to_user(
        self,
        user: Dojo_User,
        event: str | None = None,
        **kwargs: dict,
    ) -> None:
        """Send a notification to a single user."""
        logger.debug("Authorized user for the product %s", user)
        # send notifications to user after merging possible multiple notifications records (i.e. personal global + personal product)
        # kwargs.update({'user': user})
        applicable_notifications = user.applicable_notifications
        if user.is_superuser:
            # admin users get all system notifications
            logger.debug("User %s is superuser", user)
            applicable_notifications.append(self.system_notifications)

        notifications_set = Notifications.merge_notifications_list(
            applicable_notifications,
        )
        notifications_set.user = user
        self._process_notifications(event, notifications=notifications_set, **kwargs)

    def _get_manager_instance(
        self,
        alert_type: str,
    ) -> type[NotificationManagerHelpers]:
        kwargs = {
            "system_notifications": self.system_notifications,
            "system_settings": self.system_settings,
        }
        if alert_type == "slack":
            return SlackNotificationManger(**kwargs)
        if alert_type == "msteams":
            return MSTeamsNotificationManger(**kwargs)
        if alert_type == "mail":
            return EmailNotificationManger(**kwargs)
        if alert_type == "webhooks":
            return WebhookNotificationManger(**kwargs)
        if alert_type == "alert":
            return AlertNotificationManger(**kwargs)

        msg = f"Unsupported alert type: {alert_type}"
        raise TypeError(msg)

    def _process_notifications(
        self,
        event: str | None,
        notifications: Notifications | None = None,
        **kwargs: dict,
    ) -> None:
        # Quick break out if we do not have any work to do
        if not notifications:
            logger.warning("no notifications!")
            return

        logger.debug(
            "sending notification " + ("asynchronously" if we_want_async() else "synchronously"),
        )
        logger.debug("process notifications for %s", notifications.user)

        if self.system_settings.enable_slack_notifications and "slack" in getattr(
            notifications,
            event,
            getattr(notifications, "other"),
        ):
            logger.debug("Sending Slack Notification")
            self._get_manager_instance("slack").send_slack_notification(
                event,
                user=notifications.user,
                **kwargs,
            )

        if self.system_settings.enable_msteams_notifications and "msteams" in getattr(
            notifications,
            event,
            getattr(notifications, "other"),
        ):
            logger.debug("Sending MSTeams Notification")
            self._get_manager_instance("msteams").send_msteams_notification(
                event,
                user=notifications.user,
                **kwargs,
            )

        if self.system_settings.enable_mail_notifications and "mail" in getattr(
            notifications,
            event,
            getattr(notifications, "other"),
        ):
            logger.debug("Sending Mail Notification")
            self._get_manager_instance("mail").send_mail_notification(
                event,
                user=notifications.user,
                **kwargs,
            )

        if self.system_settings.enable_webhooks_notifications and "webhooks" in getattr(
            notifications,
            event,
            getattr(notifications, "other"),
        ):
            logger.debug("Sending Webhooks Notification")
            self._get_manager_instance("webhooks").send_webhooks_notification(
                event,
                user=notifications.user,
                **kwargs,
            )

        if "alert" in getattr(notifications, event, getattr(notifications, "other")):
            logger.debug(f"Sending Alert to {notifications.user}")
            self._get_manager_instance("alert").send_alert_notification(
                event,
                user=notifications.user,
                **kwargs,
            )


@app.task(ignore_result=True)
def webhook_status_cleanup(*_args: list, **_kwargs: dict):
    # If some endpoint was affected by some outage (5xx, 429, Timeout) but it was clean during last 24 hours,
    # we consider this endpoint as healthy so need to reset it
    endpoints = Notification_Webhooks.objects.filter(
        status=Notification_Webhooks.Status.STATUS_ACTIVE_TMP,
        last_error__lt=get_current_datetime() - timedelta(hours=24),
    )
    for endpoint in endpoints:
        endpoint.status = Notification_Webhooks.Status.STATUS_ACTIVE
        endpoint.first_error = None
        endpoint.last_error = None
        endpoint.note = f"Reactivation from {Notification_Webhooks.Status.STATUS_ACTIVE_TMP}"
        endpoint.save()
        logger.debug(
            f"Webhook endpoint '{endpoint.name}' reactivated from '{Notification_Webhooks.Status.STATUS_ACTIVE_TMP}' to '{Notification_Webhooks.Status.STATUS_ACTIVE}'",
        )

    # Reactivation of STATUS_INACTIVE_TMP endpoints.
    # They should reactive automatically in 60s, however in case of some unexpected event (e.g. start of whole stack),
    # endpoints should not be left in STATUS_INACTIVE_TMP state
    broken_endpoints = Notification_Webhooks.objects.filter(
        status=Notification_Webhooks.Status.STATUS_INACTIVE_TMP,
        last_error__lt=get_current_datetime() - timedelta(minutes=5),
    )
    for endpoint in broken_endpoints:
        manager = WebhookNotificationManger()
        manager._webhook_reactivation(manager, endpoint_id=endpoint.pk)
