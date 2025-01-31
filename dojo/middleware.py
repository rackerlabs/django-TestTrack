import logging
import re
from contextlib import suppress
from threading import local
from urllib.parse import quote

from auditlog.context import set_actor
from auditlog.middleware import AuditlogMiddleware as _AuditlogMiddleware
from django.conf import settings
from django.db import models
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.functional import SimpleLazyObject

logger = logging.getLogger(__name__)

EXEMPT_URLS = [re.compile(settings.LOGIN_URL.lstrip("/"))]
if hasattr(settings, "LOGIN_EXEMPT_URLS"):
    EXEMPT_URLS += [re.compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]


class LoginRequiredMiddleware:

    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """

    def __init__(self, get_response):

        self.get_response = get_response

    def __call__(self, request):
        if not hasattr(request, "user"):
            msg = (
                "The Login Required middleware "
                "requires authentication middleware to be installed. Edit your "
                "MIDDLEWARE_CLASSES setting to insert "
                "'django.contrib.auth.middleware.AuthenticationMiddleware'. If that doesn't "
                "work, ensure your TEMPLATE_CONTEXT_PROCESSORS setting includes "
                "'django.core.context_processors.auth'."
            )
            raise AttributeError(msg)
        if not request.user.is_authenticated:
            path = request.path_info.lstrip("/")
            if not any(m.match(path) for m in EXEMPT_URLS):
                if path == "logout":
                    fullURL = f"{settings.LOGIN_URL}?next=/"
                else:
                    fullURL = f"{settings.LOGIN_URL}?next={quote(request.get_full_path())}"
                return HttpResponseRedirect(fullURL)

        if request.user.is_authenticated:
            logger.debug("Authenticated user: %s", str(request.user))
            with suppress(ModuleNotFoundError):  # to avoid unittests to fail
                uwsgi = __import__("uwsgi", globals(), locals(), ["set_logvar"], 0)
                # this populates dd_user log var, so can appear in the uwsgi logs
                uwsgi.set_logvar("dd_user", str(request.user))
            path = request.path_info.lstrip("/")
            from dojo.models import Dojo_User
            if Dojo_User.force_password_reset(request.user) and path != "change_password":
                return HttpResponseRedirect(reverse("change_password"))

        return self.get_response(request)


class DojoSytemSettingsMiddleware:
    _thread_local = local()

    def __init__(self, get_response):
        self.get_response = get_response
        # avoid circular imports
        from dojo.models import System_Settings
        models.signals.post_save.connect(self.cleanup, sender=System_Settings)

    def __call__(self, request):
        self.load()
        response = self.get_response(request)
        self.cleanup()
        return response

    def process_exception(self, request, exception):
        self.cleanup()

    @classmethod
    def get_system_settings(cls):
        if hasattr(cls._thread_local, "system_settings"):
            return cls._thread_local.system_settings

        return None

    @classmethod
    def cleanup(cls, *args, **kwargs):  # noqa: ARG003
        if hasattr(cls._thread_local, "system_settings"):
            del cls._thread_local.system_settings

    @classmethod
    def load(cls):
        from dojo.models import System_Settings
        system_settings = System_Settings.objects.get(no_cache=True)
        cls._thread_local.system_settings = system_settings
        return system_settings


class System_Settings_Manager(models.Manager):

    def get_from_db(self, *args, **kwargs):
        # logger.debug('refreshing system_settings from db')
        try:
            from_db = super().get(*args, **kwargs)
        except:
            from dojo.models import System_Settings
            # this mimics the existing code that was in filters.py and utils.py.
            # cases I have seen triggering this is for example manage.py collectstatic inside a docker build where mysql is not available
            # logger.debug('unable to get system_settings from database, constructing (new) default instance. Exception was:', exc_info=True)
            return System_Settings()
        return from_db

    def get(self, no_cache=False, *args, **kwargs):  # noqa: FBT002 - this is bit hard to fix nice have this universally fixed
        if no_cache:
            # logger.debug('no_cache specified or cached value found, loading system settings from db')
            return self.get_from_db(*args, **kwargs)

        from_cache = DojoSytemSettingsMiddleware.get_system_settings()

        if not from_cache:
            # logger.debug('no cached value found, loading system settings from db')
            return self.get_from_db(*args, **kwargs)

        return from_cache


class APITrailingSlashMiddleware:

    """
    Middleware that will send a more informative error response to POST requests
    made without the trailing slash. When this middleware is not active, POST requests
    without the trailing slash will return a 301 status code, with no explanation as to why
    """

    def __init__(self, get_response):

        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        path = request.path_info.lstrip("/")
        if request.method == "POST" and "api/v2/" in path and path[-1] != "/" and response.status_code == 400:
            response.data = {"message": "Please add a trailing slash to your request."}
            # you need to change private attribute `_is_render`
            # to call render second time
            response._is_rendered = False
            response.render()
        return response


class AdditionalHeaderMiddleware:

    """Middleware that will add an arbitray amount of HTTP Request headers toall requests."""

    def __init__(self, get_response):

        self.get_response = get_response

    def __call__(self, request):
        request.META.update(settings.ADDITIONAL_HEADERS)
        return self.get_response(request)


# This solution comes from https://github.com/jazzband/django-auditlog/issues/115#issuecomment-1539262735
# It fix situation when TokenAuthentication is used in API. Otherwise, actor in AuditLog would be set to None
class AuditlogMiddleware(_AuditlogMiddleware):
    def __call__(self, request):
        remote_addr = self._get_remote_addr(request)

        user = SimpleLazyObject(lambda: getattr(request, "user", None))

        context = set_actor(actor=user, remote_addr=remote_addr)

        with context:
            return self.get_response(request)
