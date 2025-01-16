#########################################################################################################
# It is not recommended to edit file 'settings.dist.py', for production deployments.                        #
# Any customization of variables need to be done via environmental variables or in 'local_settings.py'. #
# For more information check https://documentation.defectdojo.com/getting_started/configuration/        #
#########################################################################################################

# Django settings for DefectDojo
import json
import logging
import os
import warnings
from datetime import timedelta
from email.utils import getaddresses
from pathlib import Path

import environ
from celery.schedules import crontab
from netaddr import IPNetwork, IPSet

from dojo import __version__

logger = logging.getLogger(__name__)

root = environ.Path(__file__) - 3  # Three folders back

# reference: https://pypi.org/project/django-environ/
env = environ.FileAwareEnv(
    # Set casting and default values
    DD_SITE_URL=(str, "http://localhost:8080"),
    DD_DEBUG=(bool, False),
    DD_TEMPLATE_DEBUG=(bool, False),
    DD_LOG_LEVEL=(str, ""),
    DD_DJANGO_METRICS_ENABLED=(bool, False),
    DD_LOGIN_REDIRECT_URL=(str, "/"),
    DD_LOGIN_URL=(str, "/login"),
    DD_DJANGO_ADMIN_ENABLED=(bool, True),
    DD_SESSION_COOKIE_HTTPONLY=(bool, True),
    DD_CSRF_COOKIE_HTTPONLY=(bool, True),
    DD_SECURE_SSL_REDIRECT=(bool, False),
    DD_SECURE_CROSS_ORIGIN_OPENER_POLICY=(str, "same-origin"),
    DD_SECURE_HSTS_INCLUDE_SUBDOMAINS=(bool, False),
    DD_SECURE_HSTS_SECONDS=(int, 31536000),  # One year expiration
    DD_SESSION_COOKIE_SECURE=(bool, False),
    DD_SESSION_EXPIRE_AT_BROWSER_CLOSE=(bool, False),
    DD_SESSION_COOKIE_AGE=(int, 1209600),  # 14 days
    DD_CSRF_COOKIE_SECURE=(bool, False),
    DD_CSRF_TRUSTED_ORIGINS=(list, []),
    DD_SECURE_CONTENT_TYPE_NOSNIFF=(bool, True),
    DD_CSRF_COOKIE_SAMESITE=(str, "Lax"),
    DD_SESSION_COOKIE_SAMESITE=(str, "Lax"),
    DD_APPEND_SLASH=(bool, True),
    DD_TIME_ZONE=(str, "UTC"),
    DD_LANG=(str, "en-us"),
    DD_TEAM_NAME=(str, "Security Team"),
    DD_ADMINS=(str, "DefectDojo:dojo@localhost,Admin:admin@localhost"),
    DD_WHITENOISE=(bool, False),
    DD_TRACK_MIGRATIONS=(bool, True),
    DD_SECURE_PROXY_SSL_HEADER=(bool, False),
    DD_TEST_RUNNER=(str, "django.test.runner.DiscoverRunner"),
    DD_URL_PREFIX=(str, ""),
    DD_ROOT=(str, root("dojo")),
    DD_LANGUAGE_CODE=(str, "en-us"),
    DD_SITE_ID=(int, 1),
    DD_USE_I18N=(bool, True),
    DD_USE_TZ=(bool, True),
    DD_MEDIA_URL=(str, "/media/"),
    DD_MEDIA_ROOT=(str, root("media")),
    DD_STATIC_URL=(str, "/static/"),
    DD_STATIC_ROOT=(str, root("static")),
    DD_CELERY_BROKER_URL=(str, ""),
    DD_CELERY_BROKER_SCHEME=(str, "sqla+sqlite"),
    DD_CELERY_BROKER_USER=(str, ""),
    DD_CELERY_BROKER_PASSWORD=(str, ""),
    DD_CELERY_BROKER_HOST=(str, ""),
    DD_CELERY_BROKER_PORT=(int, -1),
    DD_CELERY_BROKER_PATH=(str, "/dojo.celerydb.sqlite"),
    DD_CELERY_BROKER_PARAMS=(str, ""),
    DD_CELERY_BROKER_TRANSPORT_OPTIONS=(str, ""),
    DD_CELERY_TASK_IGNORE_RESULT=(bool, True),
    DD_CELERY_RESULT_BACKEND=(str, "django-db"),
    DD_CELERY_RESULT_EXPIRES=(int, 86400),
    DD_CELERY_BEAT_SCHEDULE_FILENAME=(str, root("dojo.celery.beat.db")),
    DD_CELERY_TASK_SERIALIZER=(str, "pickle"),
    DD_CELERY_PASS_MODEL_BY_ID=(str, True),
    DD_FOOTER_VERSION=(str, ""),
    # models should be passed to celery by ID, default is False (for now)
    DD_FORCE_LOWERCASE_TAGS=(bool, True),
    DD_MAX_TAG_LENGTH=(int, 25),
    DD_DATABASE_ENGINE=(str, "django.db.backends.postgresql"),
    DD_DATABASE_HOST=(str, "postgres"),
    DD_DATABASE_NAME=(str, "defectdojo"),
    # default django database name for testing is test_<dbname>
    DD_TEST_DATABASE_NAME=(str, "test_defectdojo"),
    DD_DATABASE_PASSWORD=(str, "defectdojo"),
    DD_DATABASE_PORT=(int, 3306),
    DD_DATABASE_USER=(str, "defectdojo"),
    DD_SECRET_KEY=(str, ""),
    DD_CREDENTIAL_AES_256_KEY=(str, "."),
    DD_DATA_UPLOAD_MAX_MEMORY_SIZE=(int, 8388608),  # Max post size set to 8mb
    DD_FORGOT_PASSWORD=(bool, True),  # do we show link "I forgot my password" on login screen
    DD_PASSWORD_RESET_TIMEOUT=(int, 259200),  # 3 days, in seconds (the deafult)
    DD_FORGOT_USERNAME=(bool, True),  # do we show link "I forgot my username" on login screen
    DD_SOCIAL_AUTH_SHOW_LOGIN_FORM=(bool, True),  # do we show user/pass input
    DD_SOCIAL_AUTH_CREATE_USER=(bool, True),  # if True creates user at first login
    DD_SOCIAL_LOGIN_AUTO_REDIRECT=(bool, False),  # auto-redirect if there is only one social login method
    DD_SOCIAL_AUTH_TRAILING_SLASH=(bool, True),
    DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_AUTH0_KEY=(str, ""),
    DD_SOCIAL_AUTH_AUTH0_SECRET=(str, ""),
    DD_SOCIAL_AUTH_AUTH0_DOMAIN=(str, ""),
    DD_SOCIAL_AUTH_AUTH0_SCOPE=(list, ["openid", "profile", "email"]),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY=(str, ""),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET=(str, ""),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS=(list, [""]),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS=(list, [""]),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY=(str, ""),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET=(str, ""),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL=(str, "https://{your-org-url}/oauth2"),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY=(str, ""),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET=(str, ""),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID=(str, ""),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE=(str, "https://graph.microsoft.com/"),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS=(bool, False),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GROUPS_FILTER=(str, ""),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS=(bool, True),
    DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT=(bool, False),
    DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_TAGS=(bool, False),
    DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_URL=(bool, False),
    DD_SOCIAL_AUTH_GITLAB_PROJECT_MIN_ACCESS_LEVEL=(int, 20),
    DD_SOCIAL_AUTH_GITLAB_KEY=(str, ""),
    DD_SOCIAL_AUTH_GITLAB_SECRET=(str, ""),
    DD_SOCIAL_AUTH_GITLAB_API_URL=(str, "https://gitlab.com"),
    DD_SOCIAL_AUTH_GITLAB_SCOPE=(list, ["read_user", "openid", "read_api", "read_repository"]),
    DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_KEYCLOAK_KEY=(str, ""),
    DD_SOCIAL_AUTH_KEYCLOAK_SECRET=(str, ""),
    DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY=(str, ""),
    DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL=(str, ""),
    DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL=(str, ""),
    DD_SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT=(str, "Login with Keycloak"),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_URL=(str, ""),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL=(str, ""),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY=(str, ""),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET=(str, ""),
    DD_SAML2_ENABLED=(bool, False),
    # Allows to override default SAML authentication backend. Check https://djangosaml2.readthedocs.io/contents/setup.html#custom-user-attributes-processing
    DD_SAML2_AUTHENTICATION_BACKENDS=(str, "djangosaml2.backends.Saml2Backend"),
    # Force Authentication to make SSO possible with SAML2
    DD_SAML2_FORCE_AUTH=(bool, True),
    DD_SAML2_LOGIN_BUTTON_TEXT=(str, "Login with SAML"),
    # Optional: display the idp SAML Logout URL in DefectDojo
    DD_SAML2_LOGOUT_URL=(str, ""),
    # Metadata is required for SAML, choose either remote url or local file path
    DD_SAML2_METADATA_AUTO_CONF_URL=(str, ""),
    DD_SAML2_METADATA_LOCAL_FILE_PATH=(str, ""),  # ex. '/public/share/idp_metadata.xml'
    # Optional, default is SITE_URL + /saml2/metadata/
    DD_SAML2_ENTITY_ID=(str, ""),
    # Allow to create user that are not already in the Django database
    DD_SAML2_CREATE_USER=(bool, False),
    DD_SAML2_ATTRIBUTES_MAP=(dict, {
        # Change Email/UserName/FirstName/LastName to corresponding SAML2 userprofile attributes.
        # format: SAML attrib:django_user_model
        "Email": "email",
        "UserName": "username",
        "Firstname": "first_name",
        "Lastname": "last_name",
    }),
    DD_SAML2_ALLOW_UNKNOWN_ATTRIBUTE=(bool, False),
    # Authentication via HTTP Proxy which put username to HTTP Header REMOTE_USER
    DD_AUTH_REMOTEUSER_ENABLED=(bool, False),
    # Names of headers which will be used for processing user data.
    # WARNING: Possible spoofing of headers. Read Warning in https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#configuration
    DD_AUTH_REMOTEUSER_USERNAME_HEADER=(str, "REMOTE_USER"),
    DD_AUTH_REMOTEUSER_EMAIL_HEADER=(str, ""),
    DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER=(str, ""),
    DD_AUTH_REMOTEUSER_LASTNAME_HEADER=(str, ""),
    DD_AUTH_REMOTEUSER_GROUPS_HEADER=(str, ""),
    DD_AUTH_REMOTEUSER_GROUPS_CLEANUP=(bool, True),
    # Comma separated list of IP ranges with trusted proxies
    DD_AUTH_REMOTEUSER_TRUSTED_PROXY=(list, ["127.0.0.1/32"]),
    # REMOTE_USER will be processed only on login page. Check https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#using-remote-user-on-login-pages-only
    DD_AUTH_REMOTEUSER_LOGIN_ONLY=(bool, False),
    # `RemoteUser` is usually used behind AuthN proxy and users should not know about this mechanism from Swagger because it is not usable by users.
    # It should be hidden by default.
    DD_AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER=(bool, False),
    # if somebody is using own documentation how to use DefectDojo in his own company
    DD_DOCUMENTATION_URL=(str, "https://documentation.defectdojo.com"),
    # merging findings doesn't always work well with dedupe and reimport etc.
    # disable it if you see any issues (and report them on github)
    DD_DISABLE_FINDING_MERGE=(bool, False),
    # SLA Notifications via alerts and JIRA comments
    # enable either DD_SLA_NOTIFY_ACTIVE or DD_SLA_NOTIFY_ACTIVE_VERIFIED_ONLY to enable the feature.
    # If desired you can enable to only notify for Findings that are linked to JIRA issues.
    # All three flags are moved to system_settings, will be removed from settings file
    DD_SLA_NOTIFY_ACTIVE=(bool, False),
    DD_SLA_NOTIFY_ACTIVE_VERIFIED_ONLY=(bool, False),
    DD_SLA_NOTIFY_WITH_JIRA_ONLY=(bool, False),
    # finetuning settings for when enabled
    DD_SLA_NOTIFY_PRE_BREACH=(int, 3),
    DD_SLA_NOTIFY_POST_BREACH=(int, 7),
    # Use business day's to calculate SLA's and age instead of calendar days
    DD_SLA_BUSINESS_DAYS=(bool, False),
    # maximum number of result in search as search can be an expensive operation
    DD_SEARCH_MAX_RESULTS=(int, 100),
    DD_SIMILAR_FINDINGS_MAX_RESULTS=(int, 25),
    # The maximum number of request/response pairs to return from the API. Values <0 return all pairs.
    DD_MAX_REQRESP_FROM_API=(int, -1),
    DD_MAX_AUTOCOMPLETE_WORDS=(int, 20000),
    DD_JIRA_SSL_VERIFY=(bool, True),
    # You can set extra Jira issue types via a simple env var that supports a csv format, like "Work Item,Vulnerability"
    DD_JIRA_EXTRA_ISSUE_TYPES=(str, ""),
    # if you want to keep logging to the console but in json format, change this here to 'json_console'
    DD_LOGGING_HANDLER=(str, "console"),
    # If true, drf-spectacular will load CSS & JS from default CDN, otherwise from static resources
    DD_DEFAULT_SWAGGER_UI=(bool, False),
    DD_ALERT_REFRESH=(bool, True),
    DD_DISABLE_ALERT_COUNTER=(bool, False),
    # to disable deleting alerts per user set value to -1
    DD_MAX_ALERTS_PER_USER=(int, 999),
    DD_TAG_PREFETCHING=(bool, True),
    DD_QUALYS_WAS_WEAKNESS_IS_VULN=(bool, False),
    # regular expression to exclude one or more parsers
    # could be usefull to limit parser allowed
    # AWS Scout2 Scan Parser is deprecated (see https://github.com/DefectDojo/django-DefectDojo/pull/5268)
    DD_PARSER_EXCLUDE=(str, ""),
    # when enabled in sytem settings,  every minute a job run to delete excess duplicates
    # we limit the amount of duplicates that can be deleted in a single run of that job
    # to prevent overlapping runs of that job from occurrring
    DD_DUPE_DELETE_MAX_PER_RUN=(int, 200),
    # when enabled 'mitigated date' and 'mitigated by' of a finding become editable
    DD_EDITABLE_MITIGATED_DATA=(bool, False),
    # new feature that tracks history across multiple reimports for the same test
    DD_TRACK_IMPORT_HISTORY=(bool, True),
    # Delete Auditlogs older than x month; -1 to keep all logs
    DD_AUDITLOG_FLUSH_RETENTION_PERIOD=(int, -1),
    # Allow grouping of findings in the same test, for example to group findings per dependency
    # DD_FEATURE_FINDING_GROUPS feature is moved to system_settings, will be removed from settings file
    DD_FEATURE_FINDING_GROUPS=(bool, True),
    DD_JIRA_TEMPLATE_ROOT=(str, "dojo/templates/issue-trackers"),
    DD_TEMPLATE_DIR_PREFIX=(str, "dojo/templates/"),
    # Initial behaviour in Defect Dojo was to delete all duplicates when an original was deleted
    # New behaviour is to leave the duplicates in place, but set the oldest of duplicates as new original
    # Set to True to revert to the old behaviour where all duplicates are deleted
    DD_DUPLICATE_CLUSTER_CASCADE_DELETE=(str, False),
    # Enable Rate Limiting for the login page
    DD_RATE_LIMITER_ENABLED=(bool, False),
    # Examples include 5/m 100/h and more https://django-ratelimit.readthedocs.io/en/stable/rates.html#simple-rates
    DD_RATE_LIMITER_RATE=(str, "5/m"),
    # Block the requests after rate limit is exceeded
    DD_RATE_LIMITER_BLOCK=(bool, False),
    # Forces the user to change password on next login.
    DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, False),
    # when enabled SonarQube API parser will download the security hotspots
    DD_SONARQUBE_API_PARSER_HOTSPOTS=(bool, True),
    # when enabled, finding importing will occur asynchronously, default False
    DD_ASYNC_FINDING_IMPORT=(bool, False),
    # The number of findings to be processed per celeryworker
    DD_ASYNC_FINDING_IMPORT_CHUNK_SIZE=(int, 100),
    # When enabled, deleting objects will be occur from the bottom up. In the example of deleting an engagement
    # The objects will be deleted as follows Endpoints -> Findings -> Tests -> Engagement
    DD_ASYNC_OBJECT_DELETE=(bool, False),
    # The number of objects to be deleted per celeryworker
    DD_ASYNC_OBEJECT_DELETE_CHUNK_SIZE=(int, 100),
    # When enabled, display the preview of objects to be deleted. This can take a long time to render
    # for very large objects
    DD_DELETE_PREVIEW=(bool, True),
    # List of acceptable file types that can be uploaded to a given object via arbitrary file upload
    DD_FILE_UPLOAD_TYPES=(list, [".txt", ".pdf", ".json", ".xml", ".csv", ".yml", ".png", ".jpeg",
                                 ".sarif", ".xlsx", ".doc", ".html", ".js", ".nessus", ".zip", ".fpr"]),
    # Max file size for scan added via API in MB
    DD_SCAN_FILE_MAX_SIZE=(int, 100),
    # When disabled, existing user tokens will not be removed but it will not be
    # possible to create new and it will not be possible to use exising.
    DD_API_TOKENS_ENABLED=(bool, True),
    # Enable endpoint which allow user to get API token when user+pass is provided
    # It is useful to disable when non-local authentication (like SAML, Azure, ...) is in place
    DD_API_TOKEN_AUTH_ENDPOINT_ENABLED=(bool, True),
    # You can set extra Jira headers by suppling a dictionary in header: value format (pass as env var like "headr_name=value,another_header=anohter_value")
    DD_ADDITIONAL_HEADERS=(dict, {}),
    # Set fields used by the hashcode generator for deduplication, via en env variable that contains a JSON string
    DD_HASHCODE_FIELDS_PER_SCANNER=(str, ""),
    # Set deduplication algorithms per parser, via en env variable that contains a JSON string
    DD_DEDUPLICATION_ALGORITHM_PER_PARSER=(str, ""),
    # Dictates whether cloud banner is created or not
    DD_CREATE_CLOUD_BANNER=(bool, True),
    # With this setting turned on, Dojo maintains an audit log of changes made to entities (Findings, Tests, Engagements, Procuts, ...)
    # If you run big import you may want to disable this because the way django-auditlog currently works, there's
    # a big performance hit. Especially during (re-)imports.
    DD_ENABLE_AUDITLOG=(bool, True),
    # Specifies whether the "first seen" date of a given report should be used over the "last seen" date
    DD_USE_FIRST_SEEN=(bool, False),
    # When set to True, use the older version of the qualys parser that is a more heavy handed in setting severity
    # with the use of CVSS scores to potentially override the severity found in the report produced by the tool
    DD_QUALYS_LEGACY_SEVERITY_PARSING=(bool, True),
    # Use System notification settings to override user's notification settings
    DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP=(list, ["user_mentioned", "review_requested"]),
    # When enabled, force the password field to be required for creating/updating users
    DD_REQUIRE_PASSWORD_ON_USER=(bool, True),
    # For HTTP requests, how long connection is open before timeout
    # This settings apply only on requests performed by "requests" lib used in Dojo code (if some included lib is using "requests" as well, this does not apply there)
    DD_REQUESTS_TIMEOUT=(int, 30),
)


def generate_url(scheme, double_slashes, user, password, host, port, path, params):
    result_list = []
    result_list.extend((scheme, ":"))
    if double_slashes:
        result_list.append("//")
    result_list.append(user)
    if len(password) > 0:
        result_list.extend((":", password))
    if len(user) > 0 or len(password) > 0:
        result_list.append("@")
    result_list.append(host)
    if port >= 0:
        result_list.extend((":", str(port)))
    if len(path) > 0 and path[0] != "/":
        result_list.append("/")
    result_list.append(path)
    if len(params) > 0 and params[0] != "?":
        result_list.append("?")
    result_list.append(params)
    return "".join(result_list)


# Read .env file as default or from the command line, DD_ENV_PATH
if Path(root("dojo/settings/.env.prod")).is_file() or "DD_ENV_PATH" in os.environ:
    env.read_env(root("dojo/settings/" + env.str("DD_ENV_PATH", ".env.prod")))

# ------------------------------------------------------------------------------
# GENERAL
# ------------------------------------------------------------------------------

# False if not in os.environ
DEBUG = env("DD_DEBUG")
TEMPLATE_DEBUG = env("DD_TEMPLATE_DEBUG")

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/2.0/ref/settings/#allowed-hosts
SITE_URL = env("DD_SITE_URL")
ALLOWED_HOSTS = tuple(env.list("DD_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"]))

# Raises django's ImproperlyConfigured exception if SECRET_KEY not in os.environ
SECRET_KEY = env("DD_SECRET_KEY")

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = env("DD_TIME_ZONE")

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = env("DD_LANGUAGE_CODE")

SITE_ID = env("DD_SITE_ID")

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = env("DD_USE_I18N")

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = env("DD_USE_TZ")

TEST_RUNNER = env("DD_TEST_RUNNER")

ALERT_REFRESH = env("DD_ALERT_REFRESH")
DISABLE_ALERT_COUNTER = env("DD_DISABLE_ALERT_COUNTER")
MAX_ALERTS_PER_USER = env("DD_MAX_ALERTS_PER_USER")

TAG_PREFETCHING = env("DD_TAG_PREFETCHING")

# ------------------------------------------------------------------------------
# DATABASE
# ------------------------------------------------------------------------------

# Parse database connection url strings like psql://user:pass@127.0.0.1:8458/db
if os.getenv("DD_DATABASE_URL") is not None:
    DATABASES = {
        "default": env.db("DD_DATABASE_URL"),
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": env("DD_DATABASE_ENGINE"),
            "NAME": env("DD_DATABASE_NAME"),
            "TEST": {
                "NAME": env("DD_TEST_DATABASE_NAME"),
            },
            "USER": env("DD_DATABASE_USER"),
            "PASSWORD": env("DD_DATABASE_PASSWORD"),
            "HOST": env("DD_DATABASE_HOST"),
            "PORT": env("DD_DATABASE_PORT"),
        },
    }

# Track migrations through source control rather than making migrations locally
if env("DD_TRACK_MIGRATIONS"):
    MIGRATION_MODULES = {"dojo": "dojo.db_migrations"}

# Default for automatically created id fields,
# see https://docs.djangoproject.com/en/3.2/releases/3.2/#customizing-type-of-auto-created-primary-keys
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# ------------------------------------------------------------------------------
# MEDIA
# ------------------------------------------------------------------------------

DOJO_ROOT = env("DD_ROOT")

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = env("DD_MEDIA_ROOT")

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = env("DD_MEDIA_URL")

# ------------------------------------------------------------------------------
# STATIC
# ------------------------------------------------------------------------------

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = env("DD_STATIC_ROOT")

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = env("DD_STATIC_URL")

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    os.path.join(Path(DOJO_ROOT).parent, "components", "node_modules"),
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
)

FILE_UPLOAD_HANDLERS = (
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
)

DATA_UPLOAD_MAX_MEMORY_SIZE = env("DD_DATA_UPLOAD_MAX_MEMORY_SIZE")

# ------------------------------------------------------------------------------
# URLS
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#root-urlconf

# AUTHENTICATION_BACKENDS = [
# 'axes.backends.AxesModelBackend',
# ]

ROOT_URLCONF = "dojo.urls"

# Python dotted path to the WSGI application used by Django's runserver.
# https://docs.djangoproject.com/en/dev/ref/settings/#wsgi-application
WSGI_APPLICATION = "dojo.wsgi.application"

URL_PREFIX = env("DD_URL_PREFIX")

# ------------------------------------------------------------------------------
# AUTHENTICATION
# ------------------------------------------------------------------------------

LOGIN_REDIRECT_URL = env("DD_LOGIN_REDIRECT_URL")
LOGIN_URL = env("DD_LOGIN_URL")

# These are the individidual modules supported by social-auth
AUTHENTICATION_BACKENDS = (
    "social_core.backends.auth0.Auth0OAuth2",
    "social_core.backends.google.GoogleOAuth2",
    "social_core.backends.okta.OktaOAuth2",
    "social_core.backends.azuread_tenant.AzureADTenantOAuth2",
    "social_core.backends.gitlab.GitLabOAuth2",
    "social_core.backends.keycloak.KeycloakOAuth2",
    "social_core.backends.github_enterprise.GithubEnterpriseOAuth2",
    "dojo.remote_user.RemoteUserBackend",
    "django.contrib.auth.backends.RemoteUserBackend",
    "django.contrib.auth.backends.ModelBackend",
)

# Make Argon2 the default password hasher by listing it first
# Unfortunately Django doesn't provide the default built-in
# PASSWORD_HASHERS list here as a variable which we could modify,
# so we have to list all the hashers present in Django :-(
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.BCryptPasswordHasher",
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

SOCIAL_AUTH_PIPELINE = (
    "social_core.pipeline.social_auth.social_details",
    "dojo.pipeline.social_uid",
    "social_core.pipeline.social_auth.auth_allowed",
    "social_core.pipeline.social_auth.social_user",
    "social_core.pipeline.user.get_username",
    "social_core.pipeline.social_auth.associate_by_email",
    "dojo.pipeline.create_user",
    "dojo.pipeline.modify_permissions",
    "social_core.pipeline.social_auth.associate_user",
    "social_core.pipeline.social_auth.load_extra_data",
    "social_core.pipeline.user.user_details",
    "dojo.pipeline.update_azure_groups",
    "dojo.pipeline.update_product_access",
)

CLASSIC_AUTH_ENABLED = True
FORGOT_PASSWORD = env("DD_FORGOT_PASSWORD")
REQUIRE_PASSWORD_ON_USER = env("DD_REQUIRE_PASSWORD_ON_USER")
FORGOT_USERNAME = env("DD_FORGOT_USERNAME")
PASSWORD_RESET_TIMEOUT = env("DD_PASSWORD_RESET_TIMEOUT")
# Showing login form (form is not needed for external auth: OKTA, Google Auth, etc.)
SHOW_LOGIN_FORM = env("DD_SOCIAL_AUTH_SHOW_LOGIN_FORM")
SOCIAL_LOGIN_AUTO_REDIRECT = env("DD_SOCIAL_LOGIN_AUTO_REDIRECT")
SOCIAL_AUTH_CREATE_USER = env("DD_SOCIAL_AUTH_CREATE_USER")

SOCIAL_AUTH_STRATEGY = "social_django.strategy.DjangoStrategy"
SOCIAL_AUTH_STORAGE = "social_django.models.DjangoStorage"
SOCIAL_AUTH_ADMIN_USER_SEARCH_FIELDS = ["username", "first_name", "last_name", "email"]
SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True

GOOGLE_OAUTH_ENABLED = env("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED")
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = env("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY")
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = env("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET")
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = tuple(env.list("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS", default=[""]))
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = tuple(env.list("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS", default=[""]))
SOCIAL_AUTH_LOGIN_ERROR_URL = "/login"
SOCIAL_AUTH_BACKEND_ERROR_URL = "/login"

OKTA_OAUTH_ENABLED = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED")
SOCIAL_AUTH_OKTA_OAUTH2_KEY = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY")
SOCIAL_AUTH_OKTA_OAUTH2_SECRET = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET")
SOCIAL_AUTH_OKTA_OAUTH2_API_URL = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL")

AZUREAD_TENANT_OAUTH2_ENABLED = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED")
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY")
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET")
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID")
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE")
AZUREAD_TENANT_OAUTH2_GET_GROUPS = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS")
AZUREAD_TENANT_OAUTH2_GROUPS_FILTER = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GROUPS_FILTER")
AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS")

GITLAB_OAUTH2_ENABLED = env("DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED")
GITLAB_PROJECT_AUTO_IMPORT = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT")
GITLAB_PROJECT_IMPORT_TAGS = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_TAGS")
GITLAB_PROJECT_IMPORT_URL = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_URL")
GITLAB_PROJECT_MIN_ACCESS_LEVEL = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_MIN_ACCESS_LEVEL")
SOCIAL_AUTH_GITLAB_KEY = env("DD_SOCIAL_AUTH_GITLAB_KEY")
SOCIAL_AUTH_GITLAB_SECRET = env("DD_SOCIAL_AUTH_GITLAB_SECRET")
SOCIAL_AUTH_GITLAB_API_URL = env("DD_SOCIAL_AUTH_GITLAB_API_URL")
SOCIAL_AUTH_GITLAB_SCOPE = env("DD_SOCIAL_AUTH_GITLAB_SCOPE")

# Add required scope if auto import is enabled
if GITLAB_PROJECT_AUTO_IMPORT:
    SOCIAL_AUTH_GITLAB_SCOPE += ["read_repository"]

AUTH0_OAUTH2_ENABLED = env("DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED")
SOCIAL_AUTH_AUTH0_KEY = env("DD_SOCIAL_AUTH_AUTH0_KEY")
SOCIAL_AUTH_AUTH0_SECRET = env("DD_SOCIAL_AUTH_AUTH0_SECRET")
SOCIAL_AUTH_AUTH0_DOMAIN = env("DD_SOCIAL_AUTH_AUTH0_DOMAIN")
SOCIAL_AUTH_AUTH0_SCOPE = env("DD_SOCIAL_AUTH_AUTH0_SCOPE")
SOCIAL_AUTH_TRAILING_SLASH = env("DD_SOCIAL_AUTH_TRAILING_SLASH")

KEYCLOAK_OAUTH2_ENABLED = env("DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED")
SOCIAL_AUTH_KEYCLOAK_KEY = env("DD_SOCIAL_AUTH_KEYCLOAK_KEY")
SOCIAL_AUTH_KEYCLOAK_SECRET = env("DD_SOCIAL_AUTH_KEYCLOAK_SECRET")
SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY = env("DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY")
SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL = env("DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL")
SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL = env("DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL")
SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT = env("DD_SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT")

GITHUB_ENTERPRISE_OAUTH2_ENABLED = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_OAUTH2_ENABLED")
SOCIAL_AUTH_GITHUB_ENTERPRISE_URL = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_URL")
SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL")
SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY")
SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET")

DOCUMENTATION_URL = env("DD_DOCUMENTATION_URL")

# Setting SLA_NOTIFY_ACTIVE and SLA_NOTIFY_ACTIVE_VERIFIED to False will disable the feature
# If you import thousands of Active findings through your pipeline everyday,
# and make the choice of enabling SLA notifications for non-verified findings,
# be mindful of performance.
# 'SLA_NOTIFY_ACTIVE', 'SLA_NOTIFY_ACTIVE_VERIFIED_ONLY' and 'SLA_NOTIFY_WITH_JIRA_ONLY' are moved to system settings, will be removed here
SLA_NOTIFY_ACTIVE = env("DD_SLA_NOTIFY_ACTIVE")  # this will include 'verified' findings as well as non-verified.
SLA_NOTIFY_ACTIVE_VERIFIED_ONLY = env("DD_SLA_NOTIFY_ACTIVE_VERIFIED_ONLY")
SLA_NOTIFY_WITH_JIRA_ONLY = env("DD_SLA_NOTIFY_WITH_JIRA_ONLY")  # Based on the 2 above, but only with a JIRA link
SLA_NOTIFY_PRE_BREACH = env("DD_SLA_NOTIFY_PRE_BREACH")  # in days, notify between dayofbreach minus this number until dayofbreach
SLA_NOTIFY_POST_BREACH = env("DD_SLA_NOTIFY_POST_BREACH")  # in days, skip notifications for findings that go past dayofbreach plus this number
SLA_BUSINESS_DAYS = env("DD_SLA_BUSINESS_DAYS")  # Use business days to calculate SLA's and age of a finding instead of calendar days


SEARCH_MAX_RESULTS = env("DD_SEARCH_MAX_RESULTS")
SIMILAR_FINDINGS_MAX_RESULTS = env("DD_SIMILAR_FINDINGS_MAX_RESULTS")
MAX_REQRESP_FROM_API = env("DD_MAX_REQRESP_FROM_API")
MAX_AUTOCOMPLETE_WORDS = env("DD_MAX_AUTOCOMPLETE_WORDS")

LOGIN_EXEMPT_URLS = (
    rf"^{URL_PREFIX}static/",
    rf"^{URL_PREFIX}webhook/([\w-]+)$",
    rf"^{URL_PREFIX}webhook/",
    rf"^{URL_PREFIX}jira/webhook/([\w-]+)$",
    rf"^{URL_PREFIX}jira/webhook/",
    rf"^{URL_PREFIX}reports/cover$",
    rf"^{URL_PREFIX}finding/image/(?P<token>[^/]+)$",
    rf"^{URL_PREFIX}api/v2/",
    r"complete/",
    r"empty_questionnaire/([\d]+)/answer",
    rf"^{URL_PREFIX}password_reset/",
    rf"^{URL_PREFIX}forgot_username",
    rf"^{URL_PREFIX}reset/",
)

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "dojo.user.validators.DojoCommonPasswordValidator",
    },
    {
        "NAME": "dojo.user.validators.MinLengthValidator",
    },
    {
        "NAME": "dojo.user.validators.MaxLengthValidator",
    },
    {
        "NAME": "dojo.user.validators.NumberValidator",
    },
    {
        "NAME": "dojo.user.validators.UppercaseValidator",
    },
    {
        "NAME": "dojo.user.validators.LowercaseValidator",
    },
    {
        "NAME": "dojo.user.validators.SymbolValidator",
    },
]

# https://django-ratelimit.readthedocs.io/en/stable/index.html
RATE_LIMITER_ENABLED = env("DD_RATE_LIMITER_ENABLED")
RATE_LIMITER_RATE = env("DD_RATE_LIMITER_RATE")  # Examples include 5/m 100/h and more https://django-ratelimit.readthedocs.io/en/stable/rates.html#simple-rates
RATE_LIMITER_BLOCK = env("DD_RATE_LIMITER_BLOCK")  # Block the requests after rate limit is exceeded
RATE_LIMITER_ACCOUNT_LOCKOUT = env("DD_RATE_LIMITER_ACCOUNT_LOCKOUT")  # Forces the user to change password on next login.

# ------------------------------------------------------------------------------
# SECURITY DIRECTIVES
# ------------------------------------------------------------------------------

# If True, the SecurityMiddleware redirects all non-HTTPS requests to HTTPS
# (except for those URLs matching a regular expression listed in SECURE_REDIRECT_EXEMPT).
SECURE_SSL_REDIRECT = env("DD_SECURE_SSL_REDIRECT")

# If True, the SecurityMiddleware sets the X-Content-Type-Options: nosniff;
SECURE_CONTENT_TYPE_NOSNIFF = env("DD_SECURE_CONTENT_TYPE_NOSNIFF")

# Whether to use HTTPOnly flag on the session cookie.
# If this is set to True, client-side JavaScript will not to be able to access the session cookie.
SESSION_COOKIE_HTTPONLY = env("DD_SESSION_COOKIE_HTTPONLY")

# Whether to use HttpOnly flag on the CSRF cookie. If this is set to True,
# client-side JavaScript will not to be able to access the CSRF cookie.
CSRF_COOKIE_HTTPONLY = env("DD_CSRF_COOKIE_HTTPONLY")

# Whether to use a secure cookie for the session cookie. If this is set to True,
# the cookie will be marked as secure, which means browsers may ensure that the
# cookie is only sent with an HTTPS connection.
SESSION_COOKIE_SECURE = env("DD_SESSION_COOKIE_SECURE")
SESSION_COOKIE_SAMESITE = env("DD_SESSION_COOKIE_SAMESITE")

# Override default Django behavior for incorrect URLs
APPEND_SLASH = env("DD_APPEND_SLASH")

# Whether to use a secure cookie for the CSRF cookie.
CSRF_COOKIE_SECURE = env("DD_CSRF_COOKIE_SECURE")
CSRF_COOKIE_SAMESITE = env("DD_CSRF_COOKIE_SAMESITE")

# A list of trusted origins for unsafe requests (e.g. POST).
# Use comma-separated list of domains, they will be split to list automatically
# Only specify this settings if the contents is not an empty list (the default)
if env("DD_CSRF_TRUSTED_ORIGINS") != ["[]"]:
    CSRF_TRUSTED_ORIGINS = env("DD_CSRF_TRUSTED_ORIGINS")

# Unless set to None, the SecurityMiddleware sets the Cross-Origin Opener Policy
# header on all responses that do not already have it to the value provided.
SECURE_CROSS_ORIGIN_OPENER_POLICY = env("DD_SECURE_CROSS_ORIGIN_OPENER_POLICY") if env("DD_SECURE_CROSS_ORIGIN_OPENER_POLICY") != "None" else None

if env("DD_SECURE_PROXY_SSL_HEADER"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

if env("DD_SECURE_HSTS_INCLUDE_SUBDOMAINS"):
    SECURE_HSTS_SECONDS = env("DD_SECURE_HSTS_SECONDS")
    SECURE_HSTS_INCLUDE_SUBDOMAINS = env("DD_SECURE_HSTS_INCLUDE_SUBDOMAINS")

SESSION_EXPIRE_AT_BROWSER_CLOSE = env("DD_SESSION_EXPIRE_AT_BROWSER_CLOSE")
SESSION_COOKIE_AGE = env("DD_SESSION_COOKIE_AGE")

# ------------------------------------------------------------------------------
# DEFECTDOJO SPECIFIC
# ------------------------------------------------------------------------------

# Credential Key
CREDENTIAL_AES_256_KEY = env("DD_CREDENTIAL_AES_256_KEY")
DB_KEY = env("DD_CREDENTIAL_AES_256_KEY")

# Used in a few places to prefix page headings and in email salutations
TEAM_NAME = env("DD_TEAM_NAME")

# Used to configure a custom version in the footer of the base.html template.
FOOTER_VERSION = env("DD_FOOTER_VERSION")

# Django-tagging settings
FORCE_LOWERCASE_TAGS = env("DD_FORCE_LOWERCASE_TAGS")
MAX_TAG_LENGTH = env("DD_MAX_TAG_LENGTH")


# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------
ADMINS = getaddresses([env("DD_ADMINS")])

# https://docs.djangoproject.com/en/dev/ref/settings/#managers
MANAGERS = ADMINS

# Django admin enabled
DJANGO_ADMIN_ENABLED = env("DD_DJANGO_ADMIN_ENABLED")

# ------------------------------------------------------------------------------
# API V2
# ------------------------------------------------------------------------------

API_TOKENS_ENABLED = env("DD_API_TOKENS_ENABLED")

API_TOKEN_AUTH_ENDPOINT_ENABLED = env("DD_API_TOKEN_AUTH_ENDPOINT_ENABLED")

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.DjangoModelPermissions",
    ),
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 25,
    "EXCEPTION_HANDLER": "dojo.api_v2.exception_handler.custom_exception_handler",
}

if API_TOKENS_ENABLED:
    REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] += ("rest_framework.authentication.TokenAuthentication",)

SPECTACULAR_SETTINGS = {
    "TITLE": "Defect Dojo API v2",
    "DESCRIPTION": "Defect Dojo - Open Source vulnerability Management made easy. Prefetch related parameters/responses not yet in the schema.",
    "VERSION": __version__,
    "SCHEMA_PATH_PREFIX": "/api/v2",
    # OTHER SETTINGS
    # the following set to False could help some client generators
    # 'ENUM_ADD_EXPLICIT_BLANK_NULL_CHOICE': False,
    "PREPROCESSING_HOOKS": ["dojo.urls.drf_spectacular_preprocessing_filter_spec"],
    "POSTPROCESSING_HOOKS": ["dojo.api_v2.prefetch.schema.prefetch_postprocessing_hook"],
    # show file selection dialogue, see https://github.com/tfranzel/drf-spectacular/issues/455
    "COMPONENT_SPLIT_REQUEST": True,
    "SWAGGER_UI_SETTINGS": {
        "docExpansion": "none",
    },
}

if not env("DD_DEFAULT_SWAGGER_UI"):
    SPECTACULAR_SETTINGS["SWAGGER_UI_DIST"] = "SIDECAR"
    SPECTACULAR_SETTINGS["SWAGGER_UI_FAVICON_HREF"] = "SIDECAR"

# ------------------------------------------------------------------------------
# TEMPLATES
# ------------------------------------------------------------------------------

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": env("DD_DEBUG"),
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "social_django.context_processors.backends",
                "social_django.context_processors.login_redirect",
                "dojo.context_processors.globalize_vars",
                "dojo.context_processors.bind_system_settings",
                "dojo.context_processors.bind_alert_count",
                "dojo.context_processors.bind_announcement",
            ],
        },
    },
]

# ------------------------------------------------------------------------------
# APPS
# ------------------------------------------------------------------------------

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "polymorphic",  # provides admin templates
    "django.contrib.admin",
    "django.contrib.humanize",
    "auditlog",
    "dojo",
    "watson",
    "tagging",  # not used, but still needed for migration 0065_django_tagulous.py (v1.10.0)
    "imagekit",
    "multiselectfield",
    "rest_framework",
    "rest_framework.authtoken",
    "dbbackup",
    "django_celery_results",
    "social_django",
    "drf_spectacular",
    "drf_spectacular_sidecar",  # required for Django collectstatic discovery
    "tagulous",
    "fontawesomefree",
    "django_filters",
)

# ------------------------------------------------------------------------------
# MIDDLEWARE
# ------------------------------------------------------------------------------
DJANGO_MIDDLEWARE_CLASSES = [
    "django.middleware.common.CommonMiddleware",
    "dojo.middleware.APITrailingSlashMiddleware",
    "dojo.middleware.DojoSytemSettingsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "dojo.middleware.LoginRequiredMiddleware",
    "dojo.middleware.AdditionalHeaderMiddleware",
    "social_django.middleware.SocialAuthExceptionMiddleware",
    "watson.middleware.SearchContextMiddleware",
    "dojo.middleware.AuditlogMiddleware",
    "crum.CurrentRequestUserMiddleware",
    "dojo.request_cache.middleware.RequestCacheMiddleware",
]

MIDDLEWARE = DJANGO_MIDDLEWARE_CLASSES

# WhiteNoise allows your web app to serve its own static files,
# making it a self-contained unit that can be deployed anywhere without relying on nginx
if env("DD_WHITENOISE"):
    WHITE_NOISE = [
        # Simplified static file serving.
        # https://warehouse.python.org/project/whitenoise/
        "whitenoise.middleware.WhiteNoiseMiddleware",
    ]
    MIDDLEWARE = MIDDLEWARE + WHITE_NOISE

EMAIL_CONFIG = env.email_url(
    "DD_EMAIL_URL", default="smtp://user@:password@localhost:25")

vars().update(EMAIL_CONFIG)

# ------------------------------------------------------------------------------
# SAML
# ------------------------------------------------------------------------------
# For more configuration and customization options, see djangosaml2 documentation
# https://djangosaml2.readthedocs.io/contents/setup.html#configuration
# To override not configurable settings, you can use local_settings.py
# function that helps convert env var into the djangosaml2 attribute mapping format
# https://djangosaml2.readthedocs.io/contents/setup.html#users-attributes-and-account-linking


def saml2_attrib_map_format(dict):
    dout = {}
    for i in dict:
        dout[i] = (dict[i],)
    return dout


SAML2_ENABLED = env("DD_SAML2_ENABLED")
SAML2_LOGIN_BUTTON_TEXT = env("DD_SAML2_LOGIN_BUTTON_TEXT")
SAML2_LOGOUT_URL = env("DD_SAML2_LOGOUT_URL")
if SAML2_ENABLED:
    from os import path

    import saml2
    import saml2.saml
    # SSO_URL = env('DD_SSO_URL')
    SAML_METADATA = {}
    if len(env("DD_SAML2_METADATA_AUTO_CONF_URL")) > 0:
        SAML_METADATA["remote"] = [{"url": env("DD_SAML2_METADATA_AUTO_CONF_URL")}]
    if len(env("DD_SAML2_METADATA_LOCAL_FILE_PATH")) > 0:
        SAML_METADATA["local"] = [env("DD_SAML2_METADATA_LOCAL_FILE_PATH")]
    INSTALLED_APPS += ("djangosaml2",)
    MIDDLEWARE.append("djangosaml2.middleware.SamlSessionMiddleware")
    AUTHENTICATION_BACKENDS += (env("DD_SAML2_AUTHENTICATION_BACKENDS"),)
    LOGIN_EXEMPT_URLS += (rf"^{URL_PREFIX}saml2/",)
    SAML_LOGOUT_REQUEST_PREFERRED_BINDING = saml2.BINDING_HTTP_POST
    SAML_IGNORE_LOGOUT_ERRORS = True
    SAML_DJANGO_USER_MAIN_ATTRIBUTE = "username"
#    SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP = '__iexact'
    SAML_USE_NAME_ID_AS_USERNAME = True
    SAML_CREATE_UNKNOWN_USER = env("DD_SAML2_CREATE_USER")
    SAML_ATTRIBUTE_MAPPING = saml2_attrib_map_format(env("DD_SAML2_ATTRIBUTES_MAP"))
    SAML_FORCE_AUTH = env("DD_SAML2_FORCE_AUTH")
    SAML_ALLOW_UNKNOWN_ATTRIBUTES = env("DD_SAML2_ALLOW_UNKNOWN_ATTRIBUTE")
    BASEDIR = Path(path.abspath(__file__)).parent
    if len(env("DD_SAML2_ENTITY_ID")) == 0:
        SAML2_ENTITY_ID = f"{SITE_URL}/saml2/metadata/"
    else:
        SAML2_ENTITY_ID = env("DD_SAML2_ENTITY_ID")

    SAML_CONFIG = {
        # full path to the xmlsec1 binary programm
        "xmlsec_binary": "/usr/bin/xmlsec1",

        # your entity id, usually your subdomain plus the url to the metadata view
        "entityid": str(SAML2_ENTITY_ID),

        # directory with attribute mapping
        "attribute_map_dir": path.join(BASEDIR, "attribute-maps"),
        # do now discard attributes not specified in attribute-maps
        "allow_unknown_attributes": SAML_ALLOW_UNKNOWN_ATTRIBUTES,
        # this block states what services we provide
        "service": {
            # we are just a lonely SP
            "sp": {
                "name": "Defect_Dojo",
                "name_id_format": saml2.saml.NAMEID_FORMAT_TRANSIENT,
                "want_response_signed": False,
                "want_assertions_signed": True,
                "force_authn": SAML_FORCE_AUTH,
                "allow_unsolicited": True,

                # For Okta add signed logout requets. Enable this:
                # "logout_requests_signed": True,

                "endpoints": {
                    # url and binding to the assetion consumer service view
                    # do not change the binding or service name
                    "assertion_consumer_service": [
                        (f"{SITE_URL}/saml2/acs/",
                        saml2.BINDING_HTTP_POST),
                    ],
                    # url and binding to the single logout service view
                    # do not change the binding or service name
                    "single_logout_service": [
                        # Disable next two lines for HTTP_REDIRECT for IDP's that only support HTTP_POST. Ex. Okta:
                        (f"{SITE_URL}/saml2/ls/",
                        saml2.BINDING_HTTP_REDIRECT),
                        (f"{SITE_URL}/saml2/ls/post",
                        saml2.BINDING_HTTP_POST),
                    ],
                },

                # attributes that this project need to identify a user
                "required_attributes": ["Email", "UserName"],

                # attributes that may be useful to have but not required
                "optional_attributes": ["Firstname", "Lastname"],

                # in this section the list of IdPs we talk to are defined
                # This is not mandatory! All the IdP available in the metadata will be considered.
                # 'idp': {
                #     # we do not need a WAYF service since there is
                #     # only an IdP defined here. This IdP should be
                #     # present in our metadata

                #     # the keys of this dictionary are entity ids
                #     'https://localhost/simplesaml/saml2/idp/metadata.php': {
                #         'single_sign_on_service': {
                #             saml2.BINDING_HTTP_REDIRECT: 'https://localhost/simplesaml/saml2/idp/SSOService.php',
                #         },
                #         'single_logout_service': {
                #             saml2.BINDING_HTTP_REDIRECT: 'https://localhost/simplesaml/saml2/idp/SingleLogoutService.php',
                #         },
                #     },
                # },
            },
        },

        # where the remote metadata is stored, local, remote or mdq server.
        # One metadatastore or many ...
        "metadata": SAML_METADATA,

        # set to 1 to output debugging information
        "debug": 0,

        # Signing
        # 'key_file': path.join(BASEDIR, 'private.key'),  # private part
        # 'cert_file': path.join(BASEDIR, 'public.pem'),  # public part

        # Encryption
        # 'encryption_keypairs': [{
        #     'key_file': path.join(BASEDIR, 'private.key'),  # private part
        #     'cert_file': path.join(BASEDIR, 'public.pem'),  # public part
        # }],

        # own metadata settings
        "contact_person": [
            {"given_name": "Lorenzo",
            "sur_name": "Gil",
            "company": "Yaco Sistemas",
            "email_address": "lgs@yaco.es",
            "contact_type": "technical"},
            {"given_name": "Angel",
            "sur_name": "Fernandez",
            "company": "Yaco Sistemas",
            "email_address": "angel@yaco.es",
            "contact_type": "administrative"},
        ],
        # you can set multilanguage information here
        "organization": {
            "name": [("Yaco Sistemas", "es"), ("Yaco Systems", "en")],
            "display_name": [("Yaco", "es"), ("Yaco", "en")],
            "url": [("http://www.yaco.es", "es"), ("http://www.yaco.com", "en")],
        },
        "valid_for": 24,  # how long is our metadata valid
    }

# ------------------------------------------------------------------------------
# REMOTE_USER
# ------------------------------------------------------------------------------

AUTH_REMOTEUSER_ENABLED = env("DD_AUTH_REMOTEUSER_ENABLED")
AUTH_REMOTEUSER_USERNAME_HEADER = env("DD_AUTH_REMOTEUSER_USERNAME_HEADER")
AUTH_REMOTEUSER_EMAIL_HEADER = env("DD_AUTH_REMOTEUSER_EMAIL_HEADER")
AUTH_REMOTEUSER_FIRSTNAME_HEADER = env("DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER")
AUTH_REMOTEUSER_LASTNAME_HEADER = env("DD_AUTH_REMOTEUSER_LASTNAME_HEADER")
AUTH_REMOTEUSER_GROUPS_HEADER = env("DD_AUTH_REMOTEUSER_GROUPS_HEADER")
AUTH_REMOTEUSER_GROUPS_CLEANUP = env("DD_AUTH_REMOTEUSER_GROUPS_CLEANUP")
AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER = env("DD_AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER")

AUTH_REMOTEUSER_TRUSTED_PROXY = IPSet()
for ip_range in env("DD_AUTH_REMOTEUSER_TRUSTED_PROXY"):
    AUTH_REMOTEUSER_TRUSTED_PROXY.add(IPNetwork(ip_range))

if env("DD_AUTH_REMOTEUSER_LOGIN_ONLY"):
    RemoteUserMiddleware = "dojo.remote_user.PersistentRemoteUserMiddleware"
else:
    RemoteUserMiddleware = "dojo.remote_user.RemoteUserMiddleware"
# we need to add middleware just behindAuthenticationMiddleware as described in https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#configuration
for i in range(len(MIDDLEWARE)):
    if MIDDLEWARE[i] == "django.contrib.auth.middleware.AuthenticationMiddleware":
        MIDDLEWARE.insert(i + 1, RemoteUserMiddleware)
        break

if AUTH_REMOTEUSER_ENABLED:
    REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] = \
        ("dojo.remote_user.RemoteUserAuthentication",) + \
        REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]

# ------------------------------------------------------------------------------
# CELERY
# ------------------------------------------------------------------------------

# Celery settings
CELERY_BROKER_URL = env("DD_CELERY_BROKER_URL") \
    if len(env("DD_CELERY_BROKER_URL")) > 0 else generate_url(
    scheme=env("DD_CELERY_BROKER_SCHEME"),
    double_slashes=True,
    user=env("DD_CELERY_BROKER_USER"),
    password=env("DD_CELERY_BROKER_PASSWORD"),
    host=env("DD_CELERY_BROKER_HOST"),
    port=env("DD_CELERY_BROKER_PORT"),
    path=env("DD_CELERY_BROKER_PATH"),
    params=env("DD_CELERY_BROKER_PARAMS"),
)
CELERY_TASK_IGNORE_RESULT = env("DD_CELERY_TASK_IGNORE_RESULT")
CELERY_RESULT_BACKEND = env("DD_CELERY_RESULT_BACKEND")
CELERY_TIMEZONE = TIME_ZONE
CELERY_RESULT_EXPIRES = env("DD_CELERY_RESULT_EXPIRES")
CELERY_BEAT_SCHEDULE_FILENAME = env("DD_CELERY_BEAT_SCHEDULE_FILENAME")
CELERY_ACCEPT_CONTENT = ["pickle", "json", "msgpack", "yaml"]
CELERY_TASK_SERIALIZER = env("DD_CELERY_TASK_SERIALIZER")
CELERY_PASS_MODEL_BY_ID = env("DD_CELERY_PASS_MODEL_BY_ID")

if len(env("DD_CELERY_BROKER_TRANSPORT_OPTIONS")) > 0:
    CELERY_BROKER_TRANSPORT_OPTIONS = json.loads(env("DD_CELERY_BROKER_TRANSPORT_OPTIONS"))

CELERY_IMPORTS = ("dojo.tools.tool_issue_updater", )

# Celery beat scheduled tasks
CELERY_BEAT_SCHEDULE = {
    "add-alerts": {
        "task": "dojo.tasks.add_alerts",
        "schedule": timedelta(hours=1),
        "args": [timedelta(hours=1)],
    },
    "cleanup-alerts": {
        "task": "dojo.tasks.cleanup_alerts",
        "schedule": timedelta(hours=8),
    },
    "dedupe-delete": {
        "task": "dojo.tasks.async_dupe_delete",
        "schedule": timedelta(minutes=1),
        "args": [timedelta(minutes=1)],
    },
    "flush_auditlog": {
        "task": "dojo.tasks.flush_auditlog",
        "schedule": timedelta(hours=8),
    },
    "update-findings-from-source-issues": {
        "task": "dojo.tools.tool_issue_updater.update_findings_from_source_issues",
        "schedule": timedelta(hours=3),
    },
    "compute-sla-age-and-notify": {
        "task": "dojo.tasks.async_sla_compute_and_notify_task",
        "schedule": crontab(hour=7, minute=30),
    },
    "risk_acceptance_expiration_handler": {
        "task": "dojo.risk_acceptance.helper.expiration_handler",
        "schedule": crontab(minute=0, hour="*/3"),  # every 3 hours
    },
    "notification_webhook_status_cleanup": {
        "task": "dojo.notifications.helper.webhook_status_cleanup",
        "schedule": timedelta(minutes=1),
    },
    # 'jira_status_reconciliation': {
    #     'task': 'dojo.tasks.jira_status_reconciliation_task',
    #     'schedule': timedelta(hours=12),
    #     'kwargs': {'mode': 'reconcile', 'dryrun': True, 'daysback': 10, 'product': None, 'engagement': None}
    # },
    # 'fix_loop_duplicates': {
    #     'task': 'dojo.tasks.fix_loop_duplicates_task',
    #     'schedule': timedelta(hours=12)
    # },

}

# ------------------------------------
# Monitoring Metrics
# ------------------------------------
# address issue when running ./manage.py collectstatic
# reference: https://github.com/korfuri/django-prometheus/issues/34
PROMETHEUS_EXPORT_MIGRATIONS = False
# django metrics for monitoring
if env("DD_DJANGO_METRICS_ENABLED"):
    DJANGO_METRICS_ENABLED = env("DD_DJANGO_METRICS_ENABLED")
    INSTALLED_APPS = (*INSTALLED_APPS, "django_prometheus")
    MIDDLEWARE = [
        "django_prometheus.middleware.PrometheusBeforeMiddleware",
        *MIDDLEWARE,
        "django_prometheus.middleware.PrometheusAfterMiddleware",
]
    database_engine = DATABASES.get("default").get("ENGINE")
    DATABASES["default"]["ENGINE"] = database_engine.replace("django.", "django_prometheus.", 1)
    # CELERY_RESULT_BACKEND.replace('django.core','django_prometheus.', 1)
    LOGIN_EXEMPT_URLS += (rf"^{URL_PREFIX}django_metrics/",)


# ------------------------------------
# Hashcode configuration
# ------------------------------------
# List of fields used to compute the hash_code
# The fields must be one of HASHCODE_ALLOWED_FIELDS
# If not present, default is the legacy behavior: see models.py, compute_hash_code_legacy function
# legacy is:
#   static scanner:  ['title', 'cwe', 'line', 'file_path', 'description']
#   dynamic scanner: ['title', 'cwe', 'line', 'file_path', 'description']
HASHCODE_FIELDS_PER_SCANNER = {
    # In checkmarx, same CWE may appear with different severities: example "sql injection" (high) and "blind sql injection" (low).
    # Including the severity in the hash_code keeps those findings not duplicate
    "Anchore Engine Scan": ["title", "severity", "component_name", "component_version", "file_path"],
    "AnchoreCTL Vuln Report": ["title", "severity", "component_name", "component_version", "file_path"],
    "AnchoreCTL Policies Report": ["title", "severity", "component_name", "file_path"],
    "Anchore Enterprise Policy Check": ["title", "severity", "component_name", "file_path"],
    "Anchore Grype": ["title", "severity", "component_name", "component_version"],
    "Aqua Scan": ["severity", "vulnerability_ids", "component_name", "component_version"],
    "Bandit Scan": ["file_path", "line", "vuln_id_from_tool"],
    "Burp Enterprise Scan": ["title", "severity", "cwe"],
    "CargoAudit Scan": ["vulnerability_ids", "severity", "component_name", "component_version", "vuln_id_from_tool"],
    "Checkmarx Scan": ["cwe", "severity", "file_path"],
    "Checkmarx OSA": ["vulnerability_ids", "component_name"],
    "Cloudsploit Scan": ["title", "description"],
    "Coverity Scan JSON Report": ["title", "cwe", "line", "file_path", "description"],
    "SonarQube Scan": ["cwe", "severity", "file_path"],
    "SonarQube API Import": ["title", "file_path", "line"],
    "Sonatype Application Scan": ["title", "cwe", "file_path", "component_name", "component_version", "vulnerability_ids"],
    "Dependency Check Scan": ["title", "cwe", "file_path"],
    "Dockle Scan": ["title", "description", "vuln_id_from_tool"],
    "Dependency Track Finding Packaging Format (FPF) Export": ["component_name", "component_version", "vulnerability_ids"],
    "Horusec Scan": ["title", "description", "file_path", "line"],
    "Mobsfscan Scan": ["title", "severity", "cwe", "file_path", "description"],
    "Tenable Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "Nexpose Scan": ["title", "severity", "vulnerability_ids", "cwe"],
    # possible improvement: in the scanner put the library name into file_path, then dedup on cwe + file_path + severity
    "NPM Audit Scan": ["title", "severity", "file_path", "vulnerability_ids", "cwe"],
    "NPM Audit v7+ Scan": ["title", "severity", "cwe", "vuln_id_from_tool"],
    # possible improvement: in the scanner put the library name into file_path, then dedup on cwe + file_path + severity
    "Yarn Audit Scan": ["title", "severity", "file_path", "vulnerability_ids", "cwe"],
    # possible improvement: in the scanner put the library name into file_path, then dedup on vulnerability_ids + file_path + severity
    "Mend Scan": ["title", "severity", "description"],
    "ZAP Scan": ["title", "cwe", "severity"],
    "Qualys Scan": ["title", "severity", "endpoints"],
    # 'Qualys Webapp Scan': ['title', 'unique_id_from_tool'],
    "PHP Symfony Security Check": ["title", "vulnerability_ids"],
    "Clair Scan": ["title", "vulnerability_ids", "description", "severity"],
    # for backwards compatibility because someone decided to rename this scanner:
    "Symfony Security Check": ["title", "vulnerability_ids"],
    "DSOP Scan": ["vulnerability_ids"],
    "Acunetix Scan": ["title", "description"],
    "Terrascan Scan": ["vuln_id_from_tool", "title", "severity", "file_path", "line", "component_name"],
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
    "GitLab Dependency Scanning Report": ["title", "vulnerability_ids", "file_path", "component_name", "component_version"],
    "SpotBugs Scan": ["cwe", "severity", "file_path", "line"],
    "JFrog Xray Unified Scan": ["vulnerability_ids", "file_path", "component_name", "component_version"],
    "JFrog Xray On Demand Binary Scan": ["title", "component_name", "component_version"],
    "Scout Suite Scan": ["file_path", "vuln_id_from_tool"],  # for now we use file_path as there is no attribute for "service"
    "Meterian Scan": ["cwe", "component_name", "component_version", "description", "severity"],
    "Github Vulnerability Scan": ["title", "severity", "component_name", "vulnerability_ids", "file_path"],
    "Solar Appscreener Scan": ["title", "file_path", "line", "severity"],
    "pip-audit Scan": ["vuln_id_from_tool", "component_name", "component_version"],
    "Rubocop Scan": ["vuln_id_from_tool", "file_path", "line"],
    "JFrog Xray Scan": ["title", "description", "component_name", "component_version"],
    "CycloneDX Scan": ["vuln_id_from_tool", "component_name", "component_version"],
    "SSLyze Scan (JSON)": ["title", "description"],
    "Harbor Vulnerability Scan": ["title", "mitigation"],
    "Rusty Hog Scan": ["file_path", "payload"],
    "StackHawk HawkScan": ["vuln_id_from_tool", "component_name", "component_version"],
    "Hydra Scan": ["title", "description"],
    "DrHeader JSON Importer": ["title", "description"],
    "Whispers": ["vuln_id_from_tool", "file_path", "line"],
    "Blackduck Hub Scan": ["title", "vulnerability_ids", "component_name", "component_version"],
    "Veracode SourceClear Scan": ["title", "vulnerability_ids", "component_name", "component_version", "severity"],
    "Vulners Scan": ["vuln_id_from_tool", "component_name"],
    "Twistlock Image Scan": ["title", "severity", "component_name", "component_version"],
    "NeuVector (REST)": ["title", "severity", "component_name", "component_version"],
    "NeuVector (compliance)": ["title", "vuln_id_from_tool", "description"],
    "Wpscan": ["title", "description", "severity"],
    "Popeye Scan": ["title", "description"],
    "Nuclei Scan": ["title", "cwe", "severity", "component_name"],
    "KubeHunter Scan": ["title", "description"],
    "kube-bench Scan": ["title", "vuln_id_from_tool", "description"],
    "Threagile risks report": ["title", "cwe", "severity"],
    "Trufflehog Scan": ["title", "description", "line"],
    "Humble Json Importer": ["title"],
    "MSDefender Parser": ["title", "description"],
    "HCLAppScan XML": ["title", "description"],
    "KICS Scan": ["file_path", "line", "severity", "description", "title"],
    "MobSF Scan": ["title", "description", "severity"],
    "MobSF Scorecard Scan": ["title", "description", "severity"],
    "OSV Scan": ["title", "description", "severity"],
    "Snyk Code Scan": ["vuln_id_from_tool", "file_path"],
    "Deepfence Threatmapper Report": ["title", "description", "severity"],
    "Bearer CLI": ["title", "severity"],
    "Nancy Scan": ["title", "vuln_id_from_tool"],
    "Wiz Scan": ["title", "description", "severity"],
    "Kubescape JSON Importer": ["title", "component_name"],
    "Kiuwan SCA Scan": ["description", "severity", "component_name", "component_version", "cwe"],
    "Rapplex Scan": ["title", "endpoints", "severity"],
    "AppCheck Web Application Scanner": ["title", "severity"],
    "AWS Inspector2 Scan": ["title", "severity", "description"],
    "Legitify Scan": ["title", "endpoints", "severity"],
    "ThreatComposer Scan": ["title", "description"],
    "Invicti Scan": ["title", "description", "severity"],
    "HackerOne Cases": ["title", "severity"],
    "KrakenD Audit Scan": ["description", "mitigation", "severity"],
    "Red Hat Satellite": ["description", "severity"],
    "Qualys Hacker Guardian Scan": ["title", "severity", "description"],
}

# Override the hardcoded settings here via the env var
if len(env("DD_HASHCODE_FIELDS_PER_SCANNER")) > 0:
    env_hashcode_fields_per_scanner = json.loads(env("DD_HASHCODE_FIELDS_PER_SCANNER"))
    for key, value in env_hashcode_fields_per_scanner.items():
        if not isinstance(value, list):
            msg = f"Fields definition '{value}' for hashcode calculation of '{key}' is not valid. It needs to be list of strings but it is {type(value)}."
            raise TypeError(msg)
        if not all(isinstance(field, str) for field in value):
            msg = f"Fields for hashcode calculation for {key} are not valid. It needs to be list of strings. Some of fields are not string."
            raise AttributeError(msg)
        if key in HASHCODE_FIELDS_PER_SCANNER:
            logger.info(f"Replacing {key} with value {value} (previously set to {HASHCODE_FIELDS_PER_SCANNER[key]}) from env var DD_HASHCODE_FIELDS_PER_SCANNER")
            HASHCODE_FIELDS_PER_SCANNER[key] = value
        if key not in HASHCODE_FIELDS_PER_SCANNER:
            logger.info(f"Adding {key} with value {value} from env var DD_HASHCODE_FIELDS_PER_SCANNER")
            HASHCODE_FIELDS_PER_SCANNER[key] = value


# This tells if we should accept cwe=0 when computing hash_code with a configurable list of fields from HASHCODE_FIELDS_PER_SCANNER (this setting doesn't apply to legacy algorithm)
# If False and cwe = 0, then the hash_code computation will fallback to legacy algorithm for the concerned finding
# Default is True (if scanner is not configured here but is configured in HASHCODE_FIELDS_PER_SCANNER, it allows null cwe)
HASHCODE_ALLOWS_NULL_CWE = {
    "Anchore Engine Scan": True,
    "AnchoreCTL Vuln Report": True,
    "AnchoreCTL Policies Report": True,
    "Anchore Enterprise Policy Check": True,
    "Anchore Grype": True,
    "AWS Prowler Scan": True,
    "AWS Prowler V3": True,
    "Checkmarx Scan": False,
    "Checkmarx OSA": True,
    "Cloudsploit Scan": True,
    "SonarQube Scan": False,
    "Dependency Check Scan": True,
    "Mobsfscan Scan": False,
    "Tenable Scan": True,
    "Nexpose Scan": True,
    "NPM Audit Scan": True,
    "NPM Audit v7+ Scan": True,
    "Yarn Audit Scan": True,
    "Mend Scan": True,
    "ZAP Scan": False,
    "Qualys Scan": True,
    "DSOP Scan": True,
    "Acunetix Scan": True,
    "Trivy Operator Scan": True,
    "Trivy Scan": True,
    "SpotBugs Scan": False,
    "Scout Suite Scan": True,
    "AWS Security Hub Scan": True,
    "Meterian Scan": True,
    "SARIF": True,
    "Hadolint Dockerfile check": True,
    "Semgrep JSON Report": True,
    "Generic Findings Import": True,
    "Edgescan Scan": True,
    "Bugcrowd API Import": True,
    "Veracode SourceClear Scan": True,
    "Vulners Scan": True,
    "Twistlock Image Scan": True,
    "Wpscan": True,
    "Rusty Hog Scan": True,
    "Codechecker Report native": True,
    "Wazuh": True,
    "Nuclei Scan": True,
    "Threagile risks report": True,
    "AWS Inspector2 Scan": True,
}

# List of fields that are known to be usable in hash_code computation)
# 'endpoints' is a pseudo field that uses the endpoints (for dynamic scanners)
# 'unique_id_from_tool' is often not needed here as it can be used directly in the dedupe algorithm, but it's also possible to use it for hashing
HASHCODE_ALLOWED_FIELDS = ["title", "cwe", "vulnerability_ids", "line", "file_path", "payload", "component_name", "component_version", "description", "endpoints", "unique_id_from_tool", "severity", "vuln_id_from_tool", "mitigation"]

# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]

# ------------------------------------
# Deduplication configuration
# ------------------------------------
# List of algorithms
# legacy one with multiple conditions (default mode)
DEDUPE_ALGO_LEGACY = "legacy"
# based on dojo_finding.unique_id_from_tool only (for checkmarx detailed, or sonarQube detailed for example)
DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL = "unique_id_from_tool"
# based on dojo_finding.hash_code only
DEDUPE_ALGO_HASH_CODE = "hash_code"
# unique_id_from_tool or hash_code
# Makes it possible to deduplicate on a technical id (same parser) and also on some functional fields (cross-parsers deduplication)
DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE = "unique_id_from_tool_or_hash_code"

DEDUPE_ALGOS = [
    DEDUPE_ALGO_LEGACY,
    DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    DEDUPE_ALGO_HASH_CODE,
    DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
]

# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user. For a details description see https://hyperlink.readthedocs.io/en/latest/api.html#attributes.
# Example:
# Finding A and B have the same hashcode. Finding A has endpoint http://defectdojo.com and finding B has endpoint https://defectdojo.com/finding.
# - An empyt list ([]) means, no fields are used. B is marked as duplicated of A.
# - Host (['host']) means: B is marked as duplicate of A because the host (defectdojo.com) is the same.
# - Host and path (['host', 'path']) means: A and B stay untouched because the path is different.
#
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]

# Choice of deduplication algorithm per parser
# Key = the scan_type from factory.py (= the test_type)
# Default is DEDUPE_ALGO_LEGACY
DEDUPLICATION_ALGORITHM_PER_PARSER = {
    "Anchore Engine Scan": DEDUPE_ALGO_HASH_CODE,
    "AnchoreCTL Vuln Report": DEDUPE_ALGO_HASH_CODE,
    "AnchoreCTL Policies Report": DEDUPE_ALGO_HASH_CODE,
    "Anchore Enterprise Policy Check": DEDUPE_ALGO_HASH_CODE,
    "Anchore Grype": DEDUPE_ALGO_HASH_CODE,
    "Aqua Scan": DEDUPE_ALGO_HASH_CODE,
    "AuditJS Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "AWS Prowler Scan": DEDUPE_ALGO_HASH_CODE,
    "AWS Prowler V3": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "AWS Security Finding Format (ASFF) Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Burp REST API": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Bandit Scan": DEDUPE_ALGO_HASH_CODE,
    "Burp Enterprise Scan": DEDUPE_ALGO_HASH_CODE,
    "CargoAudit Scan": DEDUPE_ALGO_HASH_CODE,
    "Checkmarx Scan detailed": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Checkmarx Scan": DEDUPE_ALGO_HASH_CODE,
    "Checkmarx One Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Checkmarx OSA": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Codechecker Report native": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Coverity API": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Coverity Scan JSON Report": DEDUPE_ALGO_HASH_CODE,
    "Cobalt.io API": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Crunch42 Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Dependency Track Finding Packaging Format (FPF) Export": DEDUPE_ALGO_HASH_CODE,
    "Horusec Scan": DEDUPE_ALGO_HASH_CODE,
    "Mobsfscan Scan": DEDUPE_ALGO_HASH_CODE,
    "SonarQube Scan detailed": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "SonarQube Scan": DEDUPE_ALGO_HASH_CODE,
    "SonarQube API Import": DEDUPE_ALGO_HASH_CODE,
    "Sonatype Application Scan": DEDUPE_ALGO_HASH_CODE,
    "Dependency Check Scan": DEDUPE_ALGO_HASH_CODE,
    "Dockle Scan": DEDUPE_ALGO_HASH_CODE,
    "Tenable Scan": DEDUPE_ALGO_HASH_CODE,
    "Nexpose Scan": DEDUPE_ALGO_HASH_CODE,
    "NPM Audit Scan": DEDUPE_ALGO_HASH_CODE,
    "NPM Audit v7+ Scan": DEDUPE_ALGO_HASH_CODE,
    "Yarn Audit Scan": DEDUPE_ALGO_HASH_CODE,
    "Mend Scan": DEDUPE_ALGO_HASH_CODE,
    "ZAP Scan": DEDUPE_ALGO_HASH_CODE,
    "Qualys Scan": DEDUPE_ALGO_HASH_CODE,
    "PHP Symfony Security Check": DEDUPE_ALGO_HASH_CODE,
    "Acunetix Scan": DEDUPE_ALGO_HASH_CODE,
    "Clair Scan": DEDUPE_ALGO_HASH_CODE,
    # 'Qualys Webapp Scan': DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,  # Must also uncomment qualys webapp line in hashcode fields per scanner
    "Veracode Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Veracode SourceClear Scan": DEDUPE_ALGO_HASH_CODE,
    # for backwards compatibility because someone decided to rename this scanner:
    "Symfony Security Check": DEDUPE_ALGO_HASH_CODE,
    "DSOP Scan": DEDUPE_ALGO_HASH_CODE,
    "Terrascan Scan": DEDUPE_ALGO_HASH_CODE,
    "Trivy Operator Scan": DEDUPE_ALGO_HASH_CODE,
    "Trivy Scan": DEDUPE_ALGO_HASH_CODE,
    "TFSec Scan": DEDUPE_ALGO_HASH_CODE,
    "HackerOne Cases": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Snyk Scan": DEDUPE_ALGO_HASH_CODE,
    "GitLab Dependency Scanning Report": DEDUPE_ALGO_HASH_CODE,
    "GitLab SAST Report": DEDUPE_ALGO_HASH_CODE,
    "Govulncheck Scanner": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "GitLab Container Scan": DEDUPE_ALGO_HASH_CODE,
    "GitLab Secret Detection Report": DEDUPE_ALGO_HASH_CODE,
    "Checkov Scan": DEDUPE_ALGO_HASH_CODE,
    "SpotBugs Scan": DEDUPE_ALGO_HASH_CODE,
    "JFrog Xray Unified Scan": DEDUPE_ALGO_HASH_CODE,
    "JFrog Xray On Demand Binary Scan": DEDUPE_ALGO_HASH_CODE,
    "Scout Suite Scan": DEDUPE_ALGO_HASH_CODE,
    "AWS Security Hub Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Meterian Scan": DEDUPE_ALGO_HASH_CODE,
    "Github Vulnerability Scan": DEDUPE_ALGO_HASH_CODE,
    "Cloudsploit Scan": DEDUPE_ALGO_HASH_CODE,
    "SARIF": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Azure Security Center Recommendations Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Hadolint Dockerfile check": DEDUPE_ALGO_HASH_CODE,
    "Semgrep JSON Report": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Generic Findings Import": DEDUPE_ALGO_HASH_CODE,
    "Trufflehog Scan": DEDUPE_ALGO_HASH_CODE,
    "Trufflehog3 Scan": DEDUPE_ALGO_HASH_CODE,
    "Detect-secrets Scan": DEDUPE_ALGO_HASH_CODE,
    "Solar Appscreener Scan": DEDUPE_ALGO_HASH_CODE,
    "Gitleaks Scan": DEDUPE_ALGO_HASH_CODE,
    "pip-audit Scan": DEDUPE_ALGO_HASH_CODE,
    "Nancy Scan": DEDUPE_ALGO_HASH_CODE,
    "Edgescan Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Bugcrowd API Import": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Rubocop Scan": DEDUPE_ALGO_HASH_CODE,
    "JFrog Xray Scan": DEDUPE_ALGO_HASH_CODE,
    "CycloneDX Scan": DEDUPE_ALGO_HASH_CODE,
    "SSLyze Scan (JSON)": DEDUPE_ALGO_HASH_CODE,
    "Harbor Vulnerability Scan": DEDUPE_ALGO_HASH_CODE,
    "Rusty Hog Scan": DEDUPE_ALGO_HASH_CODE,
    "StackHawk HawkScan": DEDUPE_ALGO_HASH_CODE,
    "Hydra Scan": DEDUPE_ALGO_HASH_CODE,
    "DrHeader JSON Importer": DEDUPE_ALGO_HASH_CODE,
    "PWN SAST": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Whispers": DEDUPE_ALGO_HASH_CODE,
    "Blackduck Hub Scan": DEDUPE_ALGO_HASH_CODE,
    "BlackDuck API": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Blackduck Binary Analysis": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "docker-bench-security Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Vulners Scan": DEDUPE_ALGO_HASH_CODE,
    "Twistlock Image Scan": DEDUPE_ALGO_HASH_CODE,
    "NeuVector (REST)": DEDUPE_ALGO_HASH_CODE,
    "NeuVector (compliance)": DEDUPE_ALGO_HASH_CODE,
    "Wpscan": DEDUPE_ALGO_HASH_CODE,
    "Popeye Scan": DEDUPE_ALGO_HASH_CODE,
    "Nuclei Scan": DEDUPE_ALGO_HASH_CODE,
    "KubeHunter Scan": DEDUPE_ALGO_HASH_CODE,
    "kube-bench Scan": DEDUPE_ALGO_HASH_CODE,
    "Threagile risks report": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Humble Json Importer": DEDUPE_ALGO_HASH_CODE,
    "Wazuh Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "MSDefender Parser": DEDUPE_ALGO_HASH_CODE,
    "HCLAppScan XML": DEDUPE_ALGO_HASH_CODE,
    "KICS Scan": DEDUPE_ALGO_HASH_CODE,
    "MobSF Scan": DEDUPE_ALGO_HASH_CODE,
    "MobSF Scorecard Scan": DEDUPE_ALGO_HASH_CODE,
    "OSV Scan": DEDUPE_ALGO_HASH_CODE,
    "Nosey Parker Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Bearer CLI": DEDUPE_ALGO_HASH_CODE,
    "Wiz Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Deepfence Threatmapper Report": DEDUPE_ALGO_HASH_CODE,
    "Kubescape JSON Importer": DEDUPE_ALGO_HASH_CODE,
    "Kiuwan SCA Scan": DEDUPE_ALGO_HASH_CODE,
    "Rapplex Scan": DEDUPE_ALGO_HASH_CODE,
    "AppCheck Web Application Scanner": DEDUPE_ALGO_HASH_CODE,
    "AWS Inspector2 Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Legitify Scan": DEDUPE_ALGO_HASH_CODE,
    "ThreatComposer Scan": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE,
    "Invicti Scan": DEDUPE_ALGO_HASH_CODE,
    "KrakenD Audit Scan": DEDUPE_ALGO_HASH_CODE,
    "PTART Report": DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    "Red Hat Satellite": DEDUPE_ALGO_HASH_CODE,
    "Qualys Hacker Guardian Scan": DEDUPE_ALGO_HASH_CODE,
}

# Override the hardcoded settings here via the env var
if len(env("DD_DEDUPLICATION_ALGORITHM_PER_PARSER")) > 0:
    env_dedup_algorithm_per_parser = json.loads(env("DD_DEDUPLICATION_ALGORITHM_PER_PARSER"))
    for key, value in env_dedup_algorithm_per_parser.items():
        if value not in DEDUPE_ALGOS:
            msg = f"DEDUP algorithm '{value}' for '{key}' is not valid. Use one of following values: {', '.join(DEDUPE_ALGOS)}"
            raise AttributeError(msg)
        if key in DEDUPLICATION_ALGORITHM_PER_PARSER:
            logger.info(f"Replacing {key} with value {value} (previously set to {DEDUPLICATION_ALGORITHM_PER_PARSER[key]}) from env var DD_DEDUPLICATION_ALGORITHM_PER_PARSER")
            DEDUPLICATION_ALGORITHM_PER_PARSER[key] = value
        if key not in DEDUPLICATION_ALGORITHM_PER_PARSER:
            logger.info(f"Adding {key} with value {value} from env var DD_DEDUPLICATION_ALGORITHM_PER_PARSER")
            DEDUPLICATION_ALGORITHM_PER_PARSER[key] = value

DUPE_DELETE_MAX_PER_RUN = env("DD_DUPE_DELETE_MAX_PER_RUN")

DISABLE_FINDING_MERGE = env("DD_DISABLE_FINDING_MERGE")

TRACK_IMPORT_HISTORY = env("DD_TRACK_IMPORT_HISTORY")

# ------------------------------------------------------------------------------
# JIRA
# ------------------------------------------------------------------------------
# The 'Bug' issue type is mandatory, as it is used as the default choice.
JIRA_ISSUE_TYPE_CHOICES_CONFIG = (
    ("Task", "Task"),
    ("Story", "Story"),
    ("Epic", "Epic"),
    ("Spike", "Spike"),
    ("Bug", "Bug"),
    ("Security", "Security"),
)

if env("DD_JIRA_EXTRA_ISSUE_TYPES") != "":
    for extra_type in env("DD_JIRA_EXTRA_ISSUE_TYPES").split(","):
        JIRA_ISSUE_TYPE_CHOICES_CONFIG += ((extra_type, extra_type),)

JIRA_SSL_VERIFY = env("DD_JIRA_SSL_VERIFY")

# ------------------------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------------------------
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING_HANDLER = env("DD_LOGGING_HANDLER")

LOG_LEVEL = env("DD_LOG_LEVEL")
if not LOG_LEVEL:
    LOG_LEVEL = "DEBUG" if DEBUG else "INFO"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s",
            "datefmt": "%d/%b/%Y %H:%M:%S",
        },
        "simple": {
            "format": "%(levelname)s %(funcName)s %(lineno)d %(message)s",
        },
        "json": {
            "()": "json_log_formatter.JSONFormatter",
        },
    },
    "filters": {
        "require_debug_false": {
            "()": "django.utils.log.RequireDebugFalse",
        },
        "require_debug_true": {
            "()": "django.utils.log.RequireDebugTrue",
        },
    },
    "handlers": {
        "mail_admins": {
            "level": "ERROR",
            "filters": ["require_debug_false"],
            "class": "django.utils.log.AdminEmailHandler",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "json_console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
    },
    "loggers": {
        "django.request": {
            "handlers": ["mail_admins", "console"],
            "level": str(LOG_LEVEL),
            "propagate": False,
        },
        "django.security": {
            "handlers": [rf"{LOGGING_HANDLER}"],
            "level": str(LOG_LEVEL),
            "propagate": False,
        },
        "celery": {
            "handlers": [rf"{LOGGING_HANDLER}"],
            "level": str(LOG_LEVEL),
            "propagate": False,
            # workaround some celery logging known issue
            "worker_hijack_root_logger": False,
        },
        "dojo": {
            "handlers": [rf"{LOGGING_HANDLER}"],
            "level": str(LOG_LEVEL),
            "propagate": False,
        },
        "dojo.specific-loggers.deduplication": {
            "handlers": [rf"{LOGGING_HANDLER}"],
            "level": str(LOG_LEVEL),
            "propagate": False,
        },
        "saml2": {
            "handlers": [rf"{LOGGING_HANDLER}"],
            "level": str(LOG_LEVEL),
            "propagate": False,
        },
        "MARKDOWN": {
            # The markdown library is too verbose in it's logging, reducing the verbosity in our logs.
            "handlers": [rf"{LOGGING_HANDLER}"],
            "level": str(LOG_LEVEL),
            "propagate": False,
        },
        "titlecase": {
            # The titlecase library is too verbose in it's logging, reducing the verbosity in our logs.
            "handlers": [rf"{LOGGING_HANDLER}"],
            "level": str(LOG_LEVEL),
            "propagate": False,
        },
    },
}

# override filter to ensure sensitive variables are also hidden when DEBUG = True
DEFAULT_EXCEPTION_REPORTER_FILTER = "dojo.settings.exception_filter.CustomExceptionReporterFilter"

# Issue on benchmark : "The number of GET/POST parameters exceeded settings.DATA_UPLOAD_MAX_NUMBER_FIELD S"
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10240

# Maximum size of a scan file in MB
SCAN_FILE_MAX_SIZE = env("DD_SCAN_FILE_MAX_SIZE")

# Apply a severity level to "Security Weaknesses" in Qualys WAS
QUALYS_WAS_WEAKNESS_IS_VULN = env("DD_QUALYS_WAS_WEAKNESS_IS_VULN")

# Create a unique finding for all findings in qualys WAS parser
# If using this, lines for Qualys WAS deduplication functions must be un-commented
QUALYS_WAS_UNIQUE_ID = False

# exclusion list for parsers
PARSER_EXCLUDE = env("DD_PARSER_EXCLUDE")

SERIALIZATION_MODULES = {
    "xml": "tagulous.serializers.xml_serializer",
    "json": "tagulous.serializers.json",
    "python": "tagulous.serializers.python",
    "yaml": "tagulous.serializers.pyyaml",
}

# There seems to be no way just use the default and just leave out jquery, so we have to copy...
# ... and keep it up-to-date.
TAGULOUS_AUTOCOMPLETE_JS = (
    # 'tagulous/lib/jquery.js',
    "tagulous/lib/select2-4/js/select2.full.min.js",
    "tagulous/tagulous.js",
    "tagulous/adaptor/select2-4.js",
)

# using 'element' for width should take width from css defined in template, but it doesn't. So set to 70% here.
TAGULOUS_AUTOCOMPLETE_SETTINGS = {"placeholder": "Enter some tags (comma separated, use enter to select / create a new tag)", "width": "70%"}

EDITABLE_MITIGATED_DATA = env("DD_EDITABLE_MITIGATED_DATA")

# FEATURE_FINDING_GROUPS feature is moved to system_settings, will be removed from settings file
FEATURE_FINDING_GROUPS = env("DD_FEATURE_FINDING_GROUPS")
JIRA_TEMPLATE_ROOT = env("DD_JIRA_TEMPLATE_ROOT")
TEMPLATE_DIR_PREFIX = env("DD_TEMPLATE_DIR_PREFIX")

DUPLICATE_CLUSTER_CASCADE_DELETE = env("DD_DUPLICATE_CLUSTER_CASCADE_DELETE")

# Deside if SonarQube API parser should download the security hotspots
SONARQUBE_API_PARSER_HOTSPOTS = env("DD_SONARQUBE_API_PARSER_HOTSPOTS")

# when enabled, finding importing will occur asynchronously, default False
ASYNC_FINDING_IMPORT = env("DD_ASYNC_FINDING_IMPORT")
# The number of findings to be processed per celeryworker
ASYNC_FINDING_IMPORT_CHUNK_SIZE = env("DD_ASYNC_FINDING_IMPORT_CHUNK_SIZE")
# When enabled, deleting objects will be occur from the bottom up. In the example of deleting an engagement
# The objects will be deleted as follows Endpoints -> Findings -> Tests -> Engagement
ASYNC_OBJECT_DELETE = env("DD_ASYNC_OBJECT_DELETE")
# The number of objects to be deleted per celeryworker
ASYNC_OBEJECT_DELETE_CHUNK_SIZE = env("DD_ASYNC_OBEJECT_DELETE_CHUNK_SIZE")
# When enabled, display the preview of objects to be deleted. This can take a long time to render
# for very large objects
DELETE_PREVIEW = env("DD_DELETE_PREVIEW")

# django-auditlog imports django-jsonfield-backport raises a warning that can be ignored,
# see https://github.com/laymonage/django-jsonfield-backport
SILENCED_SYSTEM_CHECKS = ["django_jsonfield_backport.W001"]

VULNERABILITY_URLS = {
    "CVE": "https://nvd.nist.gov/vuln/detail/",
    "GHSA": "https://github.com/advisories/",
    "OSV": "https://osv.dev/vulnerability/",
    "PYSEC": "https://osv.dev/vulnerability/",
    "SNYK": "https://snyk.io/vuln/",
    "RUSTSEC": "https://rustsec.org/advisories/",
    "VNS": "https://vulners.com/",
    "RHSA": "https://access.redhat.com/errata/",
    "RHBA": "https://access.redhat.com/errata/",
    "RHEA": "https://access.redhat.com/errata/",
    "FEDORA": "https://bodhi.fedoraproject.org/updates/",
    "ALSA": "https://osv.dev/vulnerability/",  # e.g. https://osv.dev/vulnerability/ALSA-2024:0827
    "ALBA": "https://osv.dev/vulnerability/",  # e.g. https://osv.dev/vulnerability/ALBA-2019:3411
    "USN": "https://ubuntu.com/security/notices/",  # e.g. https://ubuntu.com/security/notices/USN-6642-1
    "DLA": "https://security-tracker.debian.org/tracker/",  # e.g. https://security-tracker.debian.org/tracker/DLA-3917-1
    "DSA": "https://security-tracker.debian.org/tracker/",  # e.g. https://security-tracker.debian.org/tracker/DSA-5791-1
    "DTSA": "https://security-tracker.debian.org/tracker/",  # e.g. https://security-tracker.debian.org/tracker/DTSA-41-1
    "TEMP": "https://security-tracker.debian.org/tracker/",  # e.g. https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF
    "ELSA": "https://linux.oracle.com/errata/&&.html",  # e.g. https://linux.oracle.com/errata/ELSA-2024-12714.html
    "ELBA": "https://linux.oracle.com/errata/&&.html",  # e.g. https://linux.oracle.com/errata/ELBA-2024-7457.html
    "RXSA": "https://errata.rockylinux.org/",  # e.g. https://errata.rockylinux.org/RXSA-2024:4928
    "C-": "https://hub.armosec.io/docs/",  # e.g. https://hub.armosec.io/docs/c-0085
    "AVD": "https://avd.aquasec.com/misconfig/",  # e.g. https://avd.aquasec.com/misconfig/avd-ksv-01010
    "KHV": "https://avd.aquasec.com/misconfig/kubernetes/",  # e.g. https://avd.aquasec.com/misconfig/kubernetes/khv045
    "CAPEC": "https://capec.mitre.org/data/definitions/&&.html",  # e.g. https://capec.mitre.org/data/definitions/157.html
    "CWE": "https://cwe.mitre.org/data/definitions/&&.html",  # e.g. https://cwe.mitre.org/data/definitions/79.html
    "GLSA": "https://security.gentoo.org/",  # e.g. https://security.gentoo.org/glsa/202409-32
    "RLSA": "https://errata.rockylinux.org/",  # e.g. https://errata.rockylinux.org/RLSA-2024:7001
    "RLBA": "https://errata.rockylinux.org/",  # e.g. https://errata.rockylinux.org/RLBA-2024:6968
    "CGA": "https://images.chainguard.dev/security/",  # e.g. https://images.chainguard.dev/security/CGA-24pq-h5fw-43v3
}
# List of acceptable file types that can be uploaded to a given object via arbitrary file upload
FILE_UPLOAD_TYPES = env("DD_FILE_UPLOAD_TYPES")
# Fixes error
# AttributeError: Problem installing fixture '/app/dojo/fixtures/defect_dojo_sample_data.json': 'Settings' object has no attribute 'AUDITLOG_DISABLE_ON_RAW_SAVE'
AUDITLOG_DISABLE_ON_RAW_SAVE = False
#  You can set extra Jira headers by suppling a dictionary in header: value format (pass as env var like "headr_name=value,another_header=anohter_value")
ADDITIONAL_HEADERS = env("DD_ADDITIONAL_HEADERS")
# Dictates whether cloud banner is created or not
CREATE_CLOUD_BANNER = env("DD_CREATE_CLOUD_BANNER")

# ------------------------------------------------------------------------------
# Auditlog
# ------------------------------------------------------------------------------
AUDITLOG_FLUSH_RETENTION_PERIOD = env("DD_AUDITLOG_FLUSH_RETENTION_PERIOD")
ENABLE_AUDITLOG = env("DD_ENABLE_AUDITLOG")
USE_FIRST_SEEN = env("DD_USE_FIRST_SEEN")
USE_QUALYS_LEGACY_SEVERITY_PARSING = env("DD_QUALYS_LEGACY_SEVERITY_PARSING")

# ------------------------------------------------------------------------------
# Notifications
# ------------------------------------------------------------------------------
NOTIFICATIONS_SYSTEM_LEVEL_TRUMP = env("DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP")

# ------------------------------------------------------------------------------
# Timeouts
# ------------------------------------------------------------------------------
REQUESTS_TIMEOUT = env("DD_REQUESTS_TIMEOUT")

# ------------------------------------------------------------------------------
# Ignored Warnings
# ------------------------------------------------------------------------------
# These warnings are produce by polymorphic beacuser of weirdness around cascade deletes. We had to do
# some pretty out of pocket things to correct this behaviors to correct this weirdness, and therefore
# some warnings are produced trying to steer us in the right direction. Ignore those
# Reference issue: https://github.com/jazzband/django-polymorphic/issues/229
warnings.filterwarnings("ignore", message="polymorphic.base.ManagerInheritanceWarning.*")
warnings.filterwarnings("ignore", message="PolymorphicModelBase._default_manager.*")


# The setting is here to avoid RemovedInDjango60Warning. It is here only for transition period.
# TODO: - Remove this setting in Django 6.0
# TODO: More info:
# Context:
# uwsgi-1  |   File "/app/dojo/forms.py", line 515, in ImportScanForm
# uwsgi-1  |     source_code_management_uri = forms.URLField(max_length=600, required=False, help_text="Resource link to source code")
# uwsgi-1  |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# uwsgi-1  |   File "/usr/local/lib/python3.11/site-packages/django/forms/fields.py", line 769, in __init__
# uwsgi-1  |     warnings.warn(
# uwsgi-1  | django.utils.deprecation.RemovedInDjango60Warning: The default scheme will be changed from 'http' to 'https' in Django 6.0. Pass the forms.URLField.assume_scheme argument to silence this warning, or set the FORMS_URLFIELD_ASSUME_HTTPS transitional setting to True to opt into using 'https' as the new default scheme.
# +
# uwsgi-1  |   File "/usr/local/lib/python3.11/site-packages/django/conf/__init__.py", line 214, in __init__
# uwsgi-1  |     warnings.warn(
# uwsgi-1  | django.utils.deprecation.RemovedInDjango60Warning: The FORMS_URLFIELD_ASSUME_HTTPS transitional setting is deprecated.
warnings.filterwarnings("ignore", "The FORMS_URLFIELD_ASSUME_HTTPS transitional setting is deprecated.")
FORMS_URLFIELD_ASSUME_HTTPS = True
# Inspired by https://adamj.eu/tech/2023/12/07/django-fix-urlfield-assume-scheme-warnings/
