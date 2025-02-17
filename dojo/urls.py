import logging

from django.conf import settings
from django.conf.urls import include
from django.contrib import admin
from django.http import HttpResponse
from django.urls import re_path
from drf_spectacular.views import SpectacularSwaggerView
from rest_framework.authtoken import views as tokenviews
from rest_framework.routers import DefaultRouter

from dojo import views
from dojo.announcement.urls import urlpatterns as announcement_urls
from dojo.api_v2.views import (
    AnnouncementViewSet,
    AppAnalysisViewSet,
    BurpRawRequestResponseViewSet,
    ConfigurationPermissionViewSet,
    CredentialsMappingViewSet,
    CredentialsViewSet,
    DevelopmentEnvironmentViewSet,
    DojoGroupMemberViewSet,
    DojoGroupViewSet,
    DojoMetaViewSet,
    EndpointMetaImporterView,
    EndpointStatusViewSet,
    EndPointViewSet,
    EngagementPresetsViewset,
    EngagementViewSet,
    FindingTemplatesViewSet,
    FindingViewSet,
    GlobalRoleViewSet,
    ImportLanguagesView,
    ImportScanView,
    JiraInstanceViewSet,
    JiraIssuesViewSet,
    JiraProjectViewSet,
    LanguageTypeViewSet,
    LanguageViewSet,
    NetworkLocationsViewset,
    NotesViewSet,
    NoteTypeViewSet,
    NotificationsViewSet,
    NotificationWebhooksViewSet,
    ProductAPIScanConfigurationViewSet,
    ProductGroupViewSet,
    ProductMemberViewSet,
    ProductTypeGroupViewSet,
    ProductTypeMemberViewSet,
    ProductTypeViewSet,
    ProductViewSet,
    QuestionnaireAnsweredSurveyViewSet,
    QuestionnaireAnswerViewSet,
    QuestionnaireEngagementSurveyViewSet,
    QuestionnaireGeneralSurveyViewSet,
    QuestionnaireQuestionViewSet,
    RegulationsViewSet,
    ReImportScanView,
    RiskAcceptanceViewSet,
    RoleViewSet,
    SLAConfigurationViewset,
    SonarqubeIssueTransitionViewSet,
    SonarqubeIssueViewSet,
    StubFindingsViewSet,
    SystemSettingsViewSet,
    TestImportViewSet,
    TestsViewSet,
    TestTypesViewSet,
    ToolConfigurationsViewSet,
    ToolProductSettingsViewSet,
    ToolTypesViewSet,
    UserContactInfoViewSet,
    UserProfileView,
    UsersViewSet,
)
from dojo.api_v2.views import DojoSpectacularAPIView as SpectacularAPIView
from dojo.banner.urls import urlpatterns as banner_urls
from dojo.benchmark.urls import urlpatterns as benchmark_urls
from dojo.components.urls import urlpatterns as component_urls
from dojo.cred.urls import urlpatterns as cred_urls
from dojo.development_environment.urls import urlpatterns as dev_env_urls
from dojo.endpoint.urls import urlpatterns as endpoint_urls
from dojo.engagement.urls import urlpatterns as eng_urls
from dojo.finding.urls import urlpatterns as finding_urls
from dojo.finding_group.urls import urlpatterns as finding_group_urls
from dojo.github_issue_link.urls import urlpatterns as github_urls
from dojo.group.urls import urlpatterns as group_urls
from dojo.home.urls import urlpatterns as home_urls
from dojo.jira_link.urls import urlpatterns as jira_urls
from dojo.linear.urls import urlpatterns as linear_urls
from dojo.metrics.urls import urlpatterns as metrics_urls
from dojo.note_type.urls import urlpatterns as note_type_urls
from dojo.notes.urls import urlpatterns as notes_urls
from dojo.notifications.urls import urlpatterns as notifications_urls
from dojo.object.urls import urlpatterns as object_urls
from dojo.product.urls import urlpatterns as prod_urls
from dojo.product_type.urls import urlpatterns as pt_urls
from dojo.regulations.urls import urlpatterns as regulations
from dojo.reports.urls import urlpatterns as reports_urls
from dojo.search.urls import urlpatterns as search_urls
from dojo.sla_config.urls import urlpatterns as sla_urls
from dojo.survey.urls import urlpatterns as survey_urls
from dojo.system_settings.urls import urlpatterns as system_settings_urls
from dojo.test.urls import urlpatterns as test_urls
from dojo.test_type.urls import urlpatterns as test_type_urls
from dojo.tool_config.urls import urlpatterns as tool_config_urls
from dojo.tool_product.urls import urlpatterns as tool_product_urls
from dojo.tool_type.urls import urlpatterns as tool_type_urls
from dojo.user.urls import urlpatterns as user_urls
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)

admin.autodiscover()

# custom handlers
handler500 = "dojo.views.custom_error_view"
handler400 = "dojo.views.custom_bad_request_view"

# v2 api written in django-rest-framework
v2_api = DefaultRouter()
v2_api.register(r"announcements", AnnouncementViewSet, basename="announcement")
v2_api.register(r"configuration_permissions", ConfigurationPermissionViewSet, basename="permission")
v2_api.register(r"credential_mappings", CredentialsMappingViewSet, basename="cred_mapping")
v2_api.register(r"credentials", CredentialsViewSet, basename="cred_user")
v2_api.register(r"development_environments", DevelopmentEnvironmentViewSet, basename="development_environment")
v2_api.register(r"dojo_groups", DojoGroupViewSet, basename="dojo_group")
v2_api.register(r"dojo_group_members", DojoGroupMemberViewSet, basename="dojo_group_member")
v2_api.register(r"endpoints", EndPointViewSet, basename="endpoint")
v2_api.register(r"endpoint_meta_import", EndpointMetaImporterView, basename="endpointmetaimport")
v2_api.register(r"endpoint_status", EndpointStatusViewSet, basename="endpoint_status")
v2_api.register(r"engagements", EngagementViewSet, basename="engagement")
v2_api.register(r"engagement_presets", EngagementPresetsViewset, basename="engagement_presets")
v2_api.register(r"finding_templates", FindingTemplatesViewSet, basename="finding_template")
v2_api.register(r"findings", FindingViewSet, basename="finding")
v2_api.register(r"global_roles", GlobalRoleViewSet, basename="global_role")
v2_api.register(r"import-languages", ImportLanguagesView, basename="importlanguages")
v2_api.register(r"import-scan", ImportScanView, basename="importscan")
v2_api.register(r"jira_instances", JiraInstanceViewSet, basename="jira_instance")
v2_api.register(r"jira_configurations", JiraInstanceViewSet, basename="jira_configurations")  # backwards compatibility
v2_api.register(r"jira_finding_mappings", JiraIssuesViewSet, basename="jira_issue")
v2_api.register(r"jira_product_configurations", JiraProjectViewSet, basename="jira_product_configurations")  # backwards compatibility
v2_api.register(r"jira_projects", JiraProjectViewSet, basename="jira_project")
v2_api.register(r"languages", LanguageViewSet, basename="languages")
v2_api.register(r"language_types", LanguageTypeViewSet, basename="language_type")
v2_api.register(r"metadata", DojoMetaViewSet, basename="metadata")
v2_api.register(r"network_locations", NetworkLocationsViewset, basename="network_locations")
v2_api.register(r"notes", NotesViewSet, basename="notes")
v2_api.register(r"note_type", NoteTypeViewSet, basename="note_type")
v2_api.register(r"notifications", NotificationsViewSet, basename="notifications")
v2_api.register(r"notification_webhooks", NotificationWebhooksViewSet)
v2_api.register(r"products", ProductViewSet, basename="product")
v2_api.register(r"product_api_scan_configurations", ProductAPIScanConfigurationViewSet, basename="product_api_scan_configuration")
v2_api.register(r"product_groups", ProductGroupViewSet, basename="product_group")
v2_api.register(r"product_members", ProductMemberViewSet, basename="product_member")
v2_api.register(r"product_types", ProductTypeViewSet, basename="product_type")
v2_api.register(r"product_type_members", ProductTypeMemberViewSet, basename="product_type_member")
v2_api.register(r"product_type_groups", ProductTypeGroupViewSet, basename="product_type_group")
v2_api.register(r"regulations", RegulationsViewSet, basename="regulations")
v2_api.register(r"reimport-scan", ReImportScanView, basename="reimportscan")
v2_api.register(r"request_response_pairs", BurpRawRequestResponseViewSet, basename="request_response_pairs")
v2_api.register(r"risk_acceptance", RiskAcceptanceViewSet, basename="risk_acceptance")
v2_api.register(r"roles", RoleViewSet, basename="role")
v2_api.register(r"sla_configurations", SLAConfigurationViewset, basename="sla_configurations")
v2_api.register(r"sonarqube_issues", SonarqubeIssueViewSet, basename="sonarqube_issue")
v2_api.register(r"sonarqube_transitions", SonarqubeIssueTransitionViewSet, basename="sonarqube_issue_transition")
v2_api.register(r"stub_findings", StubFindingsViewSet, basename="stub_finding")
v2_api.register(r"system_settings", SystemSettingsViewSet, basename="system_settings")
v2_api.register(r"technologies", AppAnalysisViewSet, basename="app_analysis")
v2_api.register(r"tests", TestsViewSet, basename="test")
v2_api.register(r"test_types", TestTypesViewSet, basename="test_type")
v2_api.register(r"test_imports", TestImportViewSet, basename="test_imports")
v2_api.register(r"tool_configurations", ToolConfigurationsViewSet, basename="tool_configuration")
v2_api.register(r"tool_product_settings", ToolProductSettingsViewSet, basename="tool_product_settings")
v2_api.register(r"tool_types", ToolTypesViewSet, basename="tool_type")
v2_api.register(r"users", UsersViewSet, basename="user")
v2_api.register(r"user_contact_infos", UserContactInfoViewSet, basename="usercontactinfo")
v2_api.register(r"questionnaire_answers", QuestionnaireAnswerViewSet, basename="answer")
v2_api.register(r"questionnaire_answered_questionnaires", QuestionnaireAnsweredSurveyViewSet, basename="answered_survey")
v2_api.register(r"questionnaire_engagement_questionnaires", QuestionnaireEngagementSurveyViewSet, basename="engagement_survey")
v2_api.register(r"questionnaire_general_questionnaires", QuestionnaireGeneralSurveyViewSet, basename="general_survey")
v2_api.register(r"questionnaire_questions", QuestionnaireQuestionViewSet, basename="question")
ur = []
ur += dev_env_urls
ur += endpoint_urls
ur += eng_urls
ur += finding_urls
ur += finding_group_urls
ur += home_urls
ur += metrics_urls
ur += prod_urls
ur += pt_urls
ur += reports_urls
ur += search_urls
ur += test_type_urls
ur += test_urls
ur += user_urls
ur += group_urls
ur += jira_urls
ur += linear_urls
ur += github_urls
ur += tool_type_urls
ur += tool_config_urls
ur += tool_product_urls
ur += cred_urls
ur += sla_urls
ur += system_settings_urls
ur += notifications_urls
ur += object_urls
ur += benchmark_urls
ur += notes_urls
ur += note_type_urls
ur += banner_urls
ur += component_urls
ur += regulations
ur += announcement_urls

api_v2_urls = [
    #  Django Rest Framework API v2
    re_path(r"^{}api/v2/".format(get_system_setting("url_prefix")), include(v2_api.urls)),
    re_path(r"^{}api/v2/user_profile/".format(get_system_setting("url_prefix")), UserProfileView.as_view(), name="user_profile"),
]

if hasattr(settings, "API_TOKENS_ENABLED") and hasattr(settings, "API_TOKEN_AUTH_ENDPOINT_ENABLED"):
    if settings.API_TOKENS_ENABLED and settings.API_TOKEN_AUTH_ENDPOINT_ENABLED:
        api_v2_urls += [
            re_path(
                f"^{get_system_setting('url_prefix')}api/v2/api-token-auth/",
                tokenviews.obtain_auth_token,
                name="api-token-auth",
            ),
        ]

urlpatterns = []

# sometimes urlpatterns needed be added from local_settings.py before other URLs of core dojo
if hasattr(settings, "PRELOAD_URL_PATTERNS"):
    urlpatterns += settings.PRELOAD_URL_PATTERNS

urlpatterns += [
    # action history
    re_path(r"^{}history/(?P<cid>\d+)/(?P<oid>\d+)$".format(get_system_setting("url_prefix")), views.action_history, name="action_history"),
    re_path(r"^{}".format(get_system_setting("url_prefix")), include(ur)),

    # drf-spectacular = OpenAPI3
    re_path(r"^{}api/v2/oa3/schema/".format(get_system_setting("url_prefix")), SpectacularAPIView.as_view(), name="schema_oa3"),
    re_path(r"^{}api/v2/oa3/swagger-ui/".format(get_system_setting("url_prefix")), SpectacularSwaggerView.as_view(url=get_system_setting("url_prefix") + "/api/v2/oa3/schema/?format=json"), name="swagger-ui_oa3"),

    re_path(r"^robots.txt", lambda _: HttpResponse("User-Agent: *\nDisallow: /", content_type="text/plain"), name="robots_file"),
    re_path(r"^manage_files/(?P<oid>\d+)/(?P<obj_type>\w+)$", views.manage_files, name="manage_files"),
    re_path(r"^access_file/(?P<fid>\d+)/(?P<oid>\d+)/(?P<obj_type>\w+)$", views.access_file, name="access_file"),
    re_path(r"^{}/(?P<path>.*)$".format(settings.MEDIA_URL.strip("/")), views.protected_serve, {"document_root": settings.MEDIA_ROOT}),
]

urlpatterns += api_v2_urls
urlpatterns += survey_urls

if hasattr(settings, "DJANGO_METRICS_ENABLED"):
    if settings.DJANGO_METRICS_ENABLED:
        urlpatterns += [re_path(r"^{}django_metrics/".format(get_system_setting("url_prefix")), include("django_prometheus.urls"))]

if hasattr(settings, "SAML2_ENABLED"):
    if settings.SAML2_ENABLED:
        # django saml2
        urlpatterns += [re_path(r"^saml2/", include("djangosaml2.urls"))]

if hasattr(settings, "DJANGO_ADMIN_ENABLED"):
    if settings.DJANGO_ADMIN_ENABLED:
        #  django admin
        urlpatterns += [re_path(r"^{}admin/".format(get_system_setting("url_prefix")), admin.site.urls)]

# sometimes urlpatterns needed be added from local_settings.py to avoid having to modify core defect dojo files
if hasattr(settings, "EXTRA_URL_PATTERNS"):
    urlpatterns += settings.EXTRA_URL_PATTERNS


# Remove any other endpoints that drf-spectacular is guessing should be in the swagger
def drf_spectacular_preprocessing_filter_spec(endpoints):
    filtered = []
    for (path, path_regex, method, callback) in endpoints:
        # Remove all but DRF API endpoints
        if path.startswith("/api/v2/"):
            filtered.append((path, path_regex, method, callback))
    return filtered
