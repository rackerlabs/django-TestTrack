import base64
import logging
import mimetypes
from datetime import datetime

import tagulous
from crum import get_current_user
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.renderers import OpenApiJsonRenderer2
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from drf_spectacular.views import SpectacularAPIView
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.generics import GenericAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.response import Response

import dojo.jira_link.helper as jira_helper
from dojo.api_v2 import (
    mixins as dojo_mixins,
)
from dojo.api_v2 import (
    permissions,
    prefetch,
    serializers,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.cred.queries import get_authorized_cred_mappings
from dojo.endpoint.queries import (
    get_authorized_endpoint_status,
    get_authorized_endpoints,
)
from dojo.endpoint.views import get_endpoint_ids
from dojo.engagement.queries import get_authorized_engagements
from dojo.engagement.services import close_engagement, reopen_engagement
from dojo.filters import (
    ApiAppAnalysisFilter,
    ApiCredentialsFilter,
    ApiEndpointFilter,
    ApiEngagementFilter,
    ApiFindingFilter,
    ApiProductFilter,
    ApiRiskAcceptanceFilter,
    ApiTemplateFindingFilter,
    ApiTestFilter,
    ReportFindingFilter,
    ReportFindingFilterWithoutObjectLookups,
    TestImportAPIFilter,
)
from dojo.finding.queries import (
    get_authorized_findings,
    get_authorized_stub_findings,
)
from dojo.finding.views import (
    duplicate_cluster,
    reset_finding_duplicate_status_internal,
    set_finding_as_original_internal,
)
from dojo.group.queries import (
    get_authorized_group_members,
    get_authorized_groups,
)
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.jira_link.queries import (
    get_authorized_jira_issues,
    get_authorized_jira_projects,
)
from dojo.models import (
    Announcement,
    Answer,
    Answered_Survey,
    App_Analysis,
    BurpRawRequestResponse,
    Check_List,
    Cred_Mapping,
    Cred_User,
    Development_Environment,
    Dojo_Group,
    Dojo_Group_Member,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Presets,
    Engagement_Survey,
    FileUpload,
    Finding,
    Finding_Template,
    General_Survey,
    Global_Role,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Language_Type,
    Languages,
    Network_Locations,
    Note_Type,
    Notes,
    Notification_Webhooks,
    Notifications,
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
    Question,
    Regulation,
    Risk_Acceptance,
    Role,
    SLA_Configuration,
    Sonarqube_Issue,
    Sonarqube_Issue_Transition,
    Stub_Finding,
    System_Settings,
    Test,
    Test_Import,
    Test_Type,
    Tool_Configuration,
    Tool_Product_Settings,
    Tool_Type,
    User,
    UserContactInfo,
)
from dojo.product.queries import (
    get_authorized_app_analysis,
    get_authorized_dojo_meta,
    get_authorized_engagement_presets,
    get_authorized_languages,
    get_authorized_product_api_scan_configurations,
    get_authorized_product_groups,
    get_authorized_product_members,
    get_authorized_products,
)
from dojo.product_type.queries import (
    get_authorized_product_type_groups,
    get_authorized_product_type_members,
    get_authorized_product_types,
)
from dojo.reports.views import (
    prefetch_related_findings_for_report,
    report_url_resolver,
)
from dojo.risk_acceptance import api as ra_api
from dojo.risk_acceptance.helper import remove_finding_from_risk_acceptance
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.test.queries import get_authorized_test_imports, get_authorized_tests
from dojo.tool_product.queries import get_authorized_tool_product_settings
from dojo.user.utils import get_configuration_permissions_codenames
from dojo.utils import (
    async_delete,
    generate_file_response,
    get_setting,
    get_system_setting,
)

logger = logging.getLogger(__name__)


def schema_with_prefetch() -> dict:
    return {
        "list": extend_schema(
            parameters=[
                OpenApiParameter(
                    "prefetch",
                    OpenApiTypes.STR,
                    OpenApiParameter.QUERY,
                    required=False,
                    description="List of fields for which to prefetch model instances and add those to the response",
                ),
            ],
        ),
        "retrieve": extend_schema(
            parameters=[
                OpenApiParameter(
                    "prefetch",
                    OpenApiTypes.STR,
                    OpenApiParameter.QUERY,
                    required=False,
                    description="List of fields for which to prefetch model instances and add those to the response",
                ),
            ],
        ),
    }


class DojoOpenApiJsonRenderer(OpenApiJsonRenderer2):
    def get_indent(self, accepted_media_type, renderer_context):
        if accepted_media_type and "indent" in accepted_media_type:
            return super().get_indent(accepted_media_type, renderer_context)
        return renderer_context.get("indent", None)


class DojoSpectacularAPIView(SpectacularAPIView):
    renderer_classes = [DojoOpenApiJsonRenderer, *SpectacularAPIView.renderer_classes]


class DojoModelViewSet(
    viewsets.ModelViewSet,
    dojo_mixins.DeletePreviewModelMixin,
):
    pass


class PrefetchDojoModelViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    DojoModelViewSet,
):
    pass


# Authorization: authenticated users
class RoleViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = serializers.RoleSerializer
    queryset = Role.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name"]
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return Role.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class DojoGroupViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.DojoGroupSerializer
    queryset = Dojo_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "social_provider"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasDojoGroupPermission,
    )

    def get_queryset(self):
        return get_authorized_groups(Permissions.Group_View).distinct()


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class DojoGroupMemberViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.DojoGroupMemberSerializer
    queryset = Dojo_Group_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "group_id", "user_id"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasDojoGroupMemberPermission,
    )

    def get_queryset(self):
        return get_authorized_group_members(Permissions.Group_View).distinct()

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: superuser
@extend_schema_view(**schema_with_prefetch())
class GlobalRoleViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.GlobalRoleSerializer
    queryset = Global_Role.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "user", "group", "role"]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Global_Role.objects.all().order_by("id")


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class EndPointViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.EndpointSerializer
    queryset = Endpoint.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiEndpointFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEndpointPermission,
    )

    def get_queryset(self):
        return get_authorized_endpoints(Permissions.Endpoint_View).distinct()

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        endpoint = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, endpoint, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class EndpointStatusViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.EndpointStatusSerializer
    queryset = Endpoint_Status.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "mitigated",
        "false_positive",
        "out_of_scope",
        "risk_accepted",
        "mitigated_by",
        "finding",
        "endpoint",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEndpointStatusPermission,
    )

    def get_queryset(self):
        return get_authorized_endpoint_status(
            Permissions.Endpoint_View,
        ).distinct()


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class EngagementViewSet(
    PrefetchDojoModelViewSet,
    ra_api.AcceptedRisksMixin,
):
    serializer_class = serializers.EngagementSerializer
    queryset = Engagement.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiEngagementFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEngagementPermission,
    )

    @property
    def risk_application_model_class(self):
        return Engagement

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        return (
            get_authorized_engagements(Permissions.Engagement_View)
            .prefetch_related("notes", "risk_acceptance", "files")
            .distinct()
        )

    @extend_schema(
        request=OpenApiTypes.NONE, responses={status.HTTP_200_OK: ""},
    )
    @action(detail=True, methods=["post"])
    def close(self, request, pk=None):
        eng = self.get_object()
        close_engagement(eng)
        return HttpResponse()

    @extend_schema(
        request=OpenApiTypes.NONE, responses={status.HTTP_200_OK: ""},
    )
    @action(detail=True, methods=["post"])
    def reopen(self, request, pk=None):
        eng = self.get_object()
        reopen_engagement(eng)
        return HttpResponse()

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        engagement = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, engagement, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.EngagementToNotesSerializer,
        },
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"])
    def notes(self, request, pk=None):
        engagement = self.get_object()
        if request.method == "POST":
            new_note = serializers.AddNewNoteOptionSerializer(
                data=request.data,
            )
            if new_note.is_valid():
                entry = new_note.validated_data["entry"]
                private = new_note.validated_data.get("private", False)
                note_type = new_note.validated_data.get("note_type", None)
            else:
                return Response(
                    new_note.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            notes = engagement.notes.filter(note_type=note_type).first()
            if notes and note_type and note_type.is_single:
                return Response("Only one instance of this note_type allowed on an engagement.", status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(
                entry=entry,
                author=author,
                private=private,
                note_type=note_type,
            )
            note.save()
            engagement.notes.add(note)

            serialized_note = serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(
                serialized_note.data, status=status.HTTP_201_CREATED,
            )
        notes = engagement.notes.all()

        serialized_notes = serializers.EngagementToNotesSerializer(
            {"engagement_id": engagement, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.EngagementToFilesSerializer,
        },
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer},
    )
    @action(
        detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,),
    )
    def files(self, request, pk=None):
        engagement = self.get_object()
        if request.method == "POST":
            new_file = serializers.FileSerializer(data=request.data)
            if new_file.is_valid():
                title = new_file.validated_data["title"]
                file = new_file.validated_data["file"]
            else:
                return Response(
                    new_file.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            file = FileUpload(title=title, file=file)
            file.save()
            engagement.files.add(file)

            serialized_file = serializers.FileSerializer(file)
            return Response(
                serialized_file.data, status=status.HTTP_201_CREATED,
            )

        files = engagement.files.all()
        serialized_files = serializers.EngagementToFilesSerializer(
            {"engagement_id": engagement, "files": files},
        )
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["POST"],
        request=serializers.EngagementCheckListSerializer,
        responses={
            status.HTTP_201_CREATED: serializers.EngagementCheckListSerializer,
        },
    )
    @action(detail=True, methods=["get", "post"])
    def complete_checklist(self, request, pk=None):
        from dojo.api_v2.prefetch.prefetcher import _Prefetcher

        engagement = self.get_object()
        check_lists = Check_List.objects.filter(engagement=engagement)
        if request.method == "POST":
            if check_lists.count() > 0:
                return Response(
                    {
                        "message": "A completed checklist for this engagement already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            check_list = serializers.EngagementCheckListSerializer(
                data=request.data,
            )
            if not check_list.is_valid():
                return Response(
                    check_list.errors, status=status.HTTP_400_BAD_REQUEST,
                )
            check_list = Check_List(**check_list.data)
            check_list.engagement = engagement
            check_list.save()
            serialized_check_list = serializers.EngagementCheckListSerializer(
                check_list,
            )
            return Response(
                serialized_check_list.data, status=status.HTTP_201_CREATED,
            )
        prefetch_params = request.GET.get("prefetch", "").split(",")
        prefetcher = _Prefetcher()
        entry = check_lists.first()
        # Get the queried object representation
        result = serializers.EngagementCheckListSerializer(entry).data
        prefetcher._prefetch(entry, prefetch_params)
        result["prefetch"] = prefetcher.prefetched_data
        return Response(result, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        },
    )
    @action(
        detail=True,
        methods=["get"],
        url_path=r"files/download/(?P<file_id>\d+)",
    )
    def download_file(self, request, file_id, pk=None):
        engagement = self.get_object()
        # Get the file object
        file_object_qs = engagement.files.filter(id=file_id)
        file_object = (
            file_object_qs.first() if len(file_object_qs) > 0 else None
        )
        if file_object is None:
            return Response(
                {"error": "File ID not associated with Engagement"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # send file
        return generate_file_response(file_object)

    @extend_schema(
        request=serializers.EngagementUpdateJiraEpicSerializer,
        responses={status.HTTP_200_OK: serializers.EngagementUpdateJiraEpicSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def update_jira_epic(self, request, pk=None):
        engagement = self.get_object()
        try:

            if engagement.has_jira_issue:
                jira_helper.update_epic(engagement, **request.data)
                response = Response(
                    {"info": "Jira Epic update query sent"},
                    status=status.HTTP_200_OK,
                )
            else:
                jira_helper.add_epic(engagement, **request.data)
                response = Response(
                    {"info": "Jira Epic create query sent"},
                    status=status.HTTP_200_OK,
                )
        except ValidationError:
            return Response(
                {"error": "Bad Request!"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return response


# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class RiskAcceptanceViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.RiskAcceptanceSerializer
    queryset = Risk_Acceptance.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiRiskAcceptanceFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasRiskAcceptancePermission,
    )

    def destroy(self, request, pk=None):
        instance = self.get_object()
        # Remove any findings on the risk acceptance
        for finding in instance.accepted_findings.all():
            remove_finding_from_risk_acceptance(request.user, instance, finding)
        # return the response of the object being deleted
        return super().destroy(request, pk=pk)

    def get_queryset(self):
        return (
            get_authorized_risk_acceptances(Permissions.Risk_Acceptance)
            .prefetch_related(
                "notes", "engagement_set", "owner", "accepted_findings",
            )
            .distinct()
        )

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.RiskAcceptanceProofSerializer,
        },
    )
    @action(detail=True, methods=["get"])
    def download_proof(self, request, pk=None):
        risk_acceptance = self.get_object()
        # Get the file object
        file_object = risk_acceptance.path
        if file_object is None or risk_acceptance.filename() is None:
            return Response(
                {"error": "Proof has not provided to this risk acceptance..."},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Get the path of the file in media root
        file_path = f"{settings.MEDIA_ROOT}/{file_object.name}"
        file_handle = open(file_path, "rb")
        # send file
        response = FileResponse(
            file_handle,
            content_type=f"{mimetypes.guess_type(file_path)}",
            status=status.HTTP_200_OK,
        )
        response["Content-Length"] = file_object.size
        response[
            "Content-Disposition"
        ] = f'attachment; filename="{risk_acceptance.filename()}"'

        return response


# These are technologies in the UI and the API!
# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class AppAnalysisViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.AppAnalysisSerializer
    queryset = App_Analysis.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiAppAnalysisFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasAppAnalysisPermission,
    )

    def get_queryset(self):
        return get_authorized_app_analysis(Permissions.Product_View)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class CredentialsViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.CredentialSerializer
    queryset = Cred_User.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Cred_User.objects.all().order_by("id")


# Authorization: configuration
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class CredentialsMappingViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.CredentialMappingSerializer
    queryset = Cred_Mapping.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiCredentialsFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasCredentialPermission,
    )

    def get_queryset(self):
        return get_authorized_cred_mappings(Permissions.Credential_View)


# Authorization: configuration
class FindingTemplatesViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.FindingTemplateSerializer
    queryset = Finding_Template.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiTemplateFindingFilter
    permission_classes = (permissions.UserHasConfigurationPermissionStaff,)

    def get_queryset(self):
        return Finding_Template.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(
        parameters=[
            OpenApiParameter(
                "related_fields",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                required=False,
                description="Expand finding external relations (engagement, environment, product, \
                                            product_type, test, test_type)",
            ),
            OpenApiParameter(
                "prefetch",
                OpenApiTypes.STR,
                OpenApiParameter.QUERY,
                required=False,
                description="List of fields for which to prefetch model instances and add those to the response",
            ),
        ],
    ),
    retrieve=extend_schema(
        parameters=[
            OpenApiParameter(
                "related_fields",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                required=False,
                description="Expand finding external relations (engagement, environment, product, \
                                            product_type, test, test_type)",
            ),
            OpenApiParameter(
                "prefetch",
                OpenApiTypes.STR,
                OpenApiParameter.QUERY,
                required=False,
                description="List of fields for which to prefetch model instances and add those to the response",
            ),
        ],
    ),
)
class FindingViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    mixins.CreateModelMixin,
    ra_api.AcceptedFindingsMixin,
    viewsets.GenericViewSet,
    dojo_mixins.DeletePreviewModelMixin,
):
    serializer_class = serializers.FindingSerializer
    queryset = Finding.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiFindingFilter
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasFindingPermission,
    )

    # Overriding mixins.UpdateModeMixin perform_update() method to grab push_to_jira
    # data and add that as a parameter to .save()
    def perform_update(self, serializer):
        # IF JIRA is enabled and this product has a JIRA configuration
        push_to_jira = serializer.validated_data.get("push_to_jira")
        jira_project = jira_helper.get_jira_project(serializer.instance)
        if get_system_setting("enable_jira") and jira_project:
            push_to_jira = push_to_jira or jira_project.push_all_issues

        serializer.save(push_to_jira=push_to_jira)

    def get_queryset(self):
        findings = get_authorized_findings(
            Permissions.Finding_View,
        ).prefetch_related(
            "endpoints",
            "reviewers",
            "found_by",
            "notes",
            "risk_acceptance_set",
            "test",
            "tags",
            "jira_issue",
            "finding_group_set",
            "files",
            "burprawrequestresponse_set",
            "status_finding",
            "finding_meta",
            "test__test_type",
            "test__engagement",
            "test__environment",
            "test__engagement__product",
            "test__engagement__product__prod_type",
        )

        return findings.distinct()

    def get_serializer_class(self):
        if self.request and self.request.method == "POST":
            return serializers.FindingCreateSerializer
        return serializers.FindingSerializer

    @extend_schema(
        methods=["POST"],
        request=serializers.FindingCloseSerializer,
        responses={status.HTTP_200_OK: serializers.FindingCloseSerializer},
    )
    @action(detail=True, methods=["post"])
    def close(self, request, pk=None):
        finding = self.get_object()

        if request.method == "POST":
            finding_close = serializers.FindingCloseSerializer(
                data=request.data,
            )
            if finding_close.is_valid():
                finding.is_mitigated = finding_close.validated_data[
                    "is_mitigated"
                ]
                if settings.EDITABLE_MITIGATED_DATA:
                    finding.mitigated = (
                        finding_close.validated_data["mitigated"]
                        or timezone.now()
                    )
                else:
                    finding.mitigated = timezone.now()
                finding.mitigated_by = request.user
                finding.active = False
                finding.false_p = finding_close.validated_data.get(
                    "false_p", False,
                )
                finding.duplicate = finding_close.validated_data.get(
                    "duplicate", False,
                )
                finding.out_of_scope = finding_close.validated_data.get(
                    "out_of_scope", False,
                )

                endpoints_status = finding.status_finding.all()
                for e_status in endpoints_status:
                    e_status.mitigated_by = request.user
                    if settings.EDITABLE_MITIGATED_DATA:
                        e_status.mitigated_time = (
                            finding_close.validated_data["mitigated"]
                            or timezone.now()
                        )
                    else:
                        e_status.mitigated_time = timezone.now()
                    e_status.mitigated = True
                    e_status.last_modified = timezone.now()
                    e_status.save()
                finding.save()
            else:
                return Response(
                    finding_close.errors, status=status.HTTP_400_BAD_REQUEST,
                )
        serialized_finding = serializers.FindingCloseSerializer(finding)
        return Response(serialized_finding.data)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: serializers.TagSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.TagSerializer,
        responses={status.HTTP_201_CREATED: serializers.TagSerializer},
    )
    @action(detail=True, methods=["get", "post"])
    def tags(self, request, pk=None):
        finding = self.get_object()

        if request.method == "POST":
            new_tags = serializers.TagSerializer(data=request.data)
            if new_tags.is_valid():
                all_tags = finding.tags
                all_tags = serializers.TagSerializer({"tags": all_tags}).data[
                    "tags"
                ]

                for tag in tagulous.utils.parse_tags(
                    new_tags.validated_data["tags"],
                ):
                    if tag not in all_tags:
                        all_tags.append(tag)
                new_tags = tagulous.utils.render_tags(all_tags)
                finding.tags = new_tags
                finding.save()
            else:
                return Response(
                    new_tags.errors, status=status.HTTP_400_BAD_REQUEST,
                )
        tags = finding.tags
        serialized_tags = serializers.TagSerializer({"tags": tags})
        return Response(serialized_tags.data)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.BurpRawRequestResponseSerializer,
        },
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.BurpRawRequestResponseSerializer,
        responses={
            status.HTTP_201_CREATED: serializers.BurpRawRequestResponseSerializer,
        },
    )
    @action(detail=True, methods=["get", "post"])
    def request_response(self, request, pk=None):
        finding = self.get_object()

        if request.method == "POST":
            burps = serializers.BurpRawRequestResponseSerializer(
                data=request.data, many=isinstance(request.data, list),
            )
            if burps.is_valid():
                for pair in burps.validated_data["req_resp"]:
                    burp_rr = BurpRawRequestResponse(
                        finding=finding,
                        burpRequestBase64=base64.b64encode(
                            pair["request"].encode("utf-8"),
                        ),
                        burpResponseBase64=base64.b64encode(
                            pair["response"].encode("utf-8"),
                        ),
                    )
                    burp_rr.clean()
                    burp_rr.save()
            else:
                return Response(
                    burps.errors, status=status.HTTP_400_BAD_REQUEST,
                )
        # Not necessarily Burp scan specific - these are just any request/response pairs
        burp_req_resp = BurpRawRequestResponse.objects.filter(finding=finding)
        var = settings.MAX_REQRESP_FROM_API
        if var > -1:
            burp_req_resp = burp_req_resp[:var]

        burp_list = []
        for burp in burp_req_resp:
            request = burp.get_request()
            response = burp.get_response()
            burp_list.append({"request": request, "response": response})
        serialized_burps = serializers.BurpRawRequestResponseSerializer(
            {"req_resp": burp_list},
        )
        return Response(serialized_burps.data)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: serializers.FindingToNotesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"])
    def notes(self, request, pk=None):
        finding = self.get_object()
        if request.method == "POST":
            new_note = serializers.AddNewNoteOptionSerializer(
                data=request.data,
            )
            if new_note.is_valid():
                entry = new_note.validated_data["entry"]
                private = new_note.validated_data.get("private", False)
                note_type = new_note.validated_data.get("note_type", None)
            else:
                return Response(
                    new_note.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            if finding.notes:
                notes = finding.notes.filter(note_type=note_type).first()
                if notes and note_type and note_type.is_single:
                    return Response("Only one instance of this note_type allowed on a finding.", status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(
                entry=entry,
                author=author,
                private=private,
                note_type=note_type,
            )
            note.save()
            finding.notes.add(note)

            if finding.has_jira_issue:
                jira_helper.add_comment(finding, note)
            elif finding.has_jira_group_issue:
                jira_helper.add_comment(finding.finding_group, note)

            serialized_note = serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(
                serialized_note.data, status=status.HTTP_201_CREATED,
            )
        notes = finding.notes.all()

        serialized_notes = serializers.FindingToNotesSerializer(
            {"finding_id": finding, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: serializers.FindingToFilesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer},
    )
    @action(
        detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,),
    )
    def files(self, request, pk=None):
        finding = self.get_object()
        if request.method == "POST":
            new_file = serializers.FileSerializer(data=request.data)
            if new_file.is_valid():
                title = new_file.validated_data["title"]
                file = new_file.validated_data["file"]
            else:
                return Response(
                    new_file.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            file = FileUpload(title=title, file=file)
            file.save()
            finding.files.add(file)

            serialized_file = serializers.FileSerializer(file)
            return Response(
                serialized_file.data, status=status.HTTP_201_CREATED,
            )

        files = finding.files.all()
        serialized_files = serializers.FindingToFilesSerializer(
            {"finding_id": finding, "files": files},
        )
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        },
    )
    @action(
        detail=True,
        methods=["get"],
        url_path=r"files/download/(?P<file_id>\d+)",
    )
    def download_file(self, request, file_id, pk=None):
        finding = self.get_object()
        # Get the file object
        file_object_qs = finding.files.filter(id=file_id)
        file_object = (
            file_object_qs.first() if len(file_object_qs) > 0 else None
        )
        if file_object is None:
            return Response(
                {"error": "File ID not associated with Finding"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # send file
        return generate_file_response(file_object)

    @extend_schema(
        request=serializers.FindingNoteSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=["patch"])
    def remove_note(self, request, pk=None):
        """Remove Note From Finding Note"""
        finding = self.get_object()
        notes = finding.notes.all()
        if request.data["note_id"]:
            note = get_object_or_404(Notes.objects, id=request.data["note_id"])
            if note not in notes:
                return Response(
                    {"error": "Selected Note is not assigned to this Finding"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"error": "('note_id') parameter missing"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if (
            note.author.username == request.user.username
            or request.user.is_superuser
        ):
            finding.notes.remove(note)
            note.delete()
        else:
            return Response(
                {"error": "Delete Failed, You are not the Note's author"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {"Success": "Selected Note has been Removed successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )

    @extend_schema(
        methods=["PUT", "PATCH"],
        request=serializers.TagSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=["put", "patch"])
    def remove_tags(self, request, pk=None):
        """Remove Tag(s) from finding list of tags"""
        finding = self.get_object()
        delete_tags = serializers.TagSerializer(data=request.data)
        if delete_tags.is_valid():
            all_tags = finding.tags
            all_tags = serializers.TagSerializer({"tags": all_tags}).data[
                "tags"
            ]

            # serializer turns it into a string, but we need a list
            del_tags = tagulous.utils.parse_tags(
                delete_tags.validated_data["tags"],
            )
            if len(del_tags) < 1:
                return Response(
                    {"error": "Empty Tag List Not Allowed"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            for tag in del_tags:
                if tag not in all_tags:
                    return Response(
                        {
                            "error": f"'{tag}' is not a valid tag in list",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                all_tags.remove(tag)
            new_tags = tagulous.utils.render_tags(all_tags)
            finding.tags = new_tags
            finding.save()
            return Response(
                {"success": "Tag(s) Removed"},
                status=status.HTTP_204_NO_CONTENT,
            )
        return Response(
            delete_tags.errors, status=status.HTTP_400_BAD_REQUEST,
        )

    @extend_schema(
        responses={
            status.HTTP_200_OK: serializers.FindingSerializer(many=True),
        },
    )
    @action(
        detail=True,
        methods=["get"],
        url_path=r"duplicate",
        filter_backends=[],
        pagination_class=None,
    )
    def get_duplicate_cluster(self, request, pk):
        finding = self.get_object()
        result = duplicate_cluster(request, finding)
        serializer = serializers.FindingSerializer(
            instance=result, many=True, context={"request": request},
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=["post"], url_path=r"duplicate/reset")
    def reset_finding_duplicate_status(self, request, pk):
        checked_duplicate_id = reset_finding_duplicate_status_internal(
            request.user, pk,
        )
        if checked_duplicate_id is None:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=OpenApiTypes.NONE,
        parameters=[
            OpenApiParameter(
                "new_fid", OpenApiTypes.INT, OpenApiParameter.PATH,
            ),
        ],
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(
        detail=True, methods=["post"], url_path=r"original/(?P<new_fid>\d+)",
    )
    def set_finding_as_original(self, request, pk, new_fid):
        success = set_finding_as_original_internal(request.user, pk, new_fid)
        if not success:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(
        detail=False, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request):
        findings = self.get_queryset()
        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, findings, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)

    def _get_metadata(self, request, finding):
        metadata = DojoMeta.objects.filter(finding=finding)
        serializer = serializers.FindingMetaSerializer(
            instance=metadata, many=True,
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def _edit_metadata(self, request, finding):
        metadata_name = request.query_params.get("name", None)
        if metadata_name is None:
            return Response(
                "Metadata name is required", status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            DojoMeta.objects.update_or_create(
                name=metadata_name,
                finding=finding,
                defaults={
                    "name": request.data.get("name"),
                    "value": request.data.get("value"),
                },
            )

            return Response(data=request.data, status=status.HTTP_200_OK)
        except IntegrityError:
            return Response(
                "Update failed because the new name already exists",
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _add_metadata(self, request, finding):
        metadata_data = serializers.FindingMetaSerializer(data=request.data)

        if metadata_data.is_valid():
            name = metadata_data.validated_data["name"]
            value = metadata_data.validated_data["value"]

            metadata = DojoMeta(finding=finding, name=name, value=value)
            try:
                metadata.validate_unique()
                metadata.save()
            except ValidationError:
                return Response(
                    "Create failed probably because the name of the metadata already exists",
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(data=metadata_data.data, status=status.HTTP_200_OK)
        return Response(
            metadata_data.errors, status=status.HTTP_400_BAD_REQUEST,
        )

    def _remove_metadata(self, request, finding):
        name = request.query_params.get("name", None)
        if name is None:
            return Response(
                "A metadata name must be provided",
                status=status.HTTP_400_BAD_REQUEST,
            )

        metadata = get_object_or_404(
            DojoMeta.objects, finding=finding, name=name,
        )
        metadata.delete()

        return Response("Metadata deleted", status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer(many=True),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
        },
    )
    @extend_schema(
        methods=["DELETE"],
        parameters=[
            OpenApiParameter(
                "name",
                OpenApiTypes.INT,
                OpenApiParameter.QUERY,
                required=True,
                description="name of the metadata to retrieve. If name is empty, return all the \
                                    metadata associated with the finding",
            ),
        ],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Returned if the metadata was correctly deleted",
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Returned if there was a problem with the metadata information",
            ),
        },
    )
    @extend_schema(
        methods=["PUT"],
        request=serializers.FindingMetaSerializer,
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Returned if there was a problem with the metadata information",
            ),
        },
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.FindingMetaSerializer,
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Returned if there was a problem with the metadata information",
            ),
        },
    )
    @action(
        detail=True,
        methods=["post", "put", "delete", "get"],
        filter_backends=[],
        pagination_class=None,
    )
    def metadata(self, request, pk=None):
        finding = self.get_object()

        if request.method == "GET":
            return self._get_metadata(request, finding)
        if request.method == "POST":
            return self._add_metadata(request, finding)
        if request.method in ["PUT", "PATCH"]:
            return self._edit_metadata(request, finding)
        if request.method == "DELETE":
            return self._remove_metadata(request, finding)

        return Response(
            {"error", "unsupported method"}, status=status.HTTP_400_BAD_REQUEST,
        )


# Authorization: configuration
class JiraInstanceViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.JIRAInstanceSerializer
    queryset = JIRA_Instance.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "url"]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return JIRA_Instance.objects.all().order_by("id")


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class JiraIssuesViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.JIRAIssueSerializer
    queryset = JIRA_Issue.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "jira_id",
        "jira_key",
        "finding",
        "engagement",
        "finding_group",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasJiraIssuePermission,
    )

    def get_queryset(self):
        return get_authorized_jira_issues(Permissions.Product_View)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class JiraProjectViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.JIRAProjectSerializer
    queryset = JIRA_Project.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "jira_instance",
        "product",
        "engagement",
        "enabled",
        "component",
        "project_key",
        "push_all_issues",
        "enable_engagement_epic_mapping",
        "push_notes",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasJiraProductPermission,
    )

    def get_queryset(self):
        return get_authorized_jira_projects(Permissions.Product_View)


# Authorization: superuser
class SonarqubeIssueViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.SonarqubeIssueSerializer
    queryset = Sonarqube_Issue.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "key", "status", "type"]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Sonarqube_Issue.objects.all().order_by("id")


# Authorization: superuser
class SonarqubeIssueTransitionViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.SonarqubeIssueTransitionSerializer
    queryset = Sonarqube_Issue_Transition.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "sonarqube_issue",
        "finding_status",
        "sonarqube_status",
        "transitions",
    ]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Sonarqube_Issue_Transition.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ProductAPIScanConfigurationViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ProductAPIScanConfigurationSerializer
    queryset = Product_API_Scan_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "product",
        "tool_configuration",
        "service_key_1",
        "service_key_2",
        "service_key_3",
    ]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductAPIScanConfigurationPermission,
    )

    def get_queryset(self):
        return get_authorized_product_api_scan_configurations(
            Permissions.Product_API_Scan_Configuration_View,
        )


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class DojoMetaViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.MetaSerializer
    queryset = DojoMeta.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "product",
        "endpoint",
        "finding",
        "name",
        "value",
    ]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasDojoMetaPermission,
    )

    def get_queryset(self):
        return get_authorized_dojo_meta(Permissions.Product_View)

    @extend_schema(
        methods=["post", "patch"],
        request=serializers.MetaMainSerializer,
        responses={status.HTTP_200_OK: serializers.MetaMainSerializer},
        filters=False,
    )
    @action(
        detail=False, methods=["post", "patch"], pagination_class=None,
    )
    def batch(self, request, pk=None):
        serialized_data = serializers.MetaMainSerializer(data=request.data)
        if serialized_data.is_valid(raise_exception=True):
            if request.method == "POST":
                self.process_post(request.data)
            if request.method == "PATCH":
                self.process_patch(request.data)

        return Response(status=status.HTTP_201_CREATED, data=serialized_data.data)

    def process_post(self: object, data: dict):
        product = Product.objects.filter(id=data.get("product")).first()
        finding = Finding.objects.filter(id=data.get("finding")).first()
        endpoint = Endpoint.objects.filter(id=data.get("endpoint")).first()
        metalist = data.get("metadata")
        for metadata in metalist:
            try:
                DojoMeta.objects.create(
                    product=product,
                    finding=finding,
                    endpoint=endpoint,
                    name=metadata.get("name"),
                    value=metadata.get("value"),
                    )
            except (IntegrityError) as ex:  # this should not happen as the data was validated in the batch call
                raise ValidationError(str(ex))

    def process_patch(self: object, data: dict):
        product = Product.objects.filter(id=data.get("product")).first()
        finding = Finding.objects.filter(id=data.get("finding")).first()
        endpoint = Endpoint.objects.filter(id=data.get("endpoint")).first()
        metalist = data.get("metadata")
        for metadata in metalist:
            dojometa = DojoMeta.objects.filter(product=product, finding=finding, endpoint=endpoint, name=metadata.get("name"))
            if dojometa:
                try:
                    dojometa.update(
                        name=metadata.get("name"),
                        value=metadata.get("value"),
                        )
                except (IntegrityError) as ex:
                    raise ValidationError(str(ex))
            else:
                msg = f"Metadata {metadata.get('name')} not found for object."
                raise ValidationError(msg)


@extend_schema_view(**schema_with_prefetch())
class ProductViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
    dojo_mixins.DeletePreviewModelMixin,
):
    serializer_class = serializers.ProductSerializer
    queryset = Product.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiProductFilter
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductPermission,
    )

    def get_queryset(self):
        return get_authorized_products(Permissions.Product_View).distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # def list(self, request):
    #     # Note the use of `get_queryset()` instead of `self.queryset`
    #     queryset = self.get_queryset()
    #     serializer = self.serializer_class(queryset, many=True)
    #     return Response(serializer.data)

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        product = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, product, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ProductMemberViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ProductMemberSerializer
    queryset = Product_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "product_id", "user_id"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductMemberPermission,
    )

    def get_queryset(self):
        return get_authorized_product_members(
            Permissions.Product_View,
        ).distinct()

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ProductGroupViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ProductGroupSerializer
    queryset = Product_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "product_id", "group_id"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductGroupPermission,
    )

    def get_queryset(self):
        return get_authorized_product_groups(
            Permissions.Product_Group_View,
        ).distinct()

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ProductTypeViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ProductTypeSerializer
    queryset = Product_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "critical_product",
        "key_product",
        "created",
        "updated",
    ]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductTypePermission,
    )

    def get_queryset(self):
        return get_authorized_product_types(
            Permissions.Product_Type_View,
        ).distinct()

    # Overwrite perfom_create of CreateModelMixin to add current user as owner
    def perform_create(self, serializer):
        serializer.save()
        product_type_data = serializer.data
        product_type_data.pop("authorization_groups")
        product_type_data.pop("members")
        member = Product_Type_Member()
        member.user = self.request.user
        member.product_type = Product_Type(**product_type_data)
        member.role = Role.objects.get(is_owner=True)
        member.save()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        product_type = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, product_type, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ProductTypeMemberViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ProductTypeMemberSerializer
    queryset = Product_Type_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "product_type_id", "user_id"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductTypeMemberPermission,
    )

    def get_queryset(self):
        return get_authorized_product_type_members(
            Permissions.Product_Type_View,
        ).distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role.is_owner:
            owners = Product_Type_Member.objects.filter(
                product_type=instance.product_type, role__is_owner=True,
            ).count()
            if owners <= 1:
                return Response(
                    "There must be at least one owner",
                    status=status.HTTP_400_BAD_REQUEST,
                )
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ProductTypeGroupViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ProductTypeGroupSerializer
    queryset = Product_Type_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "product_type_id", "group_id"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductTypeGroupPermission,
    )

    def get_queryset(self):
        return get_authorized_product_type_groups(
            Permissions.Product_Type_Group_View,
        ).distinct()

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class StubFindingsViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.StubFindingSerializer
    queryset = Stub_Finding.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "title", "date", "severity", "description"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasFindingPermission,
    )

    def get_queryset(self):
        return get_authorized_stub_findings(
            Permissions.Finding_View,
        ).distinct()

    def get_serializer_class(self):
        if self.request and self.request.method == "POST":
            return serializers.StubFindingCreateSerializer
        return serializers.StubFindingSerializer


# Authorization: authenticated, configuration
class DevelopmentEnvironmentViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.DevelopmentEnvironmentSerializer
    queryset = Development_Environment.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, DjangoModelPermissions)

    def get_queryset(self):
        return Development_Environment.objects.all().order_by("id")


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class TestsViewSet(
    PrefetchDojoModelViewSet,
    ra_api.AcceptedRisksMixin,
):
    serializer_class = serializers.TestSerializer
    queryset = Test.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiTestFilter
    permission_classes = (IsAuthenticated, permissions.UserHasTestPermission)

    @property
    def risk_application_model_class(self):
        return Test

    def get_queryset(self):
        return (
            get_authorized_tests(Permissions.Test_View)
            .prefetch_related("notes", "files")
            .distinct()
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_serializer_class(self):
        if self.request and self.request.method == "POST":
            if self.action == "accept_risks":
                return ra_api.AcceptedRiskSerializer
            return serializers.TestCreateSerializer
        return serializers.TestSerializer

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        test = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, test, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: serializers.TestToNotesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"])
    def notes(self, request, pk=None):
        test = self.get_object()
        if request.method == "POST":
            new_note = serializers.AddNewNoteOptionSerializer(
                data=request.data,
            )
            if new_note.is_valid():
                entry = new_note.validated_data["entry"]
                private = new_note.validated_data.get("private", False)
                note_type = new_note.validated_data.get("note_type", None)
            else:
                return Response(
                    new_note.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            notes = test.notes.filter(note_type=note_type).first()
            if notes and note_type and note_type.is_single:
                return Response("Only one instance of this note_type allowed on a test.", status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(
                entry=entry,
                author=author,
                private=private,
                note_type=note_type,
            )
            note.save()
            test.notes.add(note)

            serialized_note = serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(
                serialized_note.data, status=status.HTTP_201_CREATED,
            )
        notes = test.notes.all()

        serialized_notes = serializers.TestToNotesSerializer(
            {"test_id": test, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: serializers.TestToFilesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer},
    )
    @action(
        detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,),
    )
    def files(self, request, pk=None):
        test = self.get_object()
        if request.method == "POST":
            new_file = serializers.FileSerializer(data=request.data)
            if new_file.is_valid():
                title = new_file.validated_data["title"]
                file = new_file.validated_data["file"]
            else:
                return Response(
                    new_file.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            file = FileUpload(title=title, file=file)
            file.save()
            test.files.add(file)

            serialized_file = serializers.FileSerializer(file)
            return Response(
                serialized_file.data, status=status.HTTP_201_CREATED,
            )

        files = test.files.all()
        serialized_files = serializers.TestToFilesSerializer(
            {"test_id": test, "files": files},
        )
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        },
    )
    @action(
        detail=True,
        methods=["get"],
        url_path=r"files/download/(?P<file_id>\d+)",
    )
    def download_file(self, request, file_id, pk=None):
        test = self.get_object()
        # Get the file object
        file_object_qs = test.files.filter(id=file_id)
        file_object = (
            file_object_qs.first() if len(file_object_qs) > 0 else None
        )
        if file_object is None:
            return Response(
                {"error": "File ID not associated with Test"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # send file
        return generate_file_response(file_object)


# Authorization: authenticated, configuration
class TestTypesViewSet(
    mixins.UpdateModelMixin,
    mixins.CreateModelMixin,
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = serializers.TestTypeSerializer
    queryset = Test_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "name",
    ]
    permission_classes = (IsAuthenticated, DjangoModelPermissions)

    def get_queryset(self):
        return Test_Type.objects.all().order_by("id")


# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class TestImportViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.TestImportSerializer
    queryset = Test_Import.objects.none()
    filter_backends = (DjangoFilterBackend,)

    filterset_class = TestImportAPIFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasTestImportPermission,
    )

    def get_queryset(self):
        return get_authorized_test_imports(
            Permissions.Test_View,
        ).prefetch_related(
            "test_import_finding_action_set",
            "findings_affected",
            "findings_affected__endpoints",
            "findings_affected__status_finding",
            "findings_affected__finding_meta",
            "findings_affected__jira_issue",
            "findings_affected__burprawrequestresponse_set",
            "findings_affected__jira_issue",
            "findings_affected__jira_issue",
            "findings_affected__jira_issue",
            "findings_affected__reviewers",
            "findings_affected__notes",
            "findings_affected__notes__author",
            "findings_affected__notes__history",
            "findings_affected__files",
            "findings_affected__found_by",
            "findings_affected__tags",
            "findings_affected__risk_acceptance_set",
            "test",
            "test__tags",
            "test__notes",
            "test__notes__author",
            "test__files",
            "test__test_type",
            "test__engagement",
            "test__environment",
            "test__engagement__product",
            "test__engagement__product__prod_type",
        )


# Authorization: configurations
@extend_schema_view(**schema_with_prefetch())
class ToolConfigurationsViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ToolConfigurationSerializer
    queryset = Tool_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "tool_type",
        "url",
        "authentication_type",
    ]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Tool_Configuration.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ToolProductSettingsViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.ToolProductSettingsSerializer
    queryset = Tool_Product_Settings.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "product",
        "tool_configuration",
        "tool_project_id",
        "url",
    ]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasToolProductSettingsPermission,
    )

    def get_queryset(self):
        return get_authorized_tool_product_settings(Permissions.Product_View)


# Authorization: configuration
class ToolTypesViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.ToolTypeSerializer
    queryset = Tool_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "description"]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Tool_Type.objects.all().order_by("id")


# Authorization: authenticated, configuration
class RegulationsViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.RegulationSerializer
    queryset = Regulation.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "description"]
    permission_classes = (IsAuthenticated, DjangoModelPermissions)

    def get_queryset(self):
        return Regulation.objects.all().order_by("id")


# Authorization: configuration
class UsersViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.UserSerializer
    queryset = User.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "username",
        "first_name",
        "last_name",
        "email",
        "is_active",
        "is_superuser",
    ]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return User.objects.all().order_by("id")

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user == instance:
            return Response(
                "Users may not delete themselves",
                status=status.HTTP_400_BAD_REQUEST,
            )
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


# Authorization: superuser
@extend_schema_view(**schema_with_prefetch())
class UserContactInfoViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.UserContactInfoSerializer
    queryset = UserContactInfo.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = "__all__"
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return UserContactInfo.objects.all().order_by("id")


# Authorization: authenticated users
class UserProfileView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    pagination_class = None
    serializer_class = serializers.UserProfileSerializer

    @action(
        detail=True, methods=["get"], filter_backends=[], pagination_class=None,
    )
    def get(self, request, format=None):
        user = get_current_user()
        user_contact_info = (
            user.usercontactinfo if hasattr(user, "usercontactinfo") else None
        )
        global_role = (
            user.global_role if hasattr(user, "global_role") else None
        )
        dojo_group_member = Dojo_Group_Member.objects.filter(user=user)
        product_type_member = Product_Type_Member.objects.filter(user=user)
        product_member = Product_Member.objects.filter(user=user)
        serializer = serializers.UserProfileSerializer(
            {
                "user": user,
                "user_contact_info": user_contact_info,
                "global_role": global_role,
                "dojo_group_member": dojo_group_member,
                "product_type_member": product_type_member,
                "product_member": product_member,
            },
            many=False,
        )
        return Response(serializer.data)


# Authorization: authenticated users, DjangoModelPermissions
class ImportScanView(mixins.CreateModelMixin, viewsets.GenericViewSet):

    """
    Imports a scan report into an engagement or product.

    By ID:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Provide the id of the engagement in the `engagement` parameter

    In this scenario a new Test will be created inside the engagement.

    By Names:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Provide `product_name`
    - Provide `engagement_name`
    - Optionally provide `product_type_name`

    In this scenario Defect Dojo will look up the Engagement by the provided details.

    When using names you can let the importer automatically create Engagements, Products and Product_Types
    by using `auto_create_context=True`.

    When `auto_create_context` is set to `True` you can use `deduplication_on_engagement` to restrict deduplication for
    imported Findings to the newly created Engagement.
    """

    serializer_class = serializers.ImportScanSerializer
    parser_classes = [MultiPartParser]
    queryset = Test.objects.none()
    permission_classes = (IsAuthenticated, permissions.UserHasImportPermission)

    def perform_create(self, serializer):
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(serializer.validated_data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**converted_dict)
            engagement = auto_create.get_target_engagement_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

        # when using auto_create_context, the engagement or product may not
        # have been created yet
        push_to_jira = serializer.validated_data.get("push_to_jira")
        if get_system_setting("enable_jira"):
            jira_driver = engagement or (product or None)
            if jira_project := (jira_helper.get_jira_project(jira_driver) if jira_driver else None):
                push_to_jira = push_to_jira or jira_project.push_all_issues
        logger.debug(f"push_to_jira: {push_to_jira}")
        serializer.save(push_to_jira=push_to_jira)

    def get_queryset(self):
        return get_authorized_tests(Permissions.Import_Scan_Result)


# Authorization: authenticated users, DjangoModelPermissions
class EndpointMetaImporterView(
    mixins.CreateModelMixin, viewsets.GenericViewSet,
):

    """
    Imports a CSV file into a product to propagate arbitrary meta and tags on endpoints.

    By Names:
    - Provide `product_name` of existing product

    By ID:
    - Provide the id of the product in the `product` parameter

    In this scenario Defect Dojo will look up the product by the provided details.
    """

    serializer_class = serializers.EndpointMetaImporterSerializer
    parser_classes = [MultiPartParser]
    queryset = Product.objects.none()
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasMetaImportPermission,
    )

    def perform_create(self, serializer):
        serializer.save()

    def get_queryset(self):
        return get_authorized_products(Permissions.Endpoint_Edit)


# Authorization: configuration
class LanguageTypeViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.LanguageTypeSerializer
    queryset = Language_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "language", "color"]
    permission_classes = (permissions.UserHasConfigurationPermissionStaff,)

    def get_queryset(self):
        return Language_Type.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class LanguageViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.LanguageSerializer
    queryset = Languages.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "language", "product"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasLanguagePermission,
    )

    def get_queryset(self):
        return get_authorized_languages(Permissions.Language_View).distinct()


# Authorization: object-based
class ImportLanguagesView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = serializers.ImportLanguagesSerializer
    parser_classes = [MultiPartParser]
    queryset = Product.objects.none()
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasLanguagePermission,
    )

    def get_queryset(self):
        return get_authorized_products(Permissions.Language_Add)


# Authorization: object-based
class ReImportScanView(mixins.CreateModelMixin, viewsets.GenericViewSet):

    """
    Reimports a scan report into an existing test.

    By ID:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Import a scan report and find the id of the Test
    - Provide this in the `test` parameter

    By Names:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Import a report which will create a Test
    - Provide `product_name`
    - Provide `engagement_name`
    - Optional: Provide `test_title`

    In this scenario Defect Dojo will look up the Test by the provided details.
    If no `test_title` is provided, the latest test inside the engagement will be chosen based on scan_type.

    When using names you can let the importer automatically create Engagements, Products and Product_Types
    by using `auto_create_context=True`.

    When `auto_create_context` is set to `True` you can use `deduplication_on_engagement` to restrict deduplication for
    imported Findings to the newly created Engagement.
    """

    serializer_class = serializers.ReImportScanSerializer
    parser_classes = [MultiPartParser]
    queryset = Test.objects.none()
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasReimportPermission,
    )

    def get_queryset(self):
        return get_authorized_tests(Permissions.Import_Scan_Result)

    def perform_create(self, serializer):
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(serializer.validated_data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**converted_dict)
            engagement = auto_create.get_target_engagement_if_exists(**converted_dict)
            test = auto_create.get_target_test_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

        # when using auto_create_context, the engagement or product may not
        # have been created yet
        push_to_jira = serializer.validated_data.get("push_to_jira")
        if get_system_setting("enable_jira"):
            jira_driver = test or (engagement or (product or None))
            if jira_project := (jira_helper.get_jira_project(jira_driver) if jira_driver else None):
                push_to_jira = push_to_jira or jira_project.push_all_issues
        logger.debug(f"push_to_jira: {push_to_jira}")
        serializer.save(push_to_jira=push_to_jira)


# Authorization: configuration
class NoteTypeViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.NoteTypeSerializer
    queryset = Note_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "description",
        "is_single",
        "is_active",
        "is_mandatory",
    ]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Note_Type.objects.all().order_by("id")


class BurpRawRequestResponseViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.BurpRawRequestResponseMultiSerializer
    queryset = BurpRawRequestResponse.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["finding"]

    def get_queryset(self):
        results = BurpRawRequestResponse.objects.all()
        empty_value = b""
        results = results.exclude(
            burpRequestBase64__exact=empty_value,
            burpResponseBase64__exact=empty_value,
        )
        return results.order_by("id")


# Authorization: superuser
class NotesViewSet(
    mixins.UpdateModelMixin,
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = serializers.NoteSerializer
    queryset = Notes.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "entry",
        "author",
        "private",
        "date",
        "edited",
        "edit_time",
        "editor",
    ]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Notes.objects.all().order_by("id")


def report_generate(request, obj, options):
    user = Dojo_User.objects.get(id=request.user.id)
    product_type = None
    product = None
    engagement = None
    test = None
    endpoint = None
    endpoints = None

    include_finding_notes = False
    include_finding_images = False
    include_executive_summary = False
    include_table_of_contents = False

    report_info = "Generated By {} on {}".format(
        user.get_full_name(),
        (timezone.now().strftime("%m/%d/%Y %I:%M%p %Z")),
    )

    # generate = "_generate" in request.GET
    report_name = str(obj)

    include_finding_notes = options.get("include_finding_notes", False)
    include_finding_images = options.get("include_finding_images", False)
    include_executive_summary = options.get("include_executive_summary", False)
    include_table_of_contents = options.get("include_table_of_contents", False)
    filter_string_matching = get_system_setting("filter_string_matching", False)
    report_finding_filter_class = ReportFindingFilterWithoutObjectLookups if filter_string_matching else ReportFindingFilter

    if type(obj).__name__ == "Product_Type":
        product_type = obj

        report_name = "Product Type Report: " + str(product_type)

        findings = report_finding_filter_class(
            request.GET,
            prod_type=product_type,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(
                    test__engagement__product__prod_type=product_type,
                ),
            ),
        )

        if len(findings.qs) > 0:
            start_date = timezone.make_aware(
                datetime.combine(findings.qs.last().date, datetime.min.time()),
            )
        else:
            start_date = timezone.now()

        end_date = timezone.now()

        r = relativedelta(end_date, start_date)
        months_between = (r.years * 12) + r.months
        # include current month
        months_between += 1

    elif type(obj).__name__ == "Product":
        product = obj

        report_name = "Product Report: " + str(product)

        findings = report_finding_filter_class(
            request.GET,
            product=product,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(test__engagement__product=product),
            ),
        )
        ids = get_endpoint_ids(
            Endpoint.objects.filter(product=product).distinct(),
        )
        endpoints = Endpoint.objects.filter(id__in=ids)

    elif type(obj).__name__ == "Engagement":
        engagement = obj
        findings = report_finding_filter_class(
            request.GET,
            engagement=engagement,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(test__engagement=engagement),
            ),
        )
        report_name = "Engagement Report: " + str(engagement)

        ids = set(finding.id for finding in findings.qs)  # noqa: C401
        ids = get_endpoint_ids(
            Endpoint.objects.filter(product=engagement.product).distinct(),
        )
        endpoints = Endpoint.objects.filter(id__in=ids)

    elif type(obj).__name__ == "Test":
        test = obj
        findings = report_finding_filter_class(
            request.GET,
            engagement=test.engagement,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(test=test),
            ),
        )
        report_name = "Test Report: " + str(test)

    elif type(obj).__name__ == "Endpoint":
        endpoint = obj
        host = endpoint.host
        report_name = "Endpoint Report: " + host
        endpoints = Endpoint.objects.filter(
            host=host, product=endpoint.product,
        ).distinct()
        findings = report_finding_filter_class(
            request.GET,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(endpoints__in=endpoints),
            ),
        )

    elif type(obj).__name__ == "CastTaggedQuerySet":
        findings = report_finding_filter_class(
            request.GET,
            queryset=prefetch_related_findings_for_report(obj).distinct(),
        )

        report_name = "Finding"

    else:
        raise Http404

    result = {
        "product_type": product_type,
        "product": product,
        "engagement": engagement,
        "report_name": report_name,
        "report_info": report_info,
        "test": test,
        "endpoint": endpoint,
        "endpoints": endpoints,
        "findings": findings.qs.order_by("numerical_severity"),
        "include_table_of_contents": include_table_of_contents,
        "user": user,
        "team_name": settings.TEAM_NAME,
        "title": "Generate Report",
        "user_id": request.user.id,
        "host": report_url_resolver(request),
    }

    finding_notes = []
    finding_files = []

    if include_finding_images:
        for finding in findings.qs.order_by("numerical_severity"):
            files = finding.files.all()
            if files:
                finding_files.append({"finding_id": finding, "files": files})
        result["finding_files"] = finding_files

    if include_finding_notes:
        for finding in findings.qs.order_by("numerical_severity"):
            notes = finding.notes.filter(private=False)
            if notes:
                finding_notes.append({"finding_id": finding, "notes": notes})
        result["finding_notes"] = finding_notes

    # Generating Executive summary based on obj type
    if include_executive_summary and type(obj).__name__ != "Endpoint":
        executive_summary = {}

        # Declare all required fields for executive summary
        engagement_name = None
        engagement_target_start = None
        engagement_target_end = None
        test_type_name = None
        test_target_start = None
        test_target_end = None
        test_environment_name = "unknown"  # a default of "unknown"
        test_strategy_ref = None
        total_findings = 0

        if type(obj).__name__ == "Product_Type":
            for prod_typ in obj.prod_type.all():
                engmnts = prod_typ.engagement_set.all()
                if engmnts:
                    for eng in engmnts:
                        if eng.name:
                            engagement_name = eng.name
                        engagement_target_start = eng.target_start
                        engagement_target_end = eng.target_end or "ongoing"
                        if eng.test_set.all():
                            for t in eng.test_set.all():
                                test_type_name = t.test_type.name
                                if t.environment:
                                    test_environment_name = t.environment.name
                                test_target_start = t.target_start
                                test_target_end = t.target_end or "ongoing"
                            test_strategy_ref = eng.test_strategy or ""
                total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Product":
            engs = obj.engagement_set.all()
            if engs:
                for eng in engs:
                    if eng.name:
                        engagement_name = eng.name
                    engagement_target_start = eng.target_start
                    engagement_target_end = eng.target_end or "ongoing"

                    if eng.test_set.all():
                        for t in eng.test_set.all():
                            test_type_name = t.test_type.name
                            if t.environment:
                                test_environment_name = t.environment.name
                    test_strategy_ref = eng.test_strategy or ""
                total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Engagement":
            eng = obj
            if eng.name:
                engagement_name = eng.name
            engagement_target_start = eng.target_start
            engagement_target_end = eng.target_end or "ongoing"

            if eng.test_set.all():
                for t in eng.test_set.all():
                    test_type_name = t.test_type.name
                    if t.environment:
                        test_environment_name = t.environment.name
            test_strategy_ref = eng.test_strategy or ""
            total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Test":
            t = obj
            test_type_name = t.test_type.name
            test_target_start = t.target_start
            test_target_end = t.target_end or "ongoing"
            total_findings = len(findings.qs.all())
            if t.engagement.name:
                engagement_name = t.engagement.name
            engagement_target_start = t.engagement.target_start
            engagement_target_end = t.engagement.target_end or "ongoing"
        else:
            pass  # do nothing

        executive_summary = {
            "engagement_name": engagement_name,
            "engagement_target_start": engagement_target_start,
            "engagement_target_end": engagement_target_end,
            "test_type_name": test_type_name,
            "test_target_start": test_target_start,
            "test_target_end": test_target_end,
            "test_environment_name": test_environment_name,
            "test_strategy_ref": test_strategy_ref,
            "total_findings": total_findings,
        }
        # End of executive summary generation

        result["executive_summary"] = executive_summary

    return result


# Authorization: superuser
class SystemSettingsViewSet(
    mixins.ListModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet,
):

    """Basic control over System Settings. Use 'id' 1 for PUT, PATCH operations"""

    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)
    serializer_class = serializers.SystemSettingsSerializer
    queryset = System_Settings.objects.none()

    def get_queryset(self):
        return System_Settings.objects.all().order_by("id")


# Authorization: superuser
@extend_schema_view(**schema_with_prefetch())
class NotificationsViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.NotificationsSerializer
    queryset = Notifications.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "user", "product", "template"]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Notifications.objects.all().order_by("id")


@extend_schema_view(**schema_with_prefetch())
class EngagementPresetsViewset(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.EngagementPresetsSerializer
    queryset = Engagement_Presets.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "title", "product"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEngagementPresetPermission,
    )

    def get_queryset(self):
        return get_authorized_engagement_presets(Permissions.Product_View)


class NetworkLocationsViewset(
    DojoModelViewSet,
):
    serializer_class = serializers.NetworkLocationsSerializer
    queryset = Network_Locations.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "location"]
    permission_classes = (IsAuthenticated, DjangoModelPermissions)

    def get_queryset(self):
        return Network_Locations.objects.all().order_by("id")


# Authorization: superuser
class ConfigurationPermissionViewSet(
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = serializers.ConfigurationPermissionSerializer
    queryset = Permission.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "codename"]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Permission.objects.filter(
            codename__in=get_configuration_permissions_codenames(),
        ).order_by("id")


class SLAConfigurationViewset(
    DojoModelViewSet,
):
    serializer_class = serializers.SLAConfigurationSerializer
    queryset = SLA_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, DjangoModelPermissions)

    def get_queryset(self):
        return SLA_Configuration.objects.all().order_by("id")


class QuestionnaireQuestionViewSet(
    viewsets.ReadOnlyModelViewSet,
    dojo_mixins.QuestionSubClassFieldsMixin,
):
    serializer_class = serializers.QuestionnaireQuestionSerializer
    queryset = Question.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (
        permissions.UserHasEngagementPermission,
        DjangoModelPermissions,
    )

    def get_queryset(self):
        return Question.objects.all().order_by("id")


class QuestionnaireAnswerViewSet(
    viewsets.ReadOnlyModelViewSet,
    dojo_mixins.AnswerSubClassFieldsMixin,
):
    serializer_class = serializers.QuestionnaireAnswerSerializer
    queryset = Answer.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (
        permissions.UserHasEngagementPermission,
        DjangoModelPermissions,
    )

    def get_queryset(self):
        return Answer.objects.all().order_by("id")


class QuestionnaireGeneralSurveyViewSet(
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = serializers.QuestionnaireGeneralSurveySerializer
    queryset = General_Survey.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (
        permissions.UserHasEngagementPermission,
        DjangoModelPermissions,
    )

    def get_queryset(self):
        return General_Survey.objects.all().order_by("id")


class QuestionnaireEngagementSurveyViewSet(
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = serializers.QuestionnaireEngagementSurveySerializer
    queryset = Engagement_Survey.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (
        permissions.UserHasEngagementPermission,
        DjangoModelPermissions,
    )

    def get_queryset(self):
        return Engagement_Survey.objects.all().order_by("id")

    @extend_schema(
    request=OpenApiTypes.NONE,
    parameters=[
        OpenApiParameter(
            "engagement_id", OpenApiTypes.INT, OpenApiParameter.PATH,
        ),
    ],
    responses={status.HTTP_200_OK: serializers.QuestionnaireAnsweredSurveySerializer},
    )
    @action(
        detail=True, methods=["post"], url_path=r"link_engagement/(?P<engagement_id>\d+)",
    )
    def link_engagement(self, request, pk, engagement_id):
        # Get the answered survey
        engagement_survey = self.get_object()
        # Safely get the engagement
        engagement = get_object_or_404(Engagement.objects, pk=engagement_id)
        # Link the engagement
        answered_survey, _ = Answered_Survey.objects.get_or_create(engagement=engagement, survey=engagement_survey)
        # Send a favorable response
        serialized_answered_survey = serializers.QuestionnaireAnsweredSurveySerializer(answered_survey)
        return Response(serialized_answered_survey.data)


@extend_schema_view(**schema_with_prefetch())
class QuestionnaireAnsweredSurveyViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = serializers.QuestionnaireAnsweredSurveySerializer
    queryset = Answered_Survey.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (
        permissions.UserHasEngagementPermission,
        DjangoModelPermissions,
    )

    def get_queryset(self):
        return Answered_Survey.objects.all().order_by("id")


# Authorization: configuration
class AnnouncementViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.AnnouncementSerializer
    queryset = Announcement.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = "__all__"
    permission_classes = (permissions.UserHasConfigurationPermissionStaff,)

    def get_queryset(self):
        return Announcement.objects.all().order_by("id")


class NotificationWebhooksViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.NotificationWebhooksSerializer
    queryset = Notification_Webhooks.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = "__all__"
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)  # TODO: add permission also for other users
