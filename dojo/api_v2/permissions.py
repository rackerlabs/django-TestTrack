import re

from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from rest_framework.exceptions import (
    ParseError,
    PermissionDenied,
    ValidationError,
)

from dojo.authorization.authorization import (
    user_has_configuration_permission,
    user_has_global_permission,
    user_has_permission,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.models import (
    Cred_Mapping,
    Dojo_Group,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Test,
)


def check_post_permission(request, post_model, post_pk, post_permission):
    if request.method == "POST":
        if request.data.get(post_pk) is None:
            msg = f"Unable to check for permissions: Attribute '{post_pk}' is required"
            raise ParseError(msg)
        obj = get_object_or_404(post_model, pk=request.data.get(post_pk))
        return user_has_permission(request.user, obj, post_permission)
    return True


def check_object_permission(
    request,
    object,
    get_permission,
    put_permission,
    delete_permission,
    post_permission=None,
):
    if request.method == "GET":
        return user_has_permission(request.user, object, get_permission)
    if request.method == "PUT" or request.method == "PATCH":
        return user_has_permission(request.user, object, put_permission)
    if request.method == "DELETE":
        return user_has_permission(request.user, object, delete_permission)
    if request.method == "POST":
        return user_has_permission(request.user, object, post_permission)
    return False


class UserHasAppAnalysisPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Technology_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Technology_View,
            Permissions.Technology_Edit,
            Permissions.Technology_Delete,
        )


class UserHasCredentialPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.data.get("product") is not None:
            return check_post_permission(
                request, Cred_Mapping, "product", Permissions.Credential_Add,
            )
        if request.data.get("engagement") is not None:
            return check_post_permission(
                request, Cred_Mapping, "engagement", Permissions.Credential_Add,
            )
        if request.data.get("test") is not None:
            return check_post_permission(
                request, Cred_Mapping, "test", Permissions.Credential_Add,
            )
        if request.data.get("finding") is not None:
            return check_post_permission(
                request, Cred_Mapping, "finding", Permissions.Credential_Add,
            )
        return check_post_permission(
            request, Cred_Mapping, "product", Permissions.Credential_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Credential_View,
            Permissions.Credential_Edit,
            Permissions.Credential_Delete,
        )


class UserHasDojoGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "GET":
            return user_has_configuration_permission(
                request.user, "auth.view_group",
            )
        if request.method == "POST":
            return user_has_configuration_permission(
                request.user, "auth.add_group",
            )
        return True

    def has_object_permission(self, request, view, obj):
        if request.method == "GET":
            # Users need to be authorized to view groups in general and only the groups they are a member of
            # because with the group they can see user information that might
            # be considered as confidential
            return user_has_configuration_permission(
                request.user, "auth.view_group",
            ) and user_has_permission(
                request.user, obj, Permissions.Group_View,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Group_View,
            Permissions.Group_Edit,
            Permissions.Group_Delete,
        )


class UserHasDojoGroupMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Dojo_Group, "group", Permissions.Group_Manage_Members,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Group_View,
            Permissions.Group_Manage_Members,
            Permissions.Group_Member_Delete,
        )


class UserHasDojoMetaPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            has_permission_result = True
            product_id = request.data.get("product", None)
            if product_id:
                obj = get_object_or_404(Product, pk=product_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Product_Edit,
                    )
                )
            finding_id = request.data.get("finding", None)
            if finding_id:
                obj = get_object_or_404(Finding, pk=finding_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Finding_Edit,
                    )
                )
            endpoint_id = request.data.get("endpoint", None)
            if endpoint_id:
                obj = get_object_or_404(Endpoint, pk=endpoint_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Endpoint_Edit,
                    )
                )
            return has_permission_result
        return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        product = obj.product
        if product:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    product,
                    Permissions.Product_View,
                    Permissions.Product_Edit,
                    Permissions.Product_Edit,
                )
            )
        finding = obj.finding
        if finding:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding,
                    Permissions.Finding_View,
                    Permissions.Finding_Edit,
                    Permissions.Finding_Edit,
                )
            )
        endpoint = obj.endpoint
        if endpoint:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    endpoint,
                    Permissions.Endpoint_View,
                    Permissions.Endpoint_Edit,
                    Permissions.Endpoint_Edit,
                )
            )
        return has_permission_result


class UserHasToolProductSettingsPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Product_View,
            Permissions.Product_Edit,
            Permissions.Product_Edit,
        )


class UserHasEndpointPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Endpoint_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Endpoint_View,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Delete,
        )


class UserHasEndpointStatusPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Endpoint, "endpoint", Permissions.Endpoint_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.endpoint,
            Permissions.Endpoint_View,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Edit,
        )


class UserHasEngagementPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_engagement_post = re.compile(r"^/api/v2/engagements/$")
    path_engagement = re.compile(r"^/api/v2/engagements/\d+/$")

    def has_permission(self, request, view):
        if UserHasEngagementPermission.path_engagement_post.match(
            request.path,
        ) or UserHasEngagementPermission.path_engagement.match(request.path):
            return check_post_permission(
                request, Product, "product", Permissions.Engagement_Add,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasEngagementPermission.path_engagement_post.match(
            request.path,
        ) or UserHasEngagementPermission.path_engagement.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Engagement_View,
                Permissions.Engagement_Edit,
                Permissions.Engagement_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Engagement_View,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Edit,
        )


class UserHasRiskAcceptancePermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_risk_acceptance_post = re.compile(r"^/api/v2/risk_acceptances/$")
    path_risk_acceptance = re.compile(r"^/api/v2/risk_acceptances/\d+/$")

    def has_permission(self, request, view):
        if UserHasRiskAcceptancePermission.path_risk_acceptance_post.match(
            request.path,
        ) or UserHasRiskAcceptancePermission.path_risk_acceptance.match(
            request.path,
        ):
            return check_post_permission(
                request, Product, "product", Permissions.Risk_Acceptance,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasRiskAcceptancePermission.path_risk_acceptance_post.match(
            request.path,
        ) or UserHasRiskAcceptancePermission.path_risk_acceptance.match(
            request.path,
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Risk_Acceptance,
                Permissions.Risk_Acceptance,
                Permissions.Risk_Acceptance,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Risk_Acceptance,
            Permissions.Risk_Acceptance,
            Permissions.Risk_Acceptance,
            Permissions.Risk_Acceptance,
        )


class UserHasFindingPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_finding_post = re.compile(r"^/api/v2/findings/$")
    path_finding = re.compile(r"^/api/v2/findings/\d+/$")
    path_stub_finding_post = re.compile(r"^/api/v2/stub_findings/$")
    path_stub_finding = re.compile(r"^/api/v2/stub_findings/\d+/$")

    def has_permission(self, request, view):
        if (
            UserHasFindingPermission.path_finding_post.match(request.path)
            or UserHasFindingPermission.path_finding.match(request.path)
            or UserHasFindingPermission.path_stub_finding_post.match(
                request.path,
            )
            or UserHasFindingPermission.path_stub_finding.match(request.path)
        ):
            return check_post_permission(
                request, Test, "test", Permissions.Finding_Add,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if (
            UserHasFindingPermission.path_finding_post.match(request.path)
            or UserHasFindingPermission.path_finding.match(request.path)
            or UserHasFindingPermission.path_stub_finding_post.match(
                request.path,
            )
            or UserHasFindingPermission.path_stub_finding.match(request.path)
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Finding_View,
                Permissions.Finding_Edit,
                Permissions.Finding_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Finding_View,
            Permissions.Finding_Edit,
            Permissions.Finding_Edit,
            Permissions.Finding_Edit,
        )


class UserHasImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(request.data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            converted_dict["product_type"] = auto_create.get_target_product_type_if_exists(**converted_dict)
            converted_dict["product"] = auto_create.get_target_product_if_exists(**converted_dict)
            converted_dict["engagement"] = auto_create.get_target_engagement_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(e)
        if engagement := converted_dict.get("engagement"):
            # existing engagement, nothing special to check
            return user_has_permission(
                request.user, engagement, Permissions.Import_Scan_Result,
            )
        if engagement_id := converted_dict.get("engagement_id"):
            # engagement_id doesn't exist
            msg = f'Engagement "{engagement_id}" does not exist'
            raise serializers.ValidationError(msg)

        if not converted_dict.get("auto_create_context"):
            raise_no_auto_create_import_validation_error(
                None,
                None,
                converted_dict.get("engagement_name"),
                converted_dict.get("product_name"),
                converted_dict.get("product_type_name"),
                converted_dict.get("engagement"),
                converted_dict.get("product"),
                converted_dict.get("product_type"),
                "Need engagement_id or product_name + engagement_name to perform import",
            )
            return None
        # the engagement doesn't exist, so we need to check if the user has
        # requested and is allowed to use auto_create
        return check_auto_create_permission(
            request.user,
            converted_dict.get("product"),
            converted_dict.get("product_name"),
            converted_dict.get("engagement"),
            converted_dict.get("engagement_name"),
            converted_dict.get("product_type"),
            converted_dict.get("product_type_name"),
            "Need engagement_id or product_name + engagement_name to perform import",
        )


class UserHasMetaImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(request.data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**converted_dict)
            if not product:
                product = auto_create.get_target_product_by_id_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(e)

        if product:
            # existing product, nothing special to check
            return user_has_permission(
                request.user, product, Permissions.Import_Scan_Result,
            )
        if product_id := converted_dict.get("product_id"):
            # product_id doesn't exist
            msg = f'Product "{product_id}" does not exist'
            raise serializers.ValidationError(msg)
        msg = "Need product_id or product_name to perform import"
        raise serializers.ValidationError(msg)


class UserHasProductPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product_Type,
            "prod_type",
            Permissions.Product_Type_Add_Product,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_View,
            Permissions.Product_Edit,
            Permissions.Product_Delete,
        )


class UserHasProductMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Manage_Members,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_View,
            Permissions.Product_Manage_Members,
            Permissions.Product_Member_Delete,
        )


class UserHasProductGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Group_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Group_View,
            Permissions.Product_Group_Edit,
            Permissions.Product_Group_Delete,
        )


class UserHasProductTypePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            return user_has_global_permission(
                request.user, Permissions.Product_Type_Add,
            )
        return True

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Edit,
            Permissions.Product_Type_Delete,
        )


class UserHasProductTypeMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product_Type,
            "product_type",
            Permissions.Product_Type_Manage_Members,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Member_Delete,
        )


class UserHasProductTypeGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product_Type,
            "product_type",
            Permissions.Product_Type_Group_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Type_Group_View,
            Permissions.Product_Type_Group_Edit,
            Permissions.Product_Type_Group_Delete,
        )


class UserHasReimportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(request.data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            converted_dict["product_type"] = auto_create.get_target_product_type_if_exists(**converted_dict)
            converted_dict["product"] = auto_create.get_target_product_if_exists(**converted_dict)
            converted_dict["engagement"] = auto_create.get_target_engagement_if_exists(**converted_dict)
            converted_dict["test"] = auto_create.get_target_test_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(e)

        if test := converted_dict.get("test"):
            # existing test, nothing special to check
            return user_has_permission(
                request.user, test, Permissions.Import_Scan_Result,
            )
        if test_id := converted_dict.get("test_id"):
            # test_id doesn't exist
            msg = f'Test "{test_id}" does not exist'
            raise serializers.ValidationError(msg)

        if not converted_dict.get("auto_create_context"):
            raise_no_auto_create_import_validation_error(
                converted_dict.get("test_title"),
                converted_dict.get("scan_type"),
                converted_dict.get("engagement_name"),
                converted_dict.get("product_name"),
                converted_dict.get("product_type_name"),
                converted_dict.get("engagement"),
                converted_dict.get("product"),
                converted_dict.get("product_type"),
                "Need test_id or product_name + engagement_name + scan_type to perform reimport",
            )
            return None
        # the test doesn't exist, so we need to check if the user has
        # requested and is allowed to use auto_create
        return check_auto_create_permission(
            request.user,
            converted_dict.get("product"),
            converted_dict.get("product_name"),
            converted_dict.get("engagement"),
            converted_dict.get("engagement_name"),
            converted_dict.get("product_type"),
            converted_dict.get("product_type_name"),
            "Need test_id or product_name + engagement_name + scan_type to perform reimport",
        )


class UserHasTestPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_tests_post = re.compile(r"^/api/v2/tests/$")
    path_tests = re.compile(r"^/api/v2/tests/\d+/$")

    def has_permission(self, request, view):
        if UserHasTestPermission.path_tests_post.match(
            request.path,
        ) or UserHasTestPermission.path_tests.match(request.path):
            return check_post_permission(
                request, Engagement, "engagement", Permissions.Test_Add,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasTestPermission.path_tests_post.match(
            request.path,
        ) or UserHasTestPermission.path_tests.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Test_View,
                Permissions.Test_Edit,
                Permissions.Test_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Test_View,
            Permissions.Test_Edit,
            Permissions.Test_Edit,
            Permissions.Test_Edit,
        )


class UserHasTestImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Test, "test", Permissions.Test_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.test,
            Permissions.Test_View,
            Permissions.Test_Edit,
            Permissions.Test_Delete,
        )


class UserHasLanguagePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Language_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Language_View,
            Permissions.Language_Edit,
            Permissions.Language_Delete,
        )


class UserHasProductAPIScanConfigurationPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product,
            "product",
            Permissions.Product_API_Scan_Configuration_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_API_Scan_Configuration_View,
            Permissions.Product_API_Scan_Configuration_Edit,
            Permissions.Product_API_Scan_Configuration_Delete,
        )


class UserHasJiraProductPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            has_permission_result = True
            engagement_id = request.data.get("engagement", None)
            if engagement_id:
                obj = get_object_or_404(Engagement, pk=engagement_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Engagement_Edit,
                    )
                )
            product_id = request.data.get("product", None)
            if product_id:
                obj = get_object_or_404(Product, pk=product_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Product_Edit,
                    )
                )
            return has_permission_result
        return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        engagement = obj.engagement
        if engagement:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    engagement,
                    Permissions.Engagement_View,
                    Permissions.Engagement_Edit,
                    Permissions.Engagement_Edit,
                )
            )
        product = obj.product
        if product:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    product,
                    Permissions.Product_View,
                    Permissions.Product_Edit,
                    Permissions.Product_Edit,
                )
            )
        return has_permission_result


class UserHasJiraIssuePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            has_permission_result = True
            engagement_id = request.data.get("engagement", None)
            if engagement_id:
                obj = get_object_or_404(Engagement, pk=engagement_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Engagement_Edit,
                    )
                )
            finding_id = request.data.get("finding", None)
            if finding_id:
                obj = get_object_or_404(Finding, pk=finding_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Finding_Edit,
                    )
                )
            finding_group_id = request.data.get("finding_group", None)
            if finding_group_id:
                obj = get_object_or_404(Finding_Group, pk=finding_group_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Finding_Group_Edit,
                    )
                )
            return has_permission_result
        return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        engagement = obj.engagement
        if engagement:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    engagement,
                    Permissions.Engagement_View,
                    Permissions.Engagement_Edit,
                    Permissions.Engagement_Edit,
                )
            )
        finding = obj.finding
        if finding:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding,
                    Permissions.Finding_View,
                    Permissions.Finding_Edit,
                    Permissions.Finding_Edit,
                )
            )
        finding_group = obj.finding_group
        if finding_group:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding_group,
                    Permissions.Finding_Group_View,
                    Permissions.Finding_Group_Edit,
                    Permissions.Finding_Group_Edit,
                )
            )
        return has_permission_result


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class UserHasEngagementPresetPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Product_View,
            Permissions.Product_Edit,
            Permissions.Product_Edit,
            Permissions.Product_Edit,
        )


def raise_no_auto_create_import_validation_error(
    test_title,
    scan_type,
    engagement_name,
    product_name,
    product_type_name,
    engagement,
    product,
    product_type,
    error_message,
):
    # check for mandatory fields first
    if not product_name:
        msg = "product_name parameter missing"
        raise ValidationError(msg)

    if not engagement_name:
        msg = "engagement_name parameter missing"
        raise ValidationError(msg)

    if product_type_name and not product_type:
        msg = f'Product Type "{product_type_name}" does not exist'
        raise serializers.ValidationError(msg)

    if product_name and not product:
        if product_type_name:
            msg = f'Product "{product_name}" does not exist in Product_Type "{product_type_name}"'
            raise serializers.ValidationError(msg)
        msg = f'Product "{product_name}" does not exist'
        raise serializers.ValidationError(msg)

    if engagement_name and not engagement:
        msg = f'Engagement "{engagement_name}" does not exist in Product "{product_name}"'
        raise serializers.ValidationError(msg)

    # these are only set for reimport
    if test_title:
        msg = f'Test "{test_title}" with scan_type "{scan_type}" does not exist in Engagement "{engagement_name}"'
        raise serializers.ValidationError(msg)

    if scan_type:
        msg = f'Test with scan_type "{scan_type}" does not exist in Engagement "{engagement_name}"'
        raise serializers.ValidationError(msg)

    raise ValidationError(error_message)


def check_auto_create_permission(
    user,
    product,
    product_name,
    engagement,
    engagement_name,
    product_type,
    product_type_name,
    error_message,
):
    """
    For an existing engagement, to be allowed to import a scan, the following must all be True:
    - User must have Import_Scan_Result permission for this Engagement

    For an existing product, to be allowed to import into a new engagement with name `engagement_name`, the following must all be True:
    - Product with name `product_name`  must already exist;
    - User must have Engagement_Add permission for this Product
    - User must have Import_Scan_Result permission for this Product

    If the product doesn't exist yet, to be allowed to import into a new product with name `product_name` and prod_type `product_type_name`,
    the following must all be True:
    - `auto_create_context` must be True
    - Product_Type already exists, or the user has the Product_Type_Add permission
    - User must have Product_Type_Add_Product permission for the Product_Type, or the user has the Product_Type_Add permission
    """
    if not product_name:
        msg = "product_name parameter missing"
        raise ValidationError(msg)

    if not engagement_name:
        msg = "engagement_name parameter missing"
        raise ValidationError(msg)

    if engagement:
        # existing engagement, nothing special to check
        return user_has_permission(
            user, engagement, Permissions.Import_Scan_Result,
        )

    if product and product_name and engagement_name:
        if not user_has_permission(user, product, Permissions.Engagement_Add):
            msg = f'No permission to create engagements in product "{product_name}"'
            raise PermissionDenied(msg)

        if not user_has_permission(
            user, product, Permissions.Import_Scan_Result,
        ):
            msg = f'No permission to import scans into product "{product_name}"'
            raise PermissionDenied(msg)

        # all good
        return True

    if not product and product_name:
        if not product_type_name:
            msg = f'Product "{product_name}" does not exist and no product_type_name provided to create the new product in'
            raise serializers.ValidationError(msg)

        if not product_type:
            if not user_has_global_permission(
                user, Permissions.Product_Type_Add,
            ):
                msg = f'No permission to create product_type "{product_type_name}"'
                raise PermissionDenied(msg)
            # new product type can be created with current user as owner, so
            # all objects in it can be created as well
            return True
        if not user_has_permission(
            user, product_type, Permissions.Product_Type_Add_Product,
        ):
            msg = f'No permission to create products in product_type "{product_type}"'
            raise PermissionDenied(msg)

        # product can be created, so objects in it can be created as well
        return True

    raise ValidationError(error_message)


class UserHasConfigurationPermissionStaff(permissions.DjangoModelPermissions):
    # Override map to also provide 'view' permissions
    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": [],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }

    def has_permission(self, request, view):
        return super().has_permission(request, view)


class UserHasConfigurationPermissionSuperuser(
    permissions.DjangoModelPermissions,
):
    # Override map to also provide 'view' permissions
    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": [],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }

    def has_permission(self, request, view):
        return super().has_permission(request, view)
