import base64
import collections
import json
import logging
import re
from datetime import datetime

import six
import tagulous
from django.conf import settings
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.utils import IntegrityError
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from rest_framework.exceptions import NotFound
from rest_framework.exceptions import ValidationError as RestFrameworkValidationError
from rest_framework.fields import DictField, MultipleChoiceField

import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.utils import endpoint_filter, endpoint_meta_import
from dojo.finding.helper import (
    save_vulnerability_ids,
    save_vulnerability_ids_template,
)
from dojo.finding.queries import get_authorized_findings
from dojo.group.utils import get_auth_group_name
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.importers.base_importer import BaseImporter
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    DEFAULT_NOTIFICATION,
    IMPORT_ACTIONS,
    NOTIFICATION_CHOICES,
    SEVERITIES,
    SEVERITY_CHOICES,
    STATS_FIELDS,
    Announcement,
    Answer,
    Answered_Survey,
    App_Analysis,
    BurpRawRequestResponse,
    Check_List,
    ChoiceAnswer,
    ChoiceQuestion,
    Cred_Mapping,
    Cred_User,
    Development_Environment,
    Dojo_Group,
    Dojo_Group_Member,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Params,
    Endpoint_Status,
    Engagement,
    Engagement_Presets,
    Engagement_Survey,
    FileUpload,
    Finding,
    Finding_Group,
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
    NoteHistory,
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
    Test_Import_Finding_Action,
    Test_Type,
    TextAnswer,
    TextQuestion,
    Tool_Configuration,
    Tool_Product_Settings,
    Tool_Type,
    User,
    UserContactInfo,
    Vulnerability_Id,
    Vulnerability_Id_Template,
    get_current_date,
)
from dojo.risk_acceptance.helper import add_findings_to_risk_acceptance, remove_finding_from_risk_acceptance
from dojo.tools.factory import (
    get_choices_sorted,
    requires_file,
    requires_tool_type,
)
from dojo.user.utils import get_configuration_permissions_codenames
from dojo.utils import is_scan_file_too_large

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def get_product_id_from_dict(data):
    product_id = data.get("product", None)
    if product_id:
        if isinstance(product_id, Product):
            product_id = product_id.id
        elif isinstance(product_id, str) and not product_id.isdigit():
            msg = "product must be an integer"
            raise serializers.ValidationError(msg)
    return product_id


class StatusStatisticsSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for stat in STATS_FIELDS:
            self.fields[stat.lower()] = serializers.IntegerField()


class SeverityStatusStatisticsSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for sev in SEVERITIES:
            self.fields[sev.lower()] = StatusStatisticsSerializer()

        self.fields["total"] = StatusStatisticsSerializer()


class DeltaStatisticsSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for action in IMPORT_ACTIONS:
            self.fields[
                action[1].lower()
            ] = SeverityStatusStatisticsSerializer()


class ImportStatisticsSerializer(serializers.Serializer):
    before = SeverityStatusStatisticsSerializer(
        required=False,
        help_text="Finding statistics as stored in Defect Dojo before the import",
    )
    delta = DeltaStatisticsSerializer(
        required=False,
        help_text="Finding statistics of modifications made by the reimport. Only available when TRACK_IMPORT_HISTORY hass not disabled.",
    )
    after = SeverityStatusStatisticsSerializer(
        help_text="Finding statistics as stored in Defect Dojo after the import",
    )


@extend_schema_field(
    serializers.ListField(child=serializers.CharField()),
)  # also takes basic python types
class TagListSerializerField(serializers.ListField):
    child = serializers.CharField()
    default_error_messages = {
        "not_a_list": _(
            'Expected a list of items but got type "{input_type}".',
        ),
        "invalid_json": _(
            "Invalid json list. A tag list submitted in string"
            " form must be valid json.",
        ),
        "not_a_str": _("All list items must be of string type."),
    }
    order_by = None

    def __init__(self, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)

        style = kwargs.pop("style", {})
        kwargs["style"] = {"base_template": "textarea.html"}
        kwargs["style"].update(style)

        super().__init__(**kwargs)

        self.pretty_print = pretty_print

    def to_internal_value(self, data):
        if isinstance(data, list) and data == [""] and self.allow_empty:
            return []
        if isinstance(data, six.string_types):
            if not data:
                data = []
            try:
                data = json.loads(data)
            except ValueError:
                self.fail("invalid_json")

        logger.debug(f"data as json: {data}")

        if not isinstance(data, list):
            self.fail("not_a_list", input_type=type(data).__name__)

        data_safe = []
        for s in data:
            # Ensure if the element in the list is  string
            if not isinstance(s, six.string_types):
                self.fail("not_a_str")
            # Run the children validation
            self.child.run_validation(s)
            substrings = re.findall(r'(?:"[^"]*"|[^",]+)', s)
            data_safe.extend(substrings)

        return tagulous.utils.render_tags(data_safe)

    def to_representation(self, value):
        if not isinstance(value, list):
            # we can't use isinstance because TagRelatedManager is non-existing class
            # it cannot be imported or referenced, so we fallback to string
            # comparison
            if type(value).__name__ == "TagRelatedManager":
                value = value.get_tag_list()
            elif isinstance(value, str):
                value = tagulous.utils.parse_tags(value)
            else:
                msg = f"unable to convert {type(value).__name__} into list of tags"
                raise ValueError(msg)
        return value


class TaggitSerializer(serializers.Serializer):
    def create(self, validated_data):
        to_be_tagged, validated_data = self._pop_tags(validated_data)

        tag_object = super().create(validated_data)

        return self._save_tags(tag_object, to_be_tagged)

    def update(self, instance, validated_data):
        to_be_tagged, validated_data = self._pop_tags(validated_data)

        tag_object = super().update(
            instance, validated_data,
        )

        return self._save_tags(tag_object, to_be_tagged)

    def _save_tags(self, tag_object, tags):
        for key in list(tags.keys()):
            tag_values = tags.get(key)
            # tag_object.tags = ", ".join(tag_values)
            tag_object.tags = tag_values
        tag_object.save()

        return tag_object

    def _pop_tags(self, validated_data):
        to_be_tagged = {}

        for key in list(self.fields.keys()):
            field = self.fields[key]
            if isinstance(field, TagListSerializerField):
                if key in validated_data:
                    to_be_tagged[key] = validated_data.pop(key)

        return (to_be_tagged, validated_data)


class RequestResponseDict(collections.UserList):
    def __init__(self, *args, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)
        collections.UserList.__init__(self, *args, **kwargs)
        self.pretty_print = pretty_print

    def __add__(self, rhs):
        return RequestResponseDict(list.__add__(self, rhs))

    def __getitem__(self, item):
        result = list.__getitem__(self, item)
        try:
            return RequestResponseDict(result)
        except TypeError:
            return result

    def __str__(self):
        if self.pretty_print:
            return json.dumps(
                self, sort_keys=True, indent=4, separators=(",", ": "),
            )
        return json.dumps(self)


class RequestResponseSerializerField(serializers.ListSerializer):
    child = DictField(child=serializers.CharField())
    default_error_messages = {
        "not_a_list": _(
            'Expected a list of items but got type "{input_type}".',
        ),
        "invalid_json": _(
            "Invalid json list. A tag list submitted in string"
            " form must be valid json.",
        ),
        "not_a_dict": _(
            "All list items must be of dict type with keys 'request' and 'response'",
        ),
        "not_a_str": _("All values in the dict must be of string type."),
    }
    order_by = None

    def __init__(self, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)

        style = kwargs.pop("style", {})
        kwargs["style"] = {"base_template": "textarea.html"}
        kwargs["style"].update(style)

        if "data" in kwargs:
            data = kwargs["data"]

            if isinstance(data, list):
                kwargs["many"] = True

        super().__init__(**kwargs)

        self.pretty_print = pretty_print

    def to_internal_value(self, data):
        if isinstance(data, six.string_types):
            if not data:
                data = []
            try:
                data = json.loads(data)
            except ValueError:
                self.fail("invalid_json")

        if not isinstance(data, list):
            self.fail("not_a_list", input_type=type(data).__name__)
        for s in data:
            if not isinstance(s, dict):
                self.fail("not_a_dict", input_type=type(s).__name__)

            request = s.get("request", None)
            response = s.get("response", None)

            if not isinstance(request, str):
                self.fail("not_a_str", input_type=type(request).__name__)
            if not isinstance(response, str):
                self.fail("not_a_str", input_type=type(request).__name__)

            self.child.run_validation(s)
        return data

    def to_representation(self, value):
        if not isinstance(value, RequestResponseDict):
            if not isinstance(value, list):
                # this will trigger when a queryset is found...
                burps = value.all().order_by(*self.order_by) if self.order_by else value.all()
                value = [
                    {
                        "request": burp.get_request(),
                        "response": burp.get_response(),
                    }
                    for burp in burps
                ]

        return value


class BurpRawRequestResponseSerializer(serializers.Serializer):
    req_resp = RequestResponseSerializerField(required=True)


class BurpRawRequestResponseMultiSerializer(serializers.ModelSerializer):
    burpRequestBase64 = serializers.CharField()
    burpResponseBase64 = serializers.CharField()

    def to_representation(self, data):
        return {
            "id": data.id,
            "finding": data.finding.id,
            "burpRequestBase64": data.burpRequestBase64.decode("utf-8"),
            "burpResponseBase64": data.burpResponseBase64.decode("utf-8"),
        }

    def validate(self, data):
        b64request = data.get("burpRequestBase64", None)
        b64response = data.get("burpResponseBase64", None)
        finding = data.get("finding", None)
        # Make sure all fields are present
        if not b64request or not b64response or not finding:
            msg = "burpRequestBase64, burpResponseBase64, and finding are required."
            raise ValidationError(msg)
        # Verify we have true base64 decoding
        try:
            base64.b64decode(b64request, validate=True)
            base64.b64decode(b64response, validate=True)
        except Exception as e:
            msg = "Inputs need to be valid base64 encodings"
            raise ValidationError(msg) from e
        # Encode the data in utf-8 to remove any bad characters
        data["burpRequestBase64"] = b64request.encode("utf-8")
        data["burpResponseBase64"] = b64response.encode("utf-8")
        # Run the model validation - an ValidationError will be raised if there is an issue
        BurpRawRequestResponse(finding=finding, burpRequestBase64=b64request, burpResponseBase64=b64response).clean()

        return data

    class Meta:
        model = BurpRawRequestResponse
        fields = "__all__"


class MetaSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    endpoint = serializers.PrimaryKeyRelatedField(
        queryset=Endpoint.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    finding = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )

    def validate(self, data):
        DojoMeta(**data).clean()
        return data

    class Meta:
        model = DojoMeta
        fields = "__all__"


class MetadataSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=120)
    value = serializers.CharField(max_length=300)


class MetaMainSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)

    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    endpoint = serializers.PrimaryKeyRelatedField(
        queryset=Endpoint.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    finding = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    metadata = MetadataSerializer(many=True)

    def validate(self, data):
        product_id = data.get("product", None)
        endpoint_id = data.get("endpoint", None)
        finding_id = data.get("finding", None)
        metadata = data.get("metadata")

        for item in metadata:
            # this will only verify that one and only one of product, endpoint, or finding is passed...
            DojoMeta(product=product_id,
                     endpoint=endpoint_id,
                     finding=finding_id,
                     name=item.get("name"),
                     value=item.get("value")).clean()

        return data


class ProductMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = DojoMeta
        fields = ("name", "value")


class UserSerializer(serializers.ModelSerializer):
    date_joined = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True, allow_null=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        required=False,
        validators=[validate_password],
    )
    configuration_permissions = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        queryset=Permission.objects.filter(
            codename__in=get_configuration_permissions_codenames(),
        ),
        many=True,
        required=False,
        source="user_permissions",
    )

    class Meta:
        model = Dojo_User
        fields = (
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "date_joined",
            "last_login",
            "is_active",
            "is_superuser",
            "password",
            "configuration_permissions",
        )

    def to_representation(self, instance):
        ret = super().to_representation(instance)

        # This will show only "configuration_permissions" even if user has also
        # other permissions
        all_permissions = set(ret["configuration_permissions"])
        allowed_configuration_permissions = set(
            self.fields[
                "configuration_permissions"
            ].child_relation.queryset.values_list("id", flat=True),
        )
        ret["configuration_permissions"] = list(
            all_permissions.intersection(allowed_configuration_permissions),
        )

        return ret

    def update(self, instance, validated_data):
        new_configuration_permissions = None
        if (
            "user_permissions" in validated_data
        ):  # This field was renamed from "configuration_permissions" in the meantime
            new_configuration_permissions = set(
                validated_data.pop("user_permissions"),
            )

        instance = super().update(instance, validated_data)

        # This will update only Permissions from category
        # "configuration_permissions". Others will be untouched
        if new_configuration_permissions:
            allowed_configuration_permissions = set(
                self.fields[
                    "configuration_permissions"
                ].child_relation.queryset.all(),
            )
            non_configuration_permissions = (
                set(instance.user_permissions.all())
                - allowed_configuration_permissions
            )
            new_permissions = non_configuration_permissions.union(
                new_configuration_permissions,
            )
            instance.user_permissions.set(new_permissions)

        return instance

    def create(self, validated_data):
        password = validated_data.pop("password", None)

        new_configuration_permissions = None
        if (
            "user_permissions" in validated_data
        ):  # This field was renamed from "configuration_permissions" in the meantime
            new_configuration_permissions = set(
                validated_data.pop("user_permissions"),
            )

        user = Dojo_User.objects.create(**validated_data)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        # This will create only Permissions from category
        # "configuration_permissions". There are no other Permissions.
        if new_configuration_permissions:
            user.user_permissions.set(new_configuration_permissions)

        user.save()
        return user

    def validate(self, data):
        instance_is_superuser = self.instance.is_superuser if self.instance is not None else False
        data_is_superuser = data.get("is_superuser", False)
        if not self.context["request"].user.is_superuser and (
            instance_is_superuser or data_is_superuser
        ):
            msg = "Only superusers are allowed to add or edit superusers."
            raise ValidationError(msg)

        if self.context["request"].method in ["PATCH", "PUT"] and "password" in data:
            msg = "Update of password though API is not allowed"
            raise ValidationError(msg)
        if self.context["request"].method == "POST" and "password" not in data and settings.REQUIRE_PASSWORD_ON_USER:
            msg = "Passwords must be supplied for new users"
            raise ValidationError(msg)
        return super().validate(data)


class UserContactInfoSerializer(serializers.ModelSerializer):
    user_profile = UserSerializer(many=False, source="user", read_only=True)

    class Meta:
        model = UserContactInfo
        fields = "__all__"


class UserStubSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dojo_User
        fields = ("id", "username", "first_name", "last_name")


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = "__all__"


class DojoGroupSerializer(serializers.ModelSerializer):
    configuration_permissions = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        queryset=Permission.objects.filter(
            codename__in=get_configuration_permissions_codenames(),
        ),
        many=True,
        required=False,
        source="auth_group.permissions",
    )

    class Meta:
        model = Dojo_Group
        exclude = ("auth_group",)

    def to_representation(self, instance):
        if not instance.auth_group:
            auth_group = Group(name=get_auth_group_name(instance))
            auth_group.save()
            instance.auth_group = auth_group
            members = instance.users.all()
            for member in members:
                auth_group.user_set.add(member)
            instance.save()
        ret = super().to_representation(instance)
        # This will show only "configuration_permissions" even if user has also
        # other permissions
        all_permissions = set(ret["configuration_permissions"])
        allowed_configuration_permissions = set(
            self.fields[
                "configuration_permissions"
            ].child_relation.queryset.values_list("id", flat=True),
        )
        ret["configuration_permissions"] = list(
            all_permissions.intersection(allowed_configuration_permissions),
        )

        return ret

    def create(self, validated_data):
        new_configuration_permissions = None
        if (
            "auth_group" in validated_data
            and "permissions" in validated_data["auth_group"]
        ):  # This field was renamed from "configuration_permissions" in the meantime
            new_configuration_permissions = set(
                validated_data.pop("auth_group")["permissions"],
            )

        instance = super().create(validated_data)

        # This will update only Permissions from category
        # "configuration_permissions". There are no other Permissions.
        if new_configuration_permissions:
            instance.auth_group.permissions.set(new_configuration_permissions)

        return instance

    def update(self, instance, validated_data):
        new_configuration_permissions = None
        if (
            "auth_group" in validated_data
            and "permissions" in validated_data["auth_group"]
        ):  # This field was renamed from "configuration_permissions" in the meantime
            new_configuration_permissions = set(
                validated_data.pop("auth_group")["permissions"],
            )

        instance = super().update(instance, validated_data)

        # This will update only Permissions from category
        # "configuration_permissions". Others will be untouched
        if new_configuration_permissions:
            allowed_configuration_permissions = set(
                self.fields[
                    "configuration_permissions"
                ].child_relation.queryset.all(),
            )
            non_configuration_permissions = (
                set(instance.auth_group.permissions.all())
                - allowed_configuration_permissions
            )
            new_permissions = non_configuration_permissions.union(
                new_configuration_permissions,
            )
            instance.auth_group.permissions.set(new_permissions)

        return instance


class DojoGroupMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dojo_Group_Member
        fields = "__all__"

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("group") != self.instance.group
            and not user_has_permission(
                self.context["request"].user,
                data.get("group"),
                Permissions.Group_Manage_Members,
            )
        ):
            msg = "You are not permitted to add a user to this group"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("group") != self.instance.group
            or data.get("user") != self.instance.user
        ):
            members = Dojo_Group_Member.objects.filter(
                group=data.get("group"), user=data.get("user"),
            )
            if members.count() > 0:
                msg = "Dojo_Group_Member already exists"
                raise ValidationError(msg)

        if self.instance is not None and not data.get("role").is_owner:
            owners = (
                Dojo_Group_Member.objects.filter(
                    group=data.get("group"), role__is_owner=True,
                )
                .exclude(id=self.instance.id)
                .count()
            )
            if owners < 1:
                msg = "There must be at least one owner"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("group"),
            Permissions.Group_Add_Owner,
        ):
            msg = "You are not permitted to add a user as Owner to this group"
            raise PermissionDenied(msg)

        return data


class GlobalRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Global_Role
        fields = "__all__"

    def validate(self, data):
        user = None
        group = None

        if self.instance is not None:
            user = self.instance.user
            group = self.instance.group

        if "user" in data:
            user = data.get("user")
        if "group" in data:
            group = data.get("group")

        if user is None and group is None:
            msg = "Global_Role must have either user or group"
            raise ValidationError(msg)
        if user is not None and group is not None:
            msg = "Global_Role cannot have both user and group"
            raise ValidationError(msg)

        return data


class AddUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username")


class NoteTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note_Type
        fields = "__all__"


class NoteHistorySerializer(serializers.ModelSerializer):
    current_editor = UserStubSerializer(read_only=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    class Meta:
        model = NoteHistory
        fields = "__all__"


class NoteSerializer(serializers.ModelSerializer):
    author = UserStubSerializer(many=False, read_only=True)
    editor = UserStubSerializer(read_only=True, many=False, allow_null=True)
    history = NoteHistorySerializer(read_only=True, many=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    def update(self, instance, validated_data):
        instance.entry = validated_data.get("entry")
        instance.edited = True
        instance.editor = self.context["request"].user
        instance.edit_time = timezone.now()
        history = NoteHistory(
            data=instance.entry,
            time=instance.edit_time,
            current_editor=instance.editor,
        )
        history.save()
        instance.history.add(history)
        instance.save()
        return instance

    class Meta:
        model = Notes
        fields = "__all__"


class FileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)

    class Meta:
        model = FileUpload
        fields = "__all__"

    def validate(self, data):
        if file := data.get("file"):
            # the clean will validate the file extensions and raise a Validation error if the extensions are not accepted
            FileUpload(title=file.name, file=file).clean()
            return data
        return None


class RawFileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)

    class Meta:
        model = FileUpload
        fields = ["file"]


class RiskAcceptanceProofSerializer(serializers.ModelSerializer):
    path = serializers.FileField(required=True)

    class Meta:
        model = Risk_Acceptance
        fields = ["path"]


class ProductMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Member
        fields = "__all__"

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("product") != self.instance.product
            and not user_has_permission(
                self.context["request"].user,
                data.get("product"),
                Permissions.Product_Manage_Members,
            )
        ):
            msg = "You are not permitted to add a member to this product"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("product") != self.instance.product
            or data.get("user") != self.instance.user
        ):
            members = Product_Member.objects.filter(
                product=data.get("product"), user=data.get("user"),
            )
            if members.count() > 0:
                msg = "Product_Member already exists"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("product"),
            Permissions.Product_Member_Add_Owner,
        ):
            msg = "You are not permitted to add a member as Owner to this product"
            raise PermissionDenied(msg)

        return data


class ProductGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Group
        fields = "__all__"

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("product") != self.instance.product
            and not user_has_permission(
                self.context["request"].user,
                data.get("product"),
                Permissions.Product_Group_Add,
            )
        ):
            msg = "You are not permitted to add a group to this product"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("product") != self.instance.product
            or data.get("group") != self.instance.group
        ):
            members = Product_Group.objects.filter(
                product=data.get("product"), group=data.get("group"),
            )
            if members.count() > 0:
                msg = "Product_Group already exists"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("product"),
            Permissions.Product_Group_Add_Owner,
        ):
            msg = "You are not permitted to add a group as Owner to this product"
            raise PermissionDenied(msg)

        return data


class ProductTypeMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type_Member
        fields = "__all__"

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("product_type") != self.instance.product_type
            and not user_has_permission(
                self.context["request"].user,
                data.get("product_type"),
                Permissions.Product_Type_Manage_Members,
            )
        ):
            msg = "You are not permitted to add a member to this product type"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("product_type") != self.instance.product_type
            or data.get("user") != self.instance.user
        ):
            members = Product_Type_Member.objects.filter(
                product_type=data.get("product_type"), user=data.get("user"),
            )
            if members.count() > 0:
                msg = "Product_Type_Member already exists"
                raise ValidationError(msg)

        if self.instance is not None and not data.get("role").is_owner:
            owners = (
                Product_Type_Member.objects.filter(
                    product_type=data.get("product_type"), role__is_owner=True,
                )
                .exclude(id=self.instance.id)
                .count()
            )
            if owners < 1:
                msg = "There must be at least one owner"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("product_type"),
            Permissions.Product_Type_Member_Add_Owner,
        ):
            msg = "You are not permitted to add a member as Owner to this product type"
            raise PermissionDenied(msg)

        return data


class ProductTypeGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type_Group
        fields = "__all__"

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("product_type") != self.instance.product_type
            and not user_has_permission(
                self.context["request"].user,
                data.get("product_type"),
                Permissions.Product_Type_Group_Add,
            )
        ):
            msg = "You are not permitted to add a group to this product type"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("product_type") != self.instance.product_type
            or data.get("group") != self.instance.group
        ):
            members = Product_Type_Group.objects.filter(
                product_type=data.get("product_type"), group=data.get("group"),
            )
            if members.count() > 0:
                msg = "Product_Type_Group already exists"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("product_type"),
            Permissions.Product_Type_Group_Add_Owner,
        ):
            msg = "You are not permitted to add a group as Owner to this product type"
            raise PermissionDenied(msg)

        return data


class ProductTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = "__all__"


class EngagementSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Engagement
        exclude = ("inherited_tags",)

    def validate(self, data):
        if self.context["request"].method == "POST":
            if data.get("target_start") > data.get("target_end"):
                msg = "Your target start date exceeds your target end date"
                raise serializers.ValidationError(msg)
        return data

    def build_relational_field(self, field_name, relation_info):
        if field_name == "notes":
            return NoteSerializer, {"many": True, "read_only": True}
        if field_name == "files":
            return FileSerializer, {"many": True, "read_only": True}
        return super().build_relational_field(field_name, relation_info)


class EngagementToNotesSerializer(serializers.Serializer):
    engagement_id = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), many=False, allow_null=True,
    )
    notes = NoteSerializer(many=True)


class EngagementToFilesSerializer(serializers.Serializer):
    engagement_id = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), many=False, allow_null=True,
    )
    files = FileSerializer(many=True)

    def to_representation(self, data):
        engagement = data.get("engagement_id")
        files = data.get("files")
        new_files = []
        for file in files:
            new_files.append(
                {
                    "id": file.id,
                    "file": "{site_url}/{file_access_url}".format(
                        site_url=settings.SITE_URL,
                        file_access_url=file.get_accessible_url(
                            engagement, engagement.id,
                        ),
                    ),
                    "title": file.title,
                },
            )
        return {"engagement_id": engagement.id, "files": new_files}


class EngagementCheckListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Check_List
        fields = "__all__"


class AppAnalysisSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = App_Analysis
        fields = "__all__"


class ToolTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tool_Type
        fields = "__all__"

    def validate(self, data):
        if self.context["request"].method == "POST":
            name = data.get("name")
            # Make sure this will not create a duplicate test type
            if Tool_Type.objects.filter(name=name).count() > 0:
                msg = "A Tool Type with the name already exists"
                raise serializers.ValidationError(msg)
        return data


class RegulationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Regulation
        fields = "__all__"


class ToolConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tool_Configuration
        fields = "__all__"
        extra_kwargs = {
            "password": {"write_only": True},
            "ssh": {"write_only": True},
            "api_key": {"write_only": True},
        }


class ToolProductSettingsSerializer(serializers.ModelSerializer):
    setting_url = serializers.CharField(source="url")
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=True,
    )

    class Meta:
        model = Tool_Product_Settings
        fields = "__all__"


class EndpointStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint_Status
        fields = "__all__"

    def run_validators(self, initial_data):
        try:
            return super().run_validators(initial_data)
        except RestFrameworkValidationError as exc:
            if "finding, endpoint must make a unique set" in str(exc):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg) from exc
            raise

    def create(self, validated_data):
        endpoint = validated_data.get("endpoint")
        finding = validated_data.get("finding")
        try:
            status = Endpoint_Status.objects.create(
                finding=finding, endpoint=endpoint,
            )
        except IntegrityError as ie:
            if "finding, endpoint must make a unique set" in str(ie):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg)
            raise
        status.mitigated = validated_data.get("mitigated", False)
        status.false_positive = validated_data.get("false_positive", False)
        status.out_of_scope = validated_data.get("out_of_scope", False)
        status.risk_accepted = validated_data.get("risk_accepted", False)
        status.date = validated_data.get("date", get_current_date())
        status.save()
        return status

    def update(self, instance, validated_data):
        try:
            return super().update(instance, validated_data)
        except IntegrityError as ie:
            if "finding, endpoint must make a unique set" in str(ie):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg)
            raise


class EndpointSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Endpoint
        exclude = ("inherited_tags",)

    def validate(self, data):

        if self.context["request"].method != "PATCH":
            if "product" not in data:
                msg = "Product is required"
                raise serializers.ValidationError(msg)
            protocol = data.get("protocol")
            userinfo = data.get("userinfo")
            host = data.get("host")
            port = data.get("port")
            path = data.get("path")
            query = data.get("query")
            fragment = data.get("fragment")
            product = data.get("product")
        else:
            protocol = data.get("protocol", self.instance.protocol)
            userinfo = data.get("userinfo", self.instance.userinfo)
            host = data.get("host", self.instance.host)
            port = data.get("port", self.instance.port)
            path = data.get("path", self.instance.path)
            query = data.get("query", self.instance.query)
            fragment = data.get("fragment", self.instance.fragment)
            if "product" in data and data["product"] != self.instance.product:
                msg = "Change of product is not possible"
                raise serializers.ValidationError(msg)
            product = self.instance.product

        endpoint_ins = Endpoint(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            product=product,
        )
        endpoint_ins.clean()  # Run standard validation and clean process; can raise errors

        endpoint = endpoint_filter(
            protocol=endpoint_ins.protocol,
            userinfo=endpoint_ins.userinfo,
            host=endpoint_ins.host,
            port=endpoint_ins.port,
            path=endpoint_ins.path,
            query=endpoint_ins.query,
            fragment=endpoint_ins.fragment,
            product=endpoint_ins.product,
        )
        if (
            self.context["request"].method in ["PUT", "PATCH"]
            and (
                (endpoint.count() > 1)
                or (
                    endpoint.count() == 1
                    and endpoint.first().pk != self.instance.pk
                )
            )
        ) or (
            self.context["request"].method == "POST" and endpoint.count() > 0
        ):
            msg = (
                "It appears as though an endpoint with this data already "
                "exists for this product."
            )
            raise serializers.ValidationError(msg, code="invalid")

        # use clean data
        data["protocol"] = endpoint_ins.protocol
        data["userinfo"] = endpoint_ins.userinfo
        data["host"] = endpoint_ins.host
        data["port"] = endpoint_ins.port
        data["path"] = endpoint_ins.path
        data["query"] = endpoint_ins.query
        data["fragment"] = endpoint_ins.fragment
        data["product"] = endpoint_ins.product

        return data


class EndpointParamsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint_Params
        fields = "__all__"


class JIRAIssueSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = JIRA_Issue
        fields = "__all__"

    def get_url(self, obj) -> str:
        return jira_helper.get_jira_issue_url(obj)

    def validate(self, data):
        if self.context["request"].method == "PATCH":
            engagement = data.get("engagement", self.instance.engagement)
            finding = data.get("finding", self.instance.finding)
            finding_group = data.get(
                "finding_group", self.instance.finding_group,
            )
        else:
            engagement = data.get("engagement", None)
            finding = data.get("finding", None)
            finding_group = data.get("finding_group", None)

        if (
            (engagement and not finding and not finding_group)
            or (finding and not engagement and not finding_group)
            or (finding_group and not engagement and not finding)
        ):
            pass
        else:
            msg = "Either engagement or finding or finding_group has to be set."
            raise serializers.ValidationError(msg)

        if finding:
            if (linked_finding := jira_helper.jira_already_linked(finding, data.get("jira_key"), data.get("jira_id"))) is not None:
                msg = "JIRA issue " + data.get("jira_key") + " already linked to " + reverse("view_finding", args=(linked_finding.id,))
                raise serializers.ValidationError(msg)

        return data


class JIRAInstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Instance
        fields = "__all__"
        extra_kwargs = {
            "password": {"write_only": True},
        }


class JIRAProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Project
        fields = "__all__"

    def validate(self, data):
        if self.context["request"].method == "PATCH":
            engagement = data.get("engagement", self.instance.engagement)
            product = data.get("product", self.instance.product)
        else:
            engagement = data.get("engagement", None)
            product = data.get("product", None)

        if (engagement and product) or (not engagement and not product):
            msg = "Either engagement or product has to be set."
            raise serializers.ValidationError(msg)

        return data


class SonarqubeIssueSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sonarqube_Issue
        fields = "__all__"


class SonarqubeIssueTransitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sonarqube_Issue_Transition
        fields = "__all__"


class ProductAPIScanConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_API_Scan_Configuration
        fields = "__all__"


class DevelopmentEnvironmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Development_Environment
        fields = "__all__"


class FindingGroupSerializer(serializers.ModelSerializer):
    jira_issue = JIRAIssueSerializer(read_only=True, allow_null=True)

    class Meta:
        model = Finding_Group
        fields = ("id", "name", "test", "jira_issue")


class TestSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)
    test_type_name = serializers.ReadOnlyField()
    finding_groups = FindingGroupSerializer(
        source="finding_group_set", many=True, read_only=True,
    )

    class Meta:
        model = Test
        exclude = ("inherited_tags",)

    def build_relational_field(self, field_name, relation_info):
        if field_name == "notes":
            return NoteSerializer, {"many": True, "read_only": True}
        if field_name == "files":
            return FileSerializer, {"many": True, "read_only": True}
        return super().build_relational_field(field_name, relation_info)


class TestCreateSerializer(TaggitSerializer, serializers.ModelSerializer):
    engagement = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(),
    )
    notes = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        queryset=Notes.objects.all(),
        many=True,
        required=False,
    )
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Test
        exclude = ("inherited_tags",)


class TestTypeSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Test_Type
        exclude = ("dynamically_generated",)


class TestToNotesSerializer(serializers.Serializer):
    test_id = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all(), many=False, allow_null=True,
    )
    notes = NoteSerializer(many=True)


class TestToFilesSerializer(serializers.Serializer):
    test_id = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all(), many=False, allow_null=True,
    )
    files = FileSerializer(many=True)

    def to_representation(self, data):
        test = data.get("test_id")
        files = data.get("files")
        new_files = []
        for file in files:
            new_files.append(
                {
                    "id": file.id,
                    "file": f"{settings.SITE_URL}/{file.get_accessible_url(test, test.id)}",
                    "title": file.title,
                },
            )
        return {"test_id": test.id, "files": new_files}


class TestImportFindingActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test_Import_Finding_Action
        fields = "__all__"


class TestImportSerializer(serializers.ModelSerializer):
    # findings = TestImportFindingActionSerializer(source='test_import_finding_action', many=True, read_only=True)
    test_import_finding_action_set = TestImportFindingActionSerializer(
        many=True, read_only=True,
    )

    class Meta:
        model = Test_Import
        fields = "__all__"


class RiskAcceptanceSerializer(serializers.ModelSerializer):
    recommendation = serializers.SerializerMethodField()
    decision = serializers.SerializerMethodField()
    path = serializers.SerializerMethodField()

    def create(self, validated_data):
        instance = super().create(validated_data)
        user = getattr(self.context.get("request", None), "user", None)
        add_findings_to_risk_acceptance(user, instance, instance.accepted_findings.all())
        return instance

    def update(self, instance, validated_data):
        # Determine findings to risk accept, and findings to unaccept risk
        existing_findings = Finding.objects.filter(risk_acceptance=self.instance.id)
        new_findings_ids = [x.id for x in validated_data.get("accepted_findings", [])]
        new_findings = Finding.objects.filter(id__in=new_findings_ids)
        findings_to_add = set(new_findings) - set(existing_findings)
        findings_to_remove = set(existing_findings) - set(new_findings)
        findings_to_add = Finding.objects.filter(id__in=[x.id for x in findings_to_add])
        findings_to_remove = Finding.objects.filter(id__in=[x.id for x in findings_to_remove])
        # Make the update in the database
        instance = super().update(instance, validated_data)
        user = getattr(self.context.get("request", None), "user", None)
        # Add the new findings
        add_findings_to_risk_acceptance(user, instance, findings_to_add)
        # Remove the ones that were not present in the payload
        for finding in findings_to_remove:
            remove_finding_from_risk_acceptance(user, instance, finding)
        return instance

    @extend_schema_field(serializers.CharField())
    def get_recommendation(self, obj):
        return Risk_Acceptance.TREATMENT_TRANSLATIONS.get(obj.recommendation)

    @extend_schema_field(serializers.CharField())
    def get_decision(self, obj):
        return Risk_Acceptance.TREATMENT_TRANSLATIONS.get(obj.decision)

    @extend_schema_field(serializers.CharField())
    def get_path(self, obj):
        engagement = Engagement.objects.filter(
            risk_acceptance__id__in=[obj.id],
        ).first()
        path = "No proof has been supplied"
        if engagement and obj.filename() is not None:
            path = reverse(
                "download_risk_acceptance", args=(engagement.id, obj.id),
            )
            request = self.context.get("request")
            if request:
                path = request.build_absolute_uri(path)
        return path

    @extend_schema_field(serializers.IntegerField())
    def get_engagement(self, obj):
        engagement = Engagement.objects.filter(
            risk_acceptance__id__in=[obj.id],
        ).first()
        return EngagementSerializer(read_only=True).to_representation(
            engagement,
        )

    def validate(self, data):
        def validate_findings_have_same_engagement(finding_objects: list[Finding]):
            engagements = finding_objects.values_list("test__engagement__id", flat=True).distinct().count()
            if engagements > 1:
                msg = "You are not permitted to add findings from multiple engagements"
                raise PermissionDenied(msg)

        findings = data.get("accepted_findings", [])
        findings_ids = [x.id for x in findings]
        finding_objects = Finding.objects.filter(id__in=findings_ids)
        authed_findings = get_authorized_findings(Permissions.Finding_Edit).filter(id__in=findings_ids)
        if len(findings) != len(authed_findings):
            msg = "You are not permitted to add one or more selected findings to this risk acceptance"
            raise PermissionDenied(msg)
        if self.context["request"].method == "POST":
            validate_findings_have_same_engagement(finding_objects)
        elif self.context["request"].method in ["PATCH", "PUT"]:
            existing_findings = Finding.objects.filter(risk_acceptance=self.instance.id)
            existing_and_new_findings = existing_findings | finding_objects
            validate_findings_have_same_engagement(existing_and_new_findings)
        return data

    class Meta:
        model = Risk_Acceptance
        fields = "__all__"


class FindingMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = DojoMeta
        fields = ("name", "value")


class FindingProdTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = ["id", "name"]


class FindingProductSerializer(serializers.ModelSerializer):
    prod_type = FindingProdTypeSerializer(required=False)

    class Meta:
        model = Product
        fields = ["id", "name", "prod_type"]


class FindingEngagementSerializer(serializers.ModelSerializer):
    product = FindingProductSerializer(required=False)

    class Meta:
        model = Engagement
        fields = [
            "id",
            "name",
            "description",
            "product",
            "target_start",
            "target_end",
            "branch_tag",
            "engagement_type",
            "build_id",
            "commit_hash",
            "version",
            "created",
            "updated",
        ]


class FindingEnvironmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Development_Environment
        fields = ["id", "name"]


class FindingTestTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test_Type
        fields = ["id", "name"]


class FindingTestSerializer(serializers.ModelSerializer):
    engagement = FindingEngagementSerializer(required=False)
    environment = FindingEnvironmentSerializer(required=False)
    test_type = FindingTestTypeSerializer(required=False)

    class Meta:
        model = Test
        fields = [
            "id",
            "title",
            "test_type",
            "engagement",
            "environment",
            "branch_tag",
            "build_id",
            "commit_hash",
            "version",
        ]


class FindingRelatedFieldsSerializer(serializers.Serializer):
    test = serializers.SerializerMethodField()
    jira = serializers.SerializerMethodField()

    @extend_schema_field(FindingTestSerializer)
    def get_test(self, obj):
        return FindingTestSerializer(read_only=True).to_representation(
            obj.test,
        )

    @extend_schema_field(JIRAIssueSerializer)
    def get_jira(self, obj):
        issue = jira_helper.get_jira_issue(obj)
        if issue is None:
            return None
        return JIRAIssueSerializer(read_only=True).to_representation(issue)


class VulnerabilityIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability_Id
        fields = ["vulnerability_id"]


class FindingSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)
    request_response = serializers.SerializerMethodField()
    accepted_risks = RiskAcceptanceSerializer(
        many=True, read_only=True, source="risk_acceptance_set",
    )
    push_to_jira = serializers.BooleanField(default=False)
    age = serializers.IntegerField(read_only=True)
    sla_days_remaining = serializers.IntegerField(read_only=True)
    finding_meta = FindingMetaSerializer(read_only=True, many=True)
    related_fields = serializers.SerializerMethodField(allow_null=True)
    # for backwards compatibility
    jira_creation = serializers.SerializerMethodField(read_only=True, allow_null=True)
    jira_change = serializers.SerializerMethodField(read_only=True, allow_null=True)
    display_status = serializers.SerializerMethodField()
    finding_groups = FindingGroupSerializer(
        source="finding_group_set", many=True, read_only=True,
    )
    vulnerability_ids = VulnerabilityIdSerializer(
        source="vulnerability_id_set", many=True, required=False,
    )
    reporter = serializers.PrimaryKeyRelatedField(
        required=False, queryset=User.objects.all(),
    )

    class Meta:
        model = Finding
        exclude = (
            "cve",
            "inherited_tags",
        )

    @extend_schema_field(serializers.DateTimeField())
    def get_jira_creation(self, obj):
        return jira_helper.get_jira_creation(obj)

    @extend_schema_field(serializers.DateTimeField())
    def get_jira_change(self, obj):
        return jira_helper.get_jira_change(obj)

    @extend_schema_field(FindingRelatedFieldsSerializer)
    def get_related_fields(self, obj):
        request = self.context.get("request", None)
        if request is None:
            return None

        query_params = request.query_params
        if query_params.get("related_fields", "false") == "true":
            return FindingRelatedFieldsSerializer(
                required=False,
            ).to_representation(obj)
        return None

    def get_display_status(self, obj) -> str:
        return obj.status()

    # Overriding this to push add Push to JIRA functionality
    def update(self, instance, validated_data):
        # remove tags from validated data and store them seperately
        to_be_tagged, validated_data = self._pop_tags(validated_data)

        # pop push_to_jira so it won't get send to the model as a field
        # TODO: JIRA can we remove this is_push_all_issues, already checked in
        # apiv2 viewset?
        push_to_jira = validated_data.pop(
            "push_to_jira",
        ) or jira_helper.is_push_all_issues(instance)

        # Save vulnerability ids and pop them
        if "vulnerability_id_set" in validated_data:
            vulnerability_id_set = validated_data.pop("vulnerability_id_set")
            vulnerability_ids = []
            if vulnerability_id_set:
                for vulnerability_id in vulnerability_id_set:
                    vulnerability_ids.append(
                        vulnerability_id["vulnerability_id"],
                    )
            save_vulnerability_ids(instance, vulnerability_ids)

        instance = super(TaggitSerializer, self).update(
            instance, validated_data,
        )
        # Save the reporter on the finding
        if reporter_id := validated_data.get("reporter"):
            instance.reporter = reporter_id

        # If we need to push to JIRA, an extra save call is needed.
        # Also if we need to update the mitigation date of the finding.
        # TODO: try to combine create and save, but for now I'm just fixing a
        # bug and don't want to change to much
        if push_to_jira:
            instance.save(push_to_jira=push_to_jira)

        # not sure why we are returning a tag_object, but don't want to change
        # too much now as we're just fixing a bug
        return self._save_tags(instance, to_be_tagged)

    def validate(self, data):
        if self.context["request"].method == "PATCH":
            is_active = data.get("active", self.instance.active)
            is_verified = data.get("verified", self.instance.verified)
            is_duplicate = data.get("duplicate", self.instance.duplicate)
            is_false_p = data.get("false_p", self.instance.false_p)
            is_risk_accepted = data.get(
                "risk_accepted", self.instance.risk_accepted,
            )
        else:
            is_active = data.get("active", True)
            is_verified = data.get("verified", False)
            is_duplicate = data.get("duplicate", False)
            is_false_p = data.get("false_p", False)
            is_risk_accepted = data.get("risk_accepted", False)

        if (is_active or is_verified) and is_duplicate:
            msg = "Duplicate findings cannot be verified or active"
            raise serializers.ValidationError(msg)
        if is_false_p and is_verified:
            msg = "False positive findings cannot be verified."
            raise serializers.ValidationError(msg)

        if is_risk_accepted and not self.instance.risk_accepted:
            if (
                not self.instance.test.engagement.product.enable_simple_risk_acceptance
            ):
                msg = "Simple risk acceptance is disabled for this product, use the UI to accept this finding."
                raise serializers.ValidationError(msg)

        if is_active and is_risk_accepted:
            msg = "Active findings cannot be risk accepted."
            raise serializers.ValidationError(msg)

        return data

    def validate_severity(self, value: str) -> str:
        if value not in SEVERITIES:
            msg = f"Severity must be one of the following: {SEVERITIES}"
            raise serializers.ValidationError(msg)
        return value

    def build_relational_field(self, field_name, relation_info):
        if field_name == "notes":
            return NoteSerializer, {"many": True, "read_only": True}
        return super().build_relational_field(field_name, relation_info)

    @extend_schema_field(BurpRawRequestResponseSerializer)
    def get_request_response(self, obj):
        # Not necessarily Burp scan specific - these are just any request/response pairs
        burp_req_resp = obj.burprawrequestresponse_set.all()
        var = settings.MAX_REQRESP_FROM_API
        if var > -1:
            burp_req_resp = burp_req_resp[:var]
        burp_list = []
        for burp in burp_req_resp:
            request = burp.get_request()
            response = burp.get_response()
            burp_list.append({"request": request, "response": response})
        serialized_burps = BurpRawRequestResponseSerializer(
            {"req_resp": burp_list},
        )
        return serialized_burps.data


class FindingCreateSerializer(TaggitSerializer, serializers.ModelSerializer):
    notes = serializers.PrimaryKeyRelatedField(
        read_only=True, allow_null=True, required=False, many=True,
    )
    test = serializers.PrimaryKeyRelatedField(queryset=Test.objects.all())
    thread_id = serializers.IntegerField(default=0)
    found_by = serializers.PrimaryKeyRelatedField(
        queryset=Test_Type.objects.all(), many=True,
    )
    url = serializers.CharField(allow_null=True, default=None)
    tags = TagListSerializerField(required=False)
    push_to_jira = serializers.BooleanField(default=False)
    vulnerability_ids = VulnerabilityIdSerializer(
        source="vulnerability_id_set", many=True, required=False,
    )
    reporter = serializers.PrimaryKeyRelatedField(
        required=False, queryset=User.objects.all(),
    )

    class Meta:
        model = Finding
        exclude = (
            "cve",
            "inherited_tags",
        )
        extra_kwargs = {
            "active": {"required": True},
            "verified": {"required": True},
        }

    # Overriding this to push add Push to JIRA functionality
    def create(self, validated_data):
        # remove tags from validated data and store them seperately
        to_be_tagged, validated_data = self._pop_tags(validated_data)

        # pop push_to_jira so it won't get send to the model as a field
        push_to_jira = validated_data.pop("push_to_jira")

        # Save vulnerability ids and pop them
        if "vulnerability_id_set" in validated_data:
            vulnerability_id_set = validated_data.pop("vulnerability_id_set")
        else:
            vulnerability_id_set = None

        # first save, so we have an instance to get push_all_to_jira from
        new_finding = super(TaggitSerializer, self).create(validated_data)

        if vulnerability_id_set:
            vulnerability_ids = []
            for vulnerability_id in vulnerability_id_set:
                vulnerability_ids.append(vulnerability_id["vulnerability_id"])
            validated_data["cve"] = vulnerability_ids[0]
            save_vulnerability_ids(new_finding, vulnerability_ids)
            new_finding.save()

        # TODO: JIRA can we remove this is_push_all_issues, already checked in
        # apiv2 viewset?
        push_to_jira = push_to_jira or jira_helper.is_push_all_issues(
            new_finding,
        )

        # If we need to push to JIRA, an extra save call is needed.
        # TODO: try to combine create and save, but for now I'm just fixing a
        # bug and don't want to change to much
        if push_to_jira or new_finding:
            new_finding.save(push_to_jira=push_to_jira)

        # not sure why we are returning a tag_object, but don't want to change
        # too much now as we're just fixing a bug
        return self._save_tags(new_finding, to_be_tagged)

    def validate(self, data):
        if "reporter" not in data:
            request = self.context["request"]
            data["reporter"] = request.user

        if (data.get("active") or data.get("verified")) and data.get(
            "duplicate",
        ):
            msg = "Duplicate findings cannot be verified or active"
            raise serializers.ValidationError(msg)
        if data.get("false_p") and data.get("verified"):
            msg = "False positive findings cannot be verified."
            raise serializers.ValidationError(msg)

        if "risk_accepted" in data and data.get("risk_accepted"):
            test = data.get("test")
            # test = Test.objects.get(id=test_id)
            if not test.engagement.product.enable_simple_risk_acceptance:
                msg = "Simple risk acceptance is disabled for this product, use the UI to accept this finding."
                raise serializers.ValidationError(msg)

        if (
            data.get("active")
            and "risk_accepted" in data
            and data.get("risk_accepted")
        ):
            msg = "Active findings cannot be risk accepted."
            raise serializers.ValidationError(msg)

        return data

    def validate_severity(self, value: str) -> str:
        if value not in SEVERITIES:
            msg = f"Severity must be one of the following: {SEVERITIES}"
            raise serializers.ValidationError(msg)
        return value


class VulnerabilityIdTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability_Id_Template
        fields = ["vulnerability_id"]


class FindingTemplateSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)
    vulnerability_ids = VulnerabilityIdTemplateSerializer(
        source="vulnerability_id_template_set", many=True, required=False,
    )

    class Meta:
        model = Finding_Template
        exclude = ("cve",)

    def create(self, validated_data):
        to_be_tagged, validated_data = self._pop_tags(validated_data)

        # Save vulnerability ids and pop them
        if "vulnerability_id_template_set" in validated_data:
            vulnerability_id_set = validated_data.pop(
                "vulnerability_id_template_set",
            )
        else:
            vulnerability_id_set = None

        new_finding_template = super(TaggitSerializer, self).create(
            validated_data,
        )

        if vulnerability_id_set:
            vulnerability_ids = []
            for vulnerability_id in vulnerability_id_set:
                vulnerability_ids.append(vulnerability_id["vulnerability_id"])
            validated_data["cve"] = vulnerability_ids[0]
            save_vulnerability_ids_template(
                new_finding_template, vulnerability_ids,
            )
            new_finding_template.save()

        self._save_tags(new_finding_template, to_be_tagged)
        return new_finding_template

    def update(self, instance, validated_data):
        # Save vulnerability ids and pop them
        if "vulnerability_id_template_set" in validated_data:
            vulnerability_id_set = validated_data.pop(
                "vulnerability_id_template_set",
            )
            vulnerability_ids = []
            if vulnerability_id_set:
                for vulnerability_id in vulnerability_id_set:
                    vulnerability_ids.append(
                        vulnerability_id["vulnerability_id"],
                    )
            save_vulnerability_ids_template(instance, vulnerability_ids)

        return super(TaggitSerializer, self).update(instance, validated_data)


class CredentialSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cred_User
        exclude = ("password",)


class CredentialMappingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cred_Mapping
        fields = "__all__"


class StubFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stub_Finding
        fields = "__all__"

    def validate_severity(self, value: str) -> str:
        if value not in SEVERITIES:
            msg = f"Severity must be one of the following: {SEVERITIES}"
            raise serializers.ValidationError(msg)
        return value


class StubFindingCreateSerializer(serializers.ModelSerializer):
    test = serializers.PrimaryKeyRelatedField(queryset=Test.objects.all())

    class Meta:
        model = Stub_Finding
        fields = "__all__"
        extra_kwargs = {
            "reporter": {"default": serializers.CurrentUserDefault()},
        }

    def validate_severity(self, value: str) -> str:
        if value not in SEVERITIES:
            msg = f"Severity must be one of the following: {SEVERITIES}"
            raise serializers.ValidationError(msg)
        return value


class ProductSerializer(TaggitSerializer, serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()
    findings_list = serializers.SerializerMethodField()

    tags = TagListSerializerField(required=False)
    product_meta = ProductMetaSerializer(read_only=True, many=True)

    class Meta:
        model = Product
        exclude = (
            "tid",
            "updated",
            "async_updating",
        )

    def validate(self, data):
        async_updating = getattr(self.instance, "async_updating", None)
        if async_updating:
            new_sla_config = data.get("sla_configuration", None)
            old_sla_config = getattr(self.instance, "sla_configuration", None)
            if new_sla_config and old_sla_config and new_sla_config != old_sla_config:
                msg = "Finding SLA expiration dates are currently being recalculated. The SLA configuration for this product cannot be changed until the calculation is complete."
                raise serializers.ValidationError(msg)
        return data

    def get_findings_count(self, obj) -> int:
        return obj.findings_count

    # TODO: maybe extend_schema_field is needed here?
    def get_findings_list(self, obj) -> list[int]:
        return obj.open_findings_list


class CommonImportScanSerializer(serializers.Serializer):
    scan_date = serializers.DateField(
        required=False,
        help_text="Scan completion date will be used on all findings.",
    )

    minimum_severity = serializers.ChoiceField(
        choices=SEVERITY_CHOICES,
        default="Info",
        help_text="Minimum severity level to be imported",
    )
    active = serializers.BooleanField(
        help_text="Force findings to be active/inactive or default to the original tool (None)", required=False,
    )
    verified = serializers.BooleanField(
        help_text="Force findings to be verified/not verified or default to the original tool (None)", required=False,
    )

    # TODO: why do we allow only existing endpoints?
    endpoint_to_add = serializers.PrimaryKeyRelatedField(
        queryset=Endpoint.objects.all(),
        required=False,
        default=None,
        help_text="Enter the ID of an Endpoint that is associated with the target Product. New Findings will be added to that Endpoint.",
    )
    file = serializers.FileField(allow_empty_file=True, required=False)
    product_type_name = serializers.CharField(required=False)
    product_name = serializers.CharField(required=False)
    engagement_name = serializers.CharField(required=False)
    engagement_end_date = serializers.DateField(
        required=False,
        help_text="End Date for Engagement. Default is current time + 365 days. Required format year-month-day",
    )
    source_code_management_uri = serializers.URLField(
        max_length=600,
        required=False,
        help_text="Resource link to source code",
    )

    test_title = serializers.CharField(required=False)
    auto_create_context = serializers.BooleanField(required=False)
    deduplication_on_engagement = serializers.BooleanField(required=False)
    lead = serializers.PrimaryKeyRelatedField(
        allow_null=True, default=None, queryset=User.objects.all(),
    )
    push_to_jira = serializers.BooleanField(default=False)
    environment = serializers.CharField(required=False)
    build_id = serializers.CharField(
        required=False, help_text="ID of the build that was scanned.",
    )
    branch_tag = serializers.CharField(
        required=False, help_text="Branch or Tag that was scanned.",
    )
    commit_hash = serializers.CharField(
        required=False, help_text="Commit that was scanned.",
    )
    api_scan_configuration = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        default=None,
        queryset=Product_API_Scan_Configuration.objects.all(),
    )
    service = serializers.CharField(
        required=False,
        help_text="A service is a self-contained piece of functionality within a Product. "
        "This is an optional field which is used in deduplication and closing of old findings when set. "
        "This affects the whole engagement/product depending on your deduplication scope.",
    )
    group_by = serializers.ChoiceField(
        required=False,
        choices=Finding_Group.GROUP_BY_OPTIONS,
        help_text="Choose an option to automatically group new findings by the chosen option.",
    )
    create_finding_groups_for_all_findings = serializers.BooleanField(
        help_text="If set to false, finding groups will only be created when there is more than one grouped finding",
        required=False,
        default=True,
    )
    # extra fields populated in response
    # need to use the _id suffix as without the serializer framework gets
    # confused
    test_id = serializers.IntegerField(read_only=True)
    engagement_id = serializers.IntegerField(read_only=True)
    product_id = serializers.IntegerField(read_only=True)
    product_type_id = serializers.IntegerField(read_only=True)
    statistics = ImportStatisticsSerializer(read_only=True, required=False)
    apply_tags_to_findings = serializers.BooleanField(
        help_text="If set to True, the tags will be applied to the findings",
        required=False,
    )
    apply_tags_to_endpoints = serializers.BooleanField(
        help_text="If set to True, the tags will be applied to the endpoints",
        required=False,
    )

    def get_importer(
        self,
        **kwargs: dict,
    ) -> BaseImporter:
        """
        Returns a new instance of an importer that extends
        the BaseImporter class
        """
        return DefaultImporter(**kwargs)

    def process_scan(
        self,
        data: dict,
        context: dict,
    ) -> None:
        """
        Process the scan with all of the supplied data fully massaged
        into the format we are expecting

        Raises exceptions in the event of an error
        """
        try:
            importer = self.get_importer(**context)
            context["test"], _, _, _, _, _, _ = importer.process_scan(
                context.pop("scan", None),
            )
            # Update the response body with some new data
            if test := context.get("test"):
                data["test"] = test.id
                data["test_id"] = test.id
                data["engagement_id"] = test.engagement.id
                data["product_id"] = test.engagement.product.id
                data["product_type_id"] = test.engagement.product.prod_type.id
                data["statistics"] = {"after": test.statistics}
        # convert to exception otherwise django rest framework will swallow them as 400 error
        # exceptions are already logged in the importer
        except SyntaxError as se:
            raise Exception(se)
        except ValueError as ve:
            raise Exception(ve)

    def validate(self, data: dict) -> dict:
        scan_type = data.get("scan_type")
        file = data.get("file")
        if not file and requires_file(scan_type):
            msg = f"Uploading a Report File is required for {scan_type}"
            raise serializers.ValidationError(msg)
        if file and is_scan_file_too_large(file):
            msg = f"Report file is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB"
            raise serializers.ValidationError(msg)
        tool_type = requires_tool_type(scan_type)
        if tool_type:
            api_scan_configuration = data.get("api_scan_configuration")
            if (
                api_scan_configuration
                and tool_type
                != api_scan_configuration.tool_configuration.tool_type.name
            ):
                msg = f"API scan configuration must be of tool type {tool_type}"
                raise serializers.ValidationError(msg)
        return data

    def validate_scan_date(self, value: str) -> None:
        if value and value > timezone.localdate():
            msg = "The scan_date cannot be in the future!"
            raise serializers.ValidationError(msg)
        return value

    def setup_common_context(self, data: dict) -> dict:
        """
        Process all of the user supplied inputs to massage them into the correct
        format the importer is expecting to see
        """
        context = dict(data)
        # update some vars
        context["scan"] = data.pop("file", None)

        if context.get("auto_create_context"):
            environment = Development_Environment.objects.get_or_create(name=data.get("environment", "Development"))[0]
        else:
            try:
                environment = Development_Environment.objects.get(name=data.get("environment", "Development"))
            except:
                msg = "Environment named " + data.get("environment") + " does not exist."
                raise ValidationError(msg)

        context["environment"] = environment
        # Set the active/verified status based upon the overrides
        if "active" in self.initial_data:
            context["active"] = data.get("active")
        else:
            context["active"] = None
        if "verified" in self.initial_data:
            context["verified"] = data.get("verified")
        else:
            context["verified"] = None
        # Change the way that endpoints are sent to the importer
        if endpoints_to_add := data.get("endpoint_to_add"):
            context["endpoints_to_add"] = [endpoints_to_add]
        else:
            context["endpoint_to_add"] = None
        # Convert the tags to a list if needed. At this point, the
        # TaggitListSerializer has already removed commas supplied
        # by the user, so this operation will consistently return
        # a list to be used by the importer
        if tags := context.get("tags"):
            if isinstance(tags, str):
                context["tags"] = tags.split(", ")
        # have to make the scan_date_time timezone aware otherwise uploads via
        # the API would fail (but unit tests for api upload would pass...)
        context["scan_date"] = (
            timezone.make_aware(
                datetime.combine(context.get("scan_date"), datetime.min.time()),
            )
            if context.get("scan_date")
            else None
        )

        # engagement end date was not being used at all and so target_end would also turn into None
        # in this case, do not want to change target_end unless engagement_end exists
        eng_end_date = context.get("engagement_end_date")
        if eng_end_date:
            context["target_end"] = context.get("engagement_end_date")

        return context


class ImportScanSerializer(CommonImportScanSerializer):
    scan_type = serializers.ChoiceField(choices=get_choices_sorted())
    engagement = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), required=False,
    )
    tags = TagListSerializerField(
        required=False, allow_empty=True, help_text="Add tags that help describe this scan.",
    )
    close_old_findings = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Select if old findings no longer present in the report get closed as mitigated when importing. "
        "If service has been set, only the findings for this service will be closed.",
    )
    close_old_findings_product_scope = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Select if close_old_findings applies to all findings of the same type in the product. "
        "By default, it is false meaning that only old findings of the same type in the engagement are in scope.",
    )
    version = serializers.CharField(
        required=False, help_text="Version that was scanned.",
    )
    # extra fields populated in response
    # need to use the _id suffix as without the serializer framework gets
    # confused
    test = serializers.IntegerField(
        read_only=True,
    )  # left for backwards compatibility

    def set_context(
        self,
        data: dict,
    ) -> dict:
        context = self.setup_common_context(data)
        # Process the auto create context inputs
        self.process_auto_create_create_context(context)

        return context

    def process_auto_create_create_context(
        self,
        context: dict,
    ) -> None:
        """
        Extract all of the pertinent args used to auto create any product
        types, products, or engagements. This function will also validate
        those inputs for any required info that is not present. In the event
        of an error, an exception will be raised and bubble up to the user
        """
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            auto_create.process_import_meta_data_from_dict(context)
            # Attempt to create an engagement
            context["engagement"] = auto_create.get_or_create_engagement(**context)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

    def save(self, push_to_jira=False):
        # Go through the validate method
        data = self.validated_data
        # Extract the data from the form
        context = self.set_context(data)
        # set the jira option again as it was overridden
        context["push_to_jira"] = push_to_jira
        # Import the scan with all of the supplied data
        self.process_scan(data, context)


class ReImportScanSerializer(TaggitSerializer, CommonImportScanSerializer):

    help_do_not_reactivate = "Select if the import should ignore active findings from the report, useful for triage-less scanners. Will keep existing findings closed, without reactivating them. For more information check the docs."
    do_not_reactivate = serializers.BooleanField(
        default=False, required=False, help_text=help_do_not_reactivate,
    )
    scan_type = serializers.ChoiceField(
        choices=get_choices_sorted(), required=True,
    )
    test = serializers.PrimaryKeyRelatedField(
        required=False, queryset=Test.objects.all(),
    )
    # Close the old findings if the parameter is not provided. This is to
    # maintain the old API behavior after reintroducing the close_old_findings parameter
    # also for ReImport.
    close_old_findings = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Select if old findings no longer present in the report get closed as mitigated when importing.",
    )
    close_old_findings_product_scope = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Select if close_old_findings applies to all findings of the same type in the product. "
        "By default, it is false meaning that only old findings of the same type in the engagement are in scope. "
        "Note that this only applies on the first call to reimport-scan.",
    )
    version = serializers.CharField(
        required=False,
        help_text="Version that will be set on existing Test object. Leave empty to leave existing value in place.",
    )
    tags = TagListSerializerField(
        required=False,
        allow_empty=True,
        help_text="Modify existing tags that help describe this scan. (Existing test tags will be overwritten)",
    )

    def set_context(
        self,
        data: dict,
    ) -> dict:

        return self.setup_common_context(data)

    def process_auto_create_create_context(
        self,
        auto_create_manager: AutoCreateContextManager,
        context: dict,
    ) -> None:
        """
        Extract all of the pertinent args used to auto create any product
        types, products, or engagements. This function will also validate
        those inputs for any required info that is not present. In the event
        of an error, an exception will be raised and bubble up to the user
        """
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            auto_create_manager.process_import_meta_data_from_dict(context)
            context["product"] = auto_create_manager.get_target_product_if_exists(**context)
            context["engagement"] = auto_create_manager.get_target_engagement_if_exists(**context)
            context["test"] = auto_create_manager.get_target_test_if_exists(**context)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

    def get_reimporter(
        self,
        **kwargs: dict,
    ) -> BaseImporter:
        """
        Returns a new instance of a reimporter that extends
        the BaseImporter class
        """
        return DefaultReImporter(**kwargs)

    def process_scan(
        self,
        auto_create_manager: AutoCreateContextManager,
        data: dict,
        context: dict,
    ) -> None:
        """
        Process the scan with all of the supplied data fully massaged
        into the format we are expecting

        Raises exceptions in the event of an error
        """
        statistics_before, statistics_delta = None, None
        try:
            if test := context.get("test"):
                statistics_before = test.statistics
                context["test"], _, _, _, _, _, test_import = self.get_reimporter(
                    **context,
                ).process_scan(
                    context.pop("scan", None),
                )
                if test_import:
                    statistics_delta = test_import.statistics
            elif context.get("auto_create_context"):
                # Attempt to create an engagement
                logger.debug("reimport for non-existing test, using import to create new test")
                context["engagement"] = auto_create_manager.get_or_create_engagement(**context)
                context["test"], _, _, _, _, _, _ = self.get_importer(
                    **context,
                ).process_scan(
                    context.pop("scan", None),
                )
            else:
                msg = "A test could not be found!"
                raise NotFound(msg)
            # Update the response body with some new data
            if test := context.get("test"):
                data["test"] = test
                data["test_id"] = test.id
                data["engagement_id"] = test.engagement.id
                data["product_id"] = test.engagement.product.id
                data["product_type_id"] = test.engagement.product.prod_type.id
                data["statistics"] = {}
                if statistics_before:
                    data["statistics"]["before"] = statistics_before
                if statistics_delta:
                    data["statistics"]["delta"] = statistics_delta
                data["statistics"]["after"] = test.statistics
        # convert to exception otherwise django rest framework will swallow them as 400 error
        # exceptions are already logged in the importer
        except SyntaxError as se:
            raise Exception(se)
        except ValueError as ve:
            raise Exception(ve)

    def save(self, push_to_jira=False):
        # Go through the validate method
        data = self.validated_data
        # Extract the data from the form
        context = self.set_context(data)
        # set the jira option again as it was overridden
        context["push_to_jira"] = push_to_jira
        # Process the auto create context inputs
        auto_create_manager = AutoCreateContextManager()
        self.process_auto_create_create_context(auto_create_manager, context)
        # Import the scan with all of the supplied data
        self.process_scan(auto_create_manager, data, context)


class EndpointMetaImporterSerializer(serializers.Serializer):
    file = serializers.FileField(required=True)
    create_endpoints = serializers.BooleanField(default=True, required=False)
    create_tags = serializers.BooleanField(default=True, required=False)
    create_dojo_meta = serializers.BooleanField(default=False, required=False)
    product_name = serializers.CharField(required=False)
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=False,
    )
    # extra fields populated in response
    # need to use the _id suffix as without the serializer framework gets
    # confused
    product_id = serializers.IntegerField(read_only=True)

    def validate(self, data):
        file = data.get("file")
        if file and is_scan_file_too_large(file):
            msg = f"Report file is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB"
            raise serializers.ValidationError(msg)

        return data

    def save(self):
        data = self.validated_data
        file = data.get("file")
        create_endpoints = data.get("create_endpoints", True)
        create_tags = data.get("create_tags", True)
        create_dojo_meta = data.get("create_dojo_meta", False)
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            auto_create.process_import_meta_data_from_dict(data)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**data)
            if not product:
                product = auto_create.get_target_product_by_id_if_exists(**data)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

        try:
            endpoint_meta_import(
                file,
                product,
                create_endpoints,
                create_tags,
                create_dojo_meta,
                origin="API",
            )
        except SyntaxError as se:
            raise Exception(se)
        except ValueError as ve:
            raise Exception(ve)


class LanguageTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language_Type
        fields = "__all__"


class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Languages
        fields = "__all__"


class ImportLanguagesSerializer(serializers.Serializer):
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=True,
    )
    file = serializers.FileField(required=True)

    def save(self):
        data = self.validated_data
        product = data["product"]
        languages = data["file"]

        try:
            data = languages.read()
            try:
                deserialized = json.loads(str(data, "utf-8"))
            except Exception:
                deserialized = json.loads(data)
        except Exception:
            msg = "Invalid format"
            raise Exception(msg)

        Languages.objects.filter(product=product).delete()

        for name in deserialized:
            if name not in ["header", "SUM"]:
                element = deserialized[name]

                try:
                    (
                        language_type,
                        _created,
                    ) = Language_Type.objects.get_or_create(language=name)
                except Language_Type.MultipleObjectsReturned:
                    language_type = Language_Type.objects.filter(
                        language=name,
                    ).first()

                language = Languages()
                language.product = product
                language.language = language_type
                language.files = element.get("nFiles", 0)
                language.blank = element.get("blank", 0)
                language.comment = element.get("comment", 0)
                language.code = element.get("code", 0)
                language.save()

    def validate(self, data):
        if is_scan_file_too_large(data["file"]):
            msg = f"File is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB"
            raise serializers.ValidationError(msg)
        return data


class AddNewNoteOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notes
        fields = ["entry", "private", "note_type"]


class AddNewFileOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileUpload
        fields = "__all__"


class FindingToNotesSerializer(serializers.Serializer):
    finding_id = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(), many=False, allow_null=True,
    )
    notes = NoteSerializer(many=True)


class FindingToFilesSerializer(serializers.Serializer):
    finding_id = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(), many=False, allow_null=True,
    )
    files = FileSerializer(many=True)

    def to_representation(self, data):
        finding = data.get("finding_id")
        files = data.get("files")
        new_files = []
        for file in files:
            new_files.append(
                {
                    "id": file.id,
                    "file": "{site_url}/{file_access_url}".format(
                        site_url=settings.SITE_URL,
                        file_access_url=file.get_accessible_url(
                            finding, finding.id,
                        ),
                    ),
                    "title": file.title,
                },
            )
        return {"finding_id": finding.id, "files": new_files}


class FindingCloseSerializer(serializers.ModelSerializer):
    is_mitigated = serializers.BooleanField(required=False)
    mitigated = serializers.DateTimeField(required=False)
    false_p = serializers.BooleanField(required=False)
    out_of_scope = serializers.BooleanField(required=False)
    duplicate = serializers.BooleanField(required=False)

    class Meta:
        model = Finding
        fields = (
            "is_mitigated",
            "mitigated",
            "false_p",
            "out_of_scope",
            "duplicate",
        )


class ReportGenerateOptionSerializer(serializers.Serializer):
    include_finding_notes = serializers.BooleanField(default=False)
    include_finding_images = serializers.BooleanField(default=False)
    include_executive_summary = serializers.BooleanField(default=False)
    include_table_of_contents = serializers.BooleanField(default=False)


class ExecutiveSummarySerializer(serializers.Serializer):
    engagement_name = serializers.CharField(max_length=200)
    engagement_target_start = serializers.DateField()
    engagement_target_end = serializers.DateField()
    test_type_name = serializers.CharField(max_length=200)
    test_target_start = serializers.DateTimeField()
    test_target_end = serializers.DateTimeField()
    test_environment_name = serializers.CharField(max_length=200)
    test_strategy_ref = serializers.URLField(
        max_length=200, min_length=None, allow_blank=True,
    )
    total_findings = serializers.IntegerField()


class ReportGenerateSerializer(serializers.Serializer):
    executive_summary = ExecutiveSummarySerializer(many=False, allow_null=True)
    product_type = ProductTypeSerializer(many=False, read_only=True)
    product = ProductSerializer(many=False, read_only=True)
    engagement = EngagementSerializer(many=False, read_only=True)
    report_name = serializers.CharField(max_length=200)
    report_info = serializers.CharField(max_length=200)
    test = TestSerializer(many=False, read_only=True)
    endpoint = EndpointSerializer(many=False, read_only=True)
    endpoints = EndpointSerializer(many=True, read_only=True)
    findings = FindingSerializer(many=True, read_only=True)
    user = UserStubSerializer(many=False, read_only=True)
    team_name = serializers.CharField(max_length=200)
    title = serializers.CharField(max_length=200)
    user_id = serializers.IntegerField()
    host = serializers.CharField(max_length=200)
    finding_notes = FindingToNotesSerializer(
        many=True, allow_null=True, required=False,
    )


class EngagementUpdateJiraEpicSerializer(serializers.Serializer):
    epic_name = serializers.CharField(required=False, max_length=200)
    epic_priority = serializers.CharField(required=False, allow_null=True)


class TagSerializer(serializers.Serializer):
    tags = TagListSerializerField(required=True)


class SystemSettingsSerializer(TaggitSerializer, serializers.ModelSerializer):
    class Meta:
        model = System_Settings
        fields = "__all__"

    def validate(self, data):
        if self.instance is not None:
            default_group = self.instance.default_group
            default_group_role = self.instance.default_group_role

        if "default_group" in data:
            default_group = data["default_group"]
        if "default_group_role" in data:
            default_group_role = data["default_group_role"]

        if (default_group is None and default_group_role is not None) or (
            default_group is not None and default_group_role is None
        ):
            msg = "default_group and default_group_role must either both be set or both be empty."
            raise ValidationError(msg)

        return data


class FindingNoteSerializer(serializers.Serializer):
    note_id = serializers.IntegerField()


class NotificationsSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    user = serializers.PrimaryKeyRelatedField(
        queryset=Dojo_User.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    product_type_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    product_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    engagement_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    test_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    scan_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    jira_update = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    upcoming_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    stale_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    auto_close_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    close_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    user_mentioned = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    code_review = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    review_requested = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    other = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    sla_breach = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    sla_breach_combined = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    risk_acceptance_expiration = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    template = serializers.BooleanField(default=False)

    class Meta:
        model = Notifications
        fields = "__all__"

    def validate(self, data):
        user = None
        product = None
        template = False

        if self.instance is not None:
            user = self.instance.user
            product = self.instance.product

        if "user" in data:
            user = data.get("user")
        if "product" in data:
            product = data.get("product")
        if "template" in data:
            template = data.get("template")

        if (
            template
            and Notifications.objects.filter(template=True).count() > 0
        ):
            msg = "Notification template already exists"
            raise ValidationError(msg)
        if (
            self.instance is None
            or user != self.instance.user
            or product != self.instance.product
        ):
            notifications = Notifications.objects.filter(
                user=user, product=product, template=template,
            ).count()
            if notifications > 0:
                msg = "Notification for user and product already exists"
                raise ValidationError(msg)
        return data


class EngagementPresetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Engagement_Presets
        fields = "__all__"


class NetworkLocationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Network_Locations
        fields = "__all__"


class SLAConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SLA_Configuration
        exclude = (
            "async_updating",
        )

    def validate(self, data):
        async_updating = getattr(self.instance, "async_updating", None)
        if async_updating:
            for field in ["critical", "enforce_critical", "high", "enforce_high", "medium", "enforce_medium", "low", "enforce_low"]:
                old_days = getattr(self.instance, field, None)
                new_days = data.get(field, None)
                if old_days is not None and new_days is not None and (old_days != new_days):
                    msg = "Finding SLA expiration dates are currently being calculated. The SLA days for this SLA configuration cannot be changed until the calculation is complete."
                    raise serializers.ValidationError(msg)
        return data


class UserProfileSerializer(serializers.Serializer):
    user = UserSerializer(many=False)
    user_contact_info = UserContactInfoSerializer(many=False, required=False)
    global_role = GlobalRoleSerializer(many=False, required=False)
    dojo_group_member = DojoGroupMemberSerializer(many=True)
    product_type_member = ProductTypeMemberSerializer(many=True)
    product_member = ProductMemberSerializer(many=True)


class DeletePreviewSerializer(serializers.Serializer):
    model = serializers.CharField(read_only=True)
    id = serializers.IntegerField(read_only=True, allow_null=True)
    name = serializers.CharField(read_only=True)


class ConfigurationPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        exclude = ("content_type",)


class QuestionnaireQuestionSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        if isinstance(instance, TextQuestion):
            return TextQuestionSerializer(instance=instance).data
        if isinstance(instance, ChoiceQuestion):
            return ChoiceQuestionSerializer(instance=instance).data
        return QuestionSerializer(instance=instance).data

    class Meta:
        model = Question
        exclude = ("polymorphic_ctype",)


class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        exclude = ("polymorphic_ctype",)


class TextQuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TextQuestion
        exclude = ("polymorphic_ctype",)


class ChoiceQuestionSerializer(serializers.ModelSerializer):
    choices = serializers.StringRelatedField(many=True)

    class Meta:
        model = ChoiceQuestion
        exclude = ("polymorphic_ctype",)


class QuestionnaireAnsweredSurveySerializer(serializers.ModelSerializer):
    class Meta:
        model = Answered_Survey
        fields = "__all__"


class QuestionnaireAnswerSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        if isinstance(instance, TextAnswer):
            return TextAnswerSerializer(instance=instance).data
        if isinstance(instance, ChoiceAnswer):
            return ChoiceAnswerSerializer(instance=instance).data
        return AnswerSerializer(instance=instance).data

    class Meta:
        model = Answer
        exclude = ("polymorphic_ctype",)


class AnswerSerializer(serializers.ModelSerializer):
    question = serializers.StringRelatedField()
    answered_survey = QuestionnaireAnsweredSurveySerializer()

    class Meta:
        model = Answer
        exclude = ("polymorphic_ctype",)


class TextAnswerSerializer(serializers.ModelSerializer):
    question = serializers.StringRelatedField()
    answered_survey = QuestionnaireAnsweredSurveySerializer()

    class Meta:
        model = TextAnswer
        exclude = ("polymorphic_ctype",)


class ChoiceAnswerSerializer(serializers.ModelSerializer):
    answer = serializers.StringRelatedField(many=True)
    question = serializers.StringRelatedField()
    answered_survey = QuestionnaireAnsweredSurveySerializer()

    class Meta:
        model = ChoiceAnswer
        exclude = ("polymorphic_ctype",)


class QuestionnaireEngagementSurveySerializer(serializers.ModelSerializer):
    questions = serializers.SerializerMethodField()

    @extend_schema_field(serializers.ListField(child=serializers.CharField()))
    def get_questions(self, obj):
        questions = obj.questions.all()
        formated_questions = []
        for question in questions:
            formated_question = f"Order #{question.order} - {question.text}{' (Optional)' if question.optional else ''}"
            formated_questions.append(formated_question)
        return formated_questions

    class Meta:
        model = Engagement_Survey
        fields = "__all__"


class QuestionnaireGeneralSurveySerializer(serializers.ModelSerializer):
    survey = QuestionnaireEngagementSurveySerializer()

    class Meta:
        model = General_Survey
        fields = "__all__"


class AnnouncementSerializer(serializers.ModelSerializer):

    class Meta:
        model = Announcement
        fields = "__all__"

    def create(self, validated_data):
        validated_data["id"] = 1
        try:
            return super().create(validated_data)
        except IntegrityError as e:
            if 'duplicate key value violates unique constraint "dojo_announcement_pkey"' in str(e):
                msg = "No more than one Announcement is allowed"
                raise serializers.ValidationError(msg)
            raise


class NotificationWebhooksSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification_Webhooks
        fields = "__all__"
