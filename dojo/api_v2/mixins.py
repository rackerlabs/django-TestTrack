import itertools

from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.response import Response

from dojo.api_v2 import serializers
from dojo.models import Answer, Question


class DeletePreviewModelMixin:
    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.DeletePreviewSerializer(many=True),
        },
    )
    @action(detail=True, methods=["get"], filter_backends=[], suffix="List")
    def delete_preview(self, request, pk=None):
        object = self.get_object()

        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([object])
        rels = collector.nested()

        def flatten(elem):
            if isinstance(elem, list):
                return itertools.chain.from_iterable(map(flatten, elem))
            return [elem]

        rels = [
            {
                "model": type(x).__name__,
                "id": x.id if hasattr(x, "id") else None,
                "name": str(x)
                if not isinstance(x, Token)
                else "<APITokenIsHidden>",
            }
            for x in flatten(rels)
        ]

        page = self.paginate_queryset(rels)

        serializer = serializers.DeletePreviewSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class QuestionSubClassFieldsMixin:
    def get_queryset(self):
        return Question.objects.select_subclasses()


class AnswerSubClassFieldsMixin:
    def get_queryset(self):
        return Answer.objects.select_subclasses()


class DeprecationWarningLimitOffsetPagination(LimitOffsetPagination):
    # Newly introduced max limit
    max_limit = 250
    # Represents no limit previously
    default_max_limit = None

    def get_paginated_response(self, data):
        # Determine the limit from the request
        limit = self.request.query_params.get("limit", None)
        limit = int(limit) if limit and limit.isdigit() else None
        # Base response
        response_data = {
            "count": self.count,
            "next": self.get_next_link(),
            "previous": self.get_previous_link(),
            "results": data,
        }
        # Add a deprecation warning if the limit exceeds the new max_limit
        if limit > self.max_limit:
            response_data["meta"] = {
                "warning": (
                    f"The requested limit of {limit} exceeds the newly introduced maximum limit of {self.max_limit}. "
                    f"Starting in version 2.45.0, requests exceeding this limit will be truncated to {self.max_limit} results. "
                    "Please adjust your requests to ensure compatibility."
                ),
            }

        return Response(response_data)

    # This entire function can be removed during the cut over
    def get_limit(self, request):
        limit = super().get_limit(request)
        # If no max limit was previously set, allow any requested limit
        if self.default_max_limit is None:
            return limit
        # Clamp the limit to the new max_limit if it exceeds the maximum
        if limit and limit > self.max_limit:
            return self.max_limit

        return limit