import itertools

from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action

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
        obj = self.get_object()

        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([obj])
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
