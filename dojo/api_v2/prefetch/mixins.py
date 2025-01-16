from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.response import Response

from .prefetcher import _Prefetcher


class PrefetchListMixin(ListModelMixin):
    def list(self, request, *args, **kwargs):
        prefetch_params = request.GET.get("prefetch", "")
        prefetch_params = prefetch_params.split(",") if "," in prefetch_params else request.GET.getlist("prefetch")

        prefetcher = _Prefetcher()

        # Apply the same operations as the standard list method defined in the
        # django rest framework
        queryset = self.filter_queryset(self.get_queryset())
        queryset = self.paginate_queryset(queryset)

        serializer = self.get_serializer()
        # Stores the final JSON object
        results = []

        for entry in queryset:
            results.append(serializer.to_representation(entry))
            prefetcher._prefetch(entry, prefetch_params)

        # Done in the original list method so we do it as well
        response = self.get_paginated_response(results)
        response.data["prefetch"] = prefetcher.prefetched_data
        return response


class PrefetchRetrieveMixin(RetrieveModelMixin):
    def retrieve(self, request, *args, **kwargs):
        prefetch_params = request.GET.get("prefetch", "")
        prefetch_params = prefetch_params.split(",") if "," in prefetch_params else request.GET.getlist("prefetch")

        prefetcher = _Prefetcher()

        entry = self.get_object()
        serializer = self.get_serializer()

        # Get the queried object representation
        result = serializer.to_representation(entry)
        prefetcher._prefetch(entry, prefetch_params)
        result["prefetch"] = prefetcher.prefetched_data

        return Response(result)
