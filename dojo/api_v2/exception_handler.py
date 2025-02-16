import logging

from django.core.exceptions import ValidationError
from django.db.models.deletion import RestrictedError
from rest_framework.exceptions import ParseError
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_409_CONFLICT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from rest_framework.views import exception_handler

from dojo.models import System_Settings

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if isinstance(exc, ParseError) and "JSON parse error" in str(exc):
        response = Response()
        response.status_code = HTTP_400_BAD_REQUEST
        response.data = {"message": "JSON request content is malformed"}
    elif isinstance(exc, RestrictedError):
        # An object cannot be deleted because it has dependent objects.
        response = Response()
        response.status_code = HTTP_409_CONFLICT
        response.data = {}
        response.data["message"] = str(exc)
    elif isinstance(exc, ValidationError):
        response = Response()
        response.status_code = HTTP_400_BAD_REQUEST
        response.data = {}
        response.data["message"] = str(exc)
    elif response is None:
        if System_Settings.objects.get().api_expose_error_details:
            exception_message = str(exc.args[0])
        else:
            exception_message = "Internal server error, check logs for details"
        # There is no standard error response, so we assume an unexpected
        # exception. It is logged but no details are given to the user,
        # to avoid leaking internal technical information.
        logger.error(exc)
        response = Response()
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        response.data = {}
        response.data[
            "message"
        ] = exception_message
    elif response.status_code < 500:
        # HTTP status codes lower than 500 are no technical errors.
        # They need not to be logged and we provide the exception
        # message, if it is different from the detail that is already
        # in the response.
        if isinstance(response.data, dict) and str(
            exc,
        ) != response.data.get("detail", ""):
            response.data["message"] = str(exc)
    else:
        # HTTP status code 500 or higher are technical errors.
        # They get logged and we don't change the response.
        logger.error(exc)

    return response
