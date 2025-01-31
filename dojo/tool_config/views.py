# #  product
import logging

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.forms import ToolConfigForm
from dojo.models import Tool_Configuration
from dojo.tool_config.factory import create_API
from dojo.utils import add_breadcrumb, dojo_crypto_encrypt, prepare_for_view

logger = logging.getLogger(__name__)


@user_is_configuration_authorized("dojo.add_tool_configuration")
def new_tool_config(request):
    if request.method == "POST":
        tform = ToolConfigForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            try:
                api = create_API(form_copy)
                if api and hasattr(api, "test_connection"):
                    result = api.test_connection()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         f"API connection successful with message: {result}.",
                                         extra_tags="alert-success")
                form_copy.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     "Tool Configuration successfully updated.",
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("tool_config"))
            except Exception as e:
                logger.exception("Unable to connect to API")
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags="alert-danger")
    else:
        tform = ToolConfigForm()
        if "tool_type" in request.GET:
            tform.fields["tool_type"].initial = request.GET.get("tool_type")
        add_breadcrumb(title="New Tool Configuration", top_level=False, request=request)
    return render(request, "dojo/new_tool_config.html",
                  {"tform": tform})


@user_is_configuration_authorized("dojo.change_tool_configuration")
def edit_tool_config(request, ttid):
    tool_config = Tool_Configuration.objects.get(pk=ttid)
    if request.method == "POST":
        tform = ToolConfigForm(request.POST, instance=tool_config)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.password = dojo_crypto_encrypt(tform.cleaned_data["password"])
            form_copy.ssh = dojo_crypto_encrypt(tform.cleaned_data["ssh"])
            try:
                api = create_API(form_copy)
                if api and hasattr(api, "test_connection"):
                    result = api.test_connection()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         f"API connection successful with message: {result}.",
                                         extra_tags="alert-success")
                form_copy.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     "Tool Configuration successfully updated.",
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("tool_config"))
            except Exception as e:
                logger.info(e)
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags="alert-danger")
    else:
        tool_config.password = prepare_for_view(tool_config.password)
        tool_config.ssh = prepare_for_view(tool_config.ssh)
        tform = ToolConfigForm(instance=tool_config)
    add_breadcrumb(title="Edit Tool Configuration", top_level=False, request=request)

    return render(request,
                  "dojo/edit_tool_config.html",
                  {
                      "tform": tform,
                  })


@user_is_configuration_authorized("dojo.view_tool_configuration")
def tool_config(request):
    confs = Tool_Configuration.objects.all().order_by("name")
    add_breadcrumb(title="Tool Configuration List", top_level=not len(request.GET), request=request)
    return render(request,
                  "dojo/tool_config.html",
                  {"confs": confs,
                   })
