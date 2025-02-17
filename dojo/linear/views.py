# Standard library imports
import datetime
import json
import logging

# Third party imports
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.core.exceptions import PermissionDenied
from django.db import DEFAULT_DB_ALIAS
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import View

from dojo.authorization.authorization import user_has_configuration_permission

# Local application/library imports
from dojo.forms import LinearForm, DeleteLinearInstanceForm
from dojo.models import Linear_Instance
from dojo.notifications.helper import create_notification
from dojo.utils import add_breadcrumb, add_error_message_to_response, get_setting

logger = logging.getLogger(__name__)

class ListLinearView(View):
    def get_template(self):
        return "dojo/linear.html"

    def get(self, request):
        if not user_has_configuration_permission(request.user, "dojo.view_linear_instance"):
            raise PermissionDenied
        linear_instances = Linear_Instance.objects.all()
        context = {"linear_instances": linear_instances}
        add_breadcrumb(title="Linear List", top_level=not len(request.GET), request=request)
        return render(request, self.get_template(), context)



class NewLinearView(View):
    def get_template(self):
        return "dojo/new_linear.html"

    def get_form_class(self):
        return LinearForm

    def get(self, request):
        if not user_has_configuration_permission(request.user, "dojo.add_linear_instance"):
            raise PermissionDenied
        form = self.get_form_class()()
        add_breadcrumb(title="New Linear Configuration", top_level=False, request=request)
        return render(request, self.get_template(), {"form": form})

    def post(self, request):
        if not user_has_configuration_permission(request.user, "dojo.add_linear_instance"):
            raise PermissionDenied
        form = self.get_form_class()(request.POST, instance=Linear_Instance())
        if form.is_valid():
            # create the object
            linear_instance = Linear_Instance(
                instance_name=form.cleaned_data.get("instance_name").strip(),
                team_id=form.cleaned_data.get("team_id").strip(),
                api_key=form.cleaned_data.get("api_key").strip()
            )
            linear_instance.save()
            # update the UI
            messages.add_message(
                request,
                messages.SUCCESS,
                "Linear Configuration Successfully Created.",
                extra_tags="alert-success"
            )
            create_notification(
                event="linear_config_added",
                title=f"New Linear instance was added by {request.user}"
            )
            return HttpResponseRedirect(reverse("linear"))
        return render(request, self.get_template(), {"form": form})



class EditLinearView(View):
    def get_template(self):
        return "dojo/edit_linear.html"

    def get_form_class(self):
        return LinearForm

    def get(self, request, lid=None):
        if not user_has_configuration_permission(request.user, "dojo.change_linear_instance"):
            raise PermissionDenied
        linear = Linear_Instance.objects.get(pk=lid)
        form = self.get_form_class()(instance=linear)
        add_breadcrumb(title="Edit Linear Configuration", top_level=False, request=request)
        return render(request, self.get_template(), {"form": form})

    def post(self, request, lid=None):
        if not user_has_configuration_permission(request.user, "dojo.change_linear_instance"):
            raise PermissionDenied
        linear = Linear_Instance.objects.get(pk=lid)
        form = self.get_form_class()(request.POST, instance=linear)
        if form.is_valid():
            linear.instance_name = form.cleaned_data.get("instance_name").strip()
            linear.team_id = form.cleaned_data.get("team_id").strip()
            linear.api_key = form.cleaned_data.get("api_key").strip()
            linear.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Linear Configuration Successfully Saved.",
                extra_tags="alert-success"
            )
            create_notification(
                event="linear_config_edited",
                title=f"Linear instance edited by {request.user}"
            )
            return HttpResponseRedirect(reverse("linear"))
        return render(request, self.get_template(), {"form": form})



class DeleteLinearView(View):
    def get_template(self):
        return "dojo/delete_linear.html"

    def get_form_class(self):
        return DeleteLinearInstanceForm

    def get(self, request, lid=None):
        if not user_has_configuration_permission(request.user, "dojo.delete_linear_instance"):
            raise PermissionDenied
        linear_instance = get_object_or_404(Linear_Instance, pk=lid)
        form = self.get_form_class()(instance=linear_instance)
        rels = ["Previewing the relationships has been disabled.", ""]
        display_preview = get_setting("DELETE_PREVIEW")
        if display_preview:
            collector = NestedObjects(using=DEFAULT_DB_ALIAS)
            collector.collect([linear_instance])
            rels = collector.nested()

        add_breadcrumb(title="Delete", top_level=False, request=request)
        return render(request, self.get_template(), {
            "inst": linear_instance,
            "form": form,
            "rels": rels,
            "deletable_objects": rels,
        })

    def post(self, request, lid=None):
        if not user_has_configuration_permission(request.user, "dojo.delete_linear_instance"):
            raise PermissionDenied
        linear_instance = get_object_or_404(Linear_Instance, pk=lid)
        if "id" in request.POST and str(linear_instance.id) == request.POST["id"]:
            form = self.get_form_class()(request.POST, instance=linear_instance)
            if form.is_valid():
                try:
                    linear_instance.delete()
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Linear Instance and relationships removed.",
                        extra_tags="alert-success")
                    create_notification(
                        event="linear_config_deleted",
                        title=f"Linear instance deleted by {request.user}"
                    )
                    return HttpResponseRedirect(reverse("linear"))
                except Exception as e:
                    add_error_message_to_response(f"Unable to delete Linear Instance: {str(e)}")

        rels = ["Previewing the relationships has been disabled.", ""]
        display_preview = get_setting("DELETE_PREVIEW")
        if display_preview:
            collector = NestedObjects(using=DEFAULT_DB_ALIAS)
            collector.collect([linear_instance])
            rels = collector.nested()

        add_breadcrumb(title="Delete", top_level=False, request=request)
        return render(request, self.get_template(), {
            # "inst": linear_instance,
            "form": form,
            "rels": rels,
            "deletable_objects": rels,
        })
