import logging

from django.contrib import messages
from django.core.exceptions import BadRequest
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse

from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.forms import DeleteObjectsSettingsForm, ObjectSettingsForm
from dojo.models import Objects_Product, Product
from dojo.utils import Product_Tab

logger = logging.getLogger(__name__)


@user_is_authorized(Product, Permissions.Product_Tracking_Files_Add, "pid")
def new_object(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == "POST":
        tform = ObjectSettingsForm(request.POST)
        if tform.is_valid():
            new_prod = tform.save(commit=False)
            new_prod.product = prod
            new_prod.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 "Added Tracked File to a Product",
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("view_objects", args=(pid,)))
        return None
    tform = ObjectSettingsForm()
    product_tab = Product_Tab(prod, title="Add Tracked Files to a Product", tab="settings")

    return render(request, "dojo/new_object.html",
                  {"tform": tform,
                   "product_tab": product_tab,
                   "pid": prod.id})


@user_is_authorized(Product, Permissions.Product_Tracking_Files_View, "pid")
def view_objects(request, pid):
    product = get_object_or_404(Product, id=pid)
    object_queryset = Objects_Product.objects.filter(product=pid).order_by("path", "folder", "artifact")

    product_tab = Product_Tab(product, title="Tracked Product Files, Paths and Artifacts", tab="settings")
    return render(request,
                  "dojo/view_objects.html",
                  {
                      "object_queryset": object_queryset,
                      "product_tab": product_tab,
                      "product": product,
                  })


@user_is_authorized(Product, Permissions.Product_Tracking_Files_Edit, "pid")
def edit_object(request, pid, ttid):
    object_prod = Objects_Product.objects.get(pk=ttid)
    product = get_object_or_404(Product, id=pid)
    if object_prod.product != product:
        msg = f"Product {pid} does not fit to product of Object {object_prod.product.id}"
        raise BadRequest(msg)

    if request.method == "POST":
        tform = ObjectSettingsForm(request.POST, instance=object_prod)
        if tform.is_valid():
            tform.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 "Tool Product Configuration Successfully Updated.",
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("view_objects", args=(pid,)))
    else:
        tform = ObjectSettingsForm(instance=object_prod)

    product_tab = Product_Tab(product, title="Edit Tracked Files", tab="settings")
    return render(request,
                  "dojo/edit_object.html",
                  {
                      "tform": tform,
                      "product_tab": product_tab,
                  })


@user_is_authorized(Product, Permissions.Product_Tracking_Files_Delete, "pid")
def delete_object(request, pid, ttid):
    object_prod = Objects_Product.objects.get(pk=ttid)
    product = get_object_or_404(Product, id=pid)
    if object_prod.product != product:
        msg = f"Product {pid} does not fit to product of Object {object_prod.product.id}"
        raise BadRequest(msg)

    if request.method == "POST":
        tform = ObjectSettingsForm(request.POST, instance=object_prod)
        object_prod.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             "Tracked Product Files Deleted.",
                             extra_tags="alert-success")
        return HttpResponseRedirect(reverse("view_objects", args=(pid,)))
    tform = DeleteObjectsSettingsForm(instance=object_prod)

    product_tab = Product_Tab(product, title="Delete Product Tool Configuration", tab="settings")
    return render(request,
                  "dojo/delete_object.html",
                  {
                      "tform": tform,
                      "product_tab": product_tab,
                  })
