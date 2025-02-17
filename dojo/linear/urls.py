from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r"^linear/add", views.NewLinearView.as_view(), name="add_linear"),
    re_path(r"^linear/(?P<lid>\d+)/edit$", views.EditLinearView.as_view(), name="edit_linear"),
    re_path(r"^linear/(?P<lid>\d+)/delete$", views.DeleteLinearView.as_view(), name="delete_linear"),
    re_path(r"^linear$", views.ListLinearView.as_view(), name="linear"),
]
