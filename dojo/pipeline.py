import logging
import re

import gitlab
import requests
import social_core.pipeline.user
from django.conf import settings
from social_core.backends.azuread_tenant import AzureADTenantOAuth2
from social_core.backends.google import GoogleOAuth2

from dojo.authorization.roles_permissions import Permissions, Roles
from dojo.models import Dojo_Group, Dojo_Group_Member, Product, Product_Member, Product_Type, Role
from dojo.product.queries import get_authorized_products

logger = logging.getLogger(__name__)


def social_uid(backend, details, response, *args, **kwargs):
    if settings.AZUREAD_TENANT_OAUTH2_ENABLED and isinstance(backend, AzureADTenantOAuth2):
        """Return user details from Azure AD account"""
        fullname, first_name, last_name, upn = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
            response.get("upn"),
        )
        uid = backend.get_user_id(details, response)
        return {"username": upn,
                "email": upn,
                "fullname": fullname,
                "first_name": first_name,
                "last_name": last_name,
                "uid": uid}
    if settings.GOOGLE_OAUTH_ENABLED and isinstance(backend, GoogleOAuth2):
        """Return user details from Google account"""
        if "sub" in response:
            google_uid = response["sub"]
        elif "email" in response:
            google_uid = response["email"]
        else:
            google_uid = response["id"]
        fullname, first_name, last_name, email = (
            response.get("fullname", ""),
            response.get("first_name", ""),
            response.get("last_name", ""),
            response.get("email"),
        )
        return {"username": email,
                "email": email,
                "fullname": fullname,
                "first_name": first_name,
                "last_name": last_name,
                "uid": google_uid}
    uid = backend.get_user_id(details, response)
    # Used for most backends
    if uid:
        return {"uid": uid}
    # Until OKTA PR in social-core is merged
    # This modified way needs to work
    return {"uid": response.get("preferred_username")}


def modify_permissions(backend, uid, user=None, social=None, *args, **kwargs):
    pass


def update_azure_groups(backend, uid, user=None, social=None, *args, **kwargs):
    if settings.AZUREAD_TENANT_OAUTH2_ENABLED and settings.AZUREAD_TENANT_OAUTH2_GET_GROUPS and isinstance(backend, AzureADTenantOAuth2):
        # In some wild cases, there could be two social auth users
        # connected to the same DefectDojo user. Grab the newest one
        soc = user.social_auth.order_by("-created").first()
        token = soc.extra_data["access_token"]
        group_names = []
        if "groups" not in kwargs["response"] or kwargs["response"]["groups"] == "":
            logger.warning("No groups in response. Stopping to update groups of user based on azureAD")
            return
        group_IDs = kwargs["response"]["groups"]
        for group_from_response in group_IDs:
            try:
                logger.debug("Analysing Group_ID " + group_from_response)
                request_headers = {"Authorization": "Bearer " + token}
                if is_group_id(group_from_response):
                    logger.debug("detected " + group_from_response + " as groupID and will fetch the displayName from microsoft graph")
                    group_name_request = requests.get(
                        (str(soc.extra_data["resource"]) + "/v1.0/groups/" + str(group_from_response) + "?$select=displayName"),
                        headers=request_headers,
                        timeout=settings.REQUESTS_TIMEOUT,
                    )
                    group_name_request.raise_for_status()
                    group_name_request_json = group_name_request.json()
                    group_name = group_name_request_json["displayName"]
                else:
                    logger.debug("detected " + group_from_response + " as group name and will not call microsoft graph")
                    group_name = group_from_response

                if settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER == "" or re.search(settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER, group_name):
                    group_names.append(group_name)
                else:
                    logger.debug("Skipping group " + group_name + " due to AZUREAD_TENANT_OAUTH2_GROUPS_FILTER " + settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER)
                    continue
            except Exception as e:
                logger.error(f"Could not call microsoft graph API or save groups to member: {e}")
        if len(group_names) > 0:
            assign_user_to_groups(user, group_names, Dojo_Group.AZURE)
        if settings.AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS:
            cleanup_old_groups_for_user(user, group_names)


def is_group_id(group):
    return bool(re.search(r"^[a-zA-Z0-9]{8,}-[a-zA-Z0-9]{4,}-[a-zA-Z0-9]{4,}-[a-zA-Z0-9]{4,}-[a-zA-Z0-9]{12,}$", group))


def assign_user_to_groups(user, group_names, social_provider):
    for group_name in group_names:
        group, created_group = Dojo_Group.objects.get_or_create(name=group_name, social_provider=social_provider)
        if created_group:
            logger.debug("Group %s for social provider %s was created", str(group), social_provider)
        _group_member, is_member_created = Dojo_Group_Member.objects.get_or_create(group=group, user=user, defaults={
            "role": Role.objects.get(id=Roles.Maintainer)})
        if is_member_created:
            logger.debug("User %s become member of group %s (social provider: %s)", user, str(group), social_provider)


def cleanup_old_groups_for_user(user, group_names):
    for group_member in Dojo_Group_Member.objects.select_related("group").filter(user=user):
        group = group_member.group
        if str(group) not in group_names:
            logger.debug("Deleting membership of user %s from %s group %s", user, group.social_provider, str(group))
            group_member.delete()


def update_product_access(backend, uid, user=None, social=None, *args, **kwargs):
    if settings.GITLAB_PROJECT_AUTO_IMPORT is True:
        # Get user's product names
        user_product_names = [prod.name for prod in get_authorized_products(Permissions.Product_View, user)]
        # Get Gitlab access token
        soc = user.social_auth.get()
        token = soc.extra_data["access_token"]
        # Get user's projects list on Gitlab
        gl = gitlab.Gitlab(settings.SOCIAL_AUTH_GITLAB_API_URL, oauth_token=token)
        # Get each project path_with_namespace as future product name
        projects = gl.projects.list(membership=True, min_access_level=settings.GITLAB_PROJECT_MIN_ACCESS_LEVEL, all=True)
        project_names = [project.path_with_namespace for project in projects]
        # Create product_type if necessary
        product_type, _created = Product_Type.objects.get_or_create(name="Gitlab Import")
        # For each project: create a new product or update product's authorized_users
        for project in projects:
            if project.path_with_namespace not in user_product_names:
                try:
                    # Check if there is a product with the name of the GitLab project
                    product = Product.objects.get(name=project.path_with_namespace)
                except Product.DoesNotExist:
                    # If not, create a product with that name and the GitLab product type
                    product = Product(name=project.path_with_namespace, prod_type=product_type)
                    product.save()
                _product_member, _created = Product_Member.objects.get_or_create(product=product, user=user, defaults={"role": Role.objects.get(id=Roles.Owner)})
                # Import tags and/orl URL if necessary
                if settings.GITLAB_PROJECT_IMPORT_TAGS:
                    if hasattr(project, "topics"):
                        if len(project.topics) > 0:
                            product.tags = ",".join(project.topics)
                    elif hasattr(project, "tag_list") and len(project.tag_list) > 0:
                        product.tags = ",".join(project.tag_list)
                if settings.GITLAB_PROJECT_IMPORT_URL:
                    if hasattr(project, "web_url") and len(project.web_url) > 0:
                        product.description = "[" + project.web_url + "](" + project.web_url + ")"
                if settings.GITLAB_PROJECT_IMPORT_TAGS or settings.GITLAB_PROJECT_IMPORT_URL:
                    product.save()

        # For each product: if user is not project member any more, remove him from product's list of product members
        for product_name in user_product_names:
            if product_name not in project_names:
                product = Product.objects.get(name=product_name)
                Product_Member.objects.filter(product=product, user=user).delete()


def sanitize_username(username):
    allowed_chars_regex = re.compile(r"[\w@.+_-]")
    allowed_chars = filter(allowed_chars_regex.match, list(username))
    return "".join(allowed_chars)


def create_user(strategy, details, backend, user=None, *args, **kwargs):
    if not settings.SOCIAL_AUTH_CREATE_USER:
        return None
    details["username"] = sanitize_username(details.get("username"))
    return social_core.pipeline.user.create_user(strategy, details, backend, user, args, kwargs)
