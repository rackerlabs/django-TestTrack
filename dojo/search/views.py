import itertools
import logging
import re
import shlex

from django.conf import settings
from django.db.models import Q
from django.shortcuts import render
from django.utils.translation import gettext as _
from watson import search as watson

from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.queries import get_authorized_endpoints
from dojo.endpoint.views import prefetch_for_endpoints
from dojo.engagement.queries import get_authorized_engagements
from dojo.filters import FindingFilter, FindingFilterWithoutObjectLookups
from dojo.finding.queries import get_authorized_findings, get_authorized_vulnerability_ids
from dojo.finding.views import prefetch_for_findings
from dojo.forms import SimpleSearchForm
from dojo.models import Engagement, Finding, Finding_Template, Languages, Product, Test
from dojo.product.queries import get_authorized_app_analysis, get_authorized_products
from dojo.test.queries import get_authorized_tests
from dojo.utils import add_breadcrumb, get_page_items, get_system_setting, get_words_for_field

logger = logging.getLogger(__name__)

# explicitly use our own regex pattern here as django-watson is sensitive so we want to control it here independently of models.py etc.
vulnerability_id_pattern = re.compile(r"(^[A-Z]+-[A-Z\d-]+)$")

max_results = settings.SEARCH_MAX_RESULTS


def simple_search(request):
    """
    query:     some keywords
    operators: {}
    keywords:  ['some', 'keywords']

    query:     some key-word
    operators: {}
    keywords:  ['some', 'key-word']

    query:     keyword with "space inside"
    operators: {}
    keywords:  ['keyword', 'with', 'space inside']

    query:     tag:anchore word tags:php
    operators: {'tag': ['anchore'], 'tags': ['php']}
    keywords:  ['word']

    query:     tags:php,magento
    operators: {'tags': ['php,magento']}
    keywords:  []

    query:     tags:php tags:magento
    operators: {'tags': ['php', 'magento']}
    keywords:  []

    query:     tags:"php, magento"
    operators: {'tags': ['php, magento']}
    keywords:  []

    query:     tags:anchorse some "space inside"
    operators: {'tags': ['anchorse']}
    keywords:  ['some', 'space inside']

    query:     tags:anchore vulnerability_id:CVE-2020-1234 jquery
    operators: {'tags': ['anchore'], 'vulnerability_id': ['CVE-2020-1234']}
    keywords:  ['jquery']
    """
    tests = None
    findings = None
    finding_templates = None
    products = None
    tagged_tests = None
    tagged_findings = None
    tagged_products = None
    tagged_endpoints = None
    tagged_engagements = None
    tagged_finding_templates = None
    engagements = None
    endpoints = None
    languages = None
    app_analysis = None
    vulnerability_ids = None
    clean_query = ""
    cookie = False
    form = SimpleSearchForm()

    original_clean_query = ""
    findings_filter = None
    title_words = None
    component_words = None

    # if request.method == 'GET' and "query" in request.GET:
    if request.method == "GET":
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            cookie = True

            clean_query = form.cleaned_data["query"] or ""
            original_clean_query = clean_query

            operators, keywords = parse_search_query(clean_query)

            search_tags = "tag" in operators or "test-tag" in operators or "engagement-tag" in operators or "product-tag" in operators or \
                          "tags" in operators or "test-tags" in operators or "engagement-tags" in operators or "product-tags" in operators or \
                          "not-tag" in operators or "not-test-tag" in operators or "not-engagement-tag" in operators or "not-product-tag" in operators or \
                          "not-tags" in operators or "not-test-tags" in operators or "not-engagement-tags" in operators or "not-product-tags" in operators

            search_vulnerability_ids = "vulnerability_id" in operators or not operators

            search_finding_id = "id" in operators
            search_findings = "finding" in operators or search_finding_id or search_tags or not operators

            search_finding_templates = "template" in operators or search_tags or not (operators or search_finding_id)
            search_tests = "test" in operators or search_tags or not (operators or search_finding_id)
            search_engagements = "engagement" in operators or search_tags or not (operators or search_finding_id)

            search_products = "product" in operators or search_tags or not (operators or search_finding_id)
            search_endpoints = "endpoint" in operators or search_tags or not (operators or search_finding_id)
            search_languages = "language" in operators or search_tags or not (operators or search_finding_id)
            search_technologies = "technology" in operators or search_tags or not (operators or search_finding_id)

            authorized_findings = get_authorized_findings(Permissions.Finding_View)
            authorized_tests = get_authorized_tests(Permissions.Test_View)
            authorized_engagements = get_authorized_engagements(Permissions.Engagement_View)
            authorized_products = get_authorized_products(Permissions.Product_View)
            authorized_endpoints = get_authorized_endpoints(Permissions.Endpoint_View)
            authorized_finding_templates = Finding_Template.objects.all()
            authorized_app_analysis = get_authorized_app_analysis(Permissions.Product_View)
            authorized_vulnerability_ids = get_authorized_vulnerability_ids(Permissions.Finding_View)

            # TODO: better get findings in their own query and match on id. that would allow filtering on additional fields such prod_id, etc.

            findings = authorized_findings
            tests = authorized_tests
            engagements = authorized_engagements
            products = authorized_products
            endpoints = authorized_endpoints
            app_analysis = authorized_app_analysis
            vulnerability_ids = authorized_vulnerability_ids

            findings_filter = None
            title_words = None
            component_words = None

            keywords_query = " ".join(keywords)

            if search_finding_id:
                logger.debug("searching finding id")

                findings = authorized_findings
                findings = findings.filter(id=operators["id"][0])

            elif search_findings:
                logger.debug("searching findings")
                filter_string_matching = get_system_setting("filter_string_matching", False)
                finding_filter_class = FindingFilterWithoutObjectLookups if filter_string_matching else FindingFilter
                findings_filter = finding_filter_class(request.GET, queryset=findings, user=request.user, pid=None, prefix="finding")
                # setting initial values for filters is not supported and discouraged: https://django-filter.readthedocs.io/en/stable/guide/tips.html#using-initial-values-as-defaults
                # we could try to modify request.GET before generating the filter, but for now we'll leave it as is

                title_words = get_words_for_field(Finding, "title")
                component_words = get_words_for_field(Finding, "component_name")

                findings = findings_filter.qs

                findings = apply_tag_filters(findings, operators)
                findings = apply_endpoint_filter(findings, operators)

                findings = perform_keyword_search_for_operator(findings, operators, "finding", keywords_query)

            else:
                findings = None
                findings_filter = None
                component_words = None

            # prefetch after watson to avoid inavlid query errors due to watson not understanding prefetching
            if findings is not None:  # check for None to avoid query execution
                logger.debug("prefetching findings")

                findings = get_page_items(request, findings, 25)

                findings.object_list = prefetch_for_findings(findings.object_list)

                # some over the top tag displaying happening...
                findings.object_list = findings.object_list.prefetch_related("test__engagement__product__tags")

            tag = operators.get("tag", keywords)
            tags = operators.get("tags", keywords)
            not_tag = operators.get("not-tag", keywords)
            not_tags = operators.get("not-tags", keywords)
            if (search_tags and tag) or tags or not_tag or not_tags:
                logger.debug("searching tags")

                Q1, Q2, Q3, Q4 = Q(), Q(), Q(), Q()

                if tag:
                    tag = ",".join(tag)  # contains needs a single value
                    Q1 = Q(tags__name__contains=tag)

                if tags:
                    Q2 = Q(tags__name__in=tags)

                if not_tag:
                    not_tag = ",".join(not_tag)  # contains needs a single value
                    Q3 = Q(tags__name__contains=not_tag)

                if not_tags:
                    Q4 = Q(tags__name__in=not_tags)

                tagged_findings = authorized_findings.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related("tags")
                tagged_finding_templates = authorized_finding_templates.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results]
                tagged_tests = authorized_tests.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related("tags")
                tagged_engagements = authorized_engagements.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related("tags")
                tagged_products = authorized_products.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related("tags")
                tagged_endpoints = authorized_endpoints.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related("tags")
            else:
                tagged_findings = None
                tagged_finding_templates = None
                tagged_tests = None
                tagged_engagements = None
                tagged_products = None
                tagged_endpoints = None

            tagged_results = tagged_findings or tagged_finding_templates or tagged_tests or tagged_engagements or tagged_products or tagged_endpoints

            if search_finding_templates:
                logger.debug("searching finding templates")

                finding_templates = authorized_finding_templates
                finding_templates = apply_tag_filters(finding_templates, operators)

                if keywords_query:
                    watson_results = watson.filter(finding_templates, keywords_query)
                    finding_templates = finding_templates.filter(id__in=[watson.id for watson in watson_results])

                finding_templates = finding_templates[:max_results]
            else:
                finding_templates = None

            if search_tests:
                logger.debug("searching tests")

                tests = authorized_tests
                tests = apply_tag_filters(tests, operators)

                if keywords_query:
                    watson_results = watson.filter(tests, keywords_query)
                    tests = tests.filter(id__in=[watson.id for watson in watson_results])

                tests = tests.prefetch_related("engagement", "engagement__product", "test_type", "tags", "engagement__tags", "engagement__product__tags")
                tests = tests[:max_results]
            else:
                tests = None

            if search_engagements:
                logger.debug("searching engagements")

                engagements = authorized_engagements
                engagements = apply_tag_filters(engagements, operators)

                if keywords_query:
                    watson_results = watson.filter(engagements, keywords_query)
                    engagements = engagements.filter(id__in=[watson.id for watson in watson_results])

                engagements = engagements.prefetch_related("product", "product__tags", "tags")
                engagements = engagements[:max_results]
            else:
                engagements = None

            if search_products:
                logger.debug("searching products")

                products = authorized_products
                products = apply_tag_filters(products, operators)

                if keywords_query:
                    watson_results = watson.filter(products, keywords_query)
                    products = products.filter(id__in=[watson.id for watson in watson_results])

                products = products.prefetch_related("tags")
                products = products[:max_results]
            else:
                products = None

            if search_endpoints:
                logger.debug("searching endpoint")

                endpoints = authorized_endpoints
                endpoints = apply_tag_filters(endpoints, operators)

                endpoints = endpoints.filter(Q(host__icontains=keywords_query) | Q(path__icontains=keywords_query) | Q(protocol__icontains=keywords_query) | Q(query__icontains=keywords_query) | Q(fragment__icontains=keywords_query))
                endpoints = prefetch_for_endpoints(endpoints)
                endpoints = endpoints[:max_results]
            else:
                endpoints = None

            if search_languages:
                logger.debug("searching languages")

                languages = Languages.objects.filter(language__language__icontains=keywords_query)
                languages = languages.prefetch_related("product", "product__tags")
                languages = languages[:max_results]
            else:
                languages = None

            if search_technologies:
                logger.debug("searching technologies")

                app_analysis = authorized_app_analysis
                app_analysis = app_analysis.filter(name__icontains=keywords_query)
                app_analysis = app_analysis[:max_results]
            else:
                app_analysis = None

            if search_vulnerability_ids:
                logger.debug("searching vulnerability_ids")

                vulnerability_ids = authorized_vulnerability_ids
                vulnerability_ids = apply_vulnerability_id_filter(vulnerability_ids, operators)
                if keywords_query:
                    watson_results = watson.filter(vulnerability_ids, keywords_query)
                    vulnerability_ids = vulnerability_ids.filter(id__in=[watson.id for watson in watson_results])
                vulnerability_ids = vulnerability_ids.prefetch_related("finding__test__engagement__product", "finding__test__engagement__product__tags")
                vulnerability_ids = vulnerability_ids[:max_results]
            else:
                vulnerability_ids = None

            if keywords_query:
                logger.debug("searching generic")
                logger.debug("going generic with: %s", keywords_query)
                generic = watson.search(keywords_query, models=(
                    authorized_findings, authorized_tests, authorized_engagements,
                    authorized_products, authorized_endpoints,
                    authorized_finding_templates, authorized_vulnerability_ids, authorized_app_analysis)) \
                    .prefetch_related("object")[:max_results]
            else:
                generic = None

            # paging doesn't work well with django_watson
            # paged_generic = get_page_items(request, generic, 25)

            # generic = get_page_items(request, generic, 25)
            # generic = watson.search(original_clean_query)[:50].prefetch_related('object')
            # generic = watson.search("qander document 'CVE-2019-8331'")[:10].prefetch_related('object')
            # generic = watson.search("'CVE-2020-6754'")[:10].prefetch_related('object')
            # generic = watson.search(" 'ISEC-433'")[:10].prefetch_related('object')

            logger.debug("all searched")

        else:
            logger.debug(form.errors)
            form = SimpleSearchForm()

        add_breadcrumb(title=_("Simple Search"), top_level=True, request=request)

        activetab = "findings" if findings \
            else "products" if products \
                else "engagements" if engagements else \
                    "tests" if tests else \
                         "endpoint" if endpoints else \
                            "tagged" if tagged_results else \
                                "vulnerability_ids" if vulnerability_ids else \
                                    "generic"

    response = render(request, "dojo/simple_search.html", {
        "clean_query": original_clean_query,
        "languages": languages,
        "app_analysis": app_analysis,
        "tests": tests,
        "findings": findings,
        "finding_templates": finding_templates,
        "filtered": findings_filter,
        "title_words": title_words,
        "component_words": component_words,
        "products": products,
        "tagged_tests": tagged_tests,
        "tagged_findings": tagged_findings,
        "tagged_finding_templates": tagged_finding_templates,
        "tagged_products": tagged_products,
        "tagged_endpoints": tagged_endpoints,
        "tagged_engagements": tagged_engagements,
        "engagements": engagements,
        "endpoints": endpoints,
        "vulnerability_ids": vulnerability_ids,
        "name": _("Simple Search"),
        "metric": False,
        "user": request.user,
        "form": form,
        "activetab": activetab,
        "show_product_column": True,
        "generic": generic})

    if cookie:
        response.set_cookie("highlight", value=keywords_query,
                            max_age=None, expires=None,
                            path="/", secure=True, httponly=False)
    else:
        response.delete_cookie("highlight", path="/")
    return response


# it's not google grade parsing, but let's do some basic stuff right
def parse_search_query(clean_query):
    operators = {}  # operator:parameter formatted in searchquery, i.e. tag:php
    keywords = []  # just keywords to search on

    query_parts = shlex.split(clean_query)

    for query_part in query_parts:
        if ":" in query_part:
            query_part_split = query_part.split(":", 1)

            operator = query_part_split[0]
            parameter = query_part_split[1].strip()

            if operator not in operators:
                operators[operator] = []

            operators[operator].append(parameter)
        else:
            keywords.append(vulnerability_id_fix(query_part))

    logger.debug(f"query:     {clean_query}")
    logger.debug(f"operators: {operators}")
    logger.debug(f"keywords:  {keywords}")

    return operators, keywords


def vulnerability_id_fix(keyword):
    # if the query contains hyphens, django-watson will escape these leading to problems.
    # for vulnerability_ids we make this workaround because we really want to be able to search for them
    # problem still remains for other case, i.e. searching for "valentijn-scholten" will return no results because of the hyphen.
    # see:
    # - https://github.com/etianen/django-watson/issues/223
    # - https://github.com/DefectDojo/django-DefectDojo/issues/1092
    # - https://github.com/DefectDojo/django-DefectDojo/issues/2081

    vulnerability_ids = []
    keyword_parts = keyword.split(",")
    for keyword_part in keyword_parts:
        if bool(vulnerability_id_pattern.match(keyword_part)):
            vulnerability_ids.append("'" + keyword_part + "'")

    if vulnerability_ids:
        return " ".join(vulnerability_ids)
    return keyword


def apply_tag_filters(qs, operators, *, skip_relations=False):
    tag_filters = {"tag": ""}

    if qs.model == Finding:
        tag_filters = {
            "tag": "",
            "test-tag": "test__",
            "engagement-tag": "test__engagement__",
            "product-tag": "test__engagement__product__",
        }

    if qs.model == Test:
        tag_filters = {
            "tag": "",
            "test-tag": "",
            "engagement-tag": "engagement__",
            "product-tag": "engagement__product__",
        }

    if qs.model == Engagement:
        tag_filters = {
            "tag": "",
            "test-tag": "test__",
            "engagement-tag": "",
            "product-tag": "product__",
        }

    if qs.model == Product:
        tag_filters = {
            "tag": "",
            "test-tag": "engagement__test__",
            "engagement-tag": "engagement__",
            "product-tag": "",
        }

    for tag_filter in tag_filters:
        if tag_filter in operators:
            value = operators[tag_filter]
            value = ",".join(value)  # contains needs a single value
            qs = qs.filter(**{f"{tag_filters[tag_filter]}tags__name__contains": value})

    for tag_filter in tag_filters:
        if tag_filter + "s" in operators:
            value = operators[tag_filter + "s"]
            qs = qs.filter(**{f"{tag_filters[tag_filter]}tags__name__in": value})

    # negative search based on not- prefix (not-tags, not-test-tags, not-engagement-tags, not-product-tags, etc)

    for base_tag_filter in tag_filters:
        tag_filter = "not-" + base_tag_filter
        if tag_filter in operators:
            value = operators[tag_filter]
            value = ",".join(value)  # contains needs a single value
            qs = qs.exclude(**{"{}tags__name__contains".format(tag_filters[tag_filter.replace("not-", "")]): value})

    for base_tag_filter in tag_filters:
        tag_filter = "not-" + base_tag_filter
        if tag_filter + "s" in operators:
            value = operators[tag_filter + "s"]
            qs = qs.exclude(**{"{}tags__name__in".format(tag_filters[tag_filter.replace("not-", "")]): value})

    return qs


def apply_endpoint_filter(qs, operators):
    if "endpoint" in operators:
        qs = qs.filter(endpoints__host__contains=",".join(operators["endpoint"]))

    return qs


def apply_vulnerability_id_filter(qs, operators):
    if "vulnerability_id" in operators:
        value = operators["vulnerability_id"]

        # possible value:
        # ['CVE-2020-6754]
        # ['CVE-2020-6754,CVE-2018-7489']
        # or when entered multiple times:
        # ['CVE-2020-6754,CVE-2018-7489', 'CVE-2020-1234']

        # so flatten like mad:
        vulnerability_ids = list(itertools.chain.from_iterable([vulnerability_id.split(",") for vulnerability_id in value]))
        logger.debug("vulnerability_id filter: %s", vulnerability_ids)
        qs = qs.filter(Q(vulnerability_id__in=vulnerability_ids))

    return qs


def perform_keyword_search_for_operator(qs, operators, operator, keywords_query):
    watson_results = None
    operator_query = ""
    keywords_query = keywords_query or ""

    if operator in operators:
        operator_query = " ".join(operators[operator])

    keywords_query = operator_query + keywords_query
    keywords_query = keywords_query.strip()

    if keywords_query:
        logger.debug("going watson with: %s", keywords_query)
        # watson is too slow to get all results or even to count them
        # counting also results in invalid queries with group by errors
        watson_results = watson.filter(qs, keywords_query)[:max_results]
        # watson_results = watson.filter(qs, keywords_query)
        qs = qs.filter(id__in=[watson.id for watson in watson_results])

    return qs
