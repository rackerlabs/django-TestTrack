import logging

from crum import get_current_user
from django.contrib import messages
from django.db.models import Count, Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.forms import Benchmark_Product_SummaryForm, DeleteBenchmarkForm
from dojo.models import (
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Benchmark_Type,
    Product,
)
from dojo.templatetags.display_tags import asvs_level
from dojo.utils import (
    Product_Tab,
    add_breadcrumb,
    redirect_to_return_url_or_else,
)

logger = logging.getLogger(__name__)


def add_benchmark(queryset, product):
    requirements = []
    for requirement in queryset:
        benchmark_product = Benchmark_Product()
        benchmark_product.product = product
        benchmark_product.control = requirement
        requirements.append(benchmark_product)
    Benchmark_Product.objects.bulk_create(requirements)


@user_is_authorized(Product, Permissions.Benchmark_Edit, "pid")
def update_benchmark(request, pid, _type):
    if request.method == "POST":
        bench_id = request.POST.get("bench_id")
        field = request.POST.get("field")
        value = request.POST.get("value")
        value = {"true": True, "false": False}.get(value, value)

        if field in [
            "enabled",
            "pass_fail",
            "notes",
            "get_notes",
            "delete_notes",
        ]:
            bench = Benchmark_Product.objects.get(id=bench_id)
            if field == "enabled":
                bench.enabled = value
            elif field == "pass_fail":
                bench.pass_fail = value
            elif field in ["notes", "get_notes", "delete_notes"]:
                if field == "notes":
                    bench.notes.create(entry=value, author=get_current_user())
                if field == "delete_notes":
                    bench.notes.remove(value)
                notes = bench.notes.order_by("id")
                return JsonResponse(
                    {
                        "notes": [
                            {
                                "id": n.id,
                                "entry": n.entry,
                                "author": n.author.get_full_name(),
                                "date": n.date.ctime(),
                            }
                            for n in notes
                        ],
                    },
                )

            bench.save()
            return JsonResponse({field: value})

    return redirect_to_return_url_or_else(
        request, reverse("view_product_benchmark", args=(pid, _type)),
    )


@user_is_authorized(Product, Permissions.Benchmark_Edit, "pid")
def update_benchmark_summary(request, pid, _type, summary):
    if request.method == "POST":
        field = request.POST.get("field")
        value = request.POST.get("value")
        value = {"true": True, "false": False}.get(value, value)

        if field in ["publish", "desired_level"]:
            summary = Benchmark_Product_Summary.objects.get(id=summary)
            data = {}
            if field == "publish":
                summary.publish = value
                data = {"publish": value}
            elif field == "desired_level":
                summary.desired_level = value
                data = {"desired_level": value, "text": asvs_level(summary)}

            summary.save()
            return JsonResponse(data)

    return redirect_to_return_url_or_else(
        request, reverse("view_product_benchmark", args=(pid, _type)),
    )


def return_score(queryset):
    asvs_level_1_benchmark = 0
    asvs_level_1_score = 0
    for item in queryset:
        if item["pass_fail"]:
            asvs_level_1_score = item["pass_fail__count"]
        asvs_level_1_benchmark = (
            asvs_level_1_benchmark + item["pass_fail__count"]
        )

    return asvs_level_1_benchmark, asvs_level_1_score


def score_asvs(product, benchmark_type):
    # Compliant to ASVS level 1 benchmarks
    asvs_level_1 = (
        Benchmark_Product.objects.filter(
            enabled=True,
            control__enabled=True,
            product=product,
            control__category__type=benchmark_type,
            control__category__enabled=True,
            control__level_1=True,
        )
        .values("pass_fail")
        .annotate(Count("pass_fail"))
        .order_by()
    )
    asvs_level_1_benchmark, asvs_level_1_score = return_score(asvs_level_1)

    # Compliant to ASVS level 2 benchmarks
    asvs_level_2 = (
        Benchmark_Product.objects.filter(
            ~Q(control__level_1=True),
            enabled=True,
            control__enabled=True,
            product=product,
            control__category__type=benchmark_type,
            control__category__enabled=True,
            control__level_2=True,
        )
        .values("pass_fail")
        .annotate(Count("pass_fail"))
        .order_by()
    )
    asvs_level_2_benchmark, asvs_level_2_score = return_score(asvs_level_2)

    # Compliant to ASVS level 3 benchmarks
    asvs_level_3 = (
        Benchmark_Product.objects.filter(
            ~Q(control__level_1=True),
            ~Q(control__level_2=True),
            enabled=True,
            control__enabled=True,
            control__category__enabled=True,
            product=product,
            control__category__type=benchmark_type,
            control__level_3=True,
        )
        .values("pass_fail")
        .annotate(Count("pass_fail"))
        .order_by()
    )
    asvs_level_3_benchmark, asvs_level_3_score = return_score(asvs_level_3)
    benchmark_product_summary = Benchmark_Product_Summary.objects.get(
        product=product, benchmark_type=benchmark_type,
    )

    benchmark_product_summary.asvs_level_1_benchmark = asvs_level_1_benchmark
    benchmark_product_summary.asvs_level_1_score = asvs_level_1_score
    benchmark_product_summary.asvs_level_2_benchmark = asvs_level_2_benchmark
    benchmark_product_summary.asvs_level_2_score = asvs_level_2_score
    benchmark_product_summary.asvs_level_3_benchmark = asvs_level_3_benchmark
    benchmark_product_summary.asvs_level_3_score = asvs_level_3_score

    benchmark_product_summary.save()


@user_is_authorized(Product, Permissions.Benchmark_Edit, "pid")
def benchmark_view(request, pid, benchmark_type, cat=None):
    product = get_object_or_404(Product, id=pid)
    benchmark_type = get_object_or_404(Benchmark_Type, id=benchmark_type)
    benchmark_category = Benchmark_Category.objects.filter(
        type=benchmark_type, enabled=True,
    ).order_by("name")

    # Add requirements to the product
    new_benchmarks = Benchmark_Requirement.objects.filter(
        category__type=benchmark_type, category__type__enabled=True, enabled=True,
    ).exclude(
        id__in=Benchmark_Product.objects.filter(product=product).values_list(
            "control_id", flat=True,
        ),
    )
    add_benchmark(new_benchmarks, product)

    # Create the benchmark summary category
    try:
        benchmark_product_summary = Benchmark_Product_Summary.objects.get(
            product=product, benchmark_type=benchmark_type,
        )
    except Exception:
        benchmark_product_summary = Benchmark_Product_Summary(
            product=product, benchmark_type=benchmark_type,
        )
        benchmark_product_summary.save()

    if cat:
        benchmarks = (
            Benchmark_Product.objects.select_related(
                "control", "control__category",
            )
            .filter(
                product=product.id,
                control__category=cat,
                control__category__enabled=True,
                control__category__type=type,
                control__enabled=True,
            )
            .all()
            .order_by("control__objective_number")
        )
    else:
        benchmarks = (
            Benchmark_Product.objects.select_related(
                "control", "control__category",
            )
            .filter(
                product=product.id,
                control__category__enabled=True,
                control__category__type=type,
                control__enabled=True,
            )
            .all()
            .order_by("control__category__name", "control__objective_number")
        )

    benchmark_summary_form = Benchmark_Product_SummaryForm(
        instance=benchmark_product_summary,
    )

    noted_benchmarks = (
        benchmarks.filter(notes__isnull=False).order_by("id").distinct()
    )
    for bench in benchmarks:
        if bench.id in [b.id for b in noted_benchmarks]:
            bench.noted = True
        else:
            bench.noted = False
    benchmarks = sorted(
        benchmarks,
        key=lambda x: [int(_) for _ in x.control.objective_number.split(".")],
    )
    benchmark_category = sorted(
        benchmark_category, key=lambda x: int(x.name[:3].strip("V: ")),
    )

    product_tab = Product_Tab(product, title=_("Benchmarks"), tab="benchmarks")

    add_breadcrumb(title=_("Benchmarks"), top_level=False, request=request)

    return render(
        request,
        "dojo/benchmark.html",
        {
            "benchmarks": benchmarks,
            "active_tab": "benchmarks",
            "product_tab": product_tab,
            "benchmark_product_summary": benchmark_product_summary,
            "benchmark_summary_form": benchmark_summary_form,
            "benchmark_type": benchmark_type,
            "product": product,
            "benchmark_category": benchmark_category,
        },
    )


@user_is_authorized(Product, Permissions.Benchmark_Delete, "pid")
def delete(request, pid, benchmark_type):
    product = get_object_or_404(Product, id=pid)
    benchmark_product_summary = Benchmark_Product_Summary.objects.filter(
        product=product, benchmark_type=benchmark_type,
    ).first()
    form = DeleteBenchmarkForm(instance=benchmark_product_summary)

    if request.method == "POST":
        if (
            "id" in request.POST
            and str(benchmark_product_summary.id) == request.POST["id"]
        ):
            form = DeleteBenchmarkForm(
                request.POST, instance=benchmark_product_summary,
            )
            if form.is_valid():
                benchmark_product = Benchmark_Product.objects.filter(
                    product=product, control__category__type=benchmark_type,
                )
                benchmark_product.delete()
                benchmark_product_summary.delete()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    _("Benchmarks removed."),
                    extra_tags="alert-success",
                )
                return HttpResponseRedirect(reverse("product"))

    product_tab = Product_Tab(
        product, title=_("Delete Benchmarks"), tab="benchmarks",
    )
    return render(
        request,
        "dojo/delete_benchmark.html",
        {"product": product, "form": form, "product_tab": product_tab},
    )
