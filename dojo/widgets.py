from django import forms
from django.core.paginator import Paginator
from django.template.loader import render_to_string


# agrega los imports necesarios
class TableCheckboxWidget(forms.widgets.Widget):
    template_name = "dojo/add_findings_as_accepted.html"

    def __init__(self, *args, **kwargs):
        self.findings = kwargs.pop("findings", [])
        self.request = kwargs.pop("request", None)
        self.page_number = kwargs.pop("page_number", 1)
        super().__init__(*args, **kwargs)

    def value_from_datadict(self, data, files, name):
        selected_ids = data.getlist(name)
        return [int(idn) for idn in selected_ids]

    def render(self, name, value, attrs=None, renderer=None):
        page_number = self.page_number
        paginator = Paginator(self.findings, 25)  # 10 items per page
        page = paginator.get_page(page_number)
        context = {
            "name": name,
            "findings": page.object_list,
            "paginator": paginator,
            "page_number": page_number,
            "page": page,
            "page_param": "apage",
        }
        return render_to_string(self.template_name, context)
