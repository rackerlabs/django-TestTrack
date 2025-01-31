import csv
import hashlib
import io
from datetime import datetime

from dojo.models import Finding


class ColumnMappingStrategy:
    mapped_column = None

    def __init__(self):
        self.successor = None

    def map_column_value(self, finding, column_value):
        pass

    def process_column(self, column_name, column_value, finding):
        if (
            column_name.lower() == self.mapped_column
            and column_value is not None
        ):
            self.map_column_value(finding, column_value)
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class DateColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "date"
        super().__init__()

    def map_column_value(self, finding, column_value):
        finding.date = datetime.strptime(
            column_value, "%Y-%m-%d %H:%M:%S",
        ).date()


class TitleColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "title"
        super().__init__()

    def map_column_value(self, finding, column_value):
        finding.title = column_value


class DescriptionColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "description"
        super().__init__()

    def map_column_value(self, finding, column_value):
        finding.description = column_value


class MitigationColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "mitigation"
        super().__init__()

    def map_column_value(self, finding, column_value):
        finding.mitigation = column_value


class SKFParser:
    def get_scan_types(self):
        return ["SKF Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Output of SKF Sprint summary export."

    def create_chain(self):
        date_column_strategy = DateColumnMappingStrategy()
        title_column_strategy = TitleColumnMappingStrategy()
        description_column_strategy = DescriptionColumnMappingStrategy()
        mitigation_column_strategy = MitigationColumnMappingStrategy()

        description_column_strategy.successor = mitigation_column_strategy
        title_column_strategy.successor = description_column_strategy
        date_column_strategy.successor = title_column_strategy

        return date_column_strategy

    def read_column_names(self, column_names, row):
        for index, column in enumerate(row):
            column_names[index] = column

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        column_names = {}
        chain = self.create_chain()

        reader = csv.reader(
            io.StringIO(content), delimiter=",", quotechar='"', escapechar="\\",
        )
        dupes = {}
        for row_number, row in enumerate(reader):
            finding = Finding(test=test)
            finding.severity = "Info"

            if row_number == 0:
                self.read_column_names(column_names, row)
                continue

            for column_number, column in enumerate(row):
                chain.process_column(
                    column_names[column_number], column, finding,
                )

            if finding is not None:
                key = hashlib.sha256(
                    str(
                        finding.severity
                        + "|"
                        + finding.title
                        + "|"
                        + finding.description,
                    ).encode("utf-8"),
                ).hexdigest()

                if key not in dupes:
                    dupes[key] = finding

        return list(dupes.values())
