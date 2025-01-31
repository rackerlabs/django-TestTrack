from django.db.models import Aggregate, CharField


class Sql_GroupConcat(Aggregate):
    function = "GROUP_CONCAT"
    allow_distinct = True

    def __init__(
        self, expression, separator, *, distinct=False, ordering=None, **extra,
    ):
        self.separator = separator
        super().__init__(
            expression,
            distinct="DISTINCT " if distinct else "",
            ordering=f" ORDER BY {ordering}" if ordering is not None else "",
            separator=f' SEPARATOR "{separator}"',
            output_field=CharField(),
            **extra,
        )

    def as_sql(self, compiler, connection, **extra):
        return super().as_sql(
            compiler,
            connection,
            template="%(function)s(%(distinct)s%(expressions)s%(ordering)s)",
            **extra,
        )
