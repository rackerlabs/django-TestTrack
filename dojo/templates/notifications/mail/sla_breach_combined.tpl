{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
<html>
    <body>
        {% autoescape on %}
            <p>{% trans "Hello" %} {{ user.get_full_name }},</p>
            <p>
                {% trans "Product summary" %}:
                <ul>
                    <li>{% trans "name" %}: {{ product.name }}</li>
                    <li>{% trans "product type" %}: {{ product.prod_type }}</li>
                    <li>{% trans "team manager" %}: {{ product.team_manager }}</li>
                    <li>{% trans "product manager" %}: {{ product.product_manager }}</li>
                    <li>{% trans "technical contact" %}: {{ product.technical_contact }}</li>
                </ul>
            </p>
            <p>
                {% if breach_kind == 'breached' %}
                    {% blocktranslate trimmed %}
                        These security findings have breached their SLA:
                    {% endblocktranslate %}
                {% elif breach_kind == 'prebreach' %}
                    {% blocktranslate trimmed %}
                        These security findings are about to breach their SLA:
                    {% endblocktranslate %}
                {% elif breach_kind == 'breaching' %}
                    {% blocktranslate trimmed %}
                        These security findings breaching their SLA today:
                    {% endblocktranslate %}
                {% else %}
                    This should not happen, check 'breach_kind' and 'kind' properties value in the source code.
                {% endif %}
                <br />
                <ul>
                    {% for f in findings %}
                        {% url 'view_finding' f.id as finding_url %}
                        <li>
                            <a href="{{ finding_url|full_url }}">"{{ f.title }}"</a> ({{ f.severity }} {% trans "severity" %}), {% trans "SLA age" %}: {{ f.sla_age }}
                        </li>
                    {% endfor %}
                </ul>
                <br />
                {% trans "Please refer to your SLA documentation for further guidance" %}
            </p>
            {% trans "Kind regards" %},
        </br>
        {% if system_settings.team_name %}
            {{ system_settings.team_name }}
        {% else %}
            Defect Dojo
        {% endif %}
        <br />
        <p>
            {% url 'notifications' as notification_url %}
            {% trans "You can manage your notification settings here" %}: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
        </p>
        {% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
            <br />
            <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
                <span style="font-size:16pt;
                             font-family: 'Cambria','times new roman','garamond',serif;
                             color:#ff0000">{% trans "Disclaimer" %}</span>
                <br />
                <p style="font-size:11pt;
                          line-height:10pt;
                          font-family: 'Cambria','times roman',serif">{{ system_settings.disclaimer_notifications }}</p>
            </div>
        {% endif %}
    {% endautoescape %}
</body>
</html>
