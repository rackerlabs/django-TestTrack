{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% url 'view_risk_acceptance' risk_acceptance.engagement.id risk_acceptance.id as risk_acceptance_url %}
{% url 'view_product' risk_acceptance.engagement.product.id as product_url %}
{% url 'view_engagement' risk_acceptance.engagement.id as engagement_url %}
<html>
    <body>
        {% autoescape on %}
            <p>
                {% trans "Hello" %} {{ user.get_full_name }},
            </p>
            <p>
                {{ description }}
                <br/><br/>
            
                {% if risk_acceptance.is_expired %}
                    {% blocktranslate with risk_url=risk_acceptance_url|full_url risk_findings=risk_acceptance.accepted_findings.all|length risk_date=risk_acceptance.expiration_date_handled|date %}<a href="{{risk_url}}">Risk acceptance {{ risk_acceptance }}</a> with {{ risk_findings }} has expired {{ risk_date }}{% endblocktranslate %}
                {% else %}
                    {% blocktranslate with risk_url=risk_acceptance_url|full_url risk_findings=risk_acceptance.accepted_findings.all|length risk_date=risk_acceptance.expiration_date|date %}<a href="{{risk_url}}">Risk acceptance {{ risk_acceptance }}</a> with {{ risk_findings }} will expire {{ risk_date }}{% endblocktranslate %}
                {% endif %}
                <br/>
                {% if risk_acceptance.reactivate_expired %}
                    <p>{% blocktranslate %}Findings have been reactivated</p>{% endblocktranslate %}
                {% endif %}
                <br/>
                {% if risk_acceptance.restart_sla_expired %}
                    <p>{% blocktranslate %}Findings SLA start date have been reset</p>{% endblocktranslate %}
                {% endif %}
                <br/>
                <p>
                    {% trans "Findings" %}:
                    <br/>
                    {% for finding in risk_acceptance.accepted_findings.all %}
                        {% url 'view_finding' finding.id as finding_url %}
                        <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }}) {{ finding.status }}<br/>
                    {% empty %}
                        {% trans "None" %}<br/>
                    {% endfor %}
                </p>
                <br/><br/>
                {% trans "Kind regards" %},
                <br/><br/>
                {% if system_settings.team_name %}
                        {{ system_settings.team_name }}
                    {% else %}
                        Defect Dojo
                    {% endif %}
                <br/>
                <br/>
                <p>
                    {% url 'notifications' as notification_url %}
                    {% trans "You can manage your notification settings here" %}: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
                </p>
                {% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
                    <br/>
                    <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
                        <span style="font-size:16pt;  font-family: 'Cambria','times new roman','garamond',serif; color:#ff0000;">{% trans "Disclaimer" %}</span><br/>
                        <p style="font-size:11pt; line-height:10pt; font-family: 'Cambria','times roman',serif;">{{ system_settings.disclaimer_notifications }}</p>
                    </div>
                {% endif %}
        {% endautoescape %}
    </body>
</html>
