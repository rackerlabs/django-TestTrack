{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product' test.engagement.product.id as product_url %}
{% url 'view_engagement' test.engagement.id as engagement_url %}
{% url 'view_test' test.id as test_url %}
<html>
    <body>
        {% autoescape on %}
            <p>
                {% trans "Hello" %} {{ user.get_full_name }},
            </p>
            <p>
                {{ description }}
                <br/><br/>
                {% blocktranslate %}{{ finding_count }} findings have been updated for while a scan was uploaded{% endblocktranslate %}:
                <a href="{{product_url|full_url}}">{{product}}</a> / <a href="{{engagement_url|full_url}}">{{ engagement.name }}</a> / <a href="{{ test_url|full_url }}">{{ test }}</a><br/>
                <br/>
                <details>
                <summary>{% blocktranslate %}New findings{% endblocktranslate %} ({{ findings_new | length }})</summary><br/>
                {% for finding in findings_new %}
                    {% url 'view_finding' finding.id as finding_url %}
                    <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
                {% empty %}
                    {% trans "None" %}<br/>
                {% endfor %}
                </details>
            </p>
            <p>
                <details>
                <summary>{% blocktranslate %}Reactivated findings{% endblocktranslate %} ({{ findings_reactivated | length }})</summary><br/>
                {% for finding in findings_reactivated %}
                    {% url 'view_finding' finding.id as finding_url %}
                    <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
                {% empty %}
                    {% trans "None" %}<br/>
                {% endfor %}
                </details>
            </p>
            <p>
                <details>
                <summary>{% blocktranslate %}Closed findings{% endblocktranslate %} ({{ findings_mitigated | length }})</summary><br/>
                {% for finding in findings_mitigated %}
                    {% url 'view_finding' finding.id as finding_url %}
                    <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
                {% empty %}
                    {% trans "None" %}<br/>
                {% endfor %}
                </details>
            </p>
            <p>
                <details>
                <summary>{% blocktranslate %}Untouched findings{% endblocktranslate %} ({{ findings_untouched | length }})</summary><br/>
                {% for finding in findings_untouched %}
                    {% url 'view_finding' finding.id as finding_url %}
                    <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
                {% empty %}
                    {% trans "None" %}<br/>
                {% endfor %}
                </details>
            </p>
            <br/><br/>
                {% trans "Kind regards" %},
            <br/><br/>
            {% if system_settings.team_name %}
                {{ system_settings.team_name }}
            {% else %}
                Defect Dojo
            {% endif %}
            <br/><br/>
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
