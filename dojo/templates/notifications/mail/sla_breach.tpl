{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding' finding.id as finding_url %}
<html>
    <body>
        {% autoescape on %}
            <p>
                {% trans "Hello" %} {{ user.get_full_name }},
            </p>
            <br/>
            <br/>
            <p>
                {% if sla_age < 0 %}
                  {% blocktranslate trimmed %}
                    This security finding has breached its SLA.
                    
                    - Day(s) overdue: {{sla}}
                  {% endblocktranslate %}
                {% else %}
                  {% blocktranslate trimmed %}
                    A security finding is about to breach its SLA.
                    
                    - Day(s) remaining: {{sla}}
                  {% endblocktranslate %}
                {% endif %}
            </p>
                <br/>
                - {% trans "Title" %}: <a href="{{finding_url|full_url}}">{{finding.title}}</a>
                <br/>
                - {% trans "Severity" %}: {{finding.severity}}
                <br/><br/>
                {% trans "Please refer to your SLA documentation for further guidance" %}
            </p>
            <br/></br>
            {% trans "Kind regards" %},
            </br></br>
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
