{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
<html>
    <body>
        {% autoescape on %}
            <p>
                {% trans "Hello" %},
            </p>
            <p>
              {% blocktranslate trimmed prod_url=url|full_url %}
                The new product type "{{ title }}" has been added. It can be viewed here: <a href="{{ prod_url }}">{{ title }}</a>
              {% endblocktranslate %}
            </p>
            <br/>
            <br/>
                {% trans "Kind regards" %},<br/>
            <br/>
                {% if system_settings.team_name %}
                    {{ system_settings.team_name }}
                {% else %}
                    Defect Dojo
                {% endif %}
            <p>
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
