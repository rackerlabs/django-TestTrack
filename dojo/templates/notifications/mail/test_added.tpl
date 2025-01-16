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
              {% blocktranslate trimmed with prod_url=product_url|full_url eng_url=engagement_url|full_url eng_name=engagement.name t_url=test_url|full_url %}
                A new test has been added: <a href="{{prod_url}}">{{product}}</a> / <a href="{{eng_url}}">{{ eng_name }}</a> / <a href="{{ t_url }}">{{ test }}</a><br/>
                Finding details in the 'scan_added' email, which is a separate notification (for now).
              {% endblocktranslate %}
            </p>    
            <br/>
                {% trans "Kind regards" %},</br>
            <br/>
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
