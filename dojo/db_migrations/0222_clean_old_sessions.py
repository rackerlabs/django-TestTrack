from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0221_system_settings_disclaimer_notif'),
        ('sessions', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL("DELETE FROM django_session WHERE expire_date < NOW();"),
    ]
