from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0003_userkey_certificate_and_log_status"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="userkey",
            name="certificate",
        ),
    ]
