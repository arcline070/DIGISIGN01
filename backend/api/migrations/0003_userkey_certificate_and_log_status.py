from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0002_user_auth_userkey_signaturelog_user"),
    ]

    operations = [
        migrations.AddField(
            model_name="userkey",
            name="certificate",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AlterField(
            model_name="signaturelog",
            name="status",
            field=models.CharField(
                choices=[
                    ("signed", "Signed"),
                    ("verified", "Verified"),
                    ("failed", "Failed"),
                    ("unsigned", "Unsigned"),
                ],
                default="signed",
                max_length=16,
            ),
        ),
    ]
