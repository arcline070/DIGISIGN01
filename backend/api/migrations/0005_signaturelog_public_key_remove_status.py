from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_remove_userkey_certificate"),
    ]

    operations = [
        migrations.AddField(
            model_name="signaturelog",
            name="public_key",
            field=models.TextField(default=""),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name="signaturelog",
            name="status",
        ),
    ]
