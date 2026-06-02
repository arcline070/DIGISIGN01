# Legacy initial schema (UserRSAKey + username on SignatureLog)

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="UserRSAKey",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("username", models.CharField(db_index=True, max_length=150, unique=True)),
                ("private_key_pem", models.TextField()),
                ("public_key_pem", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["username"]},
        ),
        migrations.CreateModel(
            name="SignatureLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("username", models.CharField(db_index=True, max_length=150)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("data", models.TextField()),
                ("hash_hex", models.CharField(max_length=64)),
                ("signature", models.TextField(blank=True)),
                (
                    "status",
                    models.CharField(
                        choices=[("signed", "Signed"), ("unsigned", "Unsigned")],
                        default="signed",
                        max_length=16,
                    ),
                ),
            ],
            options={"ordering": ["-timestamp"]},
        ),
    ]
