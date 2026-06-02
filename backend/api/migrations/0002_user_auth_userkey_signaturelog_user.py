from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.DeleteModel(name="SignatureLog"),
        migrations.DeleteModel(name="UserRSAKey"),
        migrations.CreateModel(
            name="UserKey",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("private_key", models.TextField()),
                ("public_key", models.TextField()),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="userkey",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "User key",
            },
        ),
        migrations.CreateModel(
            name="SignatureLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
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
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="signature_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-timestamp"],
            },
        ),
    ]
