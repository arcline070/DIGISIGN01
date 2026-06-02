from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def _generate_rsa_pem_pair():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def forwards(apps, schema_editor):
    User = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    UserKey = apps.get_model("api", "UserKey")
    UserProfile = apps.get_model("api", "UserProfile")

    existing_profiles = {p.user_id for p in UserProfile.objects.only("user_id")}

    for legacy in UserKey.objects.all():
        if legacy.user_id in existing_profiles:
            continue
        UserProfile.objects.create(
            user_id=legacy.user_id,
            public_key=legacy.public_key,
            private_key=legacy.private_key,
        )
        existing_profiles.add(legacy.user_id)

    for user in User.objects.all():
        if user.id in existing_profiles:
            continue
        private_key, public_key = _generate_rsa_pem_pair()
        UserProfile.objects.create(
            user_id=user.id,
            public_key=public_key,
            private_key=private_key,
        )
        existing_profiles.add(user.id)


def backwards(apps, schema_editor):
    UserKey = apps.get_model("api", "UserKey")
    UserProfile = apps.get_model("api", "UserProfile")
    for profile in UserProfile.objects.all():
        UserKey.objects.update_or_create(
            user_id=profile.user_id,
            defaults={
                "public_key": profile.public_key,
                "private_key": profile.private_key,
            },
        )


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0005_signaturelog_public_key_remove_status"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("public_key", models.TextField()),
                ("private_key", models.TextField()),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="profile",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"verbose_name": "User profile"},
        ),
        migrations.RunPython(forwards, backwards),
        migrations.DeleteModel(name="UserKey"),
    ]
