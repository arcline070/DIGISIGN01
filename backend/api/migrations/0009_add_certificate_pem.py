from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_userprofile_role_and_auditlog'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='certificate_pem',
            field=models.TextField(blank=True, default=''),
        ),
    ]
