# Generated by Django 5.1.7 on 2025-04-11 20:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0020_device_creation_date_device_last_seen'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='device',
            name='last_seen',
        ),
        migrations.RemoveField(
            model_name='devicelease',
            name='last_seen',
        ),
        migrations.AddField(
            model_name='device',
            name='last_active',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='devicelease',
            name='last_active',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
