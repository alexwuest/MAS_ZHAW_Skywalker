# Generated by Django 5.1.7 on 2025-04-16 07:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0021_remove_device_last_seen_remove_devicelease_last_seen_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='destinationmetadata',
            name='last_checked',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
