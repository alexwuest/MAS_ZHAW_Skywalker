# Generated by Django 5.1.7 on 2025-03-21 12:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rules', '0004_alter_destinationmetadata_lat_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='destinationmetadata',
            name='offset',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
