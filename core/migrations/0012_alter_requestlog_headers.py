# Generated by Django 5.1.3 on 2024-11-20 11:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0011_suspicousip_first_seen'),
    ]

    operations = [
        migrations.AlterField(
            model_name='requestlog',
            name='headers',
            field=models.JSONField(blank=True),
        ),
    ]
