# Generated by Django 5.2.3 on 2025-06-26 10:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_rename_name_company_company_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
    ]
