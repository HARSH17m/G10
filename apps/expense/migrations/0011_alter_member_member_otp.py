# Generated by Django 5.2.3 on 2025-06-28 11:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('expense', '0010_alter_userdetails_city_alter_userdetails_dob_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='member',
            name='member_otp',
            field=models.PositiveIntegerField(blank=True, default=987321, null=True),
        ),
    ]
