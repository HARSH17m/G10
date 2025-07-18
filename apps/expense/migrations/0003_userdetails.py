# Generated by Django 5.2.3 on 2025-06-19 08:54

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('expense', '0002_users_otp'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserDetails',
            fields=[
                ('UID', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('full_name', models.CharField(max_length=100)),
                ('dob', models.DateField()),
                ('gender', models.CharField(max_length=10)),
                ('state', models.CharField(max_length=30)),
                ('city', models.CharField(max_length=100)),
                ('occupation', models.CharField(max_length=20)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='expense.users')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
