# Generated by Django 5.2.3 on 2025-06-28 10:13

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('expense', '0009_alter_usersalary_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userdetails',
            name='city',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='dob',
            field=models.DateField(default=''),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='full_name',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='gender',
            field=models.CharField(default='', max_length=10),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='occupation',
            field=models.CharField(default='', max_length=20),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='state',
            field=models.CharField(default='', max_length=30),
        ),
        migrations.CreateModel(
            name='Member',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('member_otp', models.PositiveIntegerField(blank=True, null=True)),
                ('joined_at', models.DateTimeField(auto_now_add=True)),
                ('main_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='main_user_members', to='expense.users')),
                ('member_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='joined_as_member', to='expense.users')),
            ],
            options={
                'unique_together': {('main_user', 'member_user')},
            },
        ),
    ]
