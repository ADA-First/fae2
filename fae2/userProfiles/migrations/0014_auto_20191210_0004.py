# Generated by Django 2.2.7 on 2019-12-10 06:04

from django.db import migrations, models
import timezone_field.fields


class Migration(migrations.Migration):

    dependencies = [
        ('userProfiles', '0013_institutionalprofile_authentication'),
    ]

    operations = [
        migrations.AlterField(
            model_name='institutionalprofile',
            name='alt_domain',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='authentication',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact1_email',
            field=models.EmailField(blank=True, default='', max_length=64),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact1_name',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact1_phone',
            field=models.CharField(blank=True, default='', max_length=16),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact1_title',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact2_email',
            field=models.EmailField(blank=True, default='', max_length=64),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact2_name',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact2_phone',
            field=models.CharField(blank=True, default='', max_length=16),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='contact2_title',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='domain',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='subscription_status',
            field=models.CharField(choices=[('FREE', 'Free'), ('CURRENT', 'Current'), ('EXPIRED', 'Expired'), ('SPECIAL', 'Special')], default='FREE', max_length=8),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='title',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AlterField(
            model_name='institutionalprofile',
            name='top_level_domain',
            field=models.CharField(blank=True, default='', max_length=8),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='subscription_status',
            field=models.CharField(choices=[('FREE', 'Free'), ('CURRENT', 'Current'), ('EXPIRED', 'Expired'), ('SPECIAL', 'Special')], default='FREE', max_length=8),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='timezone',
            field=timezone_field.fields.TimeZoneField(default='America/Chicago'),
        ),
    ]