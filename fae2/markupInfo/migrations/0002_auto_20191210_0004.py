# Generated by Django 2.2.7 on 2019-12-10 06:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('markupInfo', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pagemarkupgroup',
            name='name',
            field=models.CharField(max_length=24, verbose_name='Group Name'),
        ),
        migrations.AlterField(
            model_name='pagemarkupitem',
            name='attribute',
            field=models.CharField(max_length=24, verbose_name='Attribute'),
        ),
        migrations.AlterField(
            model_name='pagemarkupitem',
            name='element',
            field=models.CharField(max_length=24, verbose_name='Element'),
        ),
        migrations.AlterField(
            model_name='pagemarkupitem',
            name='event',
            field=models.CharField(max_length=24, verbose_name='Event'),
        ),
        migrations.AlterField(
            model_name='websitemarkupgroup',
            name='name',
            field=models.CharField(max_length=24, verbose_name='Group Name'),
        ),
        migrations.AlterField(
            model_name='websitemarkupitem',
            name='attribute',
            field=models.CharField(max_length=24, verbose_name='Attribute'),
        ),
        migrations.AlterField(
            model_name='websitemarkupitem',
            name='element',
            field=models.CharField(max_length=24, verbose_name='Element'),
        ),
        migrations.AlterField(
            model_name='websitemarkupitem',
            name='event',
            field=models.CharField(max_length=24, verbose_name='Event'),
        ),
    ]
