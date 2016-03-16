# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-03-02 17:35
from __future__ import absolute_import
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='RuleCategory',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('rule_category_code', models.IntegerField(unique=True)),
                ('category_id', models.CharField(max_length=64)),
                ('title', models.CharField(max_length=256)),
                ('title_plural', models.CharField(max_length=256, verbose_name=b'Title Plural')),
                ('description', models.TextField(blank=True, null=True)),
                ('slug', models.SlugField(max_length=32)),
                ('order', models.IntegerField()),
            ],
            options={
                'ordering': ['order', 'title'],
                'verbose_name': 'Rule Category',
                'verbose_name_plural': 'Rule Categories',
            },
        ),
    ]
