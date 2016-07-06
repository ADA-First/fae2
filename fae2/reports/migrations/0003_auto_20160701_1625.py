# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-07-01 21:25
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0002_websitereport_delete_flag'),
    ]

    operations = [
        migrations.AlterField(
            model_name='websitereport',
            name='depth',
            field=models.IntegerField(choices=[(1, b'Top-level page only'), (2, b'Include second-level pages'), (3, b'Include third-level pages'), (4, b'Include fourth-level pages'), (5, b'Include fifth-level pages'), (8, b'Include maximum-level (8 levels) pages')], default=2, verbose_name=b'Depth of Evaluation'),
        ),
        migrations.AlterField(
            model_name='websitereport',
            name='max_pages',
            field=models.IntegerField(choices=[(0, b'  All pages'), (5, b'   5 pages'), (10, b'  10 pages'), (25, b'  25 pages')], default=0, verbose_name=b'Maximum Pages'),
        ),
        migrations.AlterField(
            model_name='websitereport',
            name='wait_time',
            field=models.IntegerField(choices=[(30000, b' 30 seconds'), (45000, b' 45 seconds'), (60000, b' 60 seconds'), (90000, b' 90 seconds'), (120000, b'120 seconds')], default=90000, verbose_name=b'How long to wait for website to load resources'),
        ),
    ]