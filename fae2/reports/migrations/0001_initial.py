# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2015-12-14 22:49
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('rulesets', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='FilteredURL',
            fields=[
                ('filtered_url_id', models.AutoField(primary_key=True, serialize=False)),
                ('url', models.URLField(max_length=4096, verbose_name='Other URL')),
                ('url_referenced', models.URLField(max_length=4096, verbose_name='Referenced URL')),
            ],
            options={
                'verbose_name': 'URL: Filtered',
                'verbose_name_plural': 'URL: Filtered',
                'ordering': ['url_referenced', 'url'],
            },
        ),
        migrations.CreateModel(
            name='ProcessedURL',
            fields=[
                ('processed_url_id', models.AutoField(primary_key=True, serialize=False)),
                ('page_seq_num', models.IntegerField(default=-1)),
                ('url_requested', models.URLField(max_length=4096, verbose_name='Processed URL')),
                ('url_returned', models.URLField(max_length=4096, verbose_name='Returned URL')),
                ('redirect', models.BooleanField(default=False, verbose_name='Server redirect')),
                ('http_status_code', models.IntegerField(verbose_name='http status code')),
                ('url_referenced', models.URLField(max_length=4096, verbose_name='Referenced URL')),
                ('dom_time', models.IntegerField(verbose_name='Loading DOM time')),
                ('link_time', models.IntegerField(verbose_name='Retreive links tIme')),
                ('event_time', models.IntegerField(verbose_name='Event time')),
                ('eval_time', models.IntegerField(verbose_name='Evaluation time')),
                ('save_time', models.IntegerField(verbose_name='Saving results time')),
                ('total_time', models.IntegerField(verbose_name='Total processing time')),
            ],
            options={
                'verbose_name': 'URL: Processed',
                'verbose_name_plural': 'URL: Processed',
                'ordering': ['http_status_code', 'url_returned', 'total_time'],
            },
        ),
        migrations.CreateModel(
            name='UnprocessedURL',
            fields=[
                ('unprocessed_url_id', models.AutoField(primary_key=True, serialize=False)),
                ('url', models.URLField(max_length=4096, verbose_name='Unprocessed URL')),
                ('url_referenced', models.URLField(max_length=4096, verbose_name='Referenced URL')),
                ('dom_time', models.IntegerField(verbose_name='Loading DOM time')),
                ('link_time', models.IntegerField(verbose_name='Retreive links tIme')),
                ('event_time', models.IntegerField(verbose_name='Event time')),
                ('eval_time', models.IntegerField(verbose_name='Evaluation time')),
                ('save_time', models.IntegerField(verbose_name='Saving results time')),
                ('total_time', models.IntegerField(verbose_name='Total processing time')),
            ],
            options={
                'verbose_name': 'URL: Unprocessed',
                'verbose_name_plural': 'URL: Unprocessed',
                'ordering': ['url', 'url_referenced'],
            },
        ),
        migrations.CreateModel(
            name='WebsiteReport',
            fields=[
                ('result_value', models.IntegerField(default=0)),
                ('implementation_pass_fail_score', models.IntegerField(default=-1)),
                ('implementation_score', models.IntegerField(default=-1)),
                ('implementation_pass_fail_status', models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('C', 'Complete')], default='U', max_length=2, verbose_name='Implementation Pass/Fail Status')),
                ('implementation_status', models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('C', 'Complete')], default='U', max_length=2, verbose_name='Implementation Status')),
                ('manual_check_status', models.CharField(choices=[('NC', 'Not Checked'), ('NA', 'Not Applicable'), ('P', 'Passed'), ('F', 'Fail')], default='NC', max_length=2, verbose_name='Manual Check Status')),
                ('rules_violation', models.IntegerField(default=0)),
                ('rules_warning', models.IntegerField(default=0)),
                ('rules_manual_check', models.IntegerField(default=0)),
                ('rules_passed', models.IntegerField(default=0)),
                ('rules_na', models.IntegerField(default=0)),
                ('rules_with_hidden_content', models.IntegerField(default=0)),
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('slug', models.SlugField(blank=True, default='', editable=False, max_length=256, unique=True)),
                ('title', models.CharField(default='no title', max_length=1024, verbose_name='Title')),
                ('url', models.URLField(default='', max_length=1024, verbose_name='URL')),
                ('follow', models.IntegerField(choices=[(1, 'Specified domain only'), (2, 'Next-level subdomains')], default=1, verbose_name='Follow Links in')),
                ('depth', models.IntegerField(choices=[(1, 'Top-level page only'), (2, 'Include second-level pages'), (3, 'Include third-level pages')], default=2, verbose_name='Depth of Evaluation')),
                ('max_pages', models.IntegerField(choices=[(0, ' All pages'), (10, ' 10 pages'), (25, ' 25 pages'), (50, ' 50 pages'), (100, ' 100 pages')], default=0, verbose_name='Maxiumum Pages')),
                ('browser_emulation', models.CharField(default='FIREFOX', max_length=32, verbose_name='Browser Emulation')),
                ('wait_time', models.IntegerField(choices=[(30000, ' 30 seconds'), (45000, ' 45 seconds'), (60000, ' 60 seconds'), (90000, ' 90 seconds'), (120000, '120 seconds')], default=90000, verbose_name='How long to wait for website to load resources (in milliseconds)')),
                ('span_sub_domains', models.CharField(blank=True, default='', max_length=1024, verbose_name='Span Sub-Domains (space separated)')),
                ('exclude_sub_domains', models.CharField(blank=True, default='', max_length=1024, verbose_name='Exclude Sub-Domains (space separated)')),
                ('include_domains', models.CharField(blank=True, default='', max_length=1024, verbose_name='Include Domains (space separated)')),
                ('authorization', models.TextField(blank=True, default='', max_length=8192, verbose_name='Authentication Information')),
                ('page_count', models.IntegerField(default=0, verbose_name='Number of Pages')),
                ('archive', models.BooleanField(default=False)),
                ('stats', models.BooleanField(default=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('last_viewed', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(choices=[('-', 'Created'), ('I', 'Initalized'), ('A', 'Analyzing'), ('S', 'Saving'), ('C', 'Complete'), ('E', 'Error'), ('D', 'Deleted')], default='-', max_length=10, verbose_name='Status')),
                ('processing_time', models.IntegerField(default=-1)),
                ('processed_urls_count', models.IntegerField(default=-1)),
                ('unprocessed_urls_count', models.IntegerField(default=-1)),
                ('filtered_urls_count', models.IntegerField(default=-1)),
                ('data_dir_slug', models.SlugField(editable=False)),
                ('data_directory', models.CharField(default='', max_length=1024, verbose_name='Data Directory')),
                ('data_property_file', models.CharField(default='', max_length=1024, verbose_name='Property File Name')),
                ('data_authorization_file', models.CharField(blank=True, default='', max_length=1024, verbose_name='Authorization File Name')),
                ('data_multiple_urls_file', models.CharField(blank=True, default='', max_length=1024, verbose_name='Multiple URLs File Name')),
                ('log_file', models.CharField(default='', max_length=1024, verbose_name='Log file')),
                ('ruleset', models.ForeignKey(default=2, on_delete=django.db.models.deletion.CASCADE, to='rulesets.Ruleset')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Report',
                'verbose_name_plural': 'Reports',
                'ordering': ['created'],
            },
        ),
        migrations.AddField(
            model_name='unprocessedurl',
            name='ws_report',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='unprocessed_urls', to='reports.WebsiteReport'),
        ),
        migrations.AddField(
            model_name='processedurl',
            name='ws_report',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='processed_urls', to='reports.WebsiteReport'),
        ),
        migrations.AddField(
            model_name='filteredurl',
            name='ws_report',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='filtered_urls', to='reports.WebsiteReport'),
        ),
    ]