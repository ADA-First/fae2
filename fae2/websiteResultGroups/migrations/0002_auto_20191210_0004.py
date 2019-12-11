# Generated by Django 2.2.7 on 2019-12-10 06:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('websiteResultGroups', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='websiteguidelineresultgroup',
            name='implementation_pass_fail_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Pass/Fail Status'),
        ),
        migrations.AlterField(
            model_name='websiteguidelineresultgroup',
            name='implementation_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Status'),
        ),
        migrations.AlterField(
            model_name='websiteguidelineresultgroup',
            name='manual_check_status',
            field=models.CharField(choices=[('NC', 'Not Checked'), ('NA', 'Not Applicable'), ('P', 'Passed'), ('F', 'Fail')], default='NC', max_length=2, verbose_name='Manual Check Status'),
        ),
        migrations.AlterField(
            model_name='websiteguidelineresultgroup',
            name='slug',
            field=models.SlugField(default='none', editable=False, max_length=16),
        ),
        migrations.AlterField(
            model_name='websitereportgroup',
            name='implementation_pass_fail_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Pass/Fail Status'),
        ),
        migrations.AlterField(
            model_name='websitereportgroup',
            name='implementation_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Status'),
        ),
        migrations.AlterField(
            model_name='websitereportgroup',
            name='manual_check_status',
            field=models.CharField(choices=[('NC', 'Not Checked'), ('NA', 'Not Applicable'), ('P', 'Passed'), ('F', 'Fail')], default='NC', max_length=2, verbose_name='Manual Check Status'),
        ),
        migrations.AlterField(
            model_name='websitereportgroup',
            name='title',
            field=models.CharField(default='No title', max_length=1024, verbose_name='Title'),
        ),
        migrations.AlterField(
            model_name='websiterulecategoryresultgroup',
            name='implementation_pass_fail_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Pass/Fail Status'),
        ),
        migrations.AlterField(
            model_name='websiterulecategoryresultgroup',
            name='implementation_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Status'),
        ),
        migrations.AlterField(
            model_name='websiterulecategoryresultgroup',
            name='manual_check_status',
            field=models.CharField(choices=[('NC', 'Not Checked'), ('NA', 'Not Applicable'), ('P', 'Passed'), ('F', 'Fail')], default='NC', max_length=2, verbose_name='Manual Check Status'),
        ),
        migrations.AlterField(
            model_name='websiterulecategoryresultgroup',
            name='slug',
            field=models.SlugField(default='none', editable=False, max_length=16),
        ),
        migrations.AlterField(
            model_name='websiteruleresultgroup',
            name='implementation_pass_fail_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Pass/Fail Status'),
        ),
        migrations.AlterField(
            model_name='websiteruleresultgroup',
            name='implementation_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Status'),
        ),
        migrations.AlterField(
            model_name='websiteruleresultgroup',
            name='manual_check_status',
            field=models.CharField(choices=[('NC', 'Not Checked'), ('NA', 'Not Applicable'), ('P', 'Passed'), ('F', 'Fail')], default='NC', max_length=2, verbose_name='Manual Check Status'),
        ),
        migrations.AlterField(
            model_name='websiteruleresultgroup',
            name='slug',
            field=models.SlugField(default='none', editable=False, max_length=16),
        ),
        migrations.AlterField(
            model_name='websiterulescoperesultgroup',
            name='implementation_pass_fail_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Pass/Fail Status'),
        ),
        migrations.AlterField(
            model_name='websiterulescoperesultgroup',
            name='implementation_status',
            field=models.CharField(choices=[('U', 'Undefined'), ('NA', 'Not applicable'), ('NI', 'Not Implemented'), ('PI', 'Partial Implementation'), ('AC', 'Almost Complete'), ('NI-MC', 'Not Implemented with manual checks required'), ('PI-MC', 'Partial Implementation with manual checks required'), ('AC-MC', 'Almost Complete with manual checks required'), ('C', 'Complete')], default='U', max_length=8, verbose_name='Implementation Status'),
        ),
        migrations.AlterField(
            model_name='websiterulescoperesultgroup',
            name='manual_check_status',
            field=models.CharField(choices=[('NC', 'Not Checked'), ('NA', 'Not Applicable'), ('P', 'Passed'), ('F', 'Fail')], default='NC', max_length=2, verbose_name='Manual Check Status'),
        ),
        migrations.AlterField(
            model_name='websiterulescoperesultgroup',
            name='slug',
            field=models.SlugField(default='none', editable=False, max_length=16),
        ),
    ]
