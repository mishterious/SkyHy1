# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-08-03 08:11
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('goskyhy', '0028_auto_20190802_1930'),
    ]

    operations = [
        migrations.CreateModel(
            name='ExpDaysOfWeek',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('day', models.IntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name='expdates',
            name='together',
            field=models.CharField(default='', max_length=10),
        ),
        migrations.AlterField(
            model_name='expdates',
            name='day',
            field=models.CharField(max_length=2),
        ),
        migrations.AlterField(
            model_name='expdates',
            name='month',
            field=models.CharField(max_length=2),
        ),
        migrations.AlterField(
            model_name='expdates',
            name='year',
            field=models.CharField(max_length=4),
        ),
        migrations.AddField(
            model_name='expdaysofweek',
            name='end_date',
            field=models.ManyToManyField(related_name='end_date', to='goskyhy.ExpDates'),
        ),
        migrations.AddField(
            model_name='expdaysofweek',
            name='start_date',
            field=models.ManyToManyField(related_name='start_date', to='goskyhy.ExpDates'),
        ),
        migrations.AddField(
            model_name='experiences',
            name='days_of_week_allowed',
            field=models.ManyToManyField(related_name='days_of_week_allowed', to='goskyhy.ExpDaysOfWeek'),
        ),
        migrations.AddField(
            model_name='experiences',
            name='days_of_week_not_allowed',
            field=models.ManyToManyField(related_name='exp_days_of_week_not_allowed', to='goskyhy.ExpDaysOfWeek'),
        ),
    ]
