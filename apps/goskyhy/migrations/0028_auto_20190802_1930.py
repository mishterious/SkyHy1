# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-08-03 02:30
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('goskyhy', '0027_auto_20190730_1342'),
    ]

    operations = [
        migrations.CreateModel(
            name='ExpDates',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('year', models.IntegerField()),
                ('month', models.IntegerField()),
                ('day', models.IntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name='experiences',
            name='dates',
            field=models.ManyToManyField(related_name='exp_dates', to='goskyhy.ExpDates'),
        ),
    ]
