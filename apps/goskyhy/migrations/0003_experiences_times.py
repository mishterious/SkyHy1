# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-06-13 01:14
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('goskyhy', '0002_auto_20190612_1633'),
    ]

    operations = [
        migrations.AddField(
            model_name='experiences',
            name='times',
            field=models.ManyToManyField(related_name='exps_times', to='goskyhy.Times'),
        ),
    ]
