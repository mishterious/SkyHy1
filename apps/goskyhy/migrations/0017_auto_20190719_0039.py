# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-07-19 07:39
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('goskyhy', '0016_userprofiles_friends'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='reviews',
            name='exp',
        ),
        migrations.AddField(
            model_name='reviews',
            name='exp',
            field=models.ForeignKey(default=0, on_delete=django.db.models.deletion.CASCADE, related_name='review_exp', to='goskyhy.Experiences'),
        ),
    ]
