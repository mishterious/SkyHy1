# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-07-22 22:19
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('goskyhy', '0018_auto_20190722_1345'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofiles',
            name='to_validate',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, related_name='userprof_validation', to='goskyhy.FriendValidation'),
        ),
    ]
