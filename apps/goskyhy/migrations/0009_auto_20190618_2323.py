# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-06-19 06:23
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('goskyhy', '0008_images_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='stories',
            name='images',
        ),
        migrations.AddField(
            model_name='images',
            name='exp',
            field=models.ManyToManyField(related_name='images_exp', to='goskyhy.Experiences'),
        ),
        migrations.AddField(
            model_name='images',
            name='story',
            field=models.ManyToManyField(related_name='images_story', to='goskyhy.Stories'),
        ),
        migrations.AddField(
            model_name='images',
            name='userpro',
            field=models.ManyToManyField(related_name='images_userpro', to='goskyhy.UserProfiles'),
        ),
    ]
