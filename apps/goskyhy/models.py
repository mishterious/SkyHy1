# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import re, datetime, time
from django.db import models

ALL_LETTERS_REGEX = re.compile(r'[A-Za-z]+')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


class UserManager(models.Manager):
    def basic_validator(self, postData):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        errors = {}
        email = postData['email'].lower()
        if len(postData['username']) < 3:
            errors['username'] = "Your first name should be at least 3 letters long and should only be letters"
        if len(email) < 1:
            errors['email'] = "Please enter an e-mail address"
        if not EMAIL_REGEX.match(email):
            errors['email2'] = "Please enter a Valid e-mail address"
        if re.search('[0-9]', postData['password']) is None:
            errors['numpass'] = "You need to enter at least one number to make your password Valid"
        if re.search('[A-Z]', postData['password']) is None:
            errors['capspass'] = "You will need to enter at least one capital letter"
        if len(postData['password']) < 8:
            errors['lenpass'] = "Your password needs to be at least 8 character to be Valid"
        elif postData['password'] != postData['password_confirm']:
            errors['mispass'] = "Your passwords do not match"
        user = Users.objects.filter(email=email)
        if len(user) > 0:
            errors['user'] = "User already exists in the database"

        return errors


class Users(models.Model):
    # particularly for guest users
    first_name = models.CharField(max_length=100, default="")
    last_name = models.CharField(max_length=100, default="")
    username = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    # verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()


class Messages(models.Model):
    message = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    message = models.ManyToManyField(Users, related_name="user_messages")


class Cities(models.Model):
    city = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    country = models.CharField(max_length=255)
    zipcode = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Tags(models.Model):
    tag = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Hashtags(models.Model):
    hashtag = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    

class Images(models.Model):
    title = models.CharField(max_length=255)
    alt_text = models.CharField(max_length=255)
    credit = models.CharField(max_length=100)
    path = models.CharField(max_length=255) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Users, related_name='image_user')
    # userpro = models.ManyToManyField(UserProfiles, related_name="images_userpro")


class FriendValidation(models.Model):
    #for validating friends and accepting requests
    status = models.BooleanField(default=False) #whether the request has been viewed or not: true = yes, false = no
    confirmation = models.BooleanField(default=False) #choice made: if false doesn't show up in friends + requests; if true shows up; used for deleting later too
    sender = models.ForeignKey(Users, related_name="user_sending")
    receiver = models.ForeignKey(Users, related_name="user_receiving")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


# class FriendValidationReceiver(models.Model):
#     #reciprocal to make accessing it easier in display
#     validation = models.ForeignKey(FriendValidation, related_name="receiver_validation")
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)


class UserProfiles(models.Model):
    background = models.TextField(default="")
    current_job = models.CharField(max_length=255, default="")
    trips = models.CharField(max_length=255, default="")
    music = models.CharField(max_length=255, default="")
    uniqueness = models.CharField(max_length=255, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    profile_pic = models.ForeignKey(Images, related_name="prof_images", default=0)
    user = models.ForeignKey(Users, related_name='prof_user')
    curr_city = models.ForeignKey(Cities, related_name='prof_curr_city', default=0)
    og_city = models.ForeignKey(Cities, related_name='prof_og_city', default=0)
    friends = models.ManyToManyField(Users, related_name="userprof_users", blank=True)
    all_friends = models.TextField(default="") #for all even non-account ones
    # to_validate = models.ForeignKey(FriendValidation, related_name="userprof_validation", default="")

    def __repr__(self):
        return "<Blog object: {} {} {} {} {} {} {}>".format(self.profile_pic, self.background, self.current_job, self.trips, self.music, self.uniqueness, self.user)


class Stories(models.Model):
    title = models.CharField(max_length=255)
    story = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Users, related_name="story_user")
    city = models.ForeignKey(Cities, related_name="story_city")
    tags = models.ManyToManyField(Tags, related_name="stories_tags")
    hashtags = models.ManyToManyField(Hashtags, related_name="stories_hashtags")
    images = models.ManyToManyField(Images, related_name="stories_images")
    

    def __repr__(self):
        return "<Blog object: title: {}, story: {}, user: {}, city: {}, tags: {}>".format(self.title, self.story, self.user, self.city, self.tags)    


class Language(models.Model):
    english = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Categories(models.Model):
    category = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Prices(models.Model):
    price = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Agrees(models.Model):
    local_laws = models.BooleanField(default=True)
    terms_conditions = models.BooleanField(default=True)
    confirm_person = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Times(models.Model):
    timein = models.IntegerField(default=0)
    timeout = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Locations(models.Model):
    address = models.CharField(max_length=255)
    apt_bldg = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    city = models.ForeignKey(Cities, related_name="city_location")


class ExpDates(models.Model):
    year = models.CharField(max_length=4)
    month = models.CharField(max_length=2)
    day = models.CharField(max_length=2)
    together = models.CharField(max_length=10, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class ExpDaysOfWeek(models.Model):
    # day = models.CharField(max_length=10)
    day = models.IntegerField()
    start_date = models.ManyToManyField(ExpDates, related_name="start_date")
    end_date = models.ManyToManyField(ExpDates, related_name="end_date")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Experiences(models.Model):
    title = models.CharField(max_length=255)
    host = models.CharField(max_length=255)
    description = models.CharField(max_length=255)
    distance = models.CharField(max_length=255)
    provided = models.CharField(max_length=255)
    details = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Users, related_name="exp_user")
    price = models.ForeignKey(Prices, related_name="exp_price")
    agree = models.ForeignKey(Agrees, related_name="exp_agree")
    english = models.ForeignKey(Language, related_name="exp_english")
    city = models.ForeignKey(Cities, related_name='exp_city')
    category = models.ForeignKey(Categories, related_name="exp_categories")
    location = models.ForeignKey(Locations, related_name="exp_location")
    times = models.ManyToManyField(Times, related_name='exps_times')
    tag = models.ManyToManyField(Hashtags, related_name="exp_tags")
    images = models.ManyToManyField(Images, related_name="exp_images")
    #for dates in exp creation
    dates = models.ManyToManyField(ExpDates, related_name="exp_dates")
    days_of_week_not_allowed = models.ManyToManyField(ExpDaysOfWeek, related_name="exp_days_of_week_not_allowed")
    days_of_week_allowed = models.ManyToManyField(ExpDaysOfWeek, related_name="days_of_week_allowed")


class AcceptedExperience(models.Model):
    #added for experience validation
    accepted = models.BooleanField(default=False)
    admin_accepted = models.ForeignKey(Users, related_name="accepted_exp_user")
    notes = models.TextField(default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class ExperiencesUnvalidated(models.Model):
    #before experience gets validated by admin
    title = models.CharField(max_length=255)
    host = models.CharField(max_length=255)
    description = models.CharField(max_length=255)
    distance = models.CharField(max_length=255)
    provided = models.CharField(max_length=255)
    details = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Users, related_name="un_exp_user")
    price = models.ForeignKey(Prices, related_name="un_exp_price")
    agree = models.ForeignKey(Agrees, related_name="un_exp_agree")
    english = models.ForeignKey(Language, related_name="un_exp_english")
    city = models.ForeignKey(Cities, related_name='un_exp_city')
    category = models.ForeignKey(Categories, related_name="un_exp_categories")
    location = models.ForeignKey(Locations, related_name="un_exp_location")
    times = models.ManyToManyField(Times, related_name='un_exps_times')
    tag = models.ManyToManyField(Hashtags, related_name="un_exp_tags")
    images = models.ManyToManyField(Images, related_name="un_exp_images")
    #difference
    accepted = models.ForeignKey(AcceptedExperience, related_name="exp_status")


class Reviews(models.Model):
    review = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Users, related_name='review_user')
    # exp = models.ManyToManyField(Experiences, related_name='review_exp') #FK to exp
    exp = models.ForeignKey(Experiences, related_name="review_exp", default=0)


class Likes(models.Model):
    like = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    exp = models.ForeignKey(Experiences, related_name="like_exp")
    review = models.ForeignKey(Reviews, related_name="like_review")
    story = models.ForeignKey(Stories, related_name="like_story")

    
class Orders(models.Model):
    total_cost = models.FloatField(default=0.0)
    total_items = models.IntegerField(default=0)
    order = models.CharField(max_length=255)
    summary = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Users, related_name="my_order")
    exps = models.ManyToManyField(Experiences, related_name="order_exps")


class Wish(models.Model):
    item = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(Users, related_name='mine')
    users = models.ManyToManyField(Users, related_name="wishes_likes")
    # objects = WishManager() #TODO actually create wish manager    

    def __repr__(self):
        return "<Blog object: {} {} {}>".format(self.item, self.user, self.users)
