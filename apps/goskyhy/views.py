# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, redirect
from .models import *
from django.contrib import messages
import bcrypt
#Caroline practicing w/ image uploads 16/06/19
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.db.utils import OperationalError
from django.template import RequestContext
#Caroline w/ writing experiences to database
import xlrd
#Caroline w/ geo stuff
import geocoder
import json
import urllib
#Caroline password stuff
import random, string
#Caroline email authentication stuff
from django.http import HttpResponse
from django.contrib.auth import login, authenticate
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.core.mail import EmailMessage

#API KEY FOR MAPS
api_key = 'AIzaSyD2DKhBLCKeU72doQ3jfa9JZK9yFHyeNog' #needs to be restricted; run by Mish/Tom

#temp lat/longs
lat_lng_temp = {
    1: [43.48377, -111.76901],
    2: [34.53599, 85.93186],
    3: [47.99078, 82.28011],
    4: [29.91087, 113.53124],
    5: [-36.70150, -33.51463],
    6: [-71.28024, -99.15614],
    7: [-49.74143, -54.26660],
    8: [-22.00208, 174.87553],
    9: [12.84023, 23.72611],
    10: [-8.78201, 25.84682],
    11: [-44.59384, -106.97618],
    12: [-25.73212, 170.01188],
    13: [-4.17089, -16.07254], 
    14: [58.40957, 69.26677],
    15: [40.39127, 19.39636],
    16: [-21.49216, 1.50359],
    17: [-63.28739, 101.99277],
    18: [-7.97160, 139.62952],
    19: [51.86921, 57.76351], 
    20: [33.48876, 20.98229],
    21: [-42.71466, -22.18732],
    22: [74.20217, -12.41899],
    23: [-42.18694, -35.84113],
    24: [2.09770, 97.47845],
    25: [31.10511, 24.31585],
    26: [-12.01692, -1.36486],
    27: [-21.78324, -94.71938],
    28: [-52.92683, 79.68723],
    29: [37.95345, 15.30168],
    30: [-30.58361, 114.93607]
}


def index(request, id="0"):
    # Need to collect all reviews per experience and come up with overall approximate reviews qualifications
    # Play values so 4+ starts = 60%, 3 stars = 30%, 2 stars = 20%, 1 stars = 10% &&& play values differently if high in low reviews. 
    # Reasoning: Most people who have a good expereince dont bother leaving good review 60% of the time
    # People usually leave bad reviews when having a bad personal experience. 

    # if request.session['redirect']:
    #     print "entered"
    #     request.session['redirect'] = False
    #     return redirect('/')
    
    if 'login_alert' in request.session and 'alert_shown' in request.session and request.session['alert_shown']: 
        # print request.session['alert_shown']
        del request.session['login_alert']

    #test whether can add comments or not
    bought_check = []
    purchased_if_logged_in_ids = []
    if 'login' in request.session and request.session['login']:
        orders = Orders.objects.filter(user_id=request.session['id'])
        for order in orders:
            order_exps = Orders.exps.through.objects.filter(orders_id=order.id)
            for order_exp in order_exps:
                if order_exp.experiences_id not in purchased_if_logged_in_ids:
                    purchased_if_logged_in_ids.append(order_exp.experiences_id)

    #Caroline 30/09/19: checking cart
    request.session['seeing_cart'] = False

    img_exp_list = []
    img_list = []
    experiences = []
    # start = i * 20 #show 20 right now at a time
    # id = 0
    id = int(id)
    # print "id: " + str(id)
    end = (id + 1) * 20 #add more 
    show_more = False #should display button if true
    try:
        img_exp_list = list(Experiences.images.through.objects.all().order_by('?'))


        for img_exp in img_exp_list:
            # print img_exp.images_id
            img = Images.objects.get(id=img_exp.images_id) #going to sort though all images and store the one that we want from specific exp
            #probably need to unquote image path?? Caroline 01/08/19
            img.path = urllib.unquote(img.path)
            # print img.path
            img.save()
            img_list.append(img)
            experiences.append(Experiences.objects.get(id=img_exp.experiences_id))
            # print img.id
            if 'login' not in request.session or not request.session['login']:
                bought_check.append(False)
            elif img_exp.experiences_id in purchased_if_logged_in_ids:
                bought_check.append(True)
            else:
                bought_check.append(False)

        # experiences = list(Experiences.objects.all())   
        #change into not w/ .0 - TEMPORARY
        # for exp in experiences:
        #     exp.price.price = exp.price.price[: -2]
        #     exp.save()
    
    except OperationalError:
        print 'db does not exist yet'
        pass # db doesn't exist yet

    # indices = range(len(experiences))
    if end > len(img_exp_list):
        print "last page"
        end = len(img_exp_list)
        show_more = False
    else:
        # if 'see_more' in request.POST.keys(): # and request.POST['see_more']:
        id += 1
        show_more = True
    indices = range(end)

    login_alerts = []

    # print request.session['login_alert']

    if 'login_alert' in request.session and request.session['login_alert']:
        #temp just for creating experiences
        login_alerts.append("Please log in")# before creating an experience.")
        # for alert in request.session['alert_list']:
        #     login_alerts.append(alert)
        request.session['alert_shown'] = True

    data = {
        'experiences': experiences,
        'img_exp_list': img_exp_list, 
        'img_list': img_list,
        'indices': indices,
        'login_alerts': login_alerts,
        #Caroline added 12/07/19
        'id': str(id),
        'show_more': show_more,
        #Caroline added 19/07/19
        'bought_check': bought_check
    }

    #check what display-bar shows: settings vs login/my_profile
    if 'login' not in request.session:
        data['not_logged_in'] = True
    else:
        data['not_logged_in'] = False

    #after stuff happens, delete everything in session to do with buying
    # print request.session['checkout']
    # request.session['checkout'] = False #temp
    # print 'order_id' in request.session
    if 'order_id' in request.session and 'checkout' in request.session and request.session['checkout']:
        if 'guest_logged_in' in request.session and request.session['guest_logged_in']:
            #delete stuff related to temporary sign-in
            del request.session['first_name']
            del request.session['last_name']
            del request.session['email']
            del request.session['id']
            del request.session['guest_logged_in']
            #Caroline 31/07/19: have to delete other things about orders b/c not in newsfeed
            del request.session['num_per_exp']
            del request.session['order_list']
            del request.session['exp_list']
            del request.session['img_list']
        #commented out stuff is already deleted when loading newsfeed post purchase
        # del request.session['num_per_exp']
        # del request.session['order_list']
        # del request.session['exp_list']
        # del request.session['img_list']
        del request.session['total_cost']
        del request.session['total_items']
        del request.session['order_id']

        request.session['checkout'] = False

    #Caroline 31/07/19: for cart purposes; will not show cart if not logged in
    if 'exp_most_recent' in request.session:
        data['exp_most_recent'] = request.session['exp_most_recent']
        data['num_ordered'] = 1
        if 'num_ordered' in request.session:
            data['num_ordered'] = request.session['num_ordered']
    else:
        data['exp_most_recent'] = id
        data['num_ordered'] = 0

    #Caroline 31/07/19: for cart; if guest logged in then they can see the cart (maybe change to see cart if something is in there??) w/o ordering
    if 'guest_logged_in' in request.session and request.session['guest_logged_in']:
        request.session['seeing_cart'] = True
        data['seeing_cart'] = True
    else:
        request.session['seeing_cart'] = False
        data['seeing_cart'] = False

    return render(request, 'goskyhy/index.html', data)


def pitchdeck(request):
    return render(request, 'goskyhy/pitchdeck.html')


def signin(request):
    return render(request, 'goskyhy/a_login.html')


def add_user(request):
    errors = None
    if request.method == 'POST':
        errors = Users.objects.basic_validator(request.POST)
    if errors != None and len(errors) != 0:
        print "finding errors"
        print len(errors)
        for tag, error in errors.iteritems():
            print error
            messages.error(request, error, extra_tags=tag)
        return redirect('/signin')
    else:
        print "continued to set up rest of account"
        myrequest = request.POST
        hash1 = bcrypt.hashpw(myrequest['password'].encode('utf8'), bcrypt.gensalt())
        user = Users.objects.create(first_name=myrequest['first_name'], last_name=myrequest['last_name'], username=myrequest['username'], email=myrequest['email'], password=hash1)
        user.save()
        request.session['id'] = user.id
        request.session['username'] = user.username
        request.session['email'] = user.email
        request.session['login'] = True

        if 'order_id' in request.session:
            request.session['not_logged_in'] = False
            temp_city = None
            temp_prof_pic = None
            temp_prof_pic = Images.objects.create(user=user, path="/media/profile_icon_generic.png", title="")
            temp_prof_pic.save()

            if Cities.objects.filter(city="").exists():
                temp_city = Cities.objects.get(city="") # should only be one
            else:
                temp_city = Cities.objects.create(city="", state="", country="", zipcode="")
                temp_city.save()
            UserProfiles.objects.create(user=user, profile_pic=temp_prof_pic, curr_city=temp_city, og_city=temp_city).save()

            return redirect('/add_order/' + request.session['add_item_id'] + '/' + request.session['add_item_quantity'])
        return render(request, 'goskyhy/registration_1.html')


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = Users.objects.get(id=uid)
        print "user: " + str(user.id)
        print "uid: " + str(uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        print "found error or user DNE"
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        # user.verified = True
        user.save()
        print "verified"
        request.session['user_verified_id'] = user.id #delete after saving
    #either way we'll end up in add_user, just as two different results
    return redirect('/add_user')


def continue_as_guest(request):
    return render(request, 'goskyhy/continue_as_guest.html')


def generate_guest_password(length=10):
    password_chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(password_chars) for i in range(length))


def add_guest(request):
    guest_request = request.POST
    guest_password = generate_guest_password()
    guest_username = generate_guest_password()
    hashed = bcrypt.hashpw(guest_password.encode('utf8'), bcrypt.gensalt())
    user = Users.objects.create(first_name=guest_request['first_name'], last_name=guest_request['last_name'], username=guest_username, email=guest_request['email'], password=hashed)
    user.save()
    #should get the most recently created one; should not associate w/ any other guest users even if it's the same info/person
    user = Users.objects.filter(email=guest_request['email'], first_name=guest_request['first_name'], last_name=guest_request['last_name']).order_by("-created_at").first()
    request.session['id'] = user.id
    request.session['first_name'] = user.first_name
    request.session['last_name'] = user.last_name
    request.session['email'] = user.email
    request.session['guest_logged_in'] = True
    return redirect('/add_order_guest/' + request.session['add_item_id'] + '/' + request.session['add_item_quantity'])


def login(request):
    if request.method == 'POST':
        myrequest = request.POST
        user = Users.objects.filter(email=myrequest['email']) | Users.objects.filter(username=myrequest['email'])
        # print user
        if len(user) == 0:
            errors = {}
            errors['user_not_registered'] = "Your username and email was not found, please try again!"
            for tag, error in errors.iteritems():
                messages.error(request, error, extra_tags=tag)
            return redirect('/signin')
        else:
            hash2 = user[0].password
            if bcrypt.checkpw(myrequest['password'].encode('utf8'), hash2.encode('utf8')):
                request.session['id'] = user[0].id
                request.session['username'] = user[0].username
                request.session['email'] = user[0].email
                request.session['login'] = True
                request.session['login_alert'] = False
                request.session['logged_in'] = True
                request.session['not_logged_in'] = False
                if 'order_id' in request.session:
                    request.session['not_logged_in'] = False

                    # request.session'exp_id' = request.session['exp_logging_in_id']
                    # exp_list = request.session['exp_list']
                    # img_list = request.session['img_list']
                    # range: range(len(exp_list))
                    # request.session['session_id'] = request.session['id']
                    # total_items = 0
                    # total_cost = 0
                    # order_id = 0

                    return redirect('add_order/' + request.session['add_item_id'] + '/' + request.session['add_item_quantity'])
                return redirect('/profile')
            else:
                errors = {}
                errors['no_password_found'] = "Password hasn't match with any that we have here. Please try again!"
                for tag, error in errors.iteritems():
                    messages.error(request, error, extra_tags=tag)
                return redirect('/signin')


def registration_2(request):
    data = {
        'user': Users.objects.get(id=request.session['id'])
    }
    print request.POST['city'], request.POST['state'], request.POST['country']
    print request.POST['music']
    print request.POST['background']
    print "hello we are in the registration_2"
    print "222222222222222222222222222222222222222"
    if request.method == 'POST':
        prof_pic_name, prof_pic_url = upload_helper(request)
        request.session['pic_name'] = prof_pic_name
        request.session['pic_url'] = prof_pic_url 
        request.session['current_job'] = request.POST['work']
        request.session['curr_city'] = request.POST['city'].lower()
        request.session['curr_state'] = request.POST['state'].upper()
        request.session['country'] = request.POST['country'].lower()
        request.session['ZIP'] = request.POST['zipcode']
        request.session['background'] = request.POST['background']
        request.session['music'] = request.POST['music']
    return render(request, 'goskyhy/registration_3.html', data)


def save_reg(request):
    u = Users.objects.get(id=request.session['id'])

    if request.method == 'POST':
        og_city = request.POST['og_city'].lower()
        og_state = request.POST['og_state'].upper()
        og_country = request.POST['og_country'].lower()
        og_ZIP = request.POST['og_zipcode']

        request.session['triplist'] = request.POST['triplist']
        request.session['seeing_cart'] = False
        print request.POST['og_city'], request.POST['og_state'], request.POST['og_city'], request.POST['og_country'], request.POST['og_zipcode'], request.POST['triplist']
        # if request.session['first_time']: 
        if 'pic_url' in request.session and request.session['pic_url']:
            i = Images.objects.create(title=request.session['pic_name'], path=request.session['pic_url'], user=u)
            i.save()
            print i
        else:
            i = Images.objects.create(title="temporary profile picture", path="/media/profile_icon_generic.png", user=u)

        #checking database for any similar cities to avoid repetition
        if Cities.objects.filter(city=request.session['curr_city']).exists():
            for potential_city in Cities.objects.filter(city=request.session['curr_city']):
                print potential_city.city
                if request.session['curr_state'] != potential_city.state and request.session['curr_state'] != '':
                    continue
                if request.session['country'] != potential_city.country:
                    continue
                if request.session['ZIP'] != potential_city.zipcode and request.session['ZIP'] != '':
                    continue
                curr_city = potential_city
        else:
            curr_city = Cities.objects.create(city=request.session['curr_city'], state=request.session['curr_state'], country=request.session['country'], zipcode=request.session['ZIP'])
            curr_city.save()

        if Cities.objects.filter(city=og_city).exists():
            for potential_city in Cities.objects.filter(city=og_city):
                if og_state != potential_city.state and og_state != '':
                    continue
                if og_country != potential_city.country:
                    continue
                if og_ZIP != potential_city.zipcode and og_ZIP != '':
                    continue
                og_city = potential_city
        else:
            og_city = Cities.objects.create(city=request.session['og_city'], state=request.session['og_state'], country=request.session['og_country'], zipcode=request.session['og_ZIP'])
            og_city.save()
        # friend = request.session['friend']

        print og_city
        print "77777777777777777777777777777"

        u_prof = UserProfiles.objects.create(profile_pic=i, background=request.session['background'], current_job=request.session['current_job'], trips=request.session['triplist'], music=request.session['music'], user=u, curr_city=curr_city, og_city=og_city) 
        print u_prof
        print "done"
        u_prof.save()

        return redirect('/profile')


def profile(request):
    if 'login' not in request.session:
        return redirect('/')
    if request.session['login'] == False:
        return redirect('/')
    if 'buying' not in request.session:  
        request.session['buying'] = False
    
    u = Users.objects.get(id=request.session['id'])
    u_prof = UserProfiles.objects.filter(user=u).first() #should never return > 1; only happens right now b/c of glitches
    data = {}
    data['userprofile'] = u_prof

    print u, u_prof
    print "345678654323456aaaaaaaaaaaaaaaaaaaaa7543234565432"

    mystories = Stories.objects.filter(user_id=request.session['id'])
    backwards = []
    for story in mystories:
        backwards.insert(0, story)
        print backwards
    data['stories'] = backwards

    list_of_pics = []
    if len(data['stories']) > 0:
        story_num = data['stories'][0].id #0 gets first (latest) story
        data['size'] = story_num
        print "story_num", story_num
    
    next_story_num = 0
    for story in data['stories']:
        next_story_num = story.id
        with_empties = []
        while story_num > next_story_num:
            # checking to make sure posit of img matches story (for deletion)
            story_num -= 1
            with_empties.append("")
        print "with_empties are for what", with_empties
        img_path = ""
        for img in story.images.all():
            img_path = img.path
        if img_path != "":
            with_empties.append(img_path)
            list_of_pics.extend(with_empties)
        else:
            with_empties.append("")
            list_of_pics.extend(with_empties)
        story_num -= 1
    data['pics'] = list_of_pics

    #map at bottom work
    data['loc_to_coord'] = process_trips(data['userprofile'])
    #temp json
    coords = data['loc_to_coord']

    #get map data
    map_url = "https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;q="

    # address = u_prof.location.address
    city = u_prof.curr_city.city
    country = u_prof.curr_city.country
    zipcode = u_prof.curr_city.zipcode

    all_info = [city, country, zipcode]

    for i in range(len(all_info)):
        coded = urllib.quote(all_info[i].encode("utf-8"))
        if i == len(all_info) - 1:
            coded = zipcode.encode("utf-8")
            # print coded
        request.session['map_' + str(i + 1)] = coded
        map_url += str(coded)
        if i != len(all_info) - 1:
            sep = urllib.quote(u", ", "utf-8")
            map_url += sep

    map_url += "+()&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed"

    # print map_url


    data['map_url'] = map_url
    data['map_one'] = request.session['map_1']
    data['map_two'] = request.session['map_2']
    data['map_three'] = request.session['map_3']

    for i in range(3):
        del request.session['map_' + str(i + 1)]

    #friends work
    friends_char = u_prof.all_friends[3 :]
    if friends_char == []:
        friends_char = request.session['friend']
    # print friends_char
    start = 0
    end = 0
    all_friends = []
    prof_exists = []
    friend_sans_email = [] #fix w/ nickname (can be set later)
    friend_ids = []
    friend_profiles = [] # in filtering middle
    for c in friends_char:
        if c == ']':
            end = start + friends_char[start: ].index(']') - 1
            friend_email = friends_char[start : end]

            #check if user already exists (cannot add again)
            if friend_email in all_friends:
                start = end + 5 #, + space + u + '
                continue

            all_friends.append(friend_email)

            if Users.objects.filter(email=friend_email).exists():
                prof_exists.append(True)
                friend_ids.append(Users.objects.filter(email=friend_email).first().id)
                user = Users.objects.filter(email=friend_email).first()
                friend_profiles.append(UserProfiles.objects.filter(user=user).first())
                #adding friends to database
                # u_prof.friends.add(UserProfiles.objects.filter(user=user).first())
                u_prof.friends.add(user)    

                # print UserProfiles.objects.filter(user=user).first().profile_pic.path
            else:
                prof_exists.append(False)
                friend_ids.append("")
                friend_profiles.append("")
        elif c in ',':
            end = start + friends_char[start: ].index(',') - 1
            friend_email = friends_char[start : end]

            #check if friend exists
            if friend_email in all_friends:
                start = end + 5 #, + space + u + '
                continue

            all_friends.append(friend_email)

            # at_index = friend_email.index('@')
            # friend_sans_email.append(friend_email[ : at_index])

            if Users.objects.filter(email=friend_email).exists():
                prof_exists.append(True)
                friend_ids.append(Users.objects.get(email=friend_email).id)
                user = Users.objects.get(email=friend_email)
                friend_profiles.append(UserProfiles.objects.filter(user=user).first())
                #adding friends to database
                # u_prof.friends.add(UserProfiles.objects.filter(user=user).first())
                u_prof.friends.add(user)    

                # print UserProfiles.objects.filter(user=user).first().profile_pic.path
            else:
                prof_exists.append(False)
                friend_ids.append("")
                friend_profiles.append("")
            # print friends_char[start : end]
            start = end + 5 #, + space + u + '
    # if friends_char != []:
    #     friend_email = friends_char[start : -1]
    #     all_friends.append(friend_email)

    #     # at_index = friend_email.index('@')
    #     # friend_sans_email.append(friend_email[ : at_index])

    #     if Users.objects.filter(email=friend_email).exists():
    #             prof_exists.append(True)
    #             friend_ids.append(Users.objects.get(email=friend_email).id)
    #             user = Users.objects.get(email=friend_email)
    #             friend_profiles.append(UserProfiles.objects.filter(user=user).first())
    #     else:
    #         prof_exists.append(False)
    #         friend_ids.append("")
    #         friend_profiles.append("")

        # print friends_char[start : -1]
    # print " ".join(all_friends)
    # print " ".join(friend_sans_email)
    data['friends'] = all_friends
    data['prof_exists'] = prof_exists
    data['friend_range'] = range(len(all_friends))
    data['friend_sans_email'] = friend_sans_email
    #temp w# id
    data['friend_ids'] = friend_ids
    data['friend_profiles'] = friend_profiles

    #validating friends
    pending_sent = [] #uprofs to invitations sent out
    pending_received = [] #ditto but received
    sent_validation = [] #validation status to invites sent
    received_validation = [] #ditto for received

    pending_friend_sender = UserProfiles.objects.filter(user_id=request.session['id']).first()

    if FriendValidation.objects.filter(sender=pending_friend_sender.user).exists():
        sent_validation = FriendValidation.objects.filter(sender=pending_friend_sender.user)
        for sent in sent_validation:
            pending_sent.append(sent.receiver)
    if FriendValidation.objects.filter(receiver=pending_friend_sender.user).exists():
        received_validation = FriendValidation.objects.filter(receiver=pending_friend_sender.user)
        for received in received_validation:
            pending_received.append(received.sender)

    data['sent_validating'] = pending_sent
    data['received_validating'] = pending_received
    # for p in pending_received:
    #     print p.username
    data['sent_validator'] = sent_validation
    data['received_validator'] = received_validation
    # for p in received_validation:
    #     print p.status
    data['sent_range'] = range(len(pending_sent))
    data['received_range'] = range(len(pending_received))

    #past purchased experiences display
    past_exps_id = []
    past_exps = []
    past_exps_imgs = []

    orders = Orders.objects.filter(user_id=u.id)
    for order in orders:
        order_exps = Orders.exps.through.objects.filter(orders_id=order.id)
        for order_exp in order_exps:
            if order_exp.experiences_id not in past_exps_id:
                past_exps_id.append(order_exp.experiences_id)
                past_exps.append(Experiences.objects.get(id=order_exp.experiences_id))

                exp_img = Experiences.images.through.objects.get(experiences_id=order_exp.experiences_id)
                past_exps_imgs.append(Images.objects.get(id=exp_img.images_id))

    data['past_exps_id'] = past_exps_id
    data['past_exps'] = past_exps
    data['past_exps_imgs'] = past_exps_imgs
    data['exp_range'] = range(len(past_exps))

    data['pic_url'] = data['userprofile'].profile_pic.path

    #Caroline 17/08/19: for cart purposes; will not show cart if not logged in
    if 'exp_most_recent' in request.session:
        data['exp_most_recent'] = request.session['exp_most_recent']
        data['num_ordered'] = 1
        if 'num_ordered' in request.session:
            data['num_ordered'] = request.session['num_ordered']
    else:
        data['exp_most_recent'] = 0
        data['num_ordered'] = 0

    #Caroline 17/08/19: for cart; if guest logged in then they can see the cart (maybe change to see cart if something is in there??) w/o ordering
    if 'guest_logged_in' in request.session and request.session['guest_logged_in']:
        request.session['seeing_cart'] = True
        data['seeing_cart'] = True
    else:
        request.session['seeing_cart'] = False
        data['seeing_cart'] = False

    return render(request, 'goskyhy/myprofile.html', data)

#maybe put repeat stuff into helpers?? (reorganise)
def friend_profile(request, id):
    #email should be username OR firstname + lastname (need to change models)
    u = Users.objects.get(id=id)
    data = {
        'user': u
    }
    
    u_prof = UserProfiles.objects.filter(user=u).first() #in case weird errors happen when there are registration glitches; shouldn't happen in live might remove later
    data['userprofile'] = u_prof

    #from profile
    request.session['buying'] = False

    #backwards
    mypics = Stories.objects.filter(user=u)
    backwards = []
    for mypic in mypics:
        backwards.insert(0, mypic)

    data['mypics'] = backwards

    list_of_pics = []
    if len(data['mypics']) > 0:
        story_num = data['mypics'][0].id #0 gets first (latest) story
        data['size'] = story_num
    next_story_num = 0
    for story in data['mypics']:
        next_story_num = story.id
        with_empties = []
        while story_num > next_story_num:
            # checking to make sure posit of img matches story (for deletion)
            story_num -= 1
            with_empties.append("")

        img_path = ""
        for img in story.images.all():
            # only 1 img
            img_path = img.path
        if img_path != "":
            with_empties.append(img_path)
            list_of_pics.extend(with_empties)
        else:
            with_empties.append("")
            list_of_pics.extend(with_empties)
        story_num -= 1

    data['pics'] = list_of_pics

    #map at bottom work
    data['loc_to_coord'] = process_trips(data['userprofile'])
    #temp json
    coords = data['loc_to_coord']
    #get map data
    map_url = "https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;q="

    # address = u_prof.location.address
    city = u_prof.curr_city.city
    country = u_prof.curr_city.country
    zipcode = u_prof.curr_city.zipcode

    all_info = [city, country, zipcode]

    for i in range(len(all_info)):
        coded = urllib.quote(all_info[i].encode("utf-8"))
        if i == len(all_info) - 1:
            coded = zipcode.encode("utf-8")
            # print coded
        request.session['map_' + str(i + 1)] = coded
        map_url += str(coded)
        if i != len(all_info) - 1:
            sep = urllib.quote(u", ", "utf-8")
            map_url += sep

    map_url += "+()&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed"


    data['map_url'] = map_url
    data['map_one'] = request.session['map_1']
    data['map_two'] = request.session['map_2']
    data['map_three'] = request.session['map_3']

    for i in range(3):
        del request.session['map_' + str(i + 1)]

    #friends work
    friends_char = u_prof.all_friends[3 :]
    if friends_char == []:
        friends_char = request.session['friend']
    print friends_char
    start = 0
    end = 0
    all_friends = []
    prof_exists = []
    friend_sans_email = [] #fix w/ nickname (can be set later)
    friend_ids = []
    friend_profiles = [] # in filtering middle
    for c in friends_char:
        if c == ']':
            end = start + friends_char[start: ].index(']') - 1
            friend_email = friends_char[start : end]

            #check if user already exists (cannot add again)
            if friend_email in all_friends:
                start = end + 5 #, + space + u + '
                continue

            all_friends.append(friend_email)

            if Users.objects.filter(email=friend_email).exists():
                prof_exists.append(True)
                friend_ids.append(Users.objects.get(email=friend_email).id)
                user = Users.objects.get(email=friend_email)
                friend_profiles.append(UserProfiles.objects.filter(user=user).first())
                #adding friends to database
                # u_prof.friends.add(UserProfiles.objects.filter(user=user).first())
                u_prof.friends.add(user)    

                # print UserProfiles.objects.filter(user=user).first().profile_pic.path
            else:
                prof_exists.append(False)
                friend_ids.append("")
                friend_profiles.append("")
        elif c in ',':
            end = start + friends_char[start: ].index(',') - 1
            friend_email = friends_char[start : end]

            #check if friend exists
            if friend_email in all_friends:
                start = end + 5 #, + space + u + '
                continue

            all_friends.append(friend_email)

            # at_index = friend_email.index('@')
            # friend_sans_email.append(friend_email[ : at_index])

            if Users.objects.filter(email=friend_email).exists():
                prof_exists.append(True)
                friend_ids.append(Users.objects.get(email=friend_email).id)
                user = Users.objects.get(email=friend_email)
                friend_profiles.append(UserProfiles.objects.filter(user=user).first())
                #adding friends to database
                # u_prof.friends.add(UserProfiles.objects.filter(user=user).first())
                u_prof.friends.add(user)    

                # print UserProfiles.objects.filter(user=user).first().profile_pic.path
            else:
                prof_exists.append(False)
                friend_ids.append("")
                friend_profiles.append("")
            # print friends_char[start : end]
            start = end + 5 #, + space + u + '
    # if friends_char != []:
    #     friend_email = friends_char[start : -1]
    #     all_friends.append(friend_email)

    #     # at_index = friend_email.index('@')
    #     # friend_sans_email.append(friend_email[ : at_index])

    #     if Users.objects.filter(email=friend_email).exists():
    #             prof_exists.append(True)
    #             friend_ids.append(Users.objects.get(email=friend_email).id)
    #     else:
    #         prof_exists.append(False)
    #         friend_ids.append("")
        # print friends_char[start : -1]
    # print " ".join(all_friends)
    # print " ".join(friend_sans_email)
    data['friends'] = all_friends
    data['prof_exists'] = prof_exists
    data['friend_range'] = range(len(all_friends))
    data['friend_sans_email'] = friend_sans_email
    #temp w# id
    data['friend_ids'] = friend_ids

    return render(request, 'goskyhy/friend_profile.html', data)


def pending_friend_request(request):
    #must lead to add_friend
    if request.method == 'POST':
        pending_friend_sender = UserProfiles.objects.get(user_id=request.session['id'])
        print "sender: " + str(pending_friend_sender.id)
        receiver_email = request.POST['friend']
        #check if in database
        if Users.objects.filter(email=receiver_email).exists():
            #checking if user isn't already a friend
            # print pending_friend_sender.friends.through.objects.filter(users_id=Users.objects.filter(email=receiver_email).first().id).first().id
            if not pending_friend_sender.friends.through.objects.filter(userprofiles_id=Users.objects.filter(email=receiver_email).first().id, users_id=pending_friend_sender.id).exists() and not pending_friend_sender.friends.through.objects.filter(userprofiles_id=pending_friend_sender.id, users_id=Users.objects.filter(email=receiver_email).first().id).exists():
                pending_friend_receiver = UserProfiles.objects.filter(user=Users.objects.filter(email=receiver_email).first()).first()
                #adding to list of not confirmed
                validation_sender = FriendValidation.objects.create(sender=pending_friend_sender.user, receiver=pending_friend_receiver.user, status=False)
                validation_sender.save()
            else:
                #replace later
                print "user already added"
        else:
            #just add name to user list for now?
            #later show an error page in that user doesn't exist yet?
            pending_friend_sender.all_friends = pending_friend_sender.all_friends[1 : -1] + ", u'" + receiver_email + "']"
            pending_friend_sender.save()

    return redirect('/profile')



def add_friend(request, id):
    u_prof = UserProfiles.objects.filter(user_id=request.session['id']).first() #should never return > 1 profile!! happened b/c of glitches
    if request.method == 'POST' and 'accept' in request.POST and request.POST['accept']:
        # new_friend = request.POST['friend'] #check what type it is
        new_friend_user = Users.objects.get(id=id)
        val = FriendValidation.objects.filter(sender=new_friend_user, receiver=u_prof.user, status=False).first()
        val.status = True
        val.confirmation = True
        val.save()
        if u_prof.all_friends == "":
            u_prof.all_friends = "[u'" + new_friend_user.email + "']"
        else:
            u_prof.all_friends = u_prof.all_friends[ : -1] + ", u'" + new_friend_user.email + "']"
        u_prof.friends.add(new_friend_user)
        u_prof.save()

        #other side adding
        new_friend_prof = UserProfiles.objects.get(user=new_friend_user)
        # print new_friend_prof.user.username
        if new_friend_prof.all_friends == "":
            new_friend_prof.all_friends = "[u'" + u_prof.user.email + "']"
        else: 
            new_friend_prof.all_friends = new_friend_prof.all_friends[ : -1] + ", u'" + u_prof.user.email + "']"
        # print u_prof.user.email
        new_friend_prof.save()
        # print new_friend_prof.all_friends
    else:
        #do nothing? We don't want to officially "delete from memory" I think eventually but right now we can try deleting
        rejected_friend = Users.objects.get(id=id)
        val = FriendValidation.objects.filter(sender=rejected_friend, receiver=u_prof.user, status=False).first()
        val.status = True
        val.confirmation = False
        val.save()

    return redirect('/profile')



def process_trips(userprofile):
    #Caroline edits 10/07/19: getting cities onto map
    trips = userprofile.trips #is string need to process
    loc_to_coord = process_cities(trips) #string city/country to tuple lat, lng

    for key in loc_to_coord.keys():
        lat_lng = loc_to_coord[key] #tuple, to be replaced w/ string query replacing src
        loc_to_coord[key] = "https://maps.google.com/maps?q=" + str(lat_lng[0]) + "," + str(lat_lng[1]) + "&hl=es;z=14&amp;output=embed"
        # print "map_query: " + loc_to_coord[key]
    return loc_to_coord


def process_cities(cities_string):
    #Caroline edits 10/07/19: separating cities; potentially w/ ; and ,
    list_of_chars = [c for c in cities_string]
    loc_to_coord = {}
    start = 0
    stop = 1
    temp = 1
    for c in list_of_chars:
        if c == ';':
            city_country = cities_string[start : stop - 1]
            # print 'city_country: ' + city_country
            # g = geocoder.google(city_country, key=api_key)
            # print g
            # loc_to_coord[city_country] = g.latlng #as tuple
            # print loc_to_coord[city_country]
            # print g.json
            loc_to_coord[city_country] = lat_lng_temp.get(temp)
            start = stop
            temp += 1
        stop += 1
    print loc_to_coord
    print "1123123123123123123123123123123123123123123123123123"
    return loc_to_coord



def subscribe(request):
    data = {
        'user': Users.objects.get(id=request.session['id']),
    }
    return render(request, 'goskyhy/subscription.html', data)


def newsfeed(request):
    #check if logged in
    if 'login' not in request.session or not request.session['login']:
        request.session['login_alerts'] = True
        request.session['alert_shown'] = False
        # data = {
        #     'login_alerts': ["Please log in."]
        # }
        # return render(request, "goskyhy/index.html", data)
        return redirect('/')
    #clear exp purchase session stuff
    if request.session['buying']: #does not take into account if going from orders to newsfeed w/o paying
        request.session['buying'] = False
        del request.session['order_list']
        del request.session['img_list']
        del request.session['exp_list']

    if 'num_per_exp' in request.session:
        del request.session['num_per_exp']

    #show friends' stories information
    user_friends = list(UserProfiles.friends.through.objects.filter(userprofiles_id=request.session['id']))
    print request.session['id']
    # user_friends = user_friends.extend(UserProfiles.friends.through.objects.filter(users_id=request.session['id']))
    friends = []
    stories = []
    num_stories = []
    imgs = []

    for user_friend in user_friends:
        if user_friend.userprofiles_id != request.session['id']:
            friend = UserProfiles.objects.get(id=user_friend.userprofiles_id)
        else:
            friend = UserProfiles.objects.get(id=user_friend.users_id)
        
        friends.append(friend)
        #getting stories
        friend_stories = list(Stories.objects.filter(user=friend.user))
        stories.append(friend_stories)
        num_stories.append(range(len(friend_stories)))

        img_list = []

        for story in friend_stories:
            story_imgs = Stories.images.through.objects.filter(stories_id=story.id).first()
            img = Images.objects.get(id=story_imgs.images_id)
            img_list.append(img)

        imgs.append(img_list)


    data = {
        'user': Users.objects.get(id=request.session['id']),
        # 'mystory': Stories.objects.filter(user=request.session['id']),
        # 'mypics': Images.objects.filter(user=request.session['id']),
        'friends': friends,
        'stories': stories,
        'num_stories': num_stories,
        'indices': range(len(friends)),
        'imgs': imgs
    }

    #Caroline 17/08/19: for cart purposes; will not show cart if not logged in
    if 'exp_most_recent' in request.session:
        data['exp_most_recent'] = request.session['exp_most_recent']
        data['num_ordered'] = 1
        if 'num_ordered' in request.session:
            data['num_ordered'] = request.session['num_ordered']
    else:
        data['exp_most_recent'] = 0
        data['num_ordered'] = 0

    #Caroline 17/08/19: for cart; if guest logged in then they can see the cart (maybe change to see cart if something is in there??) w/o ordering
    if 'guest_logged_in' in request.session and request.session['guest_logged_in']:
        request.session['seeing_cart'] = True
        data['seeing_cart'] = True
    else:
        request.session['seeing_cart'] = False
        data['seeing_cart'] = False

    return render(request, 'goskyhy/newsfeed.html', data)


def add_story(request):
    if request.method == 'POST':
        if request.POST['title'] and request.POST['city'] and request.POST['story']:
            u = Users.objects.get(id=request.session['id'])
            c = Cities.objects.create(city=request.POST['city'], state="Cambridgeshire", country="UK", zipcode="CB3")
            c.save()
            d = Cities.objects.filter(city=request.POST['city']).first()
            r = Stories.objects.create(title=request.POST['title'], story=request.POST['story'], user=u, city=d)
            r.save()
            pic_name, pic_url = upload_helper(request)
            image = Images.objects.create(title=pic_name, path=pic_url, user=u)
            image.save()
            r.images.add(image)
            r.save()

            k = Stories.objects.filter(title=request.POST['title']).first()
            story_parsing(k)
            return redirect('/profile')
    else:
        return redirect('/profile')


def get_tag_locations(list_of_chars, tag_starters=None, hashtag_starters=None):
    k = 0
    for c in list_of_chars:
        if c == "@" and tag_starters != None: #b/c exp don't need @; 
            #not thinking about end of string; this should work if all inputs are perfect
            tag_starters.append(k)
        if c == "#" and hashtag_starters != None:
            hashtag_starters.append(k)
        k += 1


def get_tags(starter_list, list_of_chars, list_of_tags):
    for i in starter_list:
        j = 1
        next_char = list_of_chars[i + j]
        tag = ""
        while next_char != " ":
            j += 1
            tag += next_char
            if (i + j) > (len(list_of_chars) - 1):
                break
            next_char = list_of_chars[i + j]
        list_of_tags.append(tag)


def add_to_db(story, tags_to_add=None, hashtags_to_add=None):
    #check which type is being added
    if tags_to_add != None:
        for tag in tags_to_add:
        #if not in database, then create new entry, otherwise create a link (?how?)
            if Tags.objects.filter(tag=tag).exists():
                #create a connection
                story.tags.add(Tags.objects.get(tag=tag))
                story.save()
            else:
                t = Tags.objects.create(tag=tag)
                t.save()
                story.tags.add(t)
                story.save()
    if hashtags_to_add != None:
        for hashtag in hashtags_to_add:
            if Hashtags.objects.filter(hashtag=hashtag).exists():
                story.hashtags.add(Hashtags.objects.get(hashtag=hashtag))
                story.save()
            else:
                h = Hashtags.objects.create(hashtag=hashtag)
                h.save()
                story.hashtags.add(h)
                story.save()

def add_exp_to_db(exp, hashtags_to_add=None):
    #check which type is being added
    if hashtags_to_add != None:
        for h_tag in hashtags_to_add:
        #if not in database, then create new entry, otherwise create a link (?how?)
            # print h_tag
            if Hashtags.objects.filter(hashtag=h_tag).exists():
                #create a connection
                exp.tag.add(Hashtags.objects.get(hashtag=h_tag))
                # print 
                exp.save()
            else:
                ht = Hashtags.objects.create(hashtag=h_tag)
                ht.save()
                exp.tag.add(ht)
                exp.save()
        # print len(exp.tag.through.objects())


def add_images_to_story(story, images_to_add=None):
    if images_to_add != None:
        for image in images_to_add:
            if Images.objects.filter(image=image).exists():
                story.images.add(Images.objects.get(path=image))
                story.save()
            else:
                h = Images.objects.create(path=image)
                h.save()
                story.images.add(h)
                story.save()


def story_parsing(k):
    story = Stories.objects.get(id=k.id)
    list_of_chars = [c for c in story.story]
    list_of_tags = [] #stores lst of individual tags
    list_of_hashtags = [] #ditto for hashtags
    tag_starters = [] #list of indices of where each @ is
    hashtag_starters = [] #ditto for #
    #separates out @ and # positions; considers stories don't have:
    # @#, #@, #, @, etc...
    get_tag_locations(list_of_chars, tag_starters, hashtag_starters)

    #actually getting tags
    get_tags(tag_starters, list_of_chars, list_of_tags) #gets tags
    get_tags(hashtag_starters, list_of_chars, list_of_hashtags) #gets hashtags

    #checks against database --> put in separate helper method
    add_to_db(story, tags_to_add=list_of_tags, hashtags_to_add=list_of_hashtags)


def upload_helper(request): #testing
    if request.method == 'POST' and request.FILES.get('my_file'):
        print "entered upload_helper w/o uploading"
        my_file = request.FILES.get('my_file')
        fs = FileSystemStorage()
        file_name = fs.save(my_file.name, my_file)
        uploaded_file_url = fs.url(file_name)
        # uploaded_file_url = urllib.quote(uploaded_file_url.encode("utf-8"))
        return file_name, uploaded_file_url
    return "", ""
#end Caroline's helper stuff


#Caroline practicing w/ image uploads: 16/06/19 - remove later
def simple_upload(request):
    if request.method == 'POST' and request.FILES['my_file']:
        my_file = request.FILES['my_file'] #access from request.FILES dictionary
        fs = FileSystemStorage()
        file_name = fs.save(my_file.name, my_file)
        uploaded_file_url = fs.url(file_name)
        return render(request, 'goskyhy/myprofile.html', {
                'uploaded_file_url': uploaded_file_url
            }, RequestContext(request))
    return render(request, 'goskyhy/myprofile.html')
#end Caroline practicing w/ image uploads


def remove_story(request, id):
    a = Stories.objects.filter(id=id).delete()
    return redirect('/profile')


def adventures(request):
    if 'login' not in request.session or request.session['login'] is False:
        request.session['login_alert'] = True
        request.session['alert_shown'] = False
        return redirect('/')
    # if request.session['login'] is False:
    #     request.session['login_alert'] = True
    #     return redirect('/')
    print request.session['id']
    data = {
        'user': Users.objects.get(id=request.session['id']),
        'userprofile': UserProfiles.objects.get(user_id=request.session['id'])
    }

    # print data['user']
    # print data['userprofile']

    # return render(request, 'goskyhy/myprofile.html', data)
    return render(request, 'goskyhy/new_experience.html', data)


def act_details(request):
    print "we're here"
    # data = {
    #     'user': Users.objects.get(id=request.session['id']),
    #     'experiences': Experiences.objects.get(id=id),
    # }
    return render(request, 'goskyhy/act_details.html')


# def search(request):
#     print request.POST
#     return render(request, 'goskyhy/act_details.html')

def param_to_encoded(request):
    #takes text input of search and turns it into a nicely encoded URL
    print "entered encoding"
    input_string = request.POST['search']
    print input_string
    start = 0
    end = 0
    inputs = []
    while end < len(input_string):
        if input_string[end] == "," or input_string[end] == " " or end == len(input_string) - 1:
            if end == len(input_string) - 1:
                end += 1
            query = input_string[start : end]
            inputs.append(query)
            print query
            if end == len(input_string):
                break
            while (input_string[end] == "," or input_string[end] == " "):
                end += 1
            start = end
        else:
            end += 1

    if input_string != "":
        params = ""
        for query in inputs[ : -1]:
            params += query + "+"
        params += inputs[-1]

        request.session['search_encoded_params'] = params
        return redirect('/search/' + '0')
    else:
        return redirect('/')
        # return render(request, 'goskyhy/index12.html', data)


def encoded_to_filter(encod):
    #takes encoded input and turns into the individual search params
    print "entered decoding"
    params = []
    start = 0
    end = 0

    for c in encoded:
        if end == len(encoded) - 1:
            params.append(encoded[start :])
            print encoded[start:]
            break
        if c == "+":
            params.append(encoded[start : end])
            print encoded[start : end]
            end += 1
            start = end
        else:
            end += 1
            continue

    return params


def search(request, id="0"):
    # Need to collect all reviews per experience and come up with overall approximate reviews qualifications
    # Play values so 4+ starts = 60%, 3 stars = 30%, 2 stars = 20%, 1 stars = 10% &&& play values differently if high in low reviews. 
    # Reasoning: Most people who have a good expereince dont bother leaving good review 60% of the time
    # People usually leave bad reviews when having a bad personal experience. 

    #theoretically should be the same as index BUT the experiences shown should be filtered w/ search queries


    if 'login_alert' in request.session and 'alert_shown' in request.session and request.session['alert_shown']: 
        # print request.session['alert_shown']
        del request.session['login_alert']

    #test whether can add comments or not
    bought_check = []
    purchased_if_logged_in_ids = []
    if 'login' in request.session and request.session['login']:
        orders = Orders.objects.filter(user_id=request.session['id'])
        for order in orders:
            order_exps = Orders.exps.through.objects.filter(orders_id=order.id)
            for order_exp in order_exps:
                if order_exp.experiences_id not in purchased_if_logged_in_ids:
                    purchased_if_logged_in_ids.append(order_exp.experiences_id)

    #Caroline 30/09/19: checking cart
    request.session['seeing_cart'] = False

    img_exp_list = []
    img_list = []
    experiences = None
    # start = i * 20 #show 20 right now at a time
    # id = 0
    id = int(id)
    # print "id: " + str(id)
    end = (id + 1) * 20 #add more 
    show_more = False #should display button if true

    #do querying w/ different params
    print request.session['search_encoded_params']
    queries = encoded_to_filter(request.session['search_encoded_params'])
    #temporarily only ONE at a time w/ TAGS
    queried_exps_id = []
    experiences = []
    for query in queries:
        #check for which tag(s) contains query
        #really not efficient b/c has to check every query then tag O(n * m)
        for exp_tag in Experiences.tag.through.objects.all():
            hashtag_id = exp_tag.hashtags_id
            print Hashtags.objects.get(id=hashtag_id).hashtag 
            if query.lower() in Hashtags.objects.get(id=hashtag_id).hashtag:
                print "found matching"
                exps_through = list(Experiences.tag.through.objects.filter(hashtags_id=hashtag_id))
                for exp_through in exps_through:
                    exp = Experiences.objects.get(id=exp_through.experiences_id)
                    if exp.id not in queried_exps_id:
                        queried_exps_id.append(exp.id)

    for exp_id in queried_exps_id:
        print str(exp_id)
    img_exp_list = []
    for exp_id in queried_exps_id:
        img_exp_list.extend(Experiences.images.through.objects.filter(experiences_id=exp_id))
        experiences.append(Experiences.objects.get(id=exp_id))

    for img_exp in img_exp_list:
        img = Images.objects.get(id=img_exp.images_id) 
        img.path = urllib.unquote(img.path)
        img.save()
        img_list.append(img)
        if 'login' not in request.session or not request.session['login']:
            bought_check.append(False)
        elif img_exp.experiences_id in purchased_if_logged_in_ids:
            bought_check.append(True)
        else:
            bought_check.append(False)


    # try:
    #     img_exp_list = list(Experiences.images.through.objects.all())


    #     for img_exp in img_exp_list:
    #         img = Images.objects.get(id=img_exp.images_id) 
    #         img.path = urllib.unquote(img.path)
    #         img.save()
    #         img_list.append(img)
    #         if 'login' not in request.session or not request.session['login']:
    #             bought_check.append(False)
    #         elif img_exp.experiences_id in purchased_if_logged_in_ids:
    #             bought_check.append(True)
    #         else:
    #             bought_check.append(False)

    #     experiences = list(Experiences.objects.all())   
    
    # except OperationalError:
    #     print 'db does not exist yet'
    #     pass

    if end > len(img_exp_list):
        print "last page"
        end = len(img_exp_list)
        show_more = False
    else:
        id += 1
        show_more = True
    indices = range(end)

    #end showing stuff for search

    login_alerts = []

    if 'login_alert' in request.session and request.session['login_alert']:
        #temp just for creating experiences
        login_alerts.append("Please log in")# before creating an experience.")
        request.session['alert_shown'] = True

    data = {
        'experiences': experiences,
        'img_exp_list': img_exp_list, 
        'img_list': img_list,
        'indices': indices,
        'login_alerts': login_alerts,
        'id': str(id),
        'show_more': show_more,
        'bought_check': bought_check
    }

    #check what display-bar shows: settings vs login/my_profile
    if 'login' not in request.session:
        data['not_logged_in'] = True
    else:
        data['not_logged_in'] = False

    #after stuff happens, delete everything in session to do with buying
    if 'order_id' in request.session and 'checkout' in request.session and request.session['checkout']:
        if 'guest_logged_in' in request.session and request.session['guest_logged_in']:
            #delete stuff related to temporary sign-in
            del request.session['first_name']
            del request.session['last_name']
            del request.session['email']
            del request.session['id']
            del request.session['guest_logged_in']
            #Caroline 31/07/19: have to delete other things about orders b/c not in newsfeed
            del request.session['num_per_exp']
            del request.session['order_list']
            del request.session['exp_list']
            del request.session['img_list']
        #commented out stuff is already deleted when loading newsfeed post purchase
        # del request.session['num_per_exp']
        # del request.session['order_list']
        # del request.session['exp_list']
        # del request.session['img_list']
        del request.session['total_cost']
        del request.session['total_items']
        del request.session['order_id']

        request.session['checkout'] = False

    #Caroline 31/07/19: for cart purposes; will not show cart if not logged in
    if 'exp_most_recent' in request.session:
        data['exp_most_recent'] = request.session['exp_most_recent']
        data['num_ordered'] = 1
        if 'num_ordered' in request.session:
            data['num_ordered'] = request.session['num_ordered']
    else:
        data['exp_most_recent'] = id
        data['num_ordered'] = 0

    #Caroline 31/07/19: for cart; if guest logged in then they can see the cart (maybe change to see cart if something is in there??) w/o ordering
    if 'guest_logged_in' in request.session and request.session['guest_logged_in']:
        request.session['seeing_cart'] = True
        data['seeing_cart'] = True
    else:
        request.session['seeing_cart'] = False
        data['seeing_cart'] = False

    return render(request, 'goskyhy/index12.html', data)


def searchengine(request):
    print request.POST
    return render(request, 'goskyhy/act_details.html')


def create_new(request):
    if 'login' not in request.session or not request.session['login']:
        request.session['login_alert'] = True
        request.session['alert_shown'] = False
        # data = {
        #     'login_alerts': ["Please log in before creating a new experience."]
        # }
        # request.session['redirect'] = True
        # return render(request, 'goskyhy/index.html', data)
        return redirect('/')
    data = {
        'user': Users.objects.get(id=request.session['id'])
    }
    return render(request, 'goskyhy/new_experience.html', data)


def create_new2(request):
    u = Users.objects.get(id=request.session['id'])

    request.session['title'] = request.POST.get('title')
    request.session['city'] = request.POST.get('city')
    request.session['category'] = request.POST.get('category')

    if request.POST.get('eng') is 'on':
        request.session['eng'] = True
        print request.session['eng']
    else:
        request.session['eng'] = False
        print request.session['eng']

    k = Language.objects.filter(english=True or False)
    if not k: 
        l = Language.objects.create(english=True or False)
        l.save()
        print l

    cat = Categories.objects.filter(category=request.session['category'])
    if not cat:
        c = Categories.objects.create(category=request.POST['category'])
        c.save()

    #Caroline's edits 26/06/19 - Images in experiences
    pic_name, pic_url = upload_helper(request)
    image = Images.objects.create(title=pic_name, path=pic_url, user=u)
    image.save()
    request.session['pic_name'] = pic_name
    request.session['pic_url'] = pic_url

    #Caroline's edits 08/07/19 - tags in exps
    tag_text = request.POST['tags']
    list_of_chars = [c for c in tag_text]
    print "chars in exp tags: " + ", ".join(list_of_chars)
    list_of_hashtags = [] #ditto for hashtags
    hashtag_starters = [] #ditto for #
    #separates out # positions
    get_tag_locations(list_of_chars, hashtag_starters=hashtag_starters)
    #actually getting tags
    get_tags(hashtag_starters, list_of_chars, list_of_hashtags) #gets hashtags
    request.session['tags'] = list_of_hashtags #saves in session

    #passing data into the next form w/ all associatedsaved data
    data = {
        'user': u
    }
    return render(request, 'goskyhy/new_exp2.html', data)


def create_new3(request):
    request.session['host'] = request.POST['host']
    request.session['description'] = request.POST['description']
    request.session['distance'] = request.POST['distance']
    request.session['provided'] = request.POST['provided']
    data = {
        'user': Users.objects.get(id=request.session['id'])
    }
    return render(request, 'goskyhy/new_exp3.html', data)


def create_new4(request):
    request.session['address'] = request.POST['address']
    request.session['city'] = request.POST['city']
    request.session['state'] = request.POST['state']
    request.session['zipcode'] = request.POST['zipcode']
    request.session['country'] = request.POST['country']
    # request.session['timein'] = request.POST['timein']
    # #added to test
    # request.session['date_time'] = request.POST['datetimepicker']
    # request.session['timeout'] = request.POST['timeout']
    request.session['price'] = request.POST['price']
    request.session['details'] = request.POST['details']
    if request.POST['apt_bldg'] is not None:
        request.session['apt_bldg'] = request.POST['apt_bldg']
    k = Prices.objects.filter(price=request.POST['price'])
    print k
    s = Cities.objects.filter(city=request.POST['city'], state=request.POST['state'], zipcode=request.POST['zipcode'], country=request.POST['country']).first()
    if not s:
        c = Cities.objects.create(city=request.session['city'], state=request.session['state'], country=request.session['country'], zipcode=request.session['zipcode'])
        c.save()
    if not k:
        p = Prices.objects.create(price=request.POST['price'])
        p.save()
        print p.price
        print request.session['price']

    #dealing w/ time nonsense
    if 'one_time' in request.POST and request.POST['one_time']:
        # print "entered one time"
        start_time = request.POST['timein']
        end_time = request.POST['timeout']
        request.session['timein'] = request.POST['timein']
        request.session['timeout'] = request.POST['timeout']

        #w/ date picker
        date_time = request.POST['datetimepicker']
        year = date_time[0 : 4]
        month = date_time[5 : 7]
        date = date_time[8 : 10]
        time = date_time[11 : 16]
        #save stuff to session
        request.session['one_time'] = True
        request.session['one_time_whole'] = str(year) + '.' + str(month) + '.' + str(date)
        request.session['one_time_year'] = year
        request.session['one_time_month'] = month
        request.session['one_time_date'] = date
        request.session['one_time_time'] = time

        # print "onetime: " + str(year) + "/" + str(month) + "/" + str(date) + " " + str(time)
    if 'consistent_dates' in request.POST and request.POST['consistent_dates']: #should be elif testing
        # print "entered consistent"
        # print request.POST['start_date']
        # print request.POST['end_date']
        allowed_days = [] #should be turned into NOT allowed days if 'date' not in request.POST: not_allowed_days.append(x)
        not_allowed_days = []
        #go through weekdays 
        if 'monday' in request.POST and request.POST['monday']:
            allowed_days.append(0)
        else:
            not_allowed_days.append(0)
        if 'tuesday' in request.POST and request.POST['tuesday']:
            allowed_days.append(1)
        else:
            not_allowed_days.append(1)
        if 'wednesday' in request.POST and request.POST['wednesday']:
            allowed_days.append(2)
        else:
            not_allowed_days.append(2)
        if 'thursday' in request.POST and request.POST['thursday']:
            allowed_days.append(3)
        else:
            not_allowed_days.append(3)
        if 'friday' in request.POST and request.POST['friday']:
            allowed_days.append(4)
        else:
            not_allowed_days.append(4)
        #go through weekends 
        if 'saturday' in request.POST and request.POST['saturday']:
            allowed_days.append(5)
        else:
            not_allowed_days.append(5)
        if 'sunday' in request.POST and request.POST['sunday']:
            allowed_days.append(6)
        else:
            not_allowed_days.append(6)
        #go through allowTimes
        # all times allowed ATM
        # for item in allowed_days:
        #     print item

        # for item in not_allowed_days:
            # print item

        request.session['consistent_dates'] = True
        request.session['allowed_days'] = allowed_days
        request.session['not_allowed_days'] = not_allowed_days
        request.session['start_date'] = request.POST['start_date']
        request.session['end_date'] = request.POST['end_date']

    if 'specific_dates' in request.POST and request.POST['specific_dates']: #should be elif testing
        # print "entered specific"
        list_dates = request.POST['dates'] #not working currently
        # list_years = []
        # list_months = []
        # list_days = []
        date_info = {
            0: [], #list_years
            1: [], #list_months
            2: [], #list_days
        }
        num_tracker = 0
        end = False
        num = '' #tracking number
        date = ''
        ret_list = []
        for i in range(len(list_dates)):
            c = list_dates[i]
            # print "c: " + c
            if c == ',' or i == len(list_dates) - 1:
                end = True
            if not end:
                if c == '/':
                    # print "num_tracker: " + str(num_tracker) + ", " + num
                    date_info.get(num_tracker % 3).append(num)
                    num_tracker += 1
                    num = ''
                    date += '.'
                else:
                    if c == ' ':
                        continue
                    num += c
                    date += c
            else:
                if i == len(list_dates) - 1:
                    num += c
                    date += c
                # print "num_tracker: " + str(num_tracker) + ", " + num
                date_info.get(num_tracker % 3).append(num)
                num_tracker += 1
                num = ''
                ret_list.append(date)
                date = ''
                end = False

        # print ', '.join(ret_list)
        # print "year list: " + ', '.join(date_info.get(0))
        # print "month list: " + ', '.join(date_info.get(1))
        # print "day list: " + ', '.join(date_info.get(2))

        request.session['specific_dates'] = True
        request.session['specific_dates'] = ret_list
        request.session['list_years'] = date_info.get(0)
        request.session['list_months'] = date_info.get(1)
        request.session['list_days'] = date_info.get(2)
    # print request.POST['datetimepicker']
    # print request.POST['timein']
    # print request.POST['timeout']
    d = Times.objects.filter(timein=request.POST['timein'], timeout=request.POST['timeout'])
    if not d:
        e = Times.objects.create(timein=request.POST['timein'], timeout=request.POST['timeout'])
        e.save()
    data = {
        'user': Users.objects.get(id=request.session['id'])
    }
    return render(request, 'goskyhy/new_exp4.html', data)


def save_exp(request):
    if request.method == 'POST':
        if request.POST['local_laws'] and request.POST['terms_conditions'] and request.POST['confirm_person']:
            k = Agrees.objects.filter(local_laws=True, terms_conditions=True, confirm_person=True)
            if not k:
                p = Agrees.objects.create(local_laws=True, terms_conditions=True, confirm_person=True)
                p.save()
            l = Agrees.objects.filter(local_laws=True, terms_conditions=True, confirm_person=True).first()
            d = Cities.objects.filter(city=request.session['city']).first()
            a = Locations.objects.create(address=request.session['address'], apt_bldg=request.session['apt_bldg'], city=d)
            a.save()
            b = Locations.objects.filter(address=request.session['address'], apt_bldg=request.session['apt_bldg'], city=d).first()
            u = Users.objects.get(id=request.session['id'])
            z = Prices.objects.filter(price=request.session['price']).first()
            t = Times.objects.filter(timein=request.session['timein'], timeout=request.session['timeout']).first()
            e = Language.objects.filter(english=True).first()
            g = Categories.objects.filter(category=request.session['category']).first()

            i = Images.objects.create(title=request.session['pic_name'], path=request.session['pic_url'], user=u)
            i.save()

            x = Experiences.objects.create(title=request.session['title'], host=request.session['host'], description=request.session['description'], distance=request.session['distance'], provided=request.session['provided'], details=request.session['details'], user=u, price=z, agree=l, english=e, city=d, category=g, location=b)
            x.save()
            x.times.add(t)
            x.images.add(i)
            x.save()

            #single date work
            if 'one_time' in request.session and request.session['one_time']:
                # print "entered one_time"
                date = ExpDates.objects.create(year=request.session['one_time_year'], month=request.session['one_time_month'], day=request.session['one_time_date'], together=request.session['one_time_whole'])
                # request.session['one_time_time']
                date.save()
                x.dates.add(date)
                x.save()

            #repeating dates work
            if 'consistent_dates' in request.session and request.session['consistent_dates']:
                # print "entered consistent_dates"
                allowed_days = request.session['allowed_days']
                not_allowed_days = request.session['not_allowed_days']
                start_date = request.session['start_date']
                end_date = request.session['end_date']

                start = ExpDates.objects.create(year=start_date[0 : 4], month=start_date[5 : 7], day=start_date[8 : ], together=start_date)
                start.save()
                end = ExpDates.objects.create(year=end_date[0 : 4], month=end_date[5 : 7], day=end_date[8 : ], together=end_date)
                end.save()

                for day in allowed_days:
                    date = ExpDaysOfWeek.objects.create(day=day)
                    date.save()
                    date.start_date.add(start)
                    date.end_date.add(end)
                    date.save()
                    x.days_of_week_allowed.add(day)
                    x.save()

                for day in not_allowed_days:
                    date = ExpDaysOfWeek.objects.create(day=day)
                    date.save()
                    date.start_date.add(start)
                    date.end_date.add(end)
                    date.save()
                    x.days_of_week_not_allowed.add(day)
                    x.save()

            #multiple dates work
            if 'specific_dates' in request.session and request.session['specific_dates']:
                # print "entered specific_dates"
                for i in range(len(request.session['specific_dates'])):
                    specific = request.session['specific_dates'][i]
                    year = request.session['list_years'][i]
                    month = request.session['list_months'][i]
                    day = request.session['list_days'][i]

                    date = ExpDates.objects.create(year=year, month=month, day=day, together=specific)
                    date.save()
                    x.dates.add(date)
                    x.save()

            #checks against database
            add_exp_to_db(x, hashtags_to_add=request.session['tags'])

            temp = request.session['id']
            temp2 = request.session['email']
            # request.session.clear() #why are we clearing session? If we want to get rid of stuff we should do that by tracking what we're putting in session and clear it that way
            request.session['id'] = temp
            request.session['email'] = temp2
            #Caroline 08/07/19: temp reset of buying var
            request.session['buying'] = False
    return redirect('/newsfeed')


def exp_mapping(request, experience):
    # encoding: https://www.w3schools.com/tags/ref_urlencode.asp

    map_url = "https://maps.google.com/maps?width=100%&amp;height=600&amp;hl=en&amp;q="

    address = experience.location.address
    city = experience.city.city
    country = experience.city.country
    title = experience.title
    zipcode = experience.city.zipcode

    all_info = [address, city, country, zipcode]

    for i in range(len(all_info)):
        coded = urllib.quote(all_info[i].encode("utf-8"))
        if i == len(all_info) - 1:
            coded = zipcode.encode("utf-8")[: -2]
            print coded
        request.session['map_' + str(i + 1)] = coded
        map_url += str(coded)
        if i != len(all_info) - 1:
            sep = urllib.quote(u", ", "utf-8")
            map_url += sep

    map_url += "+("
    map_url += urllib.quote(title, "utf-8")
    zipcode = zipcode.encode("utf-8")[: -2]
    request.session['map_5'] = urllib.quote(title, "utf-8")

    map_url += ")&amp;ie=UTF8&amp;t=&amp;z=14&amp;iwloc=B&amp;output=embed"

    # print map_url


def exp_details(request, id, bought): #bought = 1; not bought = 0
    data = {
        'exp' :  Experiences.objects.get(id=id)
    }

    img_id = Experiences.images.through.objects.filter(experiences_id=data['exp'].id).first().images_id
    data['img'] = Images.objects.get(id=img_id)
    # tag_ids = []
    list_of_tags = []
    exps_tags = Experiences.tag.through.objects.filter(experiences_id=data['exp'].id)
    for exp_tag in exps_tags:
        tag = Hashtags.objects.get(id=exp_tag.hashtags_id)
        # print tag.hashtag
        list_of_tags.append(tag)
    data['tags'] = list_of_tags

    #Caroline 11/07/19: getting similar tags
    #1) Temporarily just go by similar tag ids (% 10)
    #2) Find exps that INCLUDE same tag(s) (later not ready yet b/c of existing tags)
    list_exps_diff = []
    diff_exp_img = []
    list_exps_same = []
    same_exp_img = []
    tags_added_diff = 0
    tags_added_same = 0

    for tag in list_of_tags:
        if tags_added_diff > 5 and tags_added_same > 4: #tags_added > 5:
            break
        exps_tags = Experiences.tag.through.objects.all()
        for exp_tag in exps_tags:
            if tags_added_diff > 5 and tags_added_same > 4: #tags_added > 5:
                break
            if exp_tag.hashtags_id % 10 == tag.id % 10 and exp_tag.hashtags_id != tag.id:
                #Caroline note 16/07/19: find more efficient solution to check if exp has been displayed (both loops)
                experience = Experiences.objects.get(id=exp_tag.experiences_id)
                if experience.city.city == data['exp'].city.city and tags_added_same < 5 and experience.id != data['exp'].id:
                    seen = False
                    for same_exp in list_exps_same:
                        if experience.id == same_exp.id:
                            seen = True
                            break
                    if not seen:
                        list_exps_same.append(experience)
                        tags_added_same += 1
                elif experience.city.city != data['exp'].city.city and tags_added_diff < 6:
                    seen = False
                    for diff_exp in list_exps_diff:
                        if experience.id ==  diff_exp.id:
                            seen = True
                            break
                    if not seen:
                        list_exps_diff.append(experience)
                        tags_added_diff += 1

    data['list_exps_diff'] = list_exps_diff
    data['list_exps_same'] = list_exps_same

    diff_exp_img = images_from_exps(list_exps_diff, diff_exp_img)
    same_exp_img = images_from_exps(list_exps_same, same_exp_img)

    data['diff_exp_img'] = diff_exp_img
    data['same_exp_img'] = same_exp_img

    data['range_diff'] = range(len(list_exps_diff))
    data['range_same'] = range(len(list_exps_same))

    #check what display-bar shows: settings vs login/my_profile
    if 'login' not in request.session or not request.session['login']:
        data['not_logged_in'] = True #right now is marking experience as not available buy; currently testing out possibility of making a guest purchase
        request.session['login_alert'] = True
        request.session['alert_shown'] = False
    else:
        data['not_logged_in'] = False

    # print data['not_logged_in']

    #get map data
    map_url = exp_mapping(request, data['exp'])
    data['map_url'] = map_url
    data['map_one'] = request.session['map_1']
    data['map_two'] = request.session['map_2']
    data['map_three'] = request.session['map_3']
    data['map_four'] = request.session['map_4']
    data['map_five'] = request.session['map_5']

    for i in range(5):
        del request.session['map_' + str(i + 1)]

    #bought or not showing commment adding
    if int(bought) == 0:
        data['bought'] = False
    else:
        data['bought'] = True

    #showing reviews
    reviews = Reviews.objects.filter(exp=Experiences.objects.get(id=id))
    data['reviews'] = reviews
    # u_prof = UserProfiles.objects.filter(user=Users.objects.get(id=request.session['id'])).first() #to get user info
    # data['u_prof'] = u_prof
    data['review_range'] = range(len(reviews))
    data['u_profs'] = [UserProfiles.objects.get(user=review.user) for review in reviews]

    #Caroline 30/07/19: for cart purposes
    if 'exp_most_recent' in request.session:
        data['exp_most_recent'] = request.session['exp_most_recent']
        data['num_ordered'] = 1
        if 'num_ordered' in request.session:
            data['num_ordered'] = request.session['num_ordered']
    else:
        data['exp_most_recent'] = id
        data['num_ordered'] = 0

    #cart work for guest post-logins
    data['seeing_cart'] = request.session['seeing_cart']

    return render(request, 'goskyhy/exp_details.html', data)


def post_comment(request, exp_id):
    if request.method == 'POST' and 'login' in request.session and request.session['login']:
        comment_text = request.POST['comment']
        user = Users.objects.get(id=request.session['id'])
        exp = Experiences.objects.get(id=exp_id)
        review = Reviews.objects.create(review=comment_text, user=user, exp=exp)
        review.save()

    return redirect('/exp_details/' + exp_id + '/1') #b/c always will be logged in for commenting



#maybe alter to return just one image??
def images_from_exps(experiences, list_imgs):
    for exp in experiences:
        exp_img = Experiences.images.through.objects.filter(id=exp.id).first()
        image = Images.objects.filter(id=exp_img.images_id).first()
        list_imgs.append(image)
    return list_imgs


def add_order_guest(request, id, num):
    #checking if only seeing cart (and haven't added to cart yet)
    if 'seeing_cart' in request.session and request.session['seeing_cart']:
        #seems fine, testing
        exp_id_list = None
        img_id_list = None
        num_per_exp = None
        data = {
            'id': id,
            'exp_list': [],
            'img_list': [],
            'num_per_exp': [],
            'range': range(0),
            'session_id': request.session['id'],
            'total_items': 0,
            'total_cost': 0,
            'order_id': 0,
            'num_items': 0, #for if the cart hasn't been updated
        }

        if 'exp_list' in request.session:
            # print "checking cart"
            exp_id_list = request.session['exp_list']
            img_id_list = request.session['img_list']

            exp_list = [Experiences.objects.get(id=i) for i in exp_id_list]
            img_list = [Images.objects.get(id=i) for i in img_id_list]

            data['exp_list'] = exp_list
            data['img_list'] = img_list
            data['range'] = range(len(exp_list))
            data['num_per_exp'] = request.session['num_per_exp']
            data['num_items'] = len(exp_list)

        if 'total_items' in request.session:
            data['total_items'] = request.session['total_items']
        if 'total_cost' in request.session:
            data['total_cost'] = request.session['total_cost']
        if 'order_id' in request.session:
            data['order_id'] = request.session['order_id']

        if data['total_items'] > 0:
            request.session['allowed_checkout'] = True
            data['allowed_checkout'] = True
        else:
            request.session['allowed_checkout'] = False
            data['allowed_checkout'] = False

        if 'not_logged_in' in request.session and not request.session['not_logged_in']:
            data['logged_in'] = True
        else:
            data['logged_in'] = False

        request.session['seeing_cart'] = False #why?

        return render(request, 'goskyhy/orders.html', data)

    #to help w/ cart work later
    request.session['not_logged_in'] = True #not accounting post-checkout logging in yet
    request.session['buying'] = True
    request.session['checkout'] = False
    request.session['seeing_cart'] = False

    #do we need to do this elsewhere??
    if 'id' not in request.session:
        request.session['id'] = 0

    request.session['not_logged_in'] = True
    # request.session['buying'] = True #not needed?? b/c redirecting to index
    request.session['checkout'] = False

    #storing method
    num_per_exp = []

    if 'num_per_exp' in request.session:
        num_per_exp = request.session['num_per_exp']
    num_per_exp.append(1) #default
    request.session['num_per_exp'] = num_per_exp

    #setting exp selected
    exp_id_list = None
    img_id_list = None
    exp = Experiences.objects.get(id=id)
    img_id = Experiences.images.through.objects.get(experiences_id=exp.id).images_id
    img = Images.objects.get(id=img_id)

    #processing
    if 'order_list' not in request.session:
        request.session['order_list'] = 1 #first order
        exp_id_list = [id]
        img_id_list = [img_id]
    else:
        request.session['order_list'] += 1
        exp_id_list = request.session['exp_list']
        img_id_list = request.session['img_list']
        if id not in exp_id_list:
            exp_id_list.append(id)
            img_id_list.append(img_id)

    request.session['exp_list'] = exp_id_list
    request.session['img_list'] = img_id_list

    exp_list = [Experiences.objects.get(id=i) for i in exp_id_list]
    img_list = [Images.objects.get(id=i) for i in img_id_list]

    data = {
        # 'exp' :  Experiences.objects.get(id=id)
        'not_logged_in': request.session['not_logged_in'],
        'id': id,
        'exp_list': exp_list,
        'img_list': img_list,
        'range': range(len(exp_list)),
        'session_id': request.session['id'],
        'total_items': 0,
        'total_cost': 0,
        'order_id': 0,
    }

    # data['quantity'] = request.session[str(exp_id)]
    data['num_per_exp'] = num_per_exp

    if 'total_items' in request.session:
        data['total_items'] = request.session['total_items']
    if 'total_cost' in request.session:
        data['total_cost'] = request.session['total_cost']
    if 'order_id' in request.session:
        data['order_id'] = request.session['order_id']

    request.session['exp_logging_in_id'] = id

    # print request.session['id']
    # print Users.objects.get(id=request.session['id']).first_name

    #Caroline added 29/07/19: login after adding to cart
    request.session['add_item_id'] = id
    request.session['add_item_quantity'] = num

    #Checking for logged-in status for guest logins
    if 'guest_logged_in' in request.session and request.session['guest_logged_in']:
        data['guest_logged_in'] = True
        request.session['seeing_cart'] = True
        data['seeing_cart'] = True
    else:
        data['guest_logged_in'] = False
        data['seeing_cart'] = False

    print exp_list[-1].title

    for i in data['range']:
        print exp_list[i].title
        print img_list[i].path

    print data['not_logged_in']

    #Caroline 30/07/19: checking to see if allowed to checkout (only if stuff exists in cart)
    if data['total_items'] > 0:
        request.session['allowed_checkout'] = True
        data['allowed_checkout'] = True
    else:
        request.session['allowed_checkout'] = False
        data['allowed_checkout'] = False

    return render(request, 'goskyhy/orders_guest.html', data)


def buy_orders_guest(request, id, recent_exp_id, recent_num_ordered):
    exp_id_list = []
    order = None #temp default

    session_id = str(int(request.session['id']))
    # print "id: " + id
    # print "session_id: " + session_id

    user = None

    if not Users.objects.filter(id=0).exists():
        user = Users.objects.create(id=0, username="guest", email="guest@goskyhy.com", password="temp_guest1234")
    else:
        user = Users.objects.get(id=0)

    if session_id == id:
        print "entered"
        exp_id_list = request.session['exp_list']
        order = Orders.objects.create(order="temp replace later", summary="get data to replace later", user=user)
        order.save()

    total_cost = 0
    total_items = 0 #len(exp_id_list)

    num_per_exp = []
    j = 0

    for i in exp_id_list:
        num_ordered = request.session['num_per_exp'][j]
        print "exp #" + str(i) + " ordered: " + str(num_ordered)
        j += 1
        exp = Experiences.objects.get(id=i)
        exp.save()
        order.exps.add(exp)
        order.save()
        total_cost += int(float(exp.price.price)) * num_ordered
        total_items += num_ordered

    order_exps = Orders.exps.through.objects.all()

    exp_list = []
    for order_exp in order_exps:
        # print order_exp.experiences_id
        if order_exp.orders_id == order.id:
            exp_list.append(Experiences.objects.get(id=order_exp.experiences_id))

    # data = {
    #     'total_cost': total_cost,
    #     'total_items': total_items,
    #     'exp_list': exp_list
    # }

    request.session['total_cost'] = total_cost
    request.session['total_items'] = total_items
    order.total_cost = total_cost
    order.total_items = total_items
    order.save()

    request.session['order_id'] = order.id
    # request.session['exp_list'] = exp_list

    #Caroline added 29/07/19: login after adding to cart
    request.session['add_item_id'] = recent_exp_id
    request.session['add_item_quantity'] = recent_num_ordered

    # return render(request, 'goskyhy/orders.html', data)
    return redirect('/add_order_guest/' + str(recent_exp_id) + '/' + str(recent_num_ordered))

def update_num_ordered_guest(request, exp_id, id):
    num_ordered = 1
    num_per_exp = []
    # print "id: " + id
    if 'num_per_exp' in request.session:
        num_per_exp = request.session['num_per_exp']

    if request.method == 'POST':
        num_ordered = int(request.POST['quantity'])
        # print "num_ordered: " + str(num_ordered)
        # num_per_exp.append(num_per_exp)
        request.session[str(id)] = num_ordered
        num_per_exp.insert(int(id), num_ordered)
        # print "num ordered of " + str(id) + ": " + str(num_ordered)
    request.session['num_per_exp'] = num_per_exp

    #Caroline 30/07/19: for cart purposes
    request.session['exp_most_recent'] = exp_id
    request.session['num_ordered'] = num_ordered

    return redirect("/add_order_guest/" + exp_id + "/" + str(num_ordered)) #render(request, 'goskyhy/orders.html', data)


def add_order(request, id, num):
    # if 'login' not in request.session:
    #     request.session['login_alerts'] = True
    #     request.session['alert_shown'] = False
    #     data = {
    #         'login_alerts': ["Please log in before purchasing."],
    #         'not_logged_in': True
    #     }
        # request.session['redirect'] = True
        # print request.session['redirect']
        # request.session['alert_list'] = ["Please log in before purchasing."]
        # request.session['not_logged_in'] = True
        # return render(request, 'goskyhy/index.html', data)
        # return redirect("/")

    #checking if only seeing cart (and haven't added to cart yet)
    if 'seeing_cart' in request.session and request.session['seeing_cart']:
        exp_id_list = None
        img_id_list = None
        num_per_exp = None
        data = {
            'id': id,
            'exp_list': [],
            'img_list': [],
            'num_per_exp': [],
            'range': range(0),
            'session_id': request.session['id'],
            'total_items': 0,
            'total_cost': 0,
            'order_id': 0,
            'num_items': 0, #for if the cart hasn't been updated
        }

        if 'exp_list' in request.session:
            print "checking cart"
            exp_id_list = request.session['exp_list']
            img_id_list = request.session['img_list']

            exp_list = [Experiences.objects.get(id=i) for i in exp_id_list]
            img_list = [Images.objects.get(id=i) for i in img_id_list]

            data['exp_list'] = exp_list
            data['img_list'] = img_list
            data['range'] = range(len(exp_list))
            if 'num_per_exp' in request.session:
                data['num_per_exp'] = request.session['num_per_exp'] #remembers to add one in assumption
                print "found: " + str(len(data['num_per_exp']))
            else:
                data['num_per_exp'] = [1] * len(exp_list) #assumes all 1 right now
                request.session['num_per_exp'] = data['num_per_exp']
                print "not found: " + str(len(data['num_per_exp']))
            data['num_items'] = len(exp_list)

        if 'total_items' in request.session:
            data['total_items'] = request.session['total_items']
        if 'total_cost' in request.session:
            data['total_cost'] = request.session['total_cost']
        if 'order_id' in request.session:
            data['order_id'] = request.session['order_id']

        if data['total_items'] > 0:
            request.session['allowed_checkout'] = True
            data['allowed_checkout'] = True
        else:
            request.session['allowed_checkout'] = False
            data['allowed_checkout'] = False

        if 'not_logged_in' in request.session and not request.session['not_logged_in']:
            data['logged_in'] = True
        else:
            data['logged_in'] = False

        return render(request, 'goskyhy/orders.html', data)

    #to help w/ cart work later
    request.session['not_logged_in'] = False
    request.session['buying'] = True
    request.session['checkout'] = False
    request.session['seeing_cart'] = False

    #Caroline 31/07/19: if cart is empty end already
    if id == '0':
        data = {
            'num_items': 0,
            'total_cost': 0,
            'total_items': 0,
            'logged_in': True,
            'allowed_checkout': False,
        }
        return render(request, 'goskyhy/orders.html', data)

    #Caroline 31/07/19: temporarily moving to not add extra stuff
    num_per_exp = []
    if 'num_per_exp' in request.session:
        num_per_exp = request.session['num_per_exp']

    # for item in request.session['num_per_exp']:
    #     print str(item)

    # print id
    print "in the order"
    # exp = Experiences.objects.all()
    exp_id_list = None
    img_id_list = None

    if 'exp_list' in request.session:
        print "entered checking after login"
        exp_id_list = request.session['exp_list']
        img_id_list = request.session['img_list']
        # request.session['exp_list'] = exp_id_list
        # request.session['img_list'] = img_id_list

        #checking whether to add 1 to num_per_exp or not
        if id not in exp_id_list:
            num_per_exp.append(1)
            request.session['num_per_exp'] = num_per_exp
    else:
        num_per_exp.append(1)
        request.session['num_per_exp'] = num_per_exp
    # for exp_id in exp_id_list:
    #     print "exp_id: " + str(exp_id)

    exp = Experiences.objects.get(id=id)
    img_id = Experiences.images.through.objects.get(experiences_id=exp.id).images_id
    img = Images.objects.get(id=img_id)
    # print exp.title
    # print "img path: " + img.path

    # del request.session['order_list'] #temp for testing
    # print "order_list: " + str(request.session['order_list'])
    if 'order_list' not in request.session:
        request.session['order_list'] = 1 #first order
        exp_id_list = [id]
        img_id_list = [img_id]
    else:
        request.session['order_list'] += 1
        exp_id_list = request.session['exp_list']
        img_id_list = request.session['img_list']
        if id not in exp_id_list:
            exp_id_list.append(id)
            img_id_list.append(img_id)

    request.session['exp_list'] = exp_id_list
    request.session['img_list'] = img_id_list

    exp_list = [Experiences.objects.get(id=i) for i in exp_id_list]
    img_list = [Images.objects.get(id=i) for i in img_id_list]

    data = {
        # 'exp' :  Experiences.objects.get(id=id)
        'id': id,
        'exp_list': exp_list,
        'img_list': img_list,
        'range': range(len(exp_list)),
        'session_id': request.session['id'],
        'total_items': 0,
        'total_cost': 0,
        'order_id': 0,
        'num_items': 0,
    }

    for item in request.session['num_per_exp']:
        print str(item)

    # data['quantity'] = request.session[str(exp_id)]
    data['num_per_exp'] = num_per_exp

    if 'total_items' in request.session:
        data['total_items'] = request.session['total_items']
    if 'total_cost' in request.session:
        data['total_cost'] = request.session['total_cost']
    if 'order_id' in request.session:
        data['order_id'] = request.session['order_id']
    data['num_items'] = len(exp_list)

    #Caroline 30/07/19: checking to see if allowed to checkout (only if stuff exists in cart)
    if data['total_items'] > 0:
        request.session['allowed_checkout'] = True
        data['allowed_checkout'] = True
    else:
        request.session['allowed_checkout'] = False
        data['allowed_checkout'] = False

    #Caroline added 29/07/19: login after adding to cart
    request.session['add_item_id'] = id
    request.session['add_item_quantity'] = num

    #Checking for logged-in status
    if 'not_logged_in' in request.session and not request.session['not_logged_in']:
        data['logged_in'] = True
    else:
        data['logged_in'] = False

    # print exp_list[-1].title

    for i in data['range']:
        print exp_list[i].title
        print img_list[i].path
        print "9872398470298743897309275094387509834270598734"
    return render(request, 'goskyhy/orders.html', data)

def see_cart(request, exp_id, num=0):
    request.session['seeing_cart'] = True 
    if 'not_logged_in' in request.session and request.session['not_logged_in']:
        return redirect('/add_order_guest/' + str(exp_id) + '/' + str(num))
    return redirect('/add_order/' + str(exp_id) + '/' + str(num))


def update_num_ordered(request, exp_id, id):
    num_ordered = 1
    num_per_exp = []
    print "id: " + id
    if 'num_per_exp' in request.session:
        num_per_exp = request.session['num_per_exp']

    if request.method == 'POST':
        num_ordered = int(request.POST['quantity'])
        # print "num_ordered: " + str(num_ordered)
        # num_per_exp.append(num_per_exp)
        request.session[str(id)] = num_ordered
        num_per_exp.insert(int(id), num_ordered)
        # print "num ordered of " + str(id) + ": " + str(num_ordered)
    request.session['num_per_exp'] = num_per_exp

    #Caroline 30/07/19: for cart purposes
    request.session['exp_most_recent'] = exp_id
    request.session['num_ordered'] = num_ordered

    return redirect("/add_order/" + exp_id + "/" + str(num_ordered)) #render(request, 'goskyhy/orders.html', data)


def remove_order(request, id):
    print "removing"
    #id is the id of exp to be removed
    #Caroline 31/07/19: working on removing an order
    # this_user = Users.objects.get(id=request.session['id'])
    # this_wish = Wish.objects.get(id=id)
    # this_wish.users.remove(this_user)    
    exp_id_list = request.session['exp_list']
    img_id_list = request.session['img_list']
    num_per_exp = request.session['num_per_exp']
    order_list = request.session['order_list'] #what's the purpose of this???

    for i in range(len(exp_id_list)):
        print exp_id_list[i]
        print img_id_list[i]
        print num_per_exp[i]

    index = exp_id_list.index(id)
    #delete records of stuff at that index
    del exp_id_list[index]
    del img_id_list[index]
    del num_per_exp[index]
    order_list -= 1

    #add new values to session
    request.session['exp_list'] = exp_id_list
    request.session['img_list'] = img_id_list
    request.session['num_per_exp'] = num_per_exp
    request.session['order_list'] = order_list

    for i in range(len(exp_id_list)):
        print exp_id_list[i]
        print img_id_list[i]
        print num_per_exp[i]

    if len(exp_id_list) == 0:
        print "is zero"
        return redirect("/add_order/" + str(0) + "/" + str(0))
    return redirect("/add_order/" + str(exp_id_list[len(exp_id_list) - 1]) + "/" + str(num_per_exp[len(num_per_exp) - 1]))


def buy_orders(request, id, recent_exp_id, recent_num_ordered):
    exp_id_list = []
    order = None #temp default

    session_id = str(int(request.session['id']))
    # print "id: " + id
    # print "session_id: " + session_id

    if session_id == id:
        print "entered"
        exp_id_list = request.session['exp_list']
        order = Orders.objects.create(order="temp replace later", summary="get data to replace later", user=Users.objects.get(id=id))
        order.save()

    total_cost = 0
    total_items = 0 #len(exp_id_list)

    num_per_exp = []
    j = 0

    for i in exp_id_list:
        num_ordered = request.session['num_per_exp'][j]
        print "exp #" + str(i) + " ordered: " + str(num_ordered)
        j += 1
        exp = Experiences.objects.get(id=i)
        exp.save()
        order.exps.add(exp)
        order.save()
        total_cost += int(float(exp.price.price)) * num_ordered
        total_items += num_ordered

    order_exps = Orders.exps.through.objects.all()

    exp_list = []
    for order_exp in order_exps:
        # print order_exp.experiences_id
        if order_exp.orders_id == order.id:
            exp_list.append(Experiences.objects.get(id=order_exp.experiences_id))

    request.session['total_cost'] = total_cost
    request.session['total_items'] = total_items
    order.total_cost = total_cost
    order.total_items = total_items
    order.save()

    request.session['order_id'] = order.id
    # request.session['exp_list'] = exp_list

    # return render(request, 'goskyhy/orders.html', data)
    return redirect('/add_order/' + str(recent_exp_id) + '/' + str(recent_num_ordered))

def choose_purchase_account(request):
    #decide whether to continue as guest or user

    return render(request, 'goskyhy/login_guest.html')

def checkout(request): #id later
    # order = Orders.objects.get(id=id)
    #TODO Caroline: Stripe API handling stuff

    data = {
        'total_cost': request.session['total_cost'],
        'total_items': request.session['total_items'],
        'order_id': request.session['order_id'] 
    }

    request.session['checkout'] = True
    return render(request, 'goskyhy/confirm_order.html', data) #later will be checkout.html


def purchase_receipt(request, order_id):
    #TODO Caroline: email receipt w/ order details to user + host

    order = Orders.objects.get(id=order_id)
    order_exps = Orders.exps.through.objects.filter(orders_id=order_id)
    exps_ordered = []
    sellers = []
    for order_exp in order_exps:
        exp = Experiences.objects.get(id=order_exp.experiences_id)
        exps_ordered.append(exp)
        sellers.append(exp.user)
        print exp.user.first_name + " " + exp.user.last_name

    #set up to send email
    # current_site = get_current_site(request)
    mail_subject = "Order #" + str(order_id) + " Summary"
    message = render_to_string('goskyhy/receipt_email.html', {
        'order': order,
        'exps': exps_ordered,
        'indices': range(len(exps_ordered)),
        'user': order.user,
        'sellers': sellers,
        'total_cost': request.session['total_cost'],
        'total_items': request.session['total_items']
        # 'domain': current_site.domain,
        # 'uid': urlsafe_base64_encode(force_bytes(user.id)), #does our user have a primary key? Should be id add .decode() if not working
        # 'token': account_activation_token.make_token(user)
    })
    buyer_email = order.user.email
    seller_emails = [exp.user.email for exp in exps_ordered]

    # email = EmailMessage(mail_subject, message, to=[buyer_email])
    # email.send()

    return redirect('/newsfeed')


#Caroline 03/07/19 end for orders

def logout(request):
    request.session.clear()
    request.session['not_logged_in'] = True
    request.session['logged_in'] = False
    return redirect('/')


def faq(request):
    #for FAQ and temporary bug purposes
    return render(request, 'goskyhy/faq.html')

#temporary helpers for writing experiences to database
def read_from_excel(request):
    if request.method == "POST":
        file_name, loc = upload_helper(request)
        loc = loc[1:]
        wb = xlrd.open_workbook(loc)
        sheet = wb.sheet_by_index(0) #first sheet

        sheet.cell_value(0, 0) #what is this value? maybe where to start counting?

        row_one = sheet.row_values(1) #indexed from 0, 0
        num_rows = sheet.nrows 
        num_cols = 19 #14#sheet.ncols
        exp_dict = None
        category_list = ['title', 'location', 'hours_total', 'category', 'lang', 'host_info', 'plans', 'notes', 'provided', 'to_bring', 'img_url', 'stars', 'price', 'num_reviews', 'address', 'city', 'country', 'zipcode', 'hashtags']

        #write into dictionary
        for i in range(num_rows):
            if i == 0:
                exp_dict = {
                    'title': [],
                    'location': [],
                    'hours_total': [],
                    'category': [],
                    'lang': [],
                    'host_info': [],
                    'plans': [],
                    'notes': [],
                    'provided': [],
                    'to_bring': [],
                    'img_url': [],
                    'stars': [],
                    'price': [],
                    'num_reviews': [],
                    'address': [],
                    'city': [],
                    'country': [],
                    'zipcode': [],
                    'hashtags': [],
                }
            else:
                row = sheet.row_values(i)[0 : 19]
                # print len(row)
                for j in range(num_cols):
                    exp_dict[category_list[j]].append(row[j])
        # print exp_dict

        # write into db
        # extra!!! = what to bring
        # title = models.CharField(max_length=255) YES
        # host = models.CharField(max_length=255) NO
        # description = models.CharField(max_length=255) YES
        # distance = models.CharField(max_length=255) NO
        # provided = models.CharField(max_length=255) YES
        # details = models.CharField(max_length=255) YES
        # created_at = models.DateTimeField(auto_now_add=True) NO
        # updated_at = models.DateTimeField(auto_now=True) NO
        # user = models.ForeignKey(Users, related_name="exp_user") NO (default?)
        # price = models.ForeignKey(Prices, related_name="exp_price") YES
        # agree = models.ForeignKey(Agrees, related_name="exp_agree") NO (default?)
        # english = models.ForeignKey(Language, related_name="exp_english") YES
        # city = models.ForeignKey(Cities, related_name='exp_city') NO (only location)
        # category = models.ForeignKey(Categories, related_name="exp_categories") YES
        # location = models.ForeignKey(Locations, related_name="exp_location") YES
        # times = models.ManyToManyField(Times, related_name='exps_times') NO
        # tag = models.ManyToManyField(Tags, related_name="exp_tags") NO
        # images = models.ManyToManyField(Images, related_name="exp_images") NO
        # print exp_dict.get('price')
        for i in range(len(exp_dict.get('title'))):
            title = exp_dict.get('title')[i]
            host = exp_dict.get('host_info')[i]
            description = exp_dict.get('plans')[i]
            distance = "Distance is not yet provided"
            provided = exp_dict.get('provided')[i]
            details = exp_dict.get('notes')[i]
            # user = Users.objects.create(username=str(i), email=str(i) + "@gmail.com", password="temptemp" + str(i))
            # user.save()
            user = Users.objects.get(id=(i + 1))
            price = Prices.objects.create(price=exp_dict.get('price')[i])
            price.save()
            agree = Agrees.objects.create() #temp all defaulted
            english = Language.objects.create(english=(exp_dict.get('lang')[i] == "Offered in English")) #doesn't check for all langs
            english.save()
            city = Cities.objects.create(city=exp_dict.get('location')[i], country=exp_dict.get('country')[i], zipcode=exp_dict.get('zipcode')[i])
            city.save()
            category = Categories.objects.create(category=exp_dict.get('category')[i])
            category.save()
            location = Locations.objects.create(address=exp_dict.get('address')[i], city=city) #Locations.objects.create(address="1427 Lyndon Street", apt_bldg="Unit C", city=city)
            times = Times.objects.create() #defaulted temp
            # tags = exp_dict.get('hashtags')[i] #Hashtags.objects.create(hashtag="temp")

            tag_text = exp_dict.get('hashtags')[i]
            list_of_chars = [c for c in tag_text]
            list_of_hashtags = []
            hashtag_starters = []
            get_tag_locations(list_of_chars, hashtag_starters=hashtag_starters)
            get_tags(hashtag_starters, list_of_chars, list_of_hashtags)

            images = Images.objects.create(path=exp_dict.get('img_url')[i], user=user)
            images.save()
            # print images.path
            experience = Experiences.objects.create(title=title, host=host, description=description, distance=distance, provided=provided, details=details, user=user, price=price, agree=agree, english=english, city=city, category=category, location=location)
            experience.save()
            experience.times.add(times)
            add_exp_to_db(experience, hashtags_to_add=list_of_hashtags)
            experience.images.add(images)
            experience.save()
            print "done w/ " + str(i)
        print "done writing " + loc
        return render(request, 'goskyhy/read_from_excel.html')

    return render(request, 'goskyhy/read_from_excel.html')

def create_users_excel(request):
    if request.method == "POST":
        file_name, loc = upload_helper(request)
        loc = loc[1:]
        wb = xlrd.open_workbook(loc)
        profs = wb.sheet_by_index(0) #first sheet
        users = wb.sheet_by_index(1)

        # sheet.cell_value(0, 0) #what is this value? maybe where to start counting?

        #going through users first
        row_one = users.row_values(1) #titles
        num_rows = users.nrows 
        num_cols = 5#sheet.ncols
        # exp_dict = None
        for i in range(num_rows):
            if i == 0:
                continue

            row = users.row_values(i)
            u = Users.objects.create(username=row[2], email=row[3], password=row[4])
            u.save()
            print "User #" + str(u.id) + ": " + u.username + ", " + u.email + ", " + u.password

        #going through profiles
        row_one = profs.row_values(1) #titles
        num_rows = profs.nrows
        num_cols = 9 #10th is activity name
        # Profile Picture   Background  Current Job Trips   Music Taste Uniqueness  User (Sheet 2)  Current City    Original City   User's Activity Name
        for i in range(num_rows):
            row = profs.row_values(i)
            # profile_pic = models.ForeignKey(Images, related_name="prof_images")
            # background = models.TextField()
            # current_job = models.CharField(max_length=255)
            # trips = models.CharField(max_length=255)
            # music = models.CharField(max_length=255)
            # uniqueness = models.CharField(max_length=255)
            # created_at = models.DateTimeField(auto_now_add=True)
            # updated_at = models.DateTimeField(auto_now=True)
            # user = models.ForeignKey(Users, related_name='prof_user')
            # curr_city = models.ForeignKey(Cities, related_name='prof_curr_city')
            # og_city = models.ForeignKey(Cities, related_name='prof_og_city')
            # friends manytomany
            if i == 0:
                continue
            u = Users.objects.get(id=i)
            img = Images.objects.create(path=row[0], user=u)
            img.save()
            curr_city = Cities.objects.create(city=row[7])
            og_city = Cities.objects.create(city=row[8])

            u_prof = UserProfiles.objects.create(profile_pic=img, background=row[1], current_job=row[2], trips=row[3], music=row[4], uniqueness=row[5], user=u, curr_city=curr_city, og_city=og_city)
            u_prof.save()
            print "User prof #" + str(u_prof.id) + ": " + u_prof.curr_city.city
    return render(request, 'goskyhy/read_from_excel_users.html')

