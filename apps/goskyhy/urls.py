from django.conf.urls import url, include

from . import views  # This line is new!


urlpatterns = [
    url(r'^$', views.index),  # This line has changed!
    url(r'^pitchdeck$', views.pitchdeck),

    url(r'^(?P<id>\d+)', views.index),
    url(r'^add_user$', views.add_user),
    url(r'^signin$', views.signin),
    url(r'^profile$', views.profile),
    url(r'^subscribe$', views.subscribe),
    url(r'^newsfeed$', views.newsfeed),
    #added for FAQ purposes
    url(r'^faq$', views.faq),
    #added for email verification
    url(r'activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.activate, name='activate'),

    # url(r'^registration_1$', views.registration_1),
    url(r'^registration_2$', views.registration_2),
    # url(r'^registration_3$', views.registration_3),
    url(r'^save_reg$', views.save_reg),

    url(r'^create_new$', views.create_new),
    url(r'^create_new2$', views.create_new2),
    url(r'^create_new3$', views.create_new3),
    url(r'^create_new4$', views.create_new4),
    url(r'^save_exp$', views.save_exp),

    url(r'^add_story$', views.add_story),
    url(r'^remove_story/(?P<id>\d+)', views.remove_story),

    url(r'^adventures$', views.adventures),
    url(r'^exp_details/(?P<id>\d+)/(?P<bought>\d+)', views.exp_details),
    url(r'^add_order/(?P<id>\d+)/(?P<num>\d+)', views.add_order),
    url(r'^buy_orders/(?P<id>\d+)/(?P<recent_exp_id>\d+)/(?P<recent_num_ordered>\d+)', views.buy_orders),
    url(r'^update_num_ordered/(?P<exp_id>\d+)/(?P<id>\d+)', views.update_num_ordered),
    url(r'^remove_order/(?P<id>\d+)', views.remove_order),
    url(r'^post_comment/(?P<exp_id>\d+)', views.post_comment),
    url(r'^checkout', views.checkout), #/(?P<id>\d+) later
    #work w/ guest purchasing
    url(r'^add_order_guest/(?P<id>\d+)/(?P<num>\d+)', views.add_order_guest),
    url(r'^buy_orders_guest/(?P<id>\d+)/(?P<recent_exp_id>\d+)/(?P<recent_num_ordered>\d+)', views.buy_orders_guest),
    url(r'^update_num_ordered_guest/(?P<exp_id>\d+)/(?P<id>\d+)', views.update_num_ordered_guest),
    url(r'^guest_user', views.choose_purchase_account),
    url(r'^add_guest', views.add_guest),
    url(r'^continue_as_guest', views.continue_as_guest),
    #work w/ cart
    url(r'^cart/(?P<exp_id>\d+)/(?P<num>\d+)/', views.see_cart),
    #email for receipt work
    url(r'^purchase_receipt/(?P<order_id>\d+)', views.purchase_receipt),

    # url(r'^search/queries=(?P<params>[^/]+)/page=(?P<id>\d+)', views.search),
    url(r'^search/(?P<id>\d+)', views.search),
    url(r'^param_to_encoded$', views.param_to_encoded),
    url(r'^searchengine$', views.searchengine),
    url(r'^login$', views.login),
    url(r'^logout$', views.logout),

    url(r'^imagefit/', include('imagefit.urls')),
    url(r'^friend_profile/(?P<id>\d+)', views.friend_profile), # later w/o friend_profile
    url(r'^add_friend/(?P<id>\d+)', views.add_friend),
    url(r'pending_friend_request', views.pending_friend_request),

    url(r'^image_tester', views.simple_upload),
    url(r'^scripts_temp', views.read_from_excel),
    url(r'^user_scripts_temp', views.create_users_excel),
    url(r'^accounts/', include('allauth.urls')),
]