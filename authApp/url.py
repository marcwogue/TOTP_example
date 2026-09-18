

from django.urls import path
from authApp import views

urlpatterns =[
    path('signup',views.signup_view,name='signup'),
    path('login', views.login_view, name='login'),
    path("", views.dashboard_view, name= 'dashboard'),
    path ('setup_2fa', views.setup_2fa , name = 'setup_2fa'),
    path("disable_2fa", views.disable_2fa, name = 'disable_2fa'),
    path("logout", views.logout, name="logout"),
    path("verify_totp", views.verify_totp, name= "verify_totp"),
    path('totp-demo', views.totp_flow_view, name='totp'),

    
]