from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path('', main_view, name='main'),
    path("google/login/", google_login, name="google_login"),
    path('board/', board_view, name='board'),
    path("login/oauth2/google/", google_callback, name="google_callback"),
]